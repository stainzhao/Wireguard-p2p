import base64
from contextlib import ExitStack
import importlib.util
import os
import pathlib
import time
import unittest
import uuid
from unittest import mock


os.environ.setdefault("P2P_LISTEN_ADDRESS", "10.0.0.5")
ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("agent_worker_recovery", ROOT / "linux" / "p2p_agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)
KEY = base64.b64encode(b"x" * 32).decode()
CANDIDATES = [{"type": "host6", "family": "udp6", "endpoint": "[2409:8a04::1234]:51820", "priority": 910}]


class WorkerRecoveryTests(unittest.TestCase):
    def setUp(self):
        agent.STATES = {}
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.locals = self.stack.enter_context(mock.patch.object(agent, "local_wg_peers", return_value={}))
        self.wg = self.stack.enter_context(mock.patch.object(agent, "wg_set"))
        self.launch = self.stack.enter_context(mock.patch.object(agent, "launch_probe"))
        for name, value in (("save_state", None), ("local_ipv4", "192.168.1.5"),
                            ("listen_port", 51820), ("public_key", KEY),
                            ("gather_candidates", CANDIDATES), ("log_error", None)):
            self.stack.enter_context(mock.patch.object(agent, name, return_value=value))
        self.offer = dict(peer_key=KEY, peer_ip="10.0.0.8", session_id=str(uuid.uuid4()),
                          session_started_ns=agent.time_ns(), peer_instance_id=uuid.uuid4().hex,
                          candidates=CANDIDATES, lease_expires=time.time() + 180)

    def start_probe(self):
        agent.handle_offer(self.offer)
        return agent.STATES[KEY]["generation"]

    def assert_retries(self):
        state = agent.STATES[KEY]
        self.assertFalse(state["worker_running"])
        self.assertEqual(state["mode"], "idle")
        self.assertGreater(state["retry_after"], time.time())
        state["retry_after"] = 0
        self.locals.side_effect = None
        self.locals.return_value = {}
        self.launch.reset_mock()
        agent.monitor_once()
        self.launch.assert_called_once_with(KEY, state["generation"])

    def test_old_instance_cannot_roll_back_new_session(self):
        self.start_probe()
        original = dict(agent.STATES[KEY])
        result = agent.handle_offer(dict(self.offer, session_id=str(uuid.uuid4()),
                                        session_started_ns=self.offer["session_started_ns"] - 1,
                                        peer_instance_id=uuid.uuid4().hex))
        self.assertTrue(result.get("ignored"))
        self.assertEqual(agent.STATES[KEY], original)
        self.wg.assert_not_called()

    def test_instance_change_cannot_bypass_same_session_timestamp_check(self):
        self.start_probe()
        original = dict(agent.STATES[KEY])
        with self.assertRaises(ValueError):
            agent.handle_offer(dict(self.offer, session_started_ns=self.offer["session_started_ns"] - 1,
                                    peer_instance_id=uuid.uuid4().hex))
        self.assertEqual(agent.STATES[KEY], original)

    def test_replacement_and_removal_never_reuse_worker_generation(self):
        for replacement in ("instance", "session", "remove"):
            with self.subTest(replacement=replacement):
                agent.STATES = {}
                old_generation = self.start_probe()
                new_offer = dict(self.offer, session_id=str(uuid.uuid4()),
                                 session_started_ns=self.offer["session_started_ns"] + 1)
                if replacement == "instance":
                    new_offer["peer_instance_id"] = uuid.uuid4().hex
                elif replacement == "remove":
                    agent.handle_remove(self.offer)
                agent.handle_offer(new_offer)
                self.assertGreater(agent.STATES[KEY]["generation"], old_generation)
                self.assertFalse(agent.probe_generation_current(KEY, old_generation))

    def test_query_exception_releases_worker_and_monitor_retries(self):
        generation = self.start_probe()
        self.locals.side_effect = RuntimeError("simulated wg timeout")
        agent.probe_worker(KEY, generation)
        self.assert_retries()

    def test_promotion_exception_releases_worker(self):
        generation = self.start_probe()
        self.locals.side_effect = [{}, {KEY: {"latest_handshake": int(time.time()),
                                             "endpoint": CANDIDATES[0]["endpoint"]}}]
        def fail_promotion(*args):
            if "allowed-ips" in args:
                raise RuntimeError("simulated promotion failure")
        self.wg.side_effect = fail_promotion
        with mock.patch.object(agent.STOP, "wait", return_value=False):
            agent.probe_worker(KEY, generation)
        self.assert_retries()

    def test_confirmation_query_exception_releases_worker(self):
        generation = self.start_probe()
        state = agent.STATES[KEY]
        endpoint = CANDIDATES[0]["endpoint"]
        state.update(mode="direct", worker_running=False, endpoint=endpoint)
        self.locals.side_effect = RuntimeError("simulated confirmation query failure")
        with mock.patch.object(agent.STOP, "wait", return_value=False), \
                mock.patch.object(agent, "trigger_overlay_packet"):
            agent.confirmation_rekey_worker(KEY, generation, self.offer["peer_ip"], endpoint)
        self.assert_retries()

    def test_stale_worker_error_cannot_clean_up_replacement(self):
        generation = self.start_probe()
        def replace_then_fail():
            self.locals.side_effect = None
            agent.handle_offer(dict(self.offer, session_id=str(uuid.uuid4()),
                                    session_started_ns=self.offer["session_started_ns"] + 1,
                                    peer_instance_id=uuid.uuid4().hex))
            self.wg.reset_mock()
            raise RuntimeError("old worker failed after replacement")
        self.locals.side_effect = replace_then_fail
        agent.probe_worker(KEY, generation)
        self.assertTrue(agent.STATES[KEY]["worker_running"])
        self.assertEqual(agent.STATES[KEY]["mode"], "probe")
        self.wg.assert_not_called()

    def test_retry_has_new_generation_before_old_worker_finally_runs(self):
        generation = self.start_probe()
        def finish_then_retry(*args):
            state = agent.STATES[KEY]
            state.update(worker_running=False, mode="idle", retry_after=0)
            agent.monitor_once()
        with mock.patch.object(agent, "_probe_worker", side_effect=finish_then_retry):
            agent.probe_worker(KEY, generation)
        self.assertGreater(agent.STATES[KEY]["generation"], generation)
        self.assertTrue(agent.STATES[KEY]["worker_running"])
        self.wg.assert_not_called()

    def test_successful_probe_preserves_direct(self):
        generation = self.start_probe()
        self.locals.side_effect = [{}, {KEY: {"latest_handshake": int(time.time()),
                                             "endpoint": CANDIDATES[0]["endpoint"]}}]
        with mock.patch.object(agent.STOP, "wait", return_value=False), \
                mock.patch.object(agent, "should_confirmation_rekey", return_value=False):
            agent.probe_worker(KEY, generation)
        self.assertEqual(agent.STATES[KEY]["mode"], "direct")
        self.assertFalse(agent.STATES[KEY]["worker_running"])
        self.assertFalse(any("remove" in call.args for call in self.wg.call_args_list))

    def test_confirmation_finalize_failure_releases_worker(self):
        generation = self.start_probe()
        endpoint = CANDIDATES[0]["endpoint"]
        agent.STATES[KEY].update(mode="direct", worker_running=False, endpoint=endpoint)
        self.locals.return_value = {KEY: {"latest_handshake": int(time.time()), "endpoint": endpoint}}
        self.wg.side_effect = [None, None, RuntimeError("confirmation finalize failed"), None]
        with mock.patch.object(agent.STOP, "wait", return_value=False), \
                mock.patch.object(agent, "trigger_overlay_packet"):
            agent.confirmation_rekey_worker(KEY, generation, self.offer["peer_ip"], endpoint)
        self.assert_retries()


if __name__ == "__main__":
    unittest.main()
