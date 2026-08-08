//go:build linux

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const linuxClientBinary = "/usr/local/bin/wireguard-p2p"
const linuxClientUnit = "/etc/systemd/system/wireguard-p2p-client.service"

func extractClientUpdate(payload []byte, dir string) error {
	gz, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(header.Name)
		if name == "." || filepath.IsAbs(name) || strings.HasPrefix(name, ".."+string(os.PathSeparator)) {
			return errors.New("unsafe path in update archive")
		}
		target := filepath.Join(dir, name)
		rel, err := filepath.Rel(dir, target)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return errors.New("unsafe path in update archive")
		}
		if header.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(header.Mode)&0777)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, tr)
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
}

func copyFileAtomic(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	tmp := dst + ".update-new"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

func runSystemctl(args ...string) error {
	command := exec.Command("systemctl", args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %s", strings.Join(args, " "), strings.TrimSpace(string(output)))
	}
	return nil
}

func applyPlatformUpdate(payload []byte, targetVersion string) error {
	if os.Geteuid() != 0 {
		return errors.New("run update as root: sudo wireguard-p2p update")
	}
	dir, err := os.MkdirTemp("", "wireguard-p2p-update-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err := extractClientUpdate(payload, dir); err != nil {
		return err
	}
	newBinary := filepath.Join(dir, "wireguard-p2p")
	newUnit := filepath.Join(dir, "wireguard-p2p-client.service")
	if _, err := os.Stat(newBinary); err != nil {
		return errors.New("update package is missing wireguard-p2p")
	}
	if _, err := os.Stat(newUnit); err != nil {
		return errors.New("update package is missing systemd unit")
	}

	oldBinary, _ := os.ReadFile(linuxClientBinary)
	oldUnit, _ := os.ReadFile(linuxClientUnit)
	rollback := func() {
		if len(oldBinary) > 0 {
			_ = os.WriteFile(linuxClientBinary, oldBinary, 0755)
		}
		if len(oldUnit) > 0 {
			_ = os.WriteFile(linuxClientUnit, oldUnit, 0644)
		}
		_ = runSystemctl("daemon-reload")
		_ = runSystemctl("restart", "wireguard-p2p-client.service")
	}

	if err := copyFileAtomic(newBinary, linuxClientBinary, 0755); err != nil {
		return err
	}
	if err := copyFileAtomic(newUnit, linuxClientUnit, 0644); err != nil {
		rollback()
		return err
	}
	if err := runSystemctl("daemon-reload"); err != nil {
		rollback()
		return err
	}
	if err := runSystemctl("restart", "wireguard-p2p-client.service"); err != nil {
		rollback()
		return err
	}
	if err := runSystemctl("is-active", "--quiet", "wireguard-p2p-client.service"); err != nil {
		rollback()
		return errors.New("new client did not become active; previous version restored")
	}
	fmt.Printf("Updated to %s and restarted wireguard-p2p-client.service.\n", targetVersion)
	return nil
}
