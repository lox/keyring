//go:build !windows
// +build !windows

package keyring

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func init() {
	supportedBackends[PassBackend] = opener(func(cfg Config) (backendKeyring, error) {
		var err error

		pass := &passKeyring{
			passcmd: cfg.PassCmd,
			dir:     cfg.PassDir,
			prefix:  cfg.PassPrefix,
		}

		if pass.passcmd == "" {
			pass.passcmd = "pass"
		}

		if pass.dir == "" {
			if passDir, found := os.LookupEnv("PASSWORD_STORE_DIR"); found {
				pass.dir = passDir
			} else {
				homeDir, err := os.UserHomeDir()
				if err != nil {
					return nil, err
				}
				pass.dir = filepath.Join(homeDir, ".password-store")
			}
		}

		pass.dir, err = ExpandTilde(pass.dir)
		if err != nil {
			return nil, err
		}

		// fail if the pass program is not available
		_, err = exec.LookPath(pass.passcmd)
		if err != nil {
			return nil, errors.New("pass program is not available")
		}

		return pass, nil
	})
}

type passKeyring struct {
	dir     string
	passcmd string
	prefix  string
}

func (k *passKeyring) pass(args ...string) *exec.Cmd {
	cmd := exec.Command(k.passcmd, args...) //nolint:noctx // The Keyring interface does not carry context.
	if k.dir != "" {
		cmd.Env = append(os.Environ(), fmt.Sprintf("PASSWORD_STORE_DIR=%s", k.dir))
	}
	cmd.Stderr = os.Stderr

	return cmd
}

func (k *passKeyring) Get(key string) (Item, error) {
	exists, err := k.itemExists(key)
	if err != nil {
		return Item{}, err
	}
	if !exists {
		return Item{}, ErrKeyNotFound
	}

	name, err := passEntryName(k.prefix, key)
	if err != nil {
		return Item{}, err
	}
	cmd := k.pass("show", name)
	output, err := cmd.Output()
	if err != nil {
		return Item{}, err
	}

	var decoded Item
	err = json.Unmarshal(output, &decoded)

	return decoded, err
}

func (k *passKeyring) GetMetadata(_ string) (Metadata, error) {
	return Metadata{}, ErrMetadataNotSupported
}

func (k *passKeyring) Set(i Item) error {
	bytes, err := json.Marshal(i)
	if err != nil {
		return err
	}

	name, err := passEntryName(k.prefix, i.Key)
	if err != nil {
		return err
	}
	cmd := k.pass("insert", "-m", "-f", name)
	cmd.Stdin = strings.NewReader(string(bytes))

	err = cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

func (k *passKeyring) Remove(key string) error {
	exists, err := k.itemExists(key)
	if err != nil {
		return err
	}
	if !exists {
		return ErrKeyNotFound
	}

	name, err := passEntryName(k.prefix, key)
	if err != nil {
		return err
	}
	cmd := k.pass("rm", "-f", name)
	err = cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

func (k *passKeyring) itemExists(key string) (bool, error) {
	path, err := k.passEntryPath(key)
	if err != nil {
		return false, err
	}
	_, err = os.Stat(path)

	return err == nil, nil
}

func (k *passKeyring) Keys() ([]string, error) {
	var keys = []string{}
	path, err := passPrefixPath(k.dir, k.prefix)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return keys, nil
		}
		return keys, err
	}
	if !info.IsDir() {
		return keys, fmt.Errorf("%s is not a directory", path)
	}

	err = filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && filepath.Ext(p) == ".gpg" {
			name := strings.TrimPrefix(p, path)
			if name[0] == os.PathSeparator {
				name = name[1:]
			}
			keys = append(keys, name[:len(name)-4])
		}
		return nil
	})

	return keys, err
}

func (k *passKeyring) passEntryPath(key string) (string, error) {
	name, err := passEntryName(k.prefix, key)
	if err != nil {
		return "", err
	}

	return filepath.Join(k.dir, name+".gpg"), nil
}

func passPrefixPath(dir, prefix string) (string, error) {
	if err := validatePassPathPart("prefix", prefix); err != nil {
		return "", err
	}
	if prefix == "" {
		return dir, nil
	}
	return filepath.Join(dir, prefix), nil
}

func passEntryName(prefix, key string) (string, error) {
	if err := validatePassPathPart("prefix", prefix); err != nil {
		return "", err
	}
	if key == "" {
		return "", fmt.Errorf("invalid pass key %q: empty keys are not allowed", key)
	}
	if err := validatePassPathPart("key", key); err != nil {
		return "", err
	}
	if prefix == "" {
		return key, nil
	}
	return filepath.Join(prefix, key), nil
}

func validatePassPathPart(label, value string) error {
	if value == "" {
		return nil
	}
	if filepath.IsAbs(value) {
		return fmt.Errorf("invalid pass %s %q: absolute paths are not allowed", label, value)
	}
	for _, part := range strings.Split(value, string(os.PathSeparator)) {
		if part == "." || part == ".." {
			return fmt.Errorf("invalid pass %s %q: dot path segments are not allowed", label, value)
		}
	}
	return nil
}
