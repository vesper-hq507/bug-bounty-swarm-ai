package provenance

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const masterKeySize = 32

// Keyring derives stable per-agent Ed25519 keys from one owner-only master key.
// The same state directory can therefore verify persisted blackboard findings
// after process restart without storing one private key per agent.
type Keyring interface {
	Signer(agentName string) (*Signer, error)
	PublicKey(agentName string) ([]byte, error)
}

type FileKeyring struct {
	master []byte
	mu     sync.Mutex
	cache  map[string]*Signer
}

func NewFileKeyring(root string) (*FileKeyring, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, fmt.Errorf("provenance keyring root is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("creating provenance keyring: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, fmt.Errorf("securing provenance keyring: %w", err)
	}

	path := filepath.Join(root, "master.key")
	master, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		candidate := make([]byte, masterKeySize)
		if _, err := rand.Read(candidate); err != nil {
			return nil, fmt.Errorf("generating provenance master key: %w", err)
		}
		f, createErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		switch {
		case createErr == nil:
			if _, err := f.Write(candidate); err != nil {
				_ = f.Close()
				return nil, fmt.Errorf("writing provenance master key: %w", err)
			}
			if err := f.Sync(); err != nil {
				_ = f.Close()
				return nil, fmt.Errorf("syncing provenance master key: %w", err)
			}
			if err := f.Close(); err != nil {
				return nil, err
			}
			master = candidate
		case os.IsExist(createErr):
			master, err = os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("reading concurrently-created provenance master key: %w", err)
			}
		default:
			return nil, fmt.Errorf("creating provenance master key: %w", createErr)
		}
	} else if err != nil {
		return nil, fmt.Errorf("reading provenance master key: %w", err)
	}
	if len(master) != masterKeySize {
		return nil, fmt.Errorf("provenance master key has invalid length %d", len(master))
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("securing provenance master key: %w", err)
	}
	return &FileKeyring{master: append([]byte(nil), master...), cache: map[string]*Signer{}}, nil
}

func (k *FileKeyring) Signer(agentName string) (*Signer, error) {
	if k == nil {
		return nil, fmt.Errorf("provenance keyring unavailable")
	}
	agentName = strings.TrimSpace(agentName)
	if agentName == "" {
		return nil, fmt.Errorf("agent name is required")
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	if s, ok := k.cache[agentName]; ok {
		return s, nil
	}
	mac := hmac.New(sha256.New, k.master)
	_, _ = mac.Write([]byte("pentestswarm:blackboard:"))
	_, _ = mac.Write([]byte(agentName))
	seed := mac.Sum(nil)
	priv := ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize])
	pub := append(ed25519.PublicKey(nil), priv.Public().(ed25519.PublicKey)...)
	s := &Signer{priv: priv, pub: pub}
	k.cache[agentName] = s
	return s, nil
}

func (k *FileKeyring) PublicKey(agentName string) ([]byte, error) {
	s, err := k.Signer(agentName)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), s.PublicKey()...), nil
}
