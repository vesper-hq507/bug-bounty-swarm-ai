package chains

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// parseChain unmarshals + validates an exploit chain. src is used only for error
// messages (a path or an embedded name).
func parseChain(data []byte, src string) (*ExploitChain, error) {
	var c ExploitChain
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parsing exploit chain %s: %w", src, err)
	}
	if c.ID == "" {
		return nil, fmt.Errorf("exploit chain %s: id is required", src)
	}
	if c.Name == "" {
		return nil, fmt.Errorf("exploit chain %s: name is required", src)
	}
	if len(c.Links) == 0 {
		return nil, fmt.Errorf("exploit chain %s: at least one link is required", src)
	}
	return &c, nil
}

// LoadChain reads and parses an exploit chain YAML file from disk.
func LoadChain(path string) (*ExploitChain, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading exploit chain %s: %w", path, err)
	}
	return parseChain(data, path)
}

// LoadChainFS loads a chain named "<id>.yaml" from an fs.FS (the embedded
// default set, or a fetched-library dir).
func LoadChainFS(fsys fs.FS, name string) (*ExploitChain, error) {
	name = strings.TrimSuffix(name, ".yaml")
	data, err := fs.ReadFile(fsys, name+".yaml")
	if err != nil {
		return nil, fmt.Errorf("exploit chain %q not found: %w", name, err)
	}
	return parseChain(data, name)
}

// DiscoverChainsFS finds + parses all .yaml exploit chains in an fs.FS, sorted by
// id. Invalid files are skipped.
func DiscoverChainsFS(fsys fs.FS) []*ExploitChain {
	var out []*ExploitChain
	_ = fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		if data, rerr := fs.ReadFile(fsys, path); rerr == nil {
			if c, perr := parseChain(data, path); perr == nil {
				out = append(out, c)
			}
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// DiscoverChainsDir finds + parses all .yaml exploit chains under a directory on
// disk (e.g. the on-demand-fetched library). Missing dir → empty, no error.
func DiscoverChainsDir(dir string) []*ExploitChain {
	var out []*ExploitChain
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		if c, lerr := LoadChain(path); lerr == nil {
			out = append(out, c)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
