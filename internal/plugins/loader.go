package plugins

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// parsePlaybook unmarshals + validates playbook YAML. src is used only for
// error messages (a path or an embedded name).
func parsePlaybook(data []byte, src string) (*Playbook, error) {
	var pb Playbook
	if err := yaml.Unmarshal(data, &pb); err != nil {
		return nil, fmt.Errorf("parsing playbook %s: %w", src, err)
	}
	if pb.Name == "" {
		return nil, fmt.Errorf("playbook %s: name is required", src)
	}
	if len(pb.Phases) == 0 {
		return nil, fmt.Errorf("playbook %s: at least one phase is required", src)
	}
	return &pb, nil
}

// LoadPlaybook reads and parses a playbook YAML file from disk.
func LoadPlaybook(path string) (*Playbook, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading playbook %s: %w", path, err)
	}
	return parsePlaybook(data, path)
}

// LoadPlaybookFS loads a playbook named "<name>.yaml" from an fs.FS (e.g. the
// binary's embedded playbooks). Used as the fallback when a playbook isn't on
// disk, so distributed installs can run bundled playbooks by name.
func LoadPlaybookFS(fsys fs.FS, name string) (*Playbook, error) {
	name = strings.TrimSuffix(name, ".yaml")
	data, err := fs.ReadFile(fsys, name+".yaml")
	if err != nil {
		return nil, fmt.Errorf("embedded playbook %q not found: %w", name, err)
	}
	return parsePlaybook(data, name+" (bundled)")
}

// DiscoverPlaybooksFS finds and parses all .yaml playbooks in an fs.FS, sorted
// by name. Invalid files are skipped.
func DiscoverPlaybooksFS(fsys fs.FS) ([]*Playbook, error) {
	var playbooks []*Playbook
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		data, rerr := fs.ReadFile(fsys, path)
		if rerr != nil {
			return nil
		}
		if pb, perr := parsePlaybook(data, path); perr == nil {
			playbooks = append(playbooks, pb)
		}
		return nil
	})
	sort.Slice(playbooks, func(i, j int) bool { return playbooks[i].Name < playbooks[j].Name })
	return playbooks, err
}

// LoadCustomTool reads and parses a custom tool YAML definition.
func LoadCustomTool(path string) (*CustomToolDef, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading tool def %s: %w", path, err)
	}

	var tool CustomToolDef
	if err := yaml.Unmarshal(data, &tool); err != nil {
		return nil, fmt.Errorf("parsing tool def %s: %w", path, err)
	}

	if tool.Name == "" || tool.Command == "" {
		return nil, fmt.Errorf("tool def %s: name and command are required", path)
	}

	return &tool, nil
}

// DiscoverPlaybooks finds all .yaml playbook files in a directory.
func DiscoverPlaybooks(dir string) ([]*Playbook, error) {
	var playbooks []*Playbook

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip errors
		}
		if info.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}

		pb, err := LoadPlaybook(path)
		if err != nil {
			return nil // skip invalid playbooks
		}

		playbooks = append(playbooks, pb)
		return nil
	})

	return playbooks, err
}

// DiscoverCustomTools finds all tool definitions in a directory.
func DiscoverCustomTools(dir string) ([]*CustomToolDef, error) {
	var tools []*CustomToolDef

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}

		tool, err := LoadCustomTool(path)
		if err != nil {
			return nil
		}

		tools = append(tools, tool)
		return nil
	})

	return tools, err
}
