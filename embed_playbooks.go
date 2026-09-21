// Package pentestswarm (the module root) exists to embed repo assets into the
// compiled binary so distributed installs (npm, Homebrew, go install, Docker)
// ship the bundled playbooks without needing a repo checkout on disk. A
// playbook present in ./playbooks always overrides its embedded copy.
package pentestswarm

import (
	"embed"
	"io/fs"
)

//go:embed playbooks
var playbooksFS embed.FS

// BundledPlaybooks returns the embedded playbooks tree rooted so that entries
// are addressed as "<name>.yaml" (e.g. "bug-bounty.yaml").
func BundledPlaybooks() fs.FS {
	sub, err := fs.Sub(playbooksFS, "playbooks")
	if err != nil {
		return playbooksFS
	}
	return sub
}
