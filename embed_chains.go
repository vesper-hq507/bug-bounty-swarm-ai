package pentestswarm

import (
	"embed"
	"io/fs"
)

//go:embed chains
var chainsFS embed.FS

// BundledChains returns the embedded exploit-chain library rooted so entries are
// addressed as "<id>.yaml". This is the small curated default set shipped in the
// binary; the rest of the library is fetched on demand (pentestswarm chains update)
// so a fresh chain can ship the day a CVE drops, without a new binary release.
func BundledChains() fs.FS {
	sub, err := fs.Sub(chainsFS, "chains")
	if err != nil {
		return chainsFS
	}
	return sub
}
