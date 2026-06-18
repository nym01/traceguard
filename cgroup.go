package main

import (
	"context"
	"fmt"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// cgroup.go turns a kernel cgroup id into a human-readable container name.
//
// On cgroup v2 the value returned by bpf_get_current_cgroup_id() *is* the
// inode number of a directory on the cgroup2 filesystem (mounted at
// /sys/fs/cgroup). There is no syscall to map a cgroup id back to its path,
// so the standard approach is to walk the cgroup tree and stat each directory
// until we find the one whose inode matches. From the directory name we can
// recover the container id (Docker encodes it into the cgroup path), and from
// the id we ask the Docker daemon for the friendly name.

// cgroupRoot is the cgroup2 mount point to walk. It's a package-level variable
// rather than a hardcoded literal so tests can point resolution at a t.TempDir()
// and not depend on the real host filesystem.
var cgroupRoot = "/sys/fs/cgroup"

// containerNameCache memoizes cgroup-id -> container-name lookups. Resolving a
// name means walking cgroupRoot plus a `docker inspect` shell-out, neither of
// which should repeat for every event sharing a cgroup id. The empty string
// (and the short-id fallback) are cached too, so a non-container cgroup or a
// repeated Docker failure doesn't re-walk the tree on every alert.
var containerNameCache sync.Map // map[uint64]string

// resolveContainerName turns a kernel cgroup id into a friendly container name,
// or "" when the cgroup isn't a container (host root, a systemd service, etc.).
// It never returns an error: a name lookup failing must not fail the alert
// pipeline, so the worst case is an empty string or a truncated-id fallback.
func resolveContainerName(cgroupID uint64) string {
	if v, ok := containerNameCache.Load(cgroupID); ok {
		return v.(string)
	}
	name := lookupContainerName(cgroupID)
	containerNameCache.Store(cgroupID, name)
	return name
}

// lookupContainerName does the uncached work behind resolveContainerName.
func lookupContainerName(cgroupID uint64) string {
	path, err := findCgroupPath(cgroupRoot, cgroupID)
	if err != nil {
		return "" // no matching cgroup dir — treat as "not a container"
	}
	id, ok := containerIDFromCgroupPath(path)
	if !ok {
		return "" // a real cgroup, but not a Docker container
	}

	// Ask the Docker daemon for the friendly name. Bound the call so a hung
	// or unresponsive daemon can't stall alert processing.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.Name}}", id).Output()
	if err != nil {
		// docker missing, container already gone, permission denied, timeout —
		// a truncated id is still more useful to an analyst than nothing.
		return "container:" + shortID(id)
	}
	name := trimContainerName(string(out))
	if name == "" {
		return "container:" + shortID(id)
	}
	return name
}

// findCgroupPath walks the cgroup2 hierarchy under root and returns the path
// of the directory whose inode equals cgroupID. Unreadable entries are skipped
// rather than aborting the walk. Returns an error when no directory matches —
// that's the normal case for the host root cgroup and most non-container work,
// and callers treat it as "not a container" rather than a hard failure.
func findCgroupPath(root string, cgroupID uint64) (string, error) {
	var found string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// A directory we can't read (permissions, races with cgroups
			// being torn down) shouldn't abort the whole walk.
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		var st syscall.Stat_t
		if err := syscall.Stat(path, &st); err != nil {
			return nil
		}
		if st.Ino == cgroupID {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("no cgroup directory with inode %d under %s", cgroupID, root)
	}
	return found, nil
}

// containerIDFromCgroupPath extracts a Docker container id from a cgroup path,
// recognizing both cgroup-driver conventions Docker can be configured with:
//
//	cgroupfs driver: .../docker/<64-hex-id>
//	systemd driver:  .../docker-<64-hex-id>.scope
//
// It returns ok=false for anything that isn't a Docker container cgroup — the
// host root cgroup, a plain systemd service, a user slice, etc. — which is the
// common case for most events.
func containerIDFromCgroupPath(path string) (string, bool) {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		// systemd driver: a single "docker-<id>.scope" path component.
		if strings.HasPrefix(p, "docker-") && strings.HasSuffix(p, ".scope") {
			id := strings.TrimSuffix(strings.TrimPrefix(p, "docker-"), ".scope")
			if isHexID(id) {
				return id, true
			}
		}
		// cgroupfs driver: a "docker" component followed by the id component.
		if p == "docker" && i+1 < len(parts) {
			if id := parts[i+1]; isHexID(id) {
				return id, true
			}
		}
	}
	return "", false
}

// isHexID reports whether s is a full-length (64-char) lowercase/uppercase
// hex container id. Requiring the full length avoids misreading an unrelated
// "docker" path segment as a container.
func isHexID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// shortID truncates a 64-char container id to the 12-char short form Docker
// itself displays. A shorter-than-12 id (shouldn't happen) is returned as-is.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// trimContainerName cleans up the output of `docker inspect --format
// {{.Name}}`, which comes back as a leading-slash, trailing-newline string
// like "/payment-service\n". Returns just "payment-service".
func trimContainerName(s string) string {
	return strings.TrimPrefix(strings.TrimSpace(s), "/")
}
