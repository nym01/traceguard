package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A full-length (64 hex) container id used across the path-parsing cases.
const testID = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"

func TestContainerIDFromCgroupPath(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		wantID string
		wantOK bool
	}{
		{
			name:   "cgroupfs driver",
			path:   "/sys/fs/cgroup/docker/" + testID,
			wantID: testID,
			wantOK: true,
		},
		{
			name:   "systemd driver",
			path:   "/sys/fs/cgroup/system.slice/docker-" + testID + ".scope",
			wantID: testID,
			wantOK: true,
		},
		{
			name:   "host root cgroup",
			path:   "/sys/fs/cgroup",
			wantOK: false,
		},
		{
			name:   "plain systemd service",
			path:   "/sys/fs/cgroup/system.slice/sshd.service",
			wantOK: false,
		},
		{
			name:   "user slice",
			path:   "/sys/fs/cgroup/user.slice/user-1000.slice/session-3.scope",
			wantOK: false,
		},
		{
			name:   "docker segment but invalid (short) id",
			path:   "/sys/fs/cgroup/docker/deadbeef",
			wantOK: false,
		},
		{
			name:   "systemd docker scope with non-hex id",
			path:   "/sys/fs/cgroup/system.slice/docker-notahexcontaineridnotahexcontaineridnotahexcontaineridnotahex01.scope",
			wantOK: false,
		},
		{
			name:   "empty path",
			path:   "",
			wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, ok := containerIDFromCgroupPath(tc.path)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && id != tc.wantID {
				t.Fatalf("id = %q, want %q", id, tc.wantID)
			}
		})
	}
}

func TestShortID(t *testing.T) {
	if got := shortID(testID); got != testID[:12] {
		t.Fatalf("shortID = %q, want %q", got, testID[:12])
	}
	if got := shortID("abc"); got != "abc" {
		t.Fatalf("shortID short input = %q, want %q", got, "abc")
	}
}

func TestTrimContainerName(t *testing.T) {
	if got := trimContainerName("/payment-service\n"); got != "payment-service" {
		t.Fatalf("trimContainerName = %q, want %q", got, "payment-service")
	}
	if got := trimContainerName("  /web  "); got != "web" {
		t.Fatalf("trimContainerName = %q, want %q", got, "web")
	}
}

// TestResolveContainerName_NoMatch documents the common path: when cgroupRoot
// holds no directory whose inode matches, resolution returns "" (not a
// container) rather than erroring out and breaking the alert pipeline.
func TestResolveContainerName_NoMatch(t *testing.T) {
	saved := cgroupRoot
	cgroupRoot = t.TempDir() // empty: no inode can match
	defer func() { cgroupRoot = saved }()

	// A cgroup id that can't exist under an empty temp dir.
	if got := resolveContainerName(0xdeadbeefdeadbeef); got != "" {
		t.Fatalf("resolveContainerName = %q, want \"\"", got)
	}
}

// TestFindCgroupPath doesn't need a real cgroup mount: findCgroupPath matches
// by inode, so we point it at a temp directory and look up that directory's
// own inode, which it must locate.
func TestFindCgroupPath(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "docker", testID)
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(target, &st); err != nil {
		t.Fatal(err)
	}
	got, err := findCgroupPath(root, st.Ino)
	if err != nil {
		t.Fatalf("findCgroupPath: %v", err)
	}
	if got != target {
		t.Fatalf("findCgroupPath = %q, want %q", got, target)
	}

	// A non-existent inode must error (the "not a container" path).
	if _, err := findCgroupPath(root, 0); err == nil {
		t.Fatal("findCgroupPath with bogus inode: expected error, got nil")
	}
}
