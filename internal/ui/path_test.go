package ui

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestNormalizeOptionalPathFromFileURI(t *testing.T) {
	if runtime.GOOS == "windows" {
		got := normalizeOptionalPath("file:///C:/Develop/home/bd-analyzer/examples/demo/postgresql.conf")
		want := filepath.Clean(`C:\Develop\home\bd-analyzer\examples\demo\postgresql.conf`)
		if got != want {
			t.Fatalf("expected %q, got %q", want, got)
		}
		return
	}

	got := normalizeOptionalPath("file:///tmp/demo/postgresql.conf")
	want := filepath.Clean("/tmp/demo/postgresql.conf")
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestNormalizeOptionalPathLeavesPlainPath(t *testing.T) {
	input := filepath.Join("examples", "demo", "pg_hba.conf")
	if got := normalizeOptionalPath(input); got != filepath.Clean(input) {
		t.Fatalf("expected %q, got %q", filepath.Clean(input), got)
	}
}
