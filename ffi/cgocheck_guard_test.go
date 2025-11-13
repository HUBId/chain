package ffi

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const cgocheckDirective = "//go:debug cgocheck=1"

func TestFirewoodTestEnforcesCgocheckDirective(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to determine test file path")
	}

	pkgDir := filepath.Dir(thisFile)
	var found bool
	err := filepath.WalkDir(pkgDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != pkgDir {
				return fs.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}

		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(contents), cgocheckDirective) {
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to scan ffi package for cgocheck directive: %v", err)
	}
	if !found {
		t.Fatalf("no Go source file in %s contains %q; restore the directive or update the guard if Go reintroduces support", pkgDir, cgocheckDirective)
	}
}
