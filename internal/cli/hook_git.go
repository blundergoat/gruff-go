package cli

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// exportGitTree materializes a git ref in a temporary directory for B3 diff baselines.
func exportGitTree(ctx context.Context, root, ref string) (string, func(), error) {
	// #nosec G204 -- ref is passed directly to git without shell expansion.
	command := exec.CommandContext(ctx, "git", "archive", "--format=tar", ref)
	command.Dir = root
	data, err := command.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", nil, fmt.Errorf("git archive failed: %s", strings.TrimSpace(string(exitErr.Stderr)))
		}
		return "", nil, err
	}
	dir, err := os.MkdirTemp("", "gruff-go-hook-base-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	if err := extractTar(data, dir); err != nil {
		cleanup()
		return "", nil, err
	}
	return dir, cleanup, nil
}

// gitWriteTree writes the current index to the object store and returns its tree
// SHA, so `--diff unstaged` new-only matching is measured against the index (the
// working tree's true base) rather than HEAD. The tree object is content-addressed
// and harmless if unreferenced; git garbage-collects it.
func gitWriteTree(ctx context.Context, root string) (string, error) {
	// #nosec G204 -- fixed subcommand, no user-controlled arguments.
	command := exec.CommandContext(ctx, "git", "write-tree")
	command.Dir = root
	out, err := command.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("git write-tree failed: %s", strings.TrimSpace(string(exitErr.Stderr)))
		}
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// extractTar expands a git archive into root while validating every path.
func extractTar(data []byte, root string) error {
	reader := tar.NewReader(bytes.NewReader(data))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target, err := safeTarTarget(root, header.Name)
		if err != nil {
			return err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			file, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return err
			}
			if _, err := io.Copy(file, reader); err != nil {
				_ = file.Close()
				return err
			}
			if err := file.Close(); err != nil {
				return err
			}
		}
	}
}

// safeTarTarget rejects archive entries that would escape the extraction root.
func safeTarTarget(root, name string) (string, error) {
	clean := filepath.Clean(name)
	if clean == "." || filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return "", fmt.Errorf("unsafe git archive path %q", name)
	}
	target := filepath.Join(root, clean)
	if rel, err := filepath.Rel(root, target); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe git archive path %q", name)
	}
	return target, nil
}
