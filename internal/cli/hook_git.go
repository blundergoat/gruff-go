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
	"slices"
	"strings"
)

// exportGitTree materializes a git ref in a temporary directory for B3 diff
// baselines, scoped to the paths needed by the hook invocation. Explicit Go
// files widen to their package directory so project rules retain sibling context.
func exportGitTree(ctx context.Context, root, ref string, paths []string) (string, func(), error) {
	archivePaths, scoped, err := hookBaseArchivePaths(ctx, root, ref, paths)
	if err != nil {
		return "", nil, err
	}
	if scoped && len(archivePaths) == 0 {
		return emptyHookBaseDir()
	}
	args := []string{"archive", "--format=tar", ref}
	if scoped {
		args = append(args, "--")
		args = append(args, archivePaths...)
	}
	// #nosec G204 -- arguments are passed directly to git without shell expansion.
	command := exec.CommandContext(ctx, "git", args...)
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

// emptyHookBaseDir creates a temporary base root for paths absent from the git
// base, such as newly-created files.
func emptyHookBaseDir() (string, func(), error) {
	dir, err := os.MkdirTemp("", "gruff-go-hook-base-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	return dir, cleanup, nil
}

// hookBaseArchivePaths resolves user paths to git archive pathspecs. A false
// scoped return means the whole tree is required.
func hookBaseArchivePaths(ctx context.Context, root, ref string, paths []string) ([]string, bool, error) {
	if len(paths) == 0 {
		return nil, false, nil
	}
	archivePaths := map[string]struct{}{}
	for _, input := range paths {
		candidate, fullTree, ok := hookBaseArchivePath(root, input)
		if !ok {
			continue
		}
		if fullTree {
			return nil, false, nil
		}
		exists, err := gitTreeHasPath(ctx, root, ref, candidate)
		if err != nil {
			return nil, true, err
		}
		if exists {
			archivePaths[candidate] = struct{}{}
		}
	}
	out := make([]string, 0, len(archivePaths))
	for path := range archivePaths {
		out = append(out, path)
	}
	slices.Sort(out)
	return out, true, nil
}

// hookBaseArchivePath maps one hook path to the smallest base-tree path that
// preserves analysis context.
func hookBaseArchivePath(root, input string) (string, bool, bool) {
	if input == "" {
		return "", false, false
	}
	path := input
	if filepath.IsAbs(path) {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return "", false, false
		}
		path = rel
	}
	clean := filepath.ToSlash(filepath.Clean(path))
	if clean == "." {
		return "", true, true
	}
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false, false
	}
	if strings.HasSuffix(clean, ".go") {
		dir := slashParentDir(clean)
		if dir == "" {
			return "", true, true
		}
		return dir, false, true
	}
	return clean, false, true
}

// slashParentDir returns the slash-separated parent directory or empty for root.
func slashParentDir(path string) string {
	index := strings.LastIndex(path, "/")
	if index <= 0 {
		return ""
	}
	return path[:index]
}

// gitTreeHasPath reports whether ref contains any tracked file under path.
func gitTreeHasPath(ctx context.Context, root, ref, path string) (bool, error) {
	args := []string{"ls-tree", "-r", "--name-only", ref, "--", path}
	// #nosec G204 -- arguments are passed directly to git without shell expansion.
	command := exec.CommandContext(ctx, "git", args...)
	command.Dir = root
	out, err := command.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return false, fmt.Errorf("git ls-tree failed: %s", strings.TrimSpace(string(exitErr.Stderr)))
		}
		return false, err
	}
	return strings.TrimSpace(string(out)) != "", nil
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
