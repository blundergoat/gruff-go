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

// exportGitTree materializes a git ref in a temporary directory as the B3 diff baseline for a gruff-go hook run with --diff.
//
// The export is scoped to the paths the hook invocation needs.
// An explicit Go file widens to its package directory, so project rules keep sibling context.
//
// root is the repository git runs in, ref the commit or tree to export, and paths the hook's inputs; with no paths the whole tree is exported.
// It returns the temporary directory and a cleanup func that removes it; a scoped export is empty when no resolved archive path exists at ref.
// It fails with an error and a nil cleanup when path resolution, git archive, the temporary directory or tar extraction fails.
func exportGitTree(ctx context.Context, root, ref string, paths []string) (string, func(), error) {
	archivePaths, scoped, err := hookBaseArchivePaths(ctx, root, ref, paths)
	if err != nil {
		return "", nil, err
	}
	// No resolved path exists at ref, as when the hook checks a new package directory added since that commit, so the base is an empty directory.
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
	// A base ref git cannot resolve in a whole-tree run, such as a mistyped branch, fails here with git's stderr as the error text.
	// A git binary missing from PATH returns the exec error unchanged.
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
	// A failed write, such as a full disk, or an unsafe entry path aborts the export, and the partial tree is removed first.
	if err := extractTar(data, dir); err != nil {
		cleanup()
		return "", nil, err
	}
	return dir, cleanup, nil
}

// emptyHookBaseDir creates an empty base root for when no resolved hook path exists at the git base, such as a newly added package directory.
// It returns the new directory and a cleanup func that removes it; if MkdirTemp fails it returns an error and a nil cleanup.
func emptyHookBaseDir() (string, func(), error) {
	dir, err := os.MkdirTemp("", "gruff-go-hook-base-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	return dir, cleanup, nil
}

// hookBaseArchivePaths resolves user paths to git archive pathspecs; a false scoped result means the whole tree is required.
//
// root is the repository directory, ref the tree checked with git ls-tree, and paths the user's inputs, absolute or relative to root.
// It returns sorted, de-duplicated pathspecs that exist at ref, an empty list when none does; inputs outside root are skipped.
// No paths, the root itself or a Go file at the root gives scoped false; a failed ls-tree returns its error with scoped true.
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
		// A git ls-tree failure stops base preparation for the hook.
		// The hook then exits 2 with a fatal baseline payload, unless isDegradableHookGitBaseError accepts it and the run drops only the git baseline.
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

// hookBaseArchivePath maps one hook path to the smallest base-tree path that preserves analysis context.
//
// input is one hook path, made relative to root when absolute; a Go file maps to its package directory and any other path to its cleaned form.
// It returns that slash-separated path, then a full-tree flag that is true, with an empty path, for the root or a Go file at the root.
// The third result is false for an empty input or one that cannot be made relative to root or resolves outside it.
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
// path is a slash-separated path, and the result is empty when it has no slash or its last slash is the first character.
func slashParentDir(path string) string {
	index := strings.LastIndex(path, "/")
	if index <= 0 {
		return ""
	}
	return path[:index]
}

// gitTreeHasPath reports whether ref contains any tracked file under path.
//
// root is the repository directory git ls-tree runs in, and path may name a file or a directory.
// When git ls-tree fails it returns false and an error, which quotes git's stderr when the command exited non-zero.
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

// gitWriteTree writes the current index as a tree object and returns its SHA, the base for --diff unstaged new-only matching.
//
// Measuring against the index, the working tree's true base, rather than HEAD keeps a finding already in staged content from resurfacing.
// The tree object is content-addressed and harmless if unreferenced; git garbage-collects it.
//
// root is the repository directory git runs in, so its index is the one written.
// When git write-tree fails it returns an empty string and an error, which quotes git's stderr when the command exited non-zero.
func gitWriteTree(ctx context.Context, root string) (string, error) {
	// #nosec G204 -- fixed subcommand, no user-controlled arguments.
	command := exec.CommandContext(ctx, "git", "write-tree")
	command.Dir = root
	out, err := command.Output()
	// Running outside a git repository, or with an unmerged index in the middle of a merge conflict, makes git write-tree fail here.
	// gruff-go hook --diff unstaged then exits 2 with a fatal baseline payload, unless isDegradableHookGitBaseError accepts the error for that mode.
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("git write-tree failed: %s", strings.TrimSpace(string(exitErr.Stderr)))
		}
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// extractTar expands a git archive into root while validating every path.
//
// data is the tar stream from git archive, and root the directory receiving its directories and regular files; other entry types are skipped.
// It returns nil at the end of the stream, and an error when the tar cannot be read, an entry path is unsafe, or a directory or file write fails.
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
		// Symlinks and other entry types are skipped, so the base tree never holds a link that points outside the temporary directory.
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
//
// name is the archive entry name and root the extraction directory; the result is the cleaned name joined under root.
// It returns an empty string and an error quoting name when name is empty, cleans to a dot such as dir/.., is absolute, or would escape root.
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
