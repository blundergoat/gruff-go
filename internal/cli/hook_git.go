// Package cli exports git base trees for gruff-go hook diff runs.
//
// For gruff-go hook --diff <ref>, this file materializes only the needed repository paths at <ref> into an isolated temporary directory.
// Reading blobs via git ls-tree and git cat-file bypasses .gitattributes export-ignore and export-subst while rejecting symlinks and unsafe paths.
package cli

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// gitTreeEntry describes one regular blob entry returned by git ls-tree for base-tree materialization.
type gitTreeEntry struct {
	sha  string
	path string
}

// exportGitTree materializes a git ref in a temporary directory as the B3 diff baseline for a gruff-go hook run with --diff.
//
// The export is scoped to the paths the hook invocation needs, reading tree entries via git ls-tree and git cat-file so .gitattributes
// export-ignore (for example on .github/workflows/) never hides committed files from new-only comparison.
//
// root is the repository git runs in, ref the commit or tree to export, and paths the hook's inputs (empty exports the whole tree).
// It returns the temp directory and cleanup func (empty when nothing exists at ref), or an error and nil cleanup if git or file writes fail.
func exportGitTree(ctx context.Context, root, ref string, paths []string) (string, func(), error) {
	if strings.HasPrefix(ref, "-") {
		return "", nil, fmt.Errorf("git base ref %q must not start with '-'", ref)
	}
	exportPaths, scoped, err := hookBaseExportPaths(ctx, root, ref, paths)
	if err != nil {
		return "", nil, err
	}
	// No resolved path exists at ref, as when the hook checks a new package directory added since that commit, so the base is an empty directory.
	if scoped && len(exportPaths) == 0 {
		return emptyHookBaseDir()
	}
	entries, err := gitTreeRegularBlobs(ctx, root, ref, exportPaths, scoped)
	if err != nil {
		return "", nil, err
	}
	// A base revision with none of the edited files, such as files added since, has no earlier findings to compare against.
	if len(entries) == 0 {
		return emptyHookBaseDir()
	}
	dir, err := os.MkdirTemp("", "gruff-go-hook-base-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	// A failed write, missing object, or unsafe entry path aborts the export, and the partial tree is removed first.
	if err := writeGitTreeBlobs(ctx, root, entries, dir); err != nil {
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

// hookBaseExportPaths resolves user paths to git ls-tree pathspecs; a false scoped result means the whole tree is required.
//
// root is the repository directory, ref the tree checked with git ls-tree, and paths the hook's inputs (absolute or relative to root).
// Returns sorted pathspecs existing at ref (empty if none); empty paths, root, or root Go files give scoped false, and ls-tree errors return true.
func hookBaseExportPaths(ctx context.Context, root, ref string, paths []string) ([]string, bool, error) {
	if len(paths) == 0 {
		return nil, false, nil
	}
	exportSet := map[string]struct{}{}
	for _, input := range paths {
		candidate, fullTree, ok := hookBaseExportPath(root, input)
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
			exportSet[candidate] = struct{}{}
		}
	}
	out := make([]string, 0, len(exportSet))
	for path := range exportSet {
		out = append(out, path)
	}
	slices.Sort(out)
	return out, true, nil
}

// hookBaseExportPath maps one hook path to the smallest base-tree path that preserves analysis context.
//
// input is resolved relative to root; Go files map to their package directory, and root or root Go files return an empty path with fullTree true.
// The third result is false when input is empty, cannot be made relative to root, or resolves outside root.
func hookBaseExportPath(root, input string) (string, bool, bool) {
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
	if strings.HasPrefix(ref, "-") {
		return false, fmt.Errorf("git base ref %q must not start with '-'", ref)
	}
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

// gitTreeRegularBlobs lists regular file blobs in root at ref under exportPaths (or the whole tree when scoped is false).
//
// Symlinks (120000), submodules (160000), and non-blob entries are skipped so the exported base contains only safe regular files.
// It returns the matched gitTreeEntry slice (empty when none exist), or an error when git ls-tree fails or cannot be started.
func gitTreeRegularBlobs(ctx context.Context, root, ref string, exportPaths []string, scoped bool) ([]gitTreeEntry, error) {
	args := []string{"ls-tree", "-r", "-z", ref}
	// A scoped export lists only the edited paths, so a large repository is not copied for a one-file hook run.
	if scoped {
		args = append(args, "--")
		args = append(args, exportPaths...)
	}
	// #nosec G204 -- arguments are passed directly to git without shell expansion.
	command := exec.CommandContext(ctx, "git", args...)
	command.Dir = root
	out, err := command.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("git ls-tree failed: %s", strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, err
	}
	entries := []gitTreeEntry{}
	for _, record := range bytes.Split(out, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		meta, pathPart, ok := strings.Cut(string(record), "\t")
		// A record without a tab-separated path is not a file entry.
		if !ok || pathPart == "" {
			continue
		}
		fields := strings.Fields(meta)
		// Only ordinary and executable files are exported; symlinks and submodules could point outside the temporary base folder.
		if len(fields) != 3 || fields[1] != "blob" || (fields[0] != "100644" && fields[0] != "100755") {
			continue
		}
		entries = append(entries, gitTreeEntry{sha: fields[2], path: pathPart})
	}
	return entries, nil
}

// writeGitTreeBlobs reads every blob listed in entries from root via one git cat-file --batch subprocess and writes them safely under destRoot.
//
// Each entry path is validated through safeExportTarget before any parent directory or file is created under destRoot.
// It returns nil on success, or an error when git cat-file fails, a blob header is invalid, or a file write fails.
func writeGitTreeBlobs(ctx context.Context, root string, entries []gitTreeEntry, destRoot string) error {
	var stdin bytes.Buffer
	for _, entry := range entries {
		stdin.WriteString(entry.sha)
		stdin.WriteByte('\n')
	}
	// #nosec G204 -- fixed git subcommand reading SHA list from stdin without shell expansion.
	command := exec.CommandContext(ctx, "git", "cat-file", "--batch")
	command.Dir = root
	command.Stdin = &stdin
	var stderr bytes.Buffer
	command.Stderr = &stderr
	stdout, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return err
	}
	writeErr := copyGitBatchBlobs(bufio.NewReader(stdout), entries, destRoot)
	// A failed write, such as a full temp disk, leaves git blocked on unread output, so stop it before waiting or the hook would hang.
	if writeErr != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return writeErr
	}
	waitErr := command.Wait()
	if waitErr != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return fmt.Errorf("git cat-file failed: %s", msg)
		}
		return waitErr
	}
	return nil
}

// copyGitBatchBlobs streams git cat-file --batch records for entries from reader into validated regular files under destRoot.
// It returns nil once every entry is written, or an error when a batch header, blob payload, path check, or write fails.
func copyGitBatchBlobs(reader *bufio.Reader, entries []gitTreeEntry, destRoot string) error {
	for _, blob := range entries {
		header, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read git object header for %s: %w", blob.path, err)
		}
		fields := strings.Fields(header)
		// Git answers in the order the hashes were sent, so any other object here means the export is out of step and must stop.
		if len(fields) != 3 || fields[1] != "blob" {
			return fmt.Errorf("unexpected git object %q for %s", strings.TrimSpace(header), blob.path)
		}
		size, err := strconv.ParseInt(fields[2], 10, 64)
		// A size that does not parse would make the next read land in the middle of another file.
		if err != nil || size < 0 {
			return fmt.Errorf("invalid git blob size for %s: %q", blob.path, fields[2])
		}
		target, err := safeExportTarget(destRoot, blob.path)
		if err != nil {
			return err
		}
		if err := writeLimitedBlob(target, reader, size); err != nil {
			return err
		}
		// git cat-file --batch appends one trailing LF after each object payload.
		if _, err := reader.ReadByte(); err != nil {
			return fmt.Errorf("read git blob terminator for %s: %w", blob.path, err)
		}
	}
	return nil
}

// writeLimitedBlob writes exactly size bytes from reader to target, creating parent directories as needed.
// It returns nil on success, or an error when directory creation, file opening, copying, or closing fails.
func writeLimitedBlob(target string, reader io.Reader, size int64) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.CopyN(file, reader, size)
	closeErr := file.Close()
	// A short copy, such as a full temp disk, wins over the close error because it is the cause the user can act on.
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

// safeExportTarget rejects exported git blob paths that would escape the temporary base directory.
//
// name is the repository-relative blob path and root the temp export directory; returns the cleaned path joined under root.
// Returns an empty string and an error quoting name when name is empty, cleans to ".", is absolute, or would escape root.
func safeExportTarget(root, name string) (string, error) {
	clean := filepath.Clean(name)
	if clean == "." || filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return "", fmt.Errorf("unsafe git export path %q", name)
	}
	target := filepath.Join(root, clean)
	if rel, err := filepath.Rel(root, target); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe git export path %q", name)
	}
	return target, nil
}
