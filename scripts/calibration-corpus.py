#!/usr/bin/env python3
"""Build immutable, reproducible gruff-go parser-rule calibration evidence."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any


TARGET_RULES = (
    "security.weak-crypto",
    "security.insecure-random-secret",
    "security.sensitive-data-logging",
)
CLASSIFICATION_HEADER = (
    "rule_id",
    "repository",
    "module",
    "file",
    "line",
    "fingerprint",
    "label",
    "rationale",
)
ALLOWED_LABELS = {"true-positive", "false-positive", "uncertain"}
MANIFEST_KEYS = {"schemaVersion", "runId", "createdAt", "command", "scanner", "corpus", "rules"}
CORPUS_KEYS = {"name", "url", "revision", "module", "reason", "files", "findings", "report"}
SCANNER_KEYS = {"commit", "dirty", "patchSha256"}
RULE_KEYS = {"population", "repositoriesWithHits", "sample", "oracle"}
COMPARISON_KEYS = {
    "schemaVersion",
    "baselineManifest",
    "createdAt",
    "command",
    "candidateScanner",
    "rules",
}
COMPARISON_RULE_KEYS = {
    "beforeReports",
    "afterReports",
    "beforePopulation",
    "afterPopulation",
    "changedClassifications",
}

KNOWN_POSITIVES = {
    "security.weak-crypto": '''// Package oracle supplies a weak-crypto positive.
package oracle

import "crypto/md5"

func hashPassword(password string) [16]byte {
	return md5.Sum([]byte(password))
}
''',
    "security.insecure-random-secret": '''// Package oracle supplies an insecure-random positive.
package oracle

import "math/rand"

func generateSessionToken() int {
	token := rand.Intn(999999)
	return token
}
''',
    "security.sensitive-data-logging": '''// Package oracle supplies a sensitive-logging positive.
package oracle

import "log"

func login(password string) {
	log.Printf("credential supplied: %s", password)
}
''',
}


class CalibrationError(RuntimeError):
    """A contract failure that must stop evidence generation."""


def fail(message: str) -> None:
    """Raise a consistently prefixed calibration failure."""
    raise CalibrationError(f"calibration-corpus: {message}")


def require_tools(*names: str) -> None:
    """Fail before doing work when a required local executable is missing."""
    for name in names:
        if shutil.which(name) is None:
            fail(f"missing required tool: {name}")


def run(
    command: list[str],
    *,
    cwd: Path,
    allowed: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess[bytes]:
    """Run a command with captured bytes and enforce its allowed exit codes."""
    completed = subprocess.run(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode not in allowed:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        detail = f": {stderr}" if stderr else ""
        fail(f"command exited {completed.returncode}: {' '.join(command)}{detail}")
    return completed


def text_output(command: list[str], *, cwd: Path) -> str:
    """Return stripped UTF-8 stdout from a successful command."""
    return run(command, cwd=cwd).stdout.decode("utf-8", errors="strict").strip()


def resolve_path(repo_root: Path, value: str) -> Path:
    """Resolve a CLI/environment path relative to the scanner repository."""
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = repo_root / candidate
    return candidate.resolve()


def parse_args(repo_root: Path) -> argparse.Namespace:
    """Parse the explicit evidence inputs while retaining legacy env overrides."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus-root",
        default=os.environ.get(
            "GRUFF_GO_CALIBRATION_CORPUS",
            str(repo_root / ".goat-flow/scratchpad/scan-test-repos"),
        ),
    )
    parser.add_argument(
        "--spec",
        default=os.environ.get(
            "GRUFF_GO_CALIBRATION_SPEC",
            str(repo_root / "scripts/calibration-corpus-0.5.0.json"),
        ),
    )
    parser.add_argument(
        "--classifications",
        default=os.environ.get(
            "GRUFF_GO_CALIBRATION_CLASSIFICATIONS",
            str(repo_root / ".goat-flow/scratchpad/calibration-0.5.0-classifications.tsv"),
        ),
    )
    parser.add_argument(
        "--output-root",
        default=os.environ.get(
            "GRUFF_GO_CALIBRATION_OUTPUT_ROOT",
            str(repo_root / ".goat-flow/logs/calibration/0.5.0"),
        ),
    )
    parser.add_argument(
        "--bin",
        default=os.environ.get("GRUFF_GO_CALIBRATION_BIN", "/tmp/gruff-go-calibration"),
    )
    args = parser.parse_args()
    args.corpus_root = resolve_path(repo_root, args.corpus_root)
    args.spec = resolve_path(repo_root, args.spec)
    args.classifications = resolve_path(repo_root, args.classifications)
    args.output_root = resolve_path(repo_root, args.output_root)
    args.bin = resolve_path(repo_root, args.bin) if not Path(args.bin).is_absolute() else Path(args.bin)
    return args


def load_json(path: Path, label: str) -> dict[str, Any]:
    """Load a JSON object or fail with an evidence-oriented diagnostic."""
    if not path.is_file():
        fail(f"missing {label}: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"unreadable {label} {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object: {path}")
    return value


def safe_relative(value: str, label: str) -> PurePosixPath:
    """Validate a repository-relative slash path without parent traversal."""
    if not value or "\\" in value:
        fail(f"{label} must be a non-empty slash path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        fail(f"{label} must stay inside its repository: {value!r}")
    return path


def normalize_remote(value: str) -> str:
    """Normalize harmless Git URL suffix differences for pinned-origin checks."""
    normalized = value.strip().rstrip("/")
    if normalized.endswith(".git"):
        normalized = normalized[:-4]
    return normalized


def validate_spec(spec: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Validate the pinned corpus and manual-oracle input contract."""
    if set(spec) != {"schemaVersion", "repositories", "manualOracles"}:
        fail("corpus spec must contain exactly schemaVersion, repositories, and manualOracles")
    if spec["schemaVersion"] != "gruff-go.calibration-corpus.v1":
        fail(f"unsupported corpus spec schema: {spec['schemaVersion']!r}")
    repositories = spec["repositories"]
    if not isinstance(repositories, list) or len(repositories) < 3:
        fail("corpus spec must pin at least three repositories")
    expected_repo_keys = {"name", "url", "revision", "module", "reason"}
    names: set[str] = set()
    for entry in repositories:
        if not isinstance(entry, dict) or set(entry) != expected_repo_keys:
            fail(f"corpus entry must contain exactly {sorted(expected_repo_keys)}")
        name = entry["name"]
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9._-]+", name):
            fail(f"invalid corpus repository name: {name!r}")
        if name in names:
            fail(f"duplicate corpus repository name: {name}")
        names.add(name)
        if not isinstance(entry["url"], str) or not entry["url"].strip():
            fail(f"corpus URL is empty for {name}")
        if not isinstance(entry["revision"], str) or not re.fullmatch(r"[0-9a-f]{40}", entry["revision"]):
            fail(f"corpus revision for {name} must be a full lowercase Git SHA")
        safe_relative(entry["module"], f"module for {name}")
        if not isinstance(entry["reason"], str) or not entry["reason"].strip():
            fail(f"corpus inclusion reason is empty for {name}")

    manual = spec["manualOracles"]
    if not isinstance(manual, dict) or set(manual) != set(TARGET_RULES):
        fail(f"manualOracles must contain exactly {list(TARGET_RULES)}")
    oracle_keys = {"repository", "module", "file", "line", "anchor", "searchCommand", "rationale"}
    for rule_id, oracle in manual.items():
        if not isinstance(oracle, dict) or set(oracle) != oracle_keys:
            fail(f"manual oracle for {rule_id} must contain exactly {sorted(oracle_keys)}")
        if oracle["repository"] not in names:
            fail(f"manual oracle for {rule_id} names an unpinned repository")
        safe_relative(oracle["module"], f"manual oracle module for {rule_id}")
        safe_relative(oracle["file"], f"manual oracle file for {rule_id}")
        if not isinstance(oracle["line"], int) or oracle["line"] < 1:
            fail(f"manual oracle line for {rule_id} must be positive")
        for field in ("anchor", "searchCommand", "rationale"):
            if not isinstance(oracle[field], str) or not oracle[field].strip():
                fail(f"manual oracle {field} for {rule_id} must be non-empty")
    return repositories, manual


def validate_corpus_checkout(corpus_root: Path, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Resolve and verify every pinned clean Git repository and module root."""
    if not corpus_root.is_dir():
        fail(f"corpus root is missing: {corpus_root}")
    resolved: list[dict[str, Any]] = []
    for entry in entries:
        repo_root = corpus_root / entry["name"]
        if not repo_root.is_dir():
            fail(f"corpus repository is missing: {repo_root}")
        inside = text_output(["git", "rev-parse", "--is-inside-work-tree"], cwd=repo_root)
        if inside != "true":
            fail(f"corpus repository is unversioned: {repo_root}")
        status = text_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=repo_root)
        if status:
            fail(f"corpus repository is dirty and has no approved patch digest: {entry['name']}\n{status}")
        head = text_output(["git", "rev-parse", "HEAD"], cwd=repo_root)
        if head != entry["revision"]:
            fail(f"corpus revision mismatch for {entry['name']}: got {head}, want {entry['revision']}")
        remote = text_output(["git", "remote", "get-url", "origin"], cwd=repo_root)
        if normalize_remote(remote) != normalize_remote(entry["url"]):
            fail(f"corpus origin mismatch for {entry['name']}: got {remote}, want {entry['url']}")
        module_rel = safe_relative(entry["module"], f"module for {entry['name']}")
        module_root = repo_root if str(module_rel) == "." else repo_root.joinpath(*module_rel.parts)
        if not module_root.is_dir() or not (module_root / "go.mod").is_file():
            fail(f"corpus module is missing or has no go.mod: {entry['name']}/{entry['module']}")
        resolved.append({**entry, "repoRoot": repo_root, "moduleRoot": module_root})
    return resolved


def scanner_snapshot(repo_root: Path, stage: Path) -> dict[str, Any]:
    """Capture the scanner commit and a reproducible patch bundle when dirty."""
    commit = text_output(["git", "rev-parse", "HEAD"], cwd=repo_root)
    status = text_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=repo_root)
    if not status:
        return {"commit": commit, "dirty": False, "patchSha256": None}

    patch = bytearray(run(["git", "diff", "--binary", "--no-ext-diff", "HEAD", "--"], cwd=repo_root).stdout)
    untracked_raw = run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=repo_root,
    ).stdout
    untracked = sorted(path for path in untracked_raw.decode("utf-8").split("\0") if path)
    for relative in untracked:
        diff = run(
            ["git", "diff", "--no-index", "--binary", "--no-ext-diff", "--", "/dev/null", relative],
            cwd=repo_root,
            allowed=(0, 1),
        ).stdout
        patch.extend(diff)
    if not patch:
        fail("scanner worktree is dirty but its patch bundle is empty")
    patch_path = stage / "scanner.patch"
    patch_path.write_bytes(bytes(patch))
    digest = hashlib.sha256(patch).hexdigest()
    return {"commit": commit, "dirty": True, "patchSha256": digest}


def module_report_name(module: str) -> str:
    """Map a module-relative path onto a stable report filename."""
    if module == ".":
        return "root.json"
    return module.replace("/", "__") + ".json"


def parse_report(raw: bytes, label: str) -> dict[str, Any]:
    """Parse and minimally validate an unmodified scanner machine report."""
    try:
        report = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"scanner produced unreadable JSON for {label}: {exc}")
    if not isinstance(report, dict) or not isinstance(report.get("summary"), dict):
        fail(f"scanner report for {label} has no summary object")
    if not isinstance(report.get("findings"), list):
        fail(f"scanner report for {label} has no findings array")
    return report


def scan_corpus(
    binary: Path,
    stage: Path,
    entries: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Scan every pinned module, save raw reports, and collect sample fields."""
    corpus_manifest: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for entry in entries:
        label = f"{entry['name']}/{entry['module']}"
        completed = run(
            [str(binary), "analyse", "--format", "json", "--no-config", "."],
            cwd=entry["moduleRoot"],
            allowed=(0, 1),
        )
        report = parse_report(completed.stdout, label)
        files = report["summary"].get("filesScanned")
        if not isinstance(files, int) or files <= 0:
            fail(f"scanner report for {label} records files={files!r}; every module must report files>0")
        report_rel = Path("reports") / entry["name"] / module_report_name(entry["module"])
        report_path = stage / report_rel
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_bytes(completed.stdout)
        report_findings = report["findings"]
        corpus_manifest.append(
            {
                "name": entry["name"],
                "url": entry["url"],
                "revision": entry["revision"],
                "module": entry["module"],
                "reason": entry["reason"],
                "files": files,
                "findings": len(report_findings),
                "report": report_rel.as_posix(),
            }
        )
        for item in report_findings:
            if not isinstance(item, dict):
                fail(f"non-object finding in {label}")
            rule_id = item.get("ruleId")
            file_name = item.get("file")
            line = item.get("line")
            fingerprint = item.get("fingerprint")
            if not isinstance(rule_id, str) or not rule_id:
                fail(f"finding without ruleId in {label}")
            if rule_id in TARGET_RULES:
                if not isinstance(file_name, str) or not file_name:
                    fail(f"target finding without file in {label}/{rule_id}")
                if not isinstance(line, int) or line < 1:
                    fail(f"target finding without positive line in {label}/{rule_id}")
                if not isinstance(fingerprint, str) or not fingerprint:
                    fail(f"target finding without fingerprint in {label}/{rule_id}")
            findings.append(
                {
                    "rule_id": rule_id,
                    "repository": entry["name"],
                    "module": entry["module"],
                    "file": file_name if isinstance(file_name, str) else "",
                    "line": line if isinstance(line, int) else 0,
                    "fingerprint": fingerprint if isinstance(fingerprint, str) else "",
                }
            )
    return corpus_manifest, findings


def candidate_sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
    """Return the milestone's deterministic within-repository sample order."""
    return (item["module"], item["file"], item["line"], item["fingerprint"])


def stratified_sample(items: list[dict[str, Any]], limit: int = 30) -> list[dict[str, Any]]:
    """Apply the M03 quota and lexicographic round-robin redistribution algorithm."""
    by_repo: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        by_repo.setdefault(item["repository"], []).append(item)
    for candidates in by_repo.values():
        candidates.sort(key=candidate_sort_key)
    repositories = sorted(by_repo)
    if len(items) <= limit:
        return [item for repo in repositories for item in by_repo[repo]]
    if not repositories:
        return []

    base = limit // len(repositories)
    remainder = limit % len(repositories)
    selected: dict[str, list[dict[str, Any]]] = {repo: [] for repo in repositories}
    indexes: dict[str, int] = {repo: 0 for repo in repositories}
    for index, repo in enumerate(repositories):
        quota = base + (1 if index < remainder else 0)
        take = min(quota, len(by_repo[repo]))
        selected[repo].extend(by_repo[repo][:take])
        indexes[repo] = take

    slots = limit - sum(len(rows) for rows in selected.values())
    while slots > 0:
        progressed = False
        for repo in repositories:
            if slots == 0:
                break
            index = indexes[repo]
            if index >= len(by_repo[repo]):
                continue
            selected[repo].append(by_repo[repo][index])
            indexes[repo] += 1
            slots -= 1
            progressed = True
        if not progressed:
            break
    return [item for repo in repositories for item in selected[repo]]


def expected_sample(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build the full deterministic classification sequence for target rules."""
    rows: list[dict[str, Any]] = []
    for rule_id in sorted(TARGET_RULES):
        candidates = [item for item in findings if item["rule_id"] == rule_id]
        rows.extend(stratified_sample(candidates))
    return rows


def load_classifications(path: Path, expected: list[dict[str, Any]]) -> list[list[str]]:
    """Validate labels/rationales and exact deterministic sample identity/order."""
    if not path.is_file():
        fail(f"classification input is missing: {path}")
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            rows = list(csv.reader(handle, delimiter="\t"))
    except OSError as exc:
        fail(f"cannot read classifications {path}: {exc}")
    if not rows or tuple(rows[0]) != CLASSIFICATION_HEADER:
        fail(f"classifications must start with the exact header: {' '.join(CLASSIFICATION_HEADER)}")
    body = rows[1:]
    if len(body) != len(expected):
        fail(f"classification row count {len(body)} does not match deterministic sample {len(expected)}")
    validated: list[list[str]] = []
    for index, (row, candidate) in enumerate(zip(body, expected, strict=True), start=2):
        if len(row) != len(CLASSIFICATION_HEADER):
            fail(f"classification row {index} has {len(row)} fields; want {len(CLASSIFICATION_HEADER)}")
        want = [
            candidate["rule_id"],
            candidate["repository"],
            candidate["module"],
            candidate["file"],
            str(candidate["line"]),
            candidate["fingerprint"],
        ]
        if row[:6] != want:
            fail(f"classification row {index} is out of order or names the wrong finding: got {row[:6]!r}, want {want!r}")
        if row[6] not in ALLOWED_LABELS:
            fail(f"classification row {index} has invalid label {row[6]!r}")
        if not row[7].strip():
            fail(f"classification row {index} has an empty rationale")
        validated.append(row)
    return validated


def write_classifications(path: Path, rows: list[list[str]]) -> None:
    """Write the normalized accepted TSV into the immutable run directory."""
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow(CLASSIFICATION_HEADER)
        writer.writerows(rows)


def write_known_positive_fixture(stage: Path, rule_id: str) -> Path:
    """Materialize one isolated known-positive Go module for a target rule."""
    slug = rule_id.removeprefix("security.").replace(".", "-")
    fixture = stage / "oracles" / "fixtures" / slug
    fixture.mkdir(parents=True, exist_ok=True)
    (fixture / "go.mod").write_text(f"module oracle/{slug}\n\ngo 1.25.0\n", encoding="utf-8")
    (fixture / "main.go").write_text(KNOWN_POSITIVES[rule_id], encoding="utf-8")
    return fixture


def finding_at_location(
    findings: list[dict[str, Any]],
    rule_id: str,
    repository: str,
    module: str,
    file_name: str,
    line: int,
) -> bool:
    """Report whether the baseline already caught a manual missed-case candidate."""
    return any(
        item["rule_id"] == rule_id
        and item["repository"] == repository
        and item["module"] == module
        and item["file"] == file_name
        and item["line"] == line
        for item in findings
    )


def build_oracles(
    binary: Path,
    stage: Path,
    corpus_root: Path,
    entries: list[dict[str, Any]],
    manual: dict[str, dict[str, Any]],
    findings: list[dict[str, Any]],
) -> dict[str, str]:
    """Execute known positives and validate one concrete missed-case search per rule."""
    entry_by_name = {entry["name"]: entry for entry in entries}
    oracle_paths: dict[str, str] = {}
    for rule_id in TARGET_RULES:
        fixture = write_known_positive_fixture(stage, rule_id)
        completed = run(
            [str(binary), "analyse", "--format", "json", "--no-config", "."],
            cwd=fixture,
            allowed=(0, 1),
        )
        report = parse_report(completed.stdout, f"oracle/{rule_id}")
        target_findings = [item for item in report["findings"] if item.get("ruleId") == rule_id]
        if not target_findings:
            fail(f"known-positive oracle produced no {rule_id} finding")
        report_rel = Path("oracles") / f"{rule_id}-report.json"
        (stage / report_rel).write_bytes(completed.stdout)

        candidate = manual[rule_id]
        corpus_entry = entry_by_name[candidate["repository"]]
        if candidate["module"] != corpus_entry["module"]:
            fail(f"manual oracle module mismatch for {rule_id}")
        source_path = corpus_root / candidate["repository"]
        if candidate["module"] != ".":
            source_path /= candidate["module"]
        source_path /= candidate["file"]
        if not source_path.is_file():
            fail(f"manual oracle source is missing for {rule_id}: {source_path}")
        lines = source_path.read_text(encoding="utf-8").splitlines()
        if candidate["line"] > len(lines):
            fail(f"manual oracle line is outside {source_path}: {candidate['line']}")
        source_line = lines[candidate["line"] - 1]
        if candidate["anchor"] not in source_line:
            fail(f"manual oracle anchor for {rule_id} is absent at {candidate['file']}:{candidate['line']}")
        if finding_at_location(
            findings,
            rule_id,
            candidate["repository"],
            candidate["module"],
            candidate["file"],
            candidate["line"],
        ):
            fail(f"manual false-negative candidate for {rule_id} was already reported")

        fixture_rel = fixture.relative_to(stage).as_posix()
        oracle_rel = Path("oracles") / f"{rule_id}.json"
        oracle = {
            "schemaVersion": "gruff-go.calibration-oracle.v1",
            "ruleId": rule_id,
            "knownPositive": {
                "fixture": f"{fixture_rel}/main.go",
                "report": report_rel.as_posix(),
                "expectedMinimum": 1,
                "actual": len(target_findings),
                "findings": [
                    {
                        "file": item.get("file"),
                        "line": item.get("line"),
                        "fingerprint": item.get("fingerprint"),
                    }
                    for item in target_findings
                ],
            },
            "manualSearch": {
                "command": candidate["searchCommand"],
                "repository": candidate["repository"],
                "module": candidate["module"],
                "file": candidate["file"],
                "line": candidate["line"],
                "anchor": candidate["anchor"],
                "sourceLineSha256": hashlib.sha256(source_line.encode("utf-8")).hexdigest(),
                "scannerFindingAtLocation": False,
                "result": "plausible-missed-case",
                "rationale": candidate["rationale"],
            },
        }
        (stage / oracle_rel).write_text(json.dumps(oracle, indent=2) + "\n", encoding="utf-8")
        oracle_paths[rule_id] = oracle_rel.as_posix()
    return oracle_paths


def build_rule_summary(
    findings: list[dict[str, Any]],
    samples: list[dict[str, Any]],
    oracle_paths: dict[str, str],
) -> dict[str, dict[str, Any]]:
    """Record population and repository reach for every emitted rule."""
    populations: dict[str, int] = {}
    repositories: dict[str, set[str]] = {}
    for item in findings:
        rule_id = item["rule_id"]
        populations[rule_id] = populations.get(rule_id, 0) + 1
        repositories.setdefault(rule_id, set()).add(item["repository"])
    sample_counts: dict[str, int] = {}
    for item in samples:
        sample_counts[item["rule_id"]] = sample_counts.get(item["rule_id"], 0) + 1
    rule_ids = sorted(set(populations) | set(TARGET_RULES))
    result: dict[str, dict[str, Any]] = {}
    for rule_id in rule_ids:
        target = rule_id in TARGET_RULES
        result[rule_id] = {
            "population": populations.get(rule_id, 0),
            "repositoriesWithHits": len(repositories.get(rule_id, set())),
            "sample": {"path": "classifications.tsv", "rows": sample_counts.get(rule_id, 0)} if target else None,
            "oracle": oracle_paths[rule_id] if target else None,
        }
    return result


def write_comparison_template(
    stage: Path,
    created_at: str,
    scanner: dict[str, Any],
    corpus: list[dict[str, Any]],
    rules: dict[str, dict[str, Any]],
) -> None:
    """Write a structurally validated, non-baseline-mutating comparison starter."""
    reports = [entry["report"] for entry in corpus]
    template = {
        "schemaVersion": "gruff-go.calibration-comparison.v1",
        "baselineManifest": "manifest.json",
        "createdAt": created_at,
        "command": "",
        "candidateScanner": {"commit": "", "dirty": False, "patchSha256": None},
        "rules": {
            rule_id: {
                "beforeReports": reports,
                "afterReports": [],
                "beforePopulation": rules[rule_id]["population"],
                "afterPopulation": 0,
                "changedClassifications": "",
            }
            for rule_id in TARGET_RULES
        },
    }
    path = stage / "comparison-manifest.template.json"
    path.write_text(json.dumps(template, indent=2) + "\n", encoding="utf-8")


def validate_artifacts(stage: Path, expected_samples: list[dict[str, Any]]) -> None:
    """Mechanically re-read every contract surface before accepting the run."""
    manifest = load_json(stage / "manifest.json", "generated manifest")
    if set(manifest) != MANIFEST_KEYS or manifest["schemaVersion"] != "gruff-go.calibration-manifest.v1":
        fail("generated manifest top-level schema is invalid")
    if not isinstance(manifest["scanner"], dict) or set(manifest["scanner"]) != SCANNER_KEYS:
        fail("generated manifest scanner shape is invalid")
    if manifest["scanner"]["dirty"]:
        patch = stage / "scanner.patch"
        if not patch.is_file() or hashlib.sha256(patch.read_bytes()).hexdigest() != manifest["scanner"]["patchSha256"]:
            fail("scanner patch digest does not match scanner.patch")
    elif manifest["scanner"]["patchSha256"] is not None:
        fail("clean scanner must record patchSha256=null")
    corpus = manifest["corpus"]
    if not isinstance(corpus, list) or len({entry["name"] for entry in corpus}) < 3:
        fail("generated manifest has fewer than three unrelated repositories")
    for entry in corpus:
        if not isinstance(entry, dict) or set(entry) != CORPUS_KEYS:
            fail("generated corpus entry shape is invalid")
        if not isinstance(entry["files"], int) or entry["files"] <= 0:
            fail(f"generated corpus entry has files<=0: {entry['name']}/{entry['module']}")
        report_path = stage / entry["report"]
        if not report_path.is_file():
            fail(f"generated corpus report is missing: {entry['report']}")
        parse_report(report_path.read_bytes(), entry["report"])
    rules = manifest["rules"]
    if not isinstance(rules, dict):
        fail("generated manifest rules must be an object")
    for rule_id, entry in rules.items():
        if not isinstance(entry, dict) or set(entry) != RULE_KEYS:
            fail(f"generated rule summary shape is invalid: {rule_id}")
    for rule_id in TARGET_RULES:
        if rule_id not in rules or not isinstance(rules[rule_id]["sample"], dict):
            fail(f"target rule summary is missing sample evidence: {rule_id}")
        if rules[rule_id]["sample"]["rows"] != sum(1 for item in expected_samples if item["rule_id"] == rule_id):
            fail(f"target rule sample count is wrong: {rule_id}")
        if not (stage / rules[rule_id]["oracle"]).is_file():
            fail(f"target rule oracle is missing: {rule_id}")

    with (stage / "classifications.tsv").open("r", encoding="utf-8", newline="") as handle:
        classification_rows = list(csv.reader(handle, delimiter="\t"))
    if not classification_rows or tuple(classification_rows[0]) != CLASSIFICATION_HEADER:
        fail("generated classifications header is invalid")
    if len(classification_rows) - 1 != len(expected_samples):
        fail("generated classifications row count is invalid")
    for index, row in enumerate(classification_rows[1:], start=2):
        if len(row) != 8 or row[6] not in ALLOWED_LABELS or not row[7].strip():
            fail(f"generated classification row {index} has an invalid label or rationale")

    comparison = load_json(stage / "comparison-manifest.template.json", "comparison template")
    if set(comparison) != COMPARISON_KEYS or comparison["schemaVersion"] != "gruff-go.calibration-comparison.v1":
        fail("comparison manifest template top-level shape is invalid")
    if not isinstance(comparison["candidateScanner"], dict) or set(comparison["candidateScanner"]) != SCANNER_KEYS:
        fail("comparison template candidateScanner shape is invalid")
    if not isinstance(comparison["rules"], dict) or set(comparison["rules"]) != set(TARGET_RULES):
        fail("comparison template must contain exactly the target rules")
    for rule_id, entry in comparison["rules"].items():
        if not isinstance(entry, dict) or set(entry) != COMPARISON_RULE_KEYS:
            fail(f"comparison template rule shape is invalid: {rule_id}")


def main() -> int:
    """Execute the complete immutable baseline evidence protocol."""
    repo_root = Path(__file__).resolve().parents[1]
    require_tools("go", "git", "python3")
    args = parse_args(repo_root)
    spec = load_json(args.spec, "corpus spec")
    pinned, manual = validate_spec(spec)
    entries = validate_corpus_checkout(args.corpus_root, pinned)
    if not args.classifications.is_file():
        fail(f"classification input is missing: {args.classifications}")

    created = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    created_at = created.isoformat().replace("+00:00", "Z")
    scanner_commit = text_output(["git", "rev-parse", "HEAD"], cwd=repo_root)
    run_id = f"{created.strftime('%Y%m%dT%H%M%SZ')}-{scanner_commit[:12]}"
    args.output_root.mkdir(parents=True, exist_ok=True)
    final = args.output_root / run_id
    if final.exists():
        fail(f"immutable run directory already exists: {final}")
    stage = Path(tempfile.mkdtemp(prefix=f".tmp-{run_id}-", dir=args.output_root))
    accepted = False
    try:
        print(f"building calibration binary: {args.bin}", file=sys.stderr)
        run(["go", "build", "-o", str(args.bin), "./cmd/gruff-go"], cwd=repo_root)
        scanner = scanner_snapshot(repo_root, stage)
        corpus, findings = scan_corpus(args.bin, stage, entries)
        samples = expected_sample(findings)
        classifications = load_classifications(args.classifications, samples)
        write_classifications(stage / "classifications.tsv", classifications)
        oracles = build_oracles(args.bin, stage, args.corpus_root, entries, manual, findings)
        rules = build_rule_summary(findings, samples, oracles)
        command = os.environ.get("GRUFF_GO_CALIBRATION_COMMAND", "scripts/calibrate-scratchpad-corpus.sh")
        manifest = {
            "schemaVersion": "gruff-go.calibration-manifest.v1",
            "runId": run_id,
            "createdAt": created_at,
            "command": command,
            "scanner": scanner,
            "corpus": corpus,
            "rules": rules,
        }
        (stage / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        write_comparison_template(stage, created_at, scanner, corpus, rules)
        validate_artifacts(stage, samples)
        stage.rename(final)
        accepted = True
    finally:
        if not accepted and stage.exists():
            shutil.rmtree(stage)

    print(f"calibration-run={final}")
    print(f"manifest={final / 'manifest.json'}")
    print(f"corpus={len(corpus)} modules={len(corpus)} files={sum(item['files'] for item in corpus)} findings={sum(item['findings'] for item in corpus)}")
    for rule_id in TARGET_RULES:
        summary = rules[rule_id]
        print(
            f"rule={rule_id} population={summary['population']} "
            f"repositoriesWithHits={summary['repositoriesWithHits']} sample={summary['sample']['rows']} oracle=PASS"
        )
    print("validation=PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CalibrationError as exc:
        print(exc, file=sys.stderr)
        raise SystemExit(2) from exc
