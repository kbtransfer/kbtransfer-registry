#!/usr/bin/env python3
"""Rebuild `index.json` and `stats.json` for this kb-registry.

Called by GitHub Actions after every successful pack merge. Scans
`packs/` for all `{pack_id}-{version}.tar` tarballs, aggregates them
per pack_id (with a sorted `versions` list and a `latest_version`
pointer), and derives `stats.json` from the same data.

Counters (`subscribe_count` / `cite_count`) are PRESERVED across
rebuilds: they live in the existing `stats.json` and are not
recomputed from registry content. All other fields are regenerated
from scratch.

The script is idempotent: running it twice on the same git state
produces byte-identical `index.json` and `stats.json`. Sources of
non-determinism are deliberately eliminated:

    - `generated_at` uses the committer ISO timestamp of HEAD
      (not `datetime.now()`), so re-running on the same commit
      yields the same value.
    - `added_at` / `updated_at` come from
      `git log --diff-filter=A --format=%cI -- <path>`, which is
      deterministic for a given git history.
    - Every dict is emitted with sorted keys; every list is sorted
      with an explicit key (semver for `versions`, lexicographic
      for everything else).
    - `json.dumps(..., indent=2, sort_keys=True)` + trailing `\\n`.

Usage:

    python rebuild_index.py [registry_root]

`registry_root` is optional; it defaults to the current working
directory. CI pipelines run the script from the checked-out
registry root, so the no-arg form is the intended invocation.

Exit codes:
    0  success
    2  environment error (missing deps, registry root missing)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from packaging.version import InvalidVersion, Version
except ImportError as exc:  # pragma: no cover - environment check
    sys.stderr.write(
        "packaging library is required. Install with "
        "`pip install -r scripts/requirements.txt`.\n"
    )
    raise SystemExit(2) from exc

try:
    import yaml
except ImportError as exc:  # pragma: no cover - environment check
    sys.stderr.write(
        "pyyaml is required. Install with "
        "`pip install -r scripts/requirements.txt`.\n"
    )
    raise SystemExit(2) from exc

try:
    from kb_pack import parse_lock
except ImportError as exc:  # pragma: no cover - environment check
    sys.stderr.write(
        "kb_pack is not importable. Ensure the `kbtransfer` submodule is "
        "checked out (git submodule update --init) and installed "
        "(pip install -e ./kbtransfer) before running this script.\n"
    )
    raise SystemExit(2) from exc


# ── Constants ─────────────────────────────────────────────────────────

FILENAME_RE = re.compile(r"^(?P<pack_id>.+)-(?P<version>\d+\.\d+\.\d+)\.tar$")
DOMAIN_RE = re.compile(r"^\s*[Dd]omain\s*:\s*(.+?)\s*$", re.MULTILINE)


# ── Data shape pulled out of each tarball ────────────────────────────

@dataclass(frozen=True)
class PackBits:
    pack_id: str
    version: str
    tar_rel: str                  # path relative to registry root, POSIX
    sha256: str
    publisher_did: str
    license: str
    content_root: str
    composite_score: float
    domain: str
    has_decisions: bool
    has_failure_log: bool


# ── Tiny helpers ──────────────────────────────────────────────────────

def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _parse_filename(name: str) -> tuple[str, str] | None:
    m = FILENAME_RE.match(name)
    if not m:
        return None
    return m.group("pack_id"), m.group("version")


def _extract_domain(readme_text: str) -> str:
    m = DOMAIN_RE.search(readme_text)
    return m.group(1).strip() if m else ""


def _coerce_int(value: Any) -> int:
    """Accept int/float (but not bool); everything else becomes 0."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    return 0


def _coerce_float(value: Any) -> float:
    if isinstance(value, bool):
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    return 0.0


# ── Git-log lookups ──────────────────────────────────────────────────

def _git_log_added(registry_root: Path, rel_path: str) -> str:
    """ISO timestamp of the commit that first added `rel_path`, or ''.

    `git log --diff-filter=A` lists commits newest-first where the
    file was added. Under this registry's no-overwrite policy each
    tarball is added exactly once, so the list has a single entry;
    if it ever has more (file deleted + re-added), the oldest is the
    authoritative "added at" time.
    """
    try:
        result = subprocess.run(
            ["git", "log", "--diff-filter=A", "--format=%cI", "--", rel_path],
            cwd=registry_root,
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return ""
    lines = [ln for ln in result.stdout.splitlines() if ln.strip()]
    return lines[-1] if lines else ""


def _git_head_timestamp(registry_root: Path) -> str:
    """Committer ISO timestamp of HEAD, or ''.

    Used as the `generated_at` value so that two rebuild runs on the
    same commit produce the same timestamp — the file is idempotent
    per commit.
    """
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%cI", "HEAD"],
            cwd=registry_root,
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return ""
    return result.stdout.strip()


# ── Tarball scanning ─────────────────────────────────────────────────

def _read_pack(
    tar_path: Path, pack_id: str, version: str, tar_rel: str
) -> PackBits:
    expected_top = f"{pack_id}-{version}"
    manifest: dict[str, Any] | None = None
    lock_text = ""
    eval_doc: dict[str, Any] = {}
    readme_text = ""
    has_decisions = False
    has_failure_log = False

    try:
        tar = tarfile.open(tar_path, "r")
    except (tarfile.TarError, OSError) as exc:
        raise RuntimeError(f"{tar_rel}: cannot open tarball: {exc}") from exc

    with tar:
        for member in tar.getmembers():
            parts = member.name.split("/")
            if len(parts) < 2 or parts[0] != expected_top:
                continue
            rel = "/".join(parts[1:])
            is_file = member.isfile()

            if rel == "pack.manifest.yaml" and is_file:
                f = tar.extractfile(member)
                if f is not None:
                    try:
                        loaded = yaml.safe_load(f.read().decode("utf-8"))
                    except yaml.YAMLError as exc:
                        raise RuntimeError(
                            f"{tar_rel}: pack.manifest.yaml parse error: {exc}"
                        ) from exc
                    manifest = loaded if isinstance(loaded, dict) else None
            elif rel == "pack.lock" and is_file:
                f = tar.extractfile(member)
                if f is not None:
                    lock_text = f.read().decode("utf-8")
            elif rel == "attestations/evaluation.json" and is_file:
                f = tar.extractfile(member)
                if f is not None:
                    try:
                        eval_doc = json.loads(f.read().decode("utf-8"))
                    except json.JSONDecodeError:
                        eval_doc = {}
                    if not isinstance(eval_doc, dict):
                        eval_doc = {}
            elif rel == "pages/README.md" and is_file:
                f = tar.extractfile(member)
                if f is not None:
                    readme_text = f.read().decode("utf-8", errors="replace")

            if is_file and rel.startswith("pages/decisions/"):
                has_decisions = True
            if is_file and rel.startswith("pages/failure-log/"):
                has_failure_log = True

    if manifest is None:
        raise RuntimeError(
            f"{tar_rel}: pack.manifest.yaml is missing or not a mapping"
        )

    # kb_pack v0.1.1 nested manifest shape (see REGISTRY_API_NOTES.md §1.4):
    #   publisher: { id: "did:web:..." }
    #   license:   { spdx: "MIT" }      # optional
    publisher_block = manifest.get("publisher")
    if isinstance(publisher_block, dict):
        publisher_did = publisher_block.get("id", "") or ""
    else:
        publisher_did = ""

    license_block = manifest.get("license")
    if isinstance(license_block, dict):
        license_spdx = license_block.get("spdx", "") or ""
    else:
        license_spdx = ""

    content_root = ""
    if lock_text:
        try:
            content_root = parse_lock(lock_text).content_root
        except Exception as exc:
            raise RuntimeError(
                f"{tar_rel}: pack.lock unparseable: {exc}"
            ) from exc

    return PackBits(
        pack_id=pack_id,
        version=version,
        tar_rel=tar_rel,
        sha256=_sha256_file(tar_path),
        publisher_did=str(publisher_did),
        license=str(license_spdx),
        content_root=content_root,
        composite_score=_coerce_float(eval_doc.get("composite_score")),
        domain=_extract_domain(readme_text),
        has_decisions=has_decisions,
        has_failure_log=has_failure_log,
    )


# ── Version ordering ─────────────────────────────────────────────────

def _semver_sort(versions: list[str]) -> list[str]:
    """Ascending semver sort. Unparseable versions sort last, then
    lexicographically among themselves, so output is still stable."""
    parseable: list[tuple[Version, str]] = []
    unparseable: list[str] = []
    for v in versions:
        try:
            parseable.append((Version(v), v))
        except InvalidVersion:
            unparseable.append(v)
    parseable.sort(key=lambda pair: pair[0])
    return [v for _, v in parseable] + sorted(unparseable)


# ── Preservation of counters across rebuilds ─────────────────────────

def _load_prior_stats(registry_root: Path) -> dict[str, dict[str, int]]:
    """Read `stats.json` and return {pack_id: {subscribe_count, cite_count}}.

    Missing file, malformed JSON, or missing fields degrade to an
    empty dict rather than failing — a rebuild should never throw
    away counters because the existing stats file was corrupt, but
    equally it should not invent counters where none exist.
    """
    path = registry_root / "stats.json"
    if not path.is_file():
        return {}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(doc, dict):
        return {}
    prior: dict[str, dict[str, int]] = {}
    for pack_id, entry in (doc.get("packs") or {}).items():
        if not isinstance(pack_id, str) or not isinstance(entry, dict):
            continue
        prior[pack_id] = {
            "subscribe_count": _coerce_int(entry.get("subscribe_count")),
            "cite_count": _coerce_int(entry.get("cite_count")),
        }
    return prior


# ── Main build ───────────────────────────────────────────────────────

def build_reports(registry_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    packs_dir = registry_root / "packs"
    prior_stats = _load_prior_stats(registry_root)

    # Scan every tarball, bucket by pack_id.
    tarballs = sorted(p for p in packs_dir.glob("*.tar") if p.is_file())
    by_pack: dict[str, list[PackBits]] = {}
    for tar_path in tarballs:
        parsed = _parse_filename(tar_path.name)
        if parsed is None:
            # Pre-merge validator rejects non-matching filenames. If one
            # slips in, skip it silently — we neither index it nor trust
            # it. A separate lint can flag it.
            continue
        pack_id, version = parsed
        tar_rel = tar_path.relative_to(registry_root).as_posix()
        bits = _read_pack(tar_path, pack_id, version, tar_rel)
        by_pack.setdefault(pack_id, []).append(bits)

    index_entries: list[dict[str, Any]] = []
    per_publisher: dict[str, dict[str, Any]] = {}
    stats_packs: dict[str, dict[str, int]] = {}

    for pack_id in sorted(by_pack.keys()):
        bits_list = by_pack[pack_id]
        versions_sorted = _semver_sort([b.version for b in bits_list])
        latest_version = versions_sorted[-1]
        earliest_version = versions_sorted[0]

        by_version = {b.version: b for b in bits_list}
        first_bits = by_version[earliest_version]
        latest_bits = by_version[latest_version]

        added_at = _git_log_added(registry_root, first_bits.tar_rel)
        updated_at = _git_log_added(registry_root, latest_bits.tar_rel)

        prior = prior_stats.get(pack_id, {})
        subscribe_count = prior.get("subscribe_count", 0)
        cite_count = prior.get("cite_count", 0)

        entry = {
            "pack_id": pack_id,
            "latest_version": latest_version,
            "versions": versions_sorted,
            "publisher_did": latest_bits.publisher_did,
            "domain": latest_bits.domain,
            "license": latest_bits.license,
            "has_failure_log": latest_bits.has_failure_log,
            "has_decisions": latest_bits.has_decisions,
            "composite_score": latest_bits.composite_score,
            "added_at": added_at,
            "updated_at": updated_at,
            "sha256": latest_bits.sha256,
            "content_root": latest_bits.content_root,
            "subscribe_count": subscribe_count,
            "cite_count": cite_count,
        }
        index_entries.append(entry)

        stats_packs[pack_id] = {
            "subscribe_count": subscribe_count,
            "cite_count": cite_count,
        }

        pub = latest_bits.publisher_did
        if not pub:
            # No publisher to attribute to. Skip aggregation but keep
            # the index entry (operator can spot the missing DID).
            continue
        agg = per_publisher.setdefault(
            pub,
            {
                "pack_count": 0,
                "total_subscribe_count": 0,
                "total_cite_count": 0,
                "domains": set(),
                "first_published": "",
                "last_published": "",
            },
        )
        agg["pack_count"] += 1
        agg["total_subscribe_count"] += subscribe_count
        agg["total_cite_count"] += cite_count
        if latest_bits.domain:
            agg["domains"].add(latest_bits.domain)
        if added_at and (
            not agg["first_published"] or added_at < agg["first_published"]
        ):
            agg["first_published"] = added_at
        if updated_at and (
            not agg["last_published"] or updated_at > agg["last_published"]
        ):
            agg["last_published"] = updated_at

    publishers_out: dict[str, Any] = {}
    for pub in sorted(per_publisher.keys()):
        agg = per_publisher[pub]
        publishers_out[pub] = {
            "pack_count": agg["pack_count"],
            "total_subscribe_count": agg["total_subscribe_count"],
            "total_cite_count": agg["total_cite_count"],
            "domains": sorted(agg["domains"]),
            "first_published": agg["first_published"],
            "last_published": agg["last_published"],
        }

    generated_at = _git_head_timestamp(registry_root)

    index_doc = {
        "generated_at": generated_at,
        "pack_count": len(index_entries),
        "publisher_count": len(publishers_out),
        "packs": index_entries,
    }
    stats_doc = {
        "generated_at": generated_at,
        "publishers": publishers_out,
        "packs": {pack_id: stats_packs[pack_id] for pack_id in sorted(stats_packs)},
    }
    return index_doc, stats_doc


# ── Writing + entry point ────────────────────────────────────────────

def _write_json(path: Path, doc: dict[str, Any]) -> None:
    """Deterministic JSON write: indent=2, sort_keys=True, trailing newline."""
    payload = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    path.write_text(payload, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Rebuild index.json and stats.json for this kb-registry."
    )
    parser.add_argument(
        "registry_root",
        type=Path,
        nargs="?",
        default=None,
        help="Path to the registry root (containing packs/ and publishers/). "
        "Defaults to the current working directory.",
    )
    args = parser.parse_args(argv)

    root = (args.registry_root or Path.cwd()).resolve()
    if not root.is_dir():
        sys.stderr.write(f"registry root not found: {root}\n")
        return 2

    index_doc, stats_doc = build_reports(root)
    _write_json(root / "index.json", index_doc)
    _write_json(root / "stats.json", stats_doc)

    print(
        f"wrote index.json ({index_doc['pack_count']} pack(s)) "
        f"and stats.json ({len(stats_doc['publishers'])} publisher(s))"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
