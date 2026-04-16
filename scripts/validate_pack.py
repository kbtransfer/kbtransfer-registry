#!/usr/bin/env python3
"""Pre-merge validator for a single kb-registry pack submission.

Invoked by GitHub Actions as:

    python validate_pack.py <path/to/pack_id-version.tar>

Runs seven checks in order and exits with code 1 on the first failure.
A structured JSON report is always written to stdout, whether the
result is pass or fail. The script relies on `kb_pack` primitives
(`compute_roots`, `read_lock`, `verify_pack_root`) for all
cryptographic and Merkle work; this file orchestrates and adds the
registry-local schema / content / duplicate checks.

Exit codes:
    0  every check passed
    1  at least one check failed (see `error_check` / `error_detail`)
    2  environment error (kb_pack / packaging not importable)
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import shutil
import sys
import tarfile
import tempfile
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
    from kb_pack import (
        Manifest,
        ManifestError,
        compute_roots,
        load_manifest,
        read_lock,
        verify_pack_root,
    )
except ImportError as exc:  # pragma: no cover - environment check
    sys.stderr.write(
        "kb_pack is not importable. Ensure the `kbtransfer` submodule is "
        "checked out (git submodule update --init) and installed "
        "(pip install -e ./kbtransfer) before running this script.\n"
    )
    raise SystemExit(2) from exc


# ── Constants ─────────────────────────────────────────────────────────

FILENAME_RE = re.compile(r"^(?P<pack_id>.+)-(?P<version>\d+\.\d+\.\d+)\.tar$")

# Manifest schema is enforced by `kb_pack.load_manifest` (kb_pack v0.1.1
# nested shape: spec_version / pack_id / version / namespace / publisher.id
# / title / attestations / policy_surface; optional license.spdx).
# See REGISTRY_API_NOTES.md §1.4.
DID_PREFIX = "did:web:"

ENVELOPE_FIELDS = ("spec", "pack", "content_root", "issuer", "issued_at")

EXPERIENCE_PREFIXES = ("decisions/", "failure-log/")
EXPERIENCE_MIN_WORDS = 100
README_MIN_WORDS = 50


# ── Exception used internally to short-circuit on first failure ───────

class CheckFailure(Exception):
    """Raised when a check fails. Carries the check's short name and
    a human-readable detail for the JSON report."""

    def __init__(self, check_name: str, detail: str) -> None:
        super().__init__(detail)
        self.check_name = check_name
        self.detail = detail


# ── Helpers ───────────────────────────────────────────────────────────

def _did_safe(publisher_did: str) -> str:
    """Per this registry's rule: `:` and `/` become `_`.

    Intentionally differs from `kb_pack.did_to_safe_path` (which uses
    `-`). The registry's own convention is documented in
    REGISTRY_POLICY.md.
    """
    return publisher_did.replace(":", "_").replace("/", "_")


def _count_words(text: str) -> int:
    return len(text.split())


def _load_json(path: Path, check_name: str) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CheckFailure(check_name, f"{path.name} not found") from exc
    except json.JSONDecodeError as exc:
        raise CheckFailure(check_name, f"{path.name} is not valid JSON: {exc}") from exc


# ── Individual checks ────────────────────────────────────────────────

def _check_tarball_integrity(
    tar_path: Path, staging: Path
) -> tuple[str, str, Path]:
    """CHECK 1 — returns (pack_id, version, extracted_pack_dir)."""
    if not tar_path.is_file():
        raise CheckFailure(
            "tarball_integrity", f"file does not exist: {tar_path}"
        )

    m = FILENAME_RE.match(tar_path.name)
    if not m:
        raise CheckFailure(
            "tarball_integrity",
            f"filename {tar_path.name!r} does not match "
            "{pack_id}-{X.Y.Z}.tar",
        )
    pack_id = m.group("pack_id")
    version = m.group("version")

    try:
        archive = tarfile.open(tar_path, "r")
    except (tarfile.ReadError, tarfile.TarError, OSError) as exc:
        raise CheckFailure(
            "tarball_integrity", f"not a valid tar archive: {exc}"
        ) from exc

    with archive as tf:
        try:
            tf.extractall(staging, filter="data")
        except TypeError:  # Python < 3.12
            tf.extractall(staging)
        except (tarfile.TarError, OSError) as exc:
            raise CheckFailure(
                "tarball_integrity", f"tarball extraction failed: {exc}"
            ) from exc

    entries = sorted(staging.iterdir())
    dirs = [p for p in entries if p.is_dir()]
    files = [p for p in entries if p.is_file()]
    if len(dirs) != 1 or files:
        raise CheckFailure(
            "tarball_integrity",
            "tarball must contain exactly one top-level directory; "
            f"found dirs={[p.name for p in dirs]} "
            f"stray_files={[p.name for p in files]}",
        )
    expected_dir_name = f"{pack_id}-{version}"
    if dirs[0].name != expected_dir_name:
        raise CheckFailure(
            "tarball_integrity",
            f"top-level directory {dirs[0].name!r} does not match "
            f"expected {expected_dir_name!r} derived from the filename",
        )

    return pack_id, version, dirs[0]


def _check_manifest_validation(
    pack_dir: Path, expected_pack_id: str
) -> Manifest:
    """CHECK 2 — validate `pack.manifest.yaml` against the kb_pack v0.1.1
    nested schema, then apply registry-specific rules (filename ↔ pack_id
    match, semver-parseable version, `did:web:` publisher prefix).

    Schema enforcement (required fields, spec_version, publisher.id,
    attestations map) is delegated to `kb_pack.load_manifest` so that a
    future kb_pack schema change can't drift from this validator.
    Returns the parsed Manifest object so later checks can reuse
    `manifest.publisher_id` and `manifest.attestation_paths` directly.
    """
    path = pack_dir / "pack.manifest.yaml"
    if not path.is_file():
        raise CheckFailure("manifest_validation", "pack.manifest.yaml is missing")
    try:
        manifest = load_manifest(pack_dir)
    except ManifestError as exc:
        raise CheckFailure(
            "manifest_validation", f"pack.manifest.yaml invalid: {exc}"
        ) from exc
    except yaml.YAMLError as exc:
        raise CheckFailure(
            "manifest_validation", f"pack.manifest.yaml parse error: {exc}"
        ) from exc

    if manifest.pack_id != expected_pack_id:
        raise CheckFailure(
            "manifest_validation",
            f"manifest pack_id {manifest.pack_id!r} does not match "
            f"filename-derived pack_id {expected_pack_id!r}",
        )

    version_str = manifest.version
    if not isinstance(version_str, str):
        raise CheckFailure(
            "manifest_validation",
            f"manifest.version must be a string, got {type(version_str).__name__}",
        )
    try:
        Version(version_str)
    except InvalidVersion as exc:
        raise CheckFailure(
            "manifest_validation",
            f"manifest.version {version_str!r} is not a valid semver: {exc}",
        ) from exc

    publisher_did = manifest.publisher_id
    if not isinstance(publisher_did, str) or not publisher_did.startswith(DID_PREFIX):
        raise CheckFailure(
            "manifest_validation",
            f"publisher.id {publisher_did!r} must start with {DID_PREFIX!r}",
        )

    return manifest


def _check_signature_verification(
    tar_path: Path, pack_dir: Path, publisher_did: str
) -> None:
    """CHECK 3 — signature + Merkle."""
    registry_root = tar_path.resolve().parent.parent
    did_safe = _did_safe(publisher_did)
    keys_path = registry_root / "publishers" / did_safe / "keys.json"
    if not keys_path.is_file():
        raise CheckFailure(
            "signature_verification",
            f"publisher keys not found at publishers/{did_safe}/keys.json",
        )
    keys_doc = _load_json(keys_path, "signature_verification")
    # Registry keys.json schema (see REGISTRY_POLICY.md):
    #   { "did": "did:web:...",
    #     "keys": [
    #       { "key_id": "...", "algorithm": "Ed25519",
    #         "public_key_b64": "<base64 of 32 raw bytes>" },
    #       ...
    #     ]
    #   }
    # We normalize every registered public key to hex internally so it can be
    # compared byte-for-byte against the pack's signatures/publisher.pubkey
    # (also 32 raw bytes → hex) and passed to kb_pack.verify_pack_root.
    keys = keys_doc.get("keys") or []
    ed25519_hex: set[str] = set()
    for key in keys:
        if not isinstance(key, dict):
            continue
        if key.get("algorithm") != "Ed25519":
            continue
        pub_b64 = key.get("public_key_b64")
        if not isinstance(pub_b64, str) or not pub_b64.strip():
            continue
        try:
            raw = base64.b64decode(pub_b64, validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(raw) != 32:
            continue
        ed25519_hex.add(raw.hex())
    if not ed25519_hex:
        raise CheckFailure(
            "signature_verification",
            f"no valid Ed25519 keys in publishers/{did_safe}/keys.json — "
            "each key must have algorithm='Ed25519' and a 'public_key_b64' "
            "field that decodes to 32 bytes",
        )

    try:
        lock = read_lock(pack_dir)
    except Exception as exc:
        raise CheckFailure(
            "signature_verification", f"pack.lock unreadable: {exc}"
        ) from exc

    try:
        content_hex, pack_hex, _ = compute_roots(pack_dir)
    except Exception as exc:
        raise CheckFailure(
            "signature_verification",
            f"Merkle recomputation failed: {exc}",
        ) from exc

    if f"sha256:{content_hex}" != lock.content_root:
        raise CheckFailure(
            "signature_verification",
            "content_root in pack.lock does not match recomputed Merkle over "
            "pack contents",
        )
    if f"sha256:{pack_hex}" != lock.pack_root:
        raise CheckFailure(
            "signature_verification",
            "pack_root in pack.lock does not match recomputed Merkle over "
            "the full pack",
        )

    sig_path = pack_dir / "signatures" / "publisher.sig"
    pub_path = pack_dir / "signatures" / "publisher.pubkey"
    if not sig_path.is_file():
        raise CheckFailure(
            "signature_verification", "signatures/publisher.sig is missing"
        )
    if not pub_path.is_file():
        raise CheckFailure(
            "signature_verification", "signatures/publisher.pubkey is missing"
        )
    signature_bytes = sig_path.read_bytes()
    bundled_hex = pub_path.read_bytes().hex()

    if bundled_hex not in ed25519_hex:
        raise CheckFailure(
            "signature_verification",
            "bundled signatures/publisher.pubkey is not registered in "
            f"publishers/{did_safe}/keys.json",
        )

    if not verify_pack_root(pack_hex, signature_bytes, bundled_hex):
        raise CheckFailure(
            "signature_verification",
            "Ed25519 signature over pack_root did not verify",
        )


def _check_attestation_completeness(pack_dir: Path, manifest: Manifest) -> None:
    """CHECK 4 — each of the four attestations declared in the manifest's
    `attestations:` mapping exists on disk, parses as JSON, carries the
    common envelope fields, and meets its kind-specific body rule.

    Paths come from `manifest.attestation_paths` (kb_pack v0.1.1), not
    from hardcoded `attestations/<kind>.json` — the spec lets a pack
    place them anywhere it wants as long as the manifest declares them.
    """
    attestation_paths = manifest.attestation_paths

    for kind in ("provenance", "redaction", "evaluation", "license"):
        relpath = attestation_paths.get(kind)
        if not relpath:
            raise CheckFailure(
                "attestation_completeness",
                f"manifest.attestations is missing kind {kind!r}",
            )
        att_path = pack_dir / relpath
        if not att_path.is_file():
            raise CheckFailure(
                "attestation_completeness",
                f"attestation file declared at {relpath!r} does not exist",
            )
        doc = _load_json(att_path, "attestation_completeness")
        missing = [f for f in ENVELOPE_FIELDS if f not in doc]
        if missing:
            raise CheckFailure(
                "attestation_completeness",
                f"{relpath} is missing field(s): {missing}",
            )

        if kind == "redaction":
            # kb_pack.build_redaction emits a list; the registry schema
            # originally required a string. Accept both shapes — a
            # non-empty string OR a non-empty list — so either producer
            # path round-trips. Any other type (dict, int, None) is
            # still rejected.
            notes = doc.get("residual_risk_notes")
            if isinstance(notes, str):
                if notes.strip() == "":
                    raise CheckFailure(
                        "attestation_completeness",
                        f"{relpath}.residual_risk_notes string must be non-empty",
                    )
            elif isinstance(notes, list):
                if not notes:
                    raise CheckFailure(
                        "attestation_completeness",
                        f"{relpath}.residual_risk_notes list must be non-empty",
                    )
            else:
                raise CheckFailure(
                    "attestation_completeness",
                    f"{relpath}.residual_risk_notes must be a non-empty "
                    f"string or list (got {type(notes).__name__})",
                )
        elif kind == "evaluation":
            score = doc.get("composite_score")
            # Reject bools (bool is a subclass of int in Python).
            if isinstance(score, bool) or not isinstance(score, (int, float)):
                raise CheckFailure(
                    "attestation_completeness",
                    f"{relpath}.composite_score must be a number",
                )
            if not (0.0 <= float(score) <= 1.0):
                raise CheckFailure(
                    "attestation_completeness",
                    f"{relpath}.composite_score {score} is not within [0.0, 1.0]",
                )
        elif kind == "license":
            # kb_pack.build_license writes `license_spdx`; the registry
            # schema uses `spdx`. Accept either — prefer `spdx` when
            # both are present, fall back to `license_spdx` otherwise.
            spdx = doc.get("spdx") or doc.get("license_spdx")
            if not isinstance(spdx, str) or spdx.strip() == "":
                raise CheckFailure(
                    "attestation_completeness",
                    f"{relpath} must have a non-empty 'spdx' or "
                    "'license_spdx' string",
                )


def _check_experience_content(pack_dir: Path) -> None:
    """CHECK 5 — at least one decisions/ or failure-log/ file with >=100 words."""
    pages = pack_dir / "pages"
    candidates: list[Path] = []
    if pages.is_dir():
        for path in pages.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(pages).as_posix()
            if any(rel.startswith(prefix) for prefix in EXPERIENCE_PREFIXES):
                candidates.append(path)
    if not candidates:
        raise CheckFailure(
            "experience_content",
            "no file found under pages/decisions/ or pages/failure-log/",
        )
    best_count = 0
    best_path: Path | None = None
    for path in candidates:
        count = _count_words(path.read_text(encoding="utf-8", errors="replace"))
        if count >= EXPERIENCE_MIN_WORDS:
            return
        if count > best_count:
            best_count = count
            best_path = path
    label = best_path.relative_to(pack_dir).as_posix() if best_path else "(none)"
    raise CheckFailure(
        "experience_content",
        f"no experience file reached {EXPERIENCE_MIN_WORDS} words; "
        f"largest was {label} at {best_count} words",
    )


def _check_readme_domain(pack_dir: Path) -> None:
    """CHECK 6 — pages/README.md has 'domain:' / 'Domain:' and >=50 words."""
    readme = pack_dir / "pages" / "README.md"
    if not readme.is_file():
        raise CheckFailure("readme_domain", "pages/README.md is missing")
    text = readme.read_text(encoding="utf-8", errors="replace")
    if "domain:" not in text and "Domain:" not in text:
        raise CheckFailure(
            "readme_domain",
            "pages/README.md must contain 'domain:' or 'Domain:'",
        )
    word_count = _count_words(text)
    if word_count < README_MIN_WORDS:
        raise CheckFailure(
            "readme_domain",
            f"pages/README.md word count is {word_count}; "
            f"requires >= {README_MIN_WORDS}",
        )


def _check_duplicate_detection(
    tar_path: Path, pack_id: str, version: str, pack_dir: Path
) -> None:
    """CHECK 7 — no collision with ../index.json."""
    registry_root = tar_path.resolve().parent.parent
    index_path = registry_root / "index.json"
    if not index_path.is_file():
        # An empty / missing index has no entries to clash with.
        return
    index = _load_json(index_path, "duplicate_detection")

    packs = index.get("packs")
    if not isinstance(packs, list) or not packs:
        return

    try:
        content_hex, _, _ = compute_roots(pack_dir)
    except Exception as exc:
        raise CheckFailure(
            "duplicate_detection",
            f"Merkle recomputation failed while comparing against index: {exc}",
        ) from exc
    new_content_root = f"sha256:{content_hex}"

    for entry in packs:
        if not isinstance(entry, dict):
            continue
        existing_pack_id = entry.get("pack_id")
        existing_version = entry.get("version")
        existing_content_root = entry.get("content_root")

        if existing_pack_id == pack_id and existing_version == version:
            raise CheckFailure(
                "duplicate_detection",
                f"index.json already contains {pack_id}@{version}",
            )
        if (
            isinstance(existing_content_root, str)
            and existing_content_root == new_content_root
            and existing_pack_id != pack_id
        ):
            raise CheckFailure(
                "duplicate_detection",
                f"content_root {new_content_root} already registered under "
                f"pack_id {existing_pack_id!r}; cannot resubmit identical "
                f"content under pack_id {pack_id!r}",
            )


# ── Orchestrator ─────────────────────────────────────────────────────

def _passed(name: str) -> dict[str, Any]:
    return {"name": name, "passed": True, "message": ""}


def _failed(name: str, detail: str) -> dict[str, Any]:
    return {"name": name, "passed": False, "message": detail}


def validate(tar_path: Path) -> dict[str, Any]:
    """Run all seven checks in order; return the JSON-serializable report."""
    report: dict[str, Any] = {
        "pack_id": None,
        "version": None,
        "publisher_did": None,
        "checks": [],
        "overall": None,
        "error_check": None,
        "error_detail": None,
    }

    staging = Path(tempfile.mkdtemp(prefix="regvalidate-"))
    try:
        try:
            # CHECK 1
            pack_id, version, pack_dir = _check_tarball_integrity(tar_path, staging)
            report["pack_id"] = pack_id
            report["version"] = version
            report["checks"].append(_passed("tarball_integrity"))

            # CHECK 2
            manifest = _check_manifest_validation(pack_dir, pack_id)
            report["publisher_did"] = manifest.publisher_id
            report["checks"].append(_passed("manifest_validation"))

            # CHECK 3
            _check_signature_verification(tar_path, pack_dir, manifest.publisher_id)
            report["checks"].append(_passed("signature_verification"))

            # CHECK 4
            _check_attestation_completeness(pack_dir, manifest)
            report["checks"].append(_passed("attestation_completeness"))

            # CHECK 5
            _check_experience_content(pack_dir)
            report["checks"].append(_passed("experience_content"))

            # CHECK 6
            _check_readme_domain(pack_dir)
            report["checks"].append(_passed("readme_domain"))

            # CHECK 7
            _check_duplicate_detection(tar_path, pack_id, version, pack_dir)
            report["checks"].append(_passed("duplicate_detection"))

            report["overall"] = "pass"
        except CheckFailure as fail:
            report["checks"].append(_failed(fail.check_name, fail.detail))
            report["overall"] = "fail"
            report["error_check"] = fail.check_name
            report["error_detail"] = fail.detail
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate a single kb-registry pack tarball."
    )
    parser.add_argument(
        "tar_path",
        type=Path,
        help="Path to the pack tarball, e.g. packs/my.pack-1.0.0.tar",
    )
    args = parser.parse_args(argv)

    report = validate(args.tar_path)
    print(json.dumps(report, indent=2))
    return 0 if report["overall"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
