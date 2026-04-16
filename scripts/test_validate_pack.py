"""Pytest suite for validate_pack.py.

Each test builds a minimal, valid pack tarball in the pytest tmp_path
fixture, mutates the part of interest, and asserts on the structured
JSON report returned by `validate(...)`.

Real kb_pack primitives (`build_lock_for`, `write_lock`,
`sign_pack_root`) are used to produce correct Merkle roots + Ed25519
signatures, so the tests cover the signature-verification path end to
end. Nothing is fixture-checked-in; every file lives under tmp_path
and is thrown away at test teardown.

Run:

    pytest registry-repo/scripts/test_validate_pack.py
"""

from __future__ import annotations

import base64
import json
import sys
import tarfile
from pathlib import Path
from typing import Any

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Make `validate_pack` importable whether pytest is run from the repo
# root or from registry-repo/scripts/ directly.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from kb_pack import build_lock_for, sign_pack_root, write_lock  # noqa: E402

from validate_pack import _did_safe, validate  # noqa: E402


# ── Helpers ──────────────────────────────────────────────────────────

def _gen_keypair() -> tuple[str, str]:
    priv = Ed25519PrivateKey.generate()
    priv_hex = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()
    pub_hex = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    return priv_hex, pub_hex


def _build_pack(
    registry_root: Path,
    *,
    pack_id: str = "my.pack",
    version: str = "1.0.0",
    publisher_did: str = "did:web:example.com",
    license_spdx: str = "MIT",
    manifest_overrides: dict[str, Any] | None = None,
    manifest_omit: tuple[str, ...] = (),
    omit_attestation: str | None = None,
    attestation_overrides: dict[str, dict[str, Any]] | None = None,
    skip_decisions: bool = False,
    decisions_words: int = 200,
    readme_words: int = 80,
    readme_has_domain: bool = True,
    tamper_signature: bool = False,
    tamper_content_after_sign: bool = False,
    private_key_hex: str | None = None,
    public_key_hex: str | None = None,
    top_dir_override: str | None = None,
) -> tuple[Path, str, str]:
    """Write a (by default valid) pack tarball under
    `registry_root/packs/{pack_id}-{version}.tar`.

    Returns (tar_path, public_key_hex, content_root).
    """
    if private_key_hex is None or public_key_hex is None:
        private_key_hex, public_key_hex = _gen_keypair()

    packs_dir = registry_root / "packs"
    packs_dir.mkdir(parents=True, exist_ok=True)
    work_root = registry_root / f"_work-{pack_id}-{version}"
    work_root.mkdir()
    pack_dir_name = f"{pack_id}-{version}"
    pack_dir = work_root / pack_dir_name
    pack_dir.mkdir()

    # ---- Manifest (kb_pack v0.1.1 nested schema) ----------------------
    manifest = {
        "spec_version": "autoevolve-pack/0.1.1",
        "pack_id": pack_id,
        "version": version,
        "namespace": "test",
        "publisher": {"id": publisher_did},
        "title": f"Test pack {pack_id}",
        "attestations": {
            "provenance": "attestations/provenance.json",
            "redaction": "attestations/redaction.json",
            "evaluation": "attestations/evaluation.json",
            "license": "attestations/license.json",
        },
        "policy_surface": {},
        "license": {"spdx": license_spdx},
    }
    if manifest_overrides:
        manifest.update(manifest_overrides)
    for key in manifest_omit:
        manifest.pop(key, None)
    (pack_dir / "pack.manifest.yaml").write_text(yaml.safe_dump(manifest))

    # ---- Pages ---------------------------------------------------------
    pages = pack_dir / "pages"
    pages.mkdir()
    readme_parts: list[str] = ["# README", ""]
    if readme_has_domain:
        readme_parts.extend(["Domain: example", ""])
    readme_parts.append(" ".join(["word"] * readme_words))
    (pages / "README.md").write_text("\n".join(readme_parts))

    if not skip_decisions:
        decisions = pages / "decisions"
        decisions.mkdir()
        (decisions / "d1.md").write_text(
            "# Decision\n\n" + " ".join(["word"] * decisions_words)
        )

    # ---- Attestations (phase 1: without content_root) -----------------
    # We need the content_root to populate the attestations; compute it
    # now from the content files only. kb_pack.compute_roots produces
    # the content_root from manifest + README + pages/** which is all
    # we've written so far.
    from kb_pack import compute_roots as _compute  # local import to keep top-level clean

    content_hex, _, _ = _compute(pack_dir)
    content_root = f"sha256:{content_hex}"

    attestations_dir = pack_dir / "attestations"
    attestations_dir.mkdir()
    pack_ref = f"{pack_id}@{version}"
    kind_bodies: dict[str, dict[str, Any]] = {
        "provenance": {},
        "redaction": {
            "residual_risk_notes": "none known beyond the redaction policy scope",
        },
        "evaluation": {"composite_score": 0.85},
        "license": {"spdx": license_spdx},
    }
    for kind in ("provenance", "redaction", "evaluation", "license"):
        if omit_attestation == kind:
            continue
        doc: dict[str, Any] = {
            "spec": f"autoevolve-attestation/{kind}/0.1.1",
            "pack": pack_ref,
            "content_root": content_root,
            "issuer": publisher_did,
            "issued_at": "2026-04-16T00:00:00Z",
        }
        doc.update(kind_bodies[kind])
        if attestation_overrides and kind in attestation_overrides:
            doc.update(attestation_overrides[kind])
        (attestations_dir / f"{kind}.json").write_text(json.dumps(doc, indent=2))

    # ---- Lock + signature ---------------------------------------------
    lock = build_lock_for(pack_dir)
    write_lock(pack_dir, lock)

    signatures_dir = pack_dir / "signatures"
    signatures_dir.mkdir()
    pack_root_hex = lock.pack_root.removeprefix("sha256:")
    signature = sign_pack_root(pack_root_hex, private_key_hex)
    if tamper_signature:
        signature = bytes(b ^ 0x01 for b in signature)
    (signatures_dir / "publisher.sig").write_bytes(signature)
    (signatures_dir / "publisher.pubkey").write_bytes(bytes.fromhex(public_key_hex))

    if tamper_content_after_sign:
        # Modify a content file WITHOUT recomputing lock. This breaks
        # Merkle verification in check 3.
        (pages / "README.md").write_text(
            (pages / "README.md").read_text(encoding="utf-8") + "\nTAMPER"
        )

    # ---- Tarball -------------------------------------------------------
    arcname = top_dir_override if top_dir_override is not None else pack_dir_name
    tar_path = packs_dir / f"{pack_id}-{version}.tar"
    with tarfile.open(tar_path, "w") as tar:
        tar.add(pack_dir, arcname=arcname)

    return tar_path, public_key_hex, content_root


def _write_keys_json(
    registry_root: Path,
    publisher_did: str,
    public_key_hex: str,
    *,
    key_id: str = "test-2026-04",
    schema: str = "new",
) -> Path:
    """Write publishers/<did_safe>/keys.json.

    schema="new" (default): current registry schema —
        {"did", "keys": [{"key_id", "algorithm": "Ed25519", "public_key_b64"}]}.
    schema="old": legacy/kb_pack-sample schema —
        {"publisher_id", "keys": [{"key_id", "algorithm": "ed25519", "public_key_hex"}]}.
        Used exclusively to assert that Check 3 rejects the old shape.
    """
    did_safe = _did_safe(publisher_did)
    publishers_dir = registry_root / "publishers" / did_safe
    publishers_dir.mkdir(parents=True, exist_ok=True)
    if schema == "old":
        doc = {
            "publisher_id": publisher_did,
            "display_name": "Example Publisher",
            "keys": [
                {
                    "algorithm": "ed25519",
                    "key_id": key_id,
                    "public_key_hex": public_key_hex,
                }
            ],
        }
    elif schema == "new":
        pub_bytes = bytes.fromhex(public_key_hex)
        pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
        doc = {
            "did": publisher_did,
            "display_name": "Example Publisher",
            "keys": [
                {
                    "algorithm": "Ed25519",
                    "key_id": key_id,
                    "public_key_b64": pub_b64,
                }
            ],
        }
    else:
        raise ValueError(f"unknown schema: {schema!r}")
    path = publishers_dir / "keys.json"
    path.write_text(json.dumps(doc, indent=2))
    return path


def _write_index(registry_root: Path, packs: list[dict[str, Any]] | None = None) -> Path:
    doc = {
        "generated_at": "2026-04-16T00:00:00Z",
        "pack_count": len(packs or []),
        "packs": packs or [],
    }
    path = registry_root / "index.json"
    path.write_text(json.dumps(doc, indent=2))
    return path


def _setup_valid(registry_root: Path, **build_kwargs: Any) -> tuple[Path, str]:
    tar_path, pub_hex, content_root = _build_pack(registry_root, **build_kwargs)
    publisher_did = build_kwargs.get("publisher_did", "did:web:example.com")
    _write_keys_json(registry_root, publisher_did, pub_hex)
    _write_index(registry_root)
    return tar_path, content_root


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def registry_root(tmp_path: Path) -> Path:
    return tmp_path


# ── Happy path ───────────────────────────────────────────────────────

def test_happy_path(registry_root: Path) -> None:
    tar_path, _ = _setup_valid(registry_root)
    result = validate(tar_path)
    assert result["overall"] == "pass", result
    assert result["pack_id"] == "my.pack"
    assert result["version"] == "1.0.0"
    assert result["publisher_did"] == "did:web:example.com"
    assert [c["name"] for c in result["checks"]] == [
        "tarball_integrity",
        "manifest_validation",
        "signature_verification",
        "attestation_completeness",
        "experience_content",
        "readme_domain",
        "duplicate_detection",
    ]
    assert all(c["passed"] for c in result["checks"])
    assert result["error_check"] is None
    assert result["error_detail"] is None


# ── Check 1: tarball_integrity ───────────────────────────────────────

def test_tarball_missing_file(tmp_path: Path) -> None:
    result = validate(tmp_path / "no-such-pack-1.0.0.tar")
    assert result["overall"] == "fail"
    assert result["error_check"] == "tarball_integrity"
    assert "does not exist" in result["error_detail"]


def test_tarball_filename_not_parseable(registry_root: Path) -> None:
    tar_path, _ = _setup_valid(registry_root)
    bad = tar_path.with_name("badly-named.tar")
    tar_path.rename(bad)
    result = validate(bad)
    assert result["overall"] == "fail"
    assert result["error_check"] == "tarball_integrity"


def test_tarball_not_a_tar(registry_root: Path) -> None:
    packs = registry_root / "packs"
    packs.mkdir(parents=True, exist_ok=True)
    bogus = packs / "fake.pack-1.0.0.tar"
    bogus.write_bytes(b"This is not a tar archive")
    result = validate(bogus)
    assert result["overall"] == "fail"
    assert result["error_check"] == "tarball_integrity"


def test_tarball_top_dir_mismatch(registry_root: Path) -> None:
    tar_path, _, _ = _build_pack(registry_root, top_dir_override="wrong-name-2.0.0")
    _write_keys_json(registry_root, "did:web:example.com", _gen_keypair()[1])
    _write_index(registry_root)
    result = validate(tar_path)
    assert result["overall"] == "fail"
    assert result["error_check"] == "tarball_integrity"
    assert "wrong-name-2.0.0" in result["error_detail"]


# ── Check 2: manifest_validation ─────────────────────────────────────

@pytest.mark.parametrize(
    "missing_field",
    # Four of kb_pack v0.1.1's REQUIRED_FIELDS, representative of the
    # failure modes Check 2 surfaces via `kb_pack.load_manifest`:
    #  - spec_version: rejected because the versioned wire protocol
    #    cannot be recognised at all.
    #  - pack_id / version: mechanical presence, also cross-checked
    #    against filename.
    #  - publisher: without the whole block, publisher.id can't be
    #    derived for Check 3.
    ["spec_version", "pack_id", "version", "publisher"],
)
def test_manifest_missing_required_field(
    registry_root: Path, missing_field: str
) -> None:
    tar_path, _ = _setup_valid(registry_root, manifest_omit=(missing_field,))
    result = validate(tar_path)
    assert result["overall"] == "fail"
    assert result["error_check"] == "manifest_validation"
    assert missing_field in result["error_detail"]


def test_manifest_bad_semver(registry_root: Path) -> None:
    tar_path, _ = _setup_valid(
        registry_root, manifest_overrides={"version": "not-a-version"}
    )
    result = validate(tar_path)
    assert result["overall"] == "fail"
    assert result["error_check"] == "manifest_validation"


def test_manifest_bad_publisher_did_prefix(registry_root: Path) -> None:
    # publisher_did uses did:key: — validator only accepts did:web:.
    # keys.json is written under the :/ -> _ safe name derived from
    # the bad DID so that Check 2 (not Check 3) is what fires.
    tar_path, pub_hex, _ = _build_pack(
        registry_root, publisher_did="did:key:zsomething"
    )
    _write_keys_json(registry_root, "did:key:zsomething", pub_hex)
    _write_index(registry_root)
    result = validate(tar_path)
    assert result["overall"] == "fail"
    assert result["error_check"] == "manifest_validation"
    assert "did:web:" in result["error_detail"]


def test_manifest_pack_id_mismatch(registry_root: Path) -> None:
    # Tarball filename encodes pack_id=foo, but the manifest says bar.
    tar_path, _ = _setup_valid(
        registry_root,
        pack_id="foo",
        manifest_overrides={"pack_id": "bar"},
    )
    result = validate(tar_path)
    assert result["overall"] == "fail"
    assert result["error_check"] == "manifest_validation"


# ── Check 3: signature_verification ──────────────────────────────────

def test_signature_keys_file_missing(registry_root: Path) -> None:
    tar_path, _, _ = _build_pack(registry_root)
    _write_index(registry_root)
    result = validate(tar_path)
    assert result["overall"] == "fail"
    assert result["error_check"] == "signature_verification"
    assert "publishers/did_web_example.com/keys.json" in result["error_detail"]


def test_signature_bundled_key_not_registered(registry_root: Path) -> None:
    tar_path, _, _ = _build_pack(registry_root)
    _, other_pub = _gen_keypair()
    _write_keys_json(registry_root, "did:web:example.com", other_pub)
    _write_index(registry_root)
    result = validate(tar_path)
    assert result["overall"] == "fail"
    assert result["error_check"] == "signature_verification"
    assert "not registered" in result["error_detail"]


def test_signature_tampered_signature_bytes(registry_root: Path) -> None:
    tar_path, _ = _setup_valid(registry_root, tamper_signature=True)
    result = validate(tar_path)
    assert result["overall"] == "fail"
    assert result["error_check"] == "signature_verification"


def test_signature_content_tampered_after_lock(registry_root: Path) -> None:
    tar_path, _ = _setup_valid(registry_root, tamper_content_after_sign=True)
    result = validate(tar_path)
    assert result["overall"] == "fail"
    assert result["error_check"] == "signature_verification"
    assert "content_root" in result["error_detail"] or "pack_root" in result["error_detail"]


def test_signature_new_schema_keys_json_passes(registry_root: Path) -> None:
    """keys.json in the current registry schema (did / Ed25519 / public_key_b64)
    must be accepted by Check 3."""
    tar_path, pub_hex, _ = _build_pack(registry_root)
    keys_path = _write_keys_json(
        registry_root, "did:web:example.com", pub_hex, schema="new"
    )
    _write_index(registry_root)

    # Belt-and-suspenders: verify the on-disk file really does use the new
    # schema so this test can't silently pass against the legacy shape.
    doc = json.loads(keys_path.read_text())
    assert "did" in doc and "publisher_id" not in doc
    assert doc["keys"][0]["algorithm"] == "Ed25519"
    assert "public_key_b64" in doc["keys"][0]
    assert "public_key_hex" not in doc["keys"][0]

    result = validate(tar_path)
    assert result["overall"] == "pass", result
    by_name = {c["name"]: c for c in result["checks"]}
    assert by_name["signature_verification"]["passed"]


def test_signature_old_schema_keys_json_rejected(registry_root: Path) -> None:
    """keys.json in the legacy kb_pack-sample schema
    (publisher_id / ed25519 / public_key_hex) must fail Check 3 with an
    error that names the required Ed25519 + public_key_b64 fields."""
    tar_path, pub_hex, _ = _build_pack(registry_root)
    keys_path = _write_keys_json(
        registry_root, "did:web:example.com", pub_hex, schema="old"
    )
    _write_index(registry_root)

    # Confirm the fixture really did write the legacy shape.
    doc = json.loads(keys_path.read_text())
    assert "publisher_id" in doc
    assert doc["keys"][0]["algorithm"] == "ed25519"
    assert "public_key_hex" in doc["keys"][0]

    result = validate(tar_path)
    assert result["overall"] == "fail"
    assert result["error_check"] == "signature_verification"
    detail = result["error_detail"]
    assert "Ed25519" in detail, detail
    assert "public_key_b64" in detail, detail


# ── Check 4: attestation_completeness ────────────────────────────────

@pytest.mark.parametrize("kind", ["provenance", "redaction", "evaluation", "license"])
def test_attestation_missing(registry_root: Path, kind: str) -> None:
    tar_path, _ = _setup_valid(registry_root, omit_attestation=kind)
    result = validate(tar_path)
    assert result["overall"] == "fail"
    assert result["error_check"] == "attestation_completeness"
    assert kind in result["error_detail"]


def test_attestation_redaction_empty_notes(registry_root: Path) -> None:
    tar_path, _ = _setup_valid(
        registry_root,
        attestation_overrides={"redaction": {"residual_risk_notes": ""}},
    )
    result = validate(tar_path)
    assert result["overall"] == "fail"
    assert result["error_check"] == "attestation_completeness"
    assert "residual_risk_notes" in result["error_detail"]


def test_attestation_redaction_notes_wrong_type(registry_root: Path) -> None:
    # Check 4 now accepts both non-empty strings and non-empty lists for
    # residual_risk_notes (see test_residual_risk_notes_list_accepted
    # below). A value that is neither — dict, int, None — must still
    # fail.
    tar_path, _ = _setup_valid(
        registry_root,
        attestation_overrides={"redaction": {"residual_risk_notes": {"nope": 1}}},
    )
    result = validate(tar_path)
    assert result["overall"] == "fail"
    assert result["error_check"] == "attestation_completeness"
    assert "string or list" in result["error_detail"]


def test_residual_risk_notes_list_accepted(registry_root: Path) -> None:
    # kb_pack.build_redaction produces residual_risk_notes as a list.
    # Check 4 must accept that shape (as long as the list is non-empty)
    # so a pack built through the documented kb_pack path verifies
    # without hand-patching the attestation.
    tar_path, _ = _setup_valid(
        registry_root,
        attestation_overrides={
            "redaction": {"residual_risk_notes": ["PII risk", "timing info leaked"]}
        },
    )
    result = validate(tar_path)
    assert result["overall"] == "pass", result
    by_name = {c["name"]: c for c in result["checks"]}
    assert by_name["attestation_completeness"]["passed"]


def test_license_spdx_field_accepted(registry_root: Path) -> None:
    # kb_pack.build_license writes the SPDX under `license_spdx`;
    # the registry's canonical field is `spdx`. Check 4 must accept
    # either. We simulate kb_pack's output by overriding the license
    # body so `spdx` is absent (None — which falls back to license_spdx
    # via `or`) and `license_spdx` carries the value.
    tar_path, _ = _setup_valid(
        registry_root,
        attestation_overrides={
            "license": {"spdx": None, "license_spdx": "Apache-2.0"},
        },
    )
    result = validate(tar_path)
    assert result["overall"] == "pass", result
    by_name = {c["name"]: c for c in result["checks"]}
    assert by_name["attestation_completeness"]["passed"]


@pytest.mark.parametrize("bad_score", [-0.1, 1.5, "0.8", True, None])
def test_attestation_composite_score_out_of_range(
    registry_root: Path, bad_score: Any
) -> None:
    tar_path, _ = _setup_valid(
        registry_root,
        attestation_overrides={"evaluation": {"composite_score": bad_score}},
    )
    result = validate(tar_path)
    assert result["overall"] == "fail"
    assert result["error_check"] == "attestation_completeness"


def test_attestation_license_spdx_empty(registry_root: Path) -> None:
    tar_path, _ = _setup_valid(
        registry_root,
        attestation_overrides={"license": {"spdx": ""}},
    )
    result = validate(tar_path)
    assert result["overall"] == "fail"
    assert result["error_check"] == "attestation_completeness"


# ── Check 5: experience_content ──────────────────────────────────────

def test_experience_no_file(registry_root: Path) -> None:
    tar_path, _ = _setup_valid(registry_root, skip_decisions=True)
    result = validate(tar_path)
    assert result["overall"] == "fail"
    assert result["error_check"] == "experience_content"
    assert "decisions/" in result["error_detail"]


def test_experience_file_too_short(registry_root: Path) -> None:
    tar_path, _ = _setup_valid(registry_root, decisions_words=40)
    result = validate(tar_path)
    assert result["overall"] == "fail"
    assert result["error_check"] == "experience_content"


# ── Check 6: readme_domain ───────────────────────────────────────────

def test_readme_no_domain_marker(registry_root: Path) -> None:
    tar_path, _ = _setup_valid(registry_root, readme_has_domain=False)
    result = validate(tar_path)
    assert result["overall"] == "fail"
    assert result["error_check"] == "readme_domain"
    assert "domain" in result["error_detail"].lower()


def test_readme_word_count_below_threshold(registry_root: Path) -> None:
    # Domain marker present, but word count too low.
    tar_path, _ = _setup_valid(registry_root, readme_words=5)
    result = validate(tar_path)
    assert result["overall"] == "fail"
    assert result["error_check"] == "readme_domain"
    assert "word count" in result["error_detail"]


# ── Check 7: duplicate_detection ─────────────────────────────────────

def test_duplicate_same_pack_id_and_version(registry_root: Path) -> None:
    tar_path, pub_hex, content_root = _build_pack(registry_root)
    _write_keys_json(registry_root, "did:web:example.com", pub_hex)
    _write_index(
        registry_root,
        packs=[
            {
                "pack_id": "my.pack",
                "version": "1.0.0",
                "content_root": content_root,
                "publisher_did": "did:web:example.com",
            }
        ],
    )
    result = validate(tar_path)
    assert result["overall"] == "fail"
    assert result["error_check"] == "duplicate_detection"
    assert "my.pack@1.0.0" in result["error_detail"]


def test_duplicate_content_root_under_different_pack_id(registry_root: Path) -> None:
    tar_path, pub_hex, content_root = _build_pack(registry_root)
    _write_keys_json(registry_root, "did:web:example.com", pub_hex)
    _write_index(
        registry_root,
        packs=[
            {
                "pack_id": "someone-else.pack",
                "version": "1.0.0",
                "content_root": content_root,
            }
        ],
    )
    result = validate(tar_path)
    assert result["overall"] == "fail"
    assert result["error_check"] == "duplicate_detection"


def test_duplicate_same_pack_id_different_version_ok(registry_root: Path) -> None:
    # Index already has my.pack@0.9.0. Submitting my.pack@1.0.0 should pass.
    tar_path, pub_hex, _ = _build_pack(registry_root, version="1.0.0")
    _write_keys_json(registry_root, "did:web:example.com", pub_hex)
    _write_index(
        registry_root,
        packs=[
            {
                "pack_id": "my.pack",
                "version": "0.9.0",
                "content_root": "sha256:" + "0" * 64,
            }
        ],
    )
    result = validate(tar_path)
    assert result["overall"] == "pass", result


def test_duplicate_content_root_same_pack_id_allowed(registry_root: Path) -> None:
    # Same pack_id republished under a different version with identical
    # content_root is NOT flagged (rule B only catches cross-pack_id reuse).
    # We fake this by pre-seeding an entry with the same pack_id + same
    # content_root but a different version.
    tar_path, pub_hex, content_root = _build_pack(registry_root, version="1.0.0")
    _write_keys_json(registry_root, "did:web:example.com", pub_hex)
    _write_index(
        registry_root,
        packs=[
            {
                "pack_id": "my.pack",
                "version": "0.9.0",
                "content_root": content_root,
            }
        ],
    )
    result = validate(tar_path)
    assert result["overall"] == "pass", result


def test_duplicate_missing_index_is_ok(registry_root: Path) -> None:
    tar_path, pub_hex, _ = _build_pack(registry_root)
    _write_keys_json(registry_root, "did:web:example.com", pub_hex)
    # No index.json on disk.
    result = validate(tar_path)
    assert result["overall"] == "pass", result


# ── Output shape invariants (applies to every outcome) ───────────────

def test_report_shape_on_pass(registry_root: Path) -> None:
    tar_path, _ = _setup_valid(registry_root)
    result = validate(tar_path)
    assert set(result.keys()) == {
        "pack_id",
        "version",
        "publisher_did",
        "checks",
        "overall",
        "error_check",
        "error_detail",
    }
    for check in result["checks"]:
        assert set(check.keys()) == {"name", "passed", "message"}


def test_report_shape_on_fail(tmp_path: Path) -> None:
    result = validate(tmp_path / "nowhere-1.0.0.tar")
    assert set(result.keys()) == {
        "pack_id",
        "version",
        "publisher_did",
        "checks",
        "overall",
        "error_check",
        "error_detail",
    }
    # The single check we ran should be marked failed.
    assert result["checks"][-1]["passed"] is False
    assert result["overall"] == "fail"
    assert result["error_check"] is not None
    assert result["error_detail"] is not None


def test_did_safe_encoding() -> None:
    assert _did_safe("did:web:example.com") == "did_web_example.com"
    assert _did_safe("did:web:example.com/org") == "did_web_example.com_org"
