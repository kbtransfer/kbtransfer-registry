# REGISTRY_POLICY.md

## 1. Purpose

This is a git-hosted registry of signed, attested KBTransfer packs.
Consumers fetch packs by `pack_id` and verify them locally against the
publisher keys recorded here. Every submission is cryptographically
checked pre-merge and cannot be silently mutated after merge.

## 2. What this registry accepts

Every pack submission must pass all seven checks in
[scripts/validate_pack.py](scripts/validate_pack.py). Checks run in
order; the first failure blocks the PR. The names below are exactly
the strings that appear in the validator's JSON output under
`checks[].name`:

1. **`tarball_integrity`** — filename matches `{pack_id}-{version}.tar`, archive opens, exactly one top-level directory named `{pack_id}-{version}`.
2. **`manifest_validation`** — `pack.manifest.yaml` parses against the kb_pack v0.1.1 nested schema (delegated to `kb_pack.load_manifest`): `spec_version`, `pack_id`, `version`, `namespace`, `publisher.id`, `title`, `attestations`, `policy_surface` all present; plus the registry-local rules that `pack_id` matches the filename, `version` is parseable by `packaging`, and `publisher.id` begins with `did:web:`. See [REGISTRY_API_NOTES.md §1.4](../REGISTRY_API_NOTES.md) for the canonical YAML shape.
3. **`signature_verification`** — Ed25519 signature over the pack_root Merkle verifies against a public key registered in `publishers/<did_safe>/keys.json`; content_root and pack_root in `pack.lock` match a recomputation from the tarball.
4. **`attestation_completeness`** — all four attestations (`provenance`, `redaction`, `evaluation`, `license`) are present with required envelope fields; `redaction.residual_risk_notes` is a non-empty string; `evaluation.composite_score` is a number in `[0.0, 1.0]`; `license.spdx` is a non-empty string.
5. **`experience_content`** — at least one file under `pages/decisions/` or `pages/failure-log/` contains ≥100 words.
6. **`readme_domain`** — `pages/README.md` exists, contains `domain:` or `Domain:`, and has ≥50 total words.
7. **`duplicate_detection`** — no existing `index.json` entry with the same `pack_id@version`; no existing entry where the same `content_root` is already registered under a different `pack_id`.

## 3. What this registry does NOT accept

- **Reference-only packs.** A pack whose `pages/` contains only generic documentation, API references, or external tutorials, with no `decisions/` or `failure-log/` content, fails check 5 and will not merge.
- **Stubs.** An experience file under 100 words fails check 5. If you cannot describe a decision or a failure in at least 100 words, you don't yet have operational experience worth publishing.
- **Prohibited content.** Illegal content; content intended to harm people or systems; copyrighted material without a license whose SPDX identifier is listed in the OSI-approved or Creative Commons open-license registries. The registry operators will remove such packs on credible report without waiting for a process (see §8).
- **Synthetic packs.** Packs generated from an LLM prompt with no real operational experience behind them. The registry cannot detect this mechanically; review is social. A pattern of synthetic submissions from a publisher causes their DID to be delisted from the mirror recommendations at `registry.kbtransfer.dev`.

## 4. Publisher registration

Register once per publisher. Follow-up pack submissions reuse the same keys.json.

1. Generate an Ed25519 key pair through the KBTransfer CLI:
   ```
   kb init my-kb --tier team
   ```
   The `team` tier writes your public key to `.kb/keys/` and prints the base64 form you will paste into `keys.json`. Keep the private key in `.kb/keys/`; never put it in a PR.
2. Fork this repo.
3. Create `publishers/<did_safe>/keys.json`, where `<did_safe>` is your DID with `:` and `/` replaced by `_` (e.g. `did:web:my-team.example` → `did_web_my-team.example`).
4. Minimum required `keys.json` structure:
   ```json
   {
     "did": "did:web:my-team.example",
     "keys": [
       {
         "key_id": "2026-04-primary",
         "algorithm": "Ed25519",
         "public_key_b64": "BASE64_32_BYTE_PUBLIC_KEY="
       }
     ]
   }
   ```
   - `did` MUST equal `did_web_my-team.example` when re-encoded (colon/slash → underscore); the `validate_publisher` job enforces this.
   - `algorithm` MUST be the exact string `Ed25519` (capital E). Lowercase `ed25519` is rejected.
   - `public_key_b64` MUST be standard base64 (with padding) of exactly 32 raw bytes.
5. Open a PR. The `validate_publisher` job checks schema and the did↔directory match and posts a success or failure comment.
6. After merge, you can submit packs signed by that `key_id`.

To rotate a key, add a new entry to `keys` in a follow-up PR. Do not delete old entries until no live pack still points to them — signature verification for those packs would start failing.

## 5. Pack submission

Worked example: you are publishing `my-team.patterns.circuit-breaker@1.0.0`.

```
# 1. Stand up a fresh KB.
kb init my-kb --tier team --publisher-id did:web:my-team.example
cd my-kb && git init && git add . && git commit -m "fresh KB"

# 2. Ingest source material (docs, transcripts, Slack exports).
#    The agent populates pages/ with wiki-style notes.
#    This is the step that can take hours; it is out of scope here.

# 3. Draft a pack from a subset of pages.
kb/draft_pack/0.1  pack_id=my-team.patterns.circuit-breaker  version=1.0.0

# 4. Distill: redact PII, add attestations, verify with a second model.
/kb-distill my-team.patterns.circuit-breaker

# 5. Build the signed tarball.
kb/publish/0.1  pack_id=my-team.patterns.circuit-breaker

# 6. Submit.
#    Fork this repo, copy the produced tarball into packs/ (FLAT
#    layout — see the path convention note below), open a PR.
cp my-kb/published/my-team.patterns.circuit-breaker-1.0.0.tar \
   <registry-fork>/packs/my-team.patterns.circuit-breaker-1.0.0.tar
```

**Path convention (flat, not nested).** Every tarball lives at
`packs/<pack_id>-<version>.tar` — the `pack_id` and `version` are
both in the filename, separated by a hyphen. Do **not** create a
subdirectory per pack:

```
packs/my-team.patterns.circuit-breaker-1.0.0.tar    ← correct
packs/my-team.patterns.circuit-breaker/1.0.0.tar    ← rejected
```

The second form fails `tarball_integrity` (Check 1) because the
filename `1.0.0.tar` does not match the `{pack_id}-{version}.tar`
regex — the pack_id is derived from the filename, not the parent
directory. `rebuild_index.py` also scans `packs/*.tar` flat; nested
layouts are invisible to it.

Open a PR containing exactly that one file (or that file plus a new `publishers/<did_safe>/keys.json` on your first-ever submission — see `check_single_file` in [validate-pr.yml](.github/workflows/validate-pr.yml) for the one-or-two-file rule). CI will run the seven checks in §2 and post a pass/fail comment. On pass, the PR is auto-merged after 30 minutes unless someone comments `/hold`.

## 6. Trust model

**Individual and team tiers: Trust On First Use (TOFU).** The first time a consumer's KB encounters a publisher, it pins the public keys from their `publishers/<did_safe>/keys.json` into its local trust store. Subsequent verifications use the pinned key; a change to the published keys without matching local re-trust causes signature verification to fail loudly. In practice this means that as a consumer you trust a publisher's FIRST `keys.json` you see, and any change after that requires you to explicitly re-pin. This is exactly the SSH-known-hosts trust model applied to Ed25519 signing keys.

**Enterprise tier: strict allowlist.** Enterprise consumers configure their policy with an explicit list of allowed publisher DIDs. Encountering a pack from a DID not in the allowlist causes ingestion to refuse, regardless of how many valid signatures the pack carries. This mode trades flexibility for auditability: every publisher whose packs reach production was reviewed and added by a named human.

Both tiers verify signatures and attestations locally on ingestion — the registry itself is never a trust root, only a distribution layer.

## 7. Versioning rules

- **semver required.** `version` in `pack.manifest.yaml` must match `^\d+\.\d+\.\d+$` and be parseable by the `packaging` library.
- **Published versions are immutable.** Once `packs/<pack_id>-<version>.tar` is on `main`, the bytes do not change. `rebuild-index.yml` will not reprocess a tarball whose sha256 it has already indexed; `validate_pack.py` blocks any PR that tries to overwrite an existing `pack_id@version`.
- **To update, publish a new version.** Bump `version`, build, sign, submit. The old version stays at its old `content_root`. Consumers choose whether to move forward via semver constraints in their policy.
- **No yanking in v1.** There is no mechanism in this spec version to mark a version as deprecated, recalled, or revoked. Packs that must be withdrawn for legal or security reasons are removed from `main` by the registry operators via a takedown PR (see §8), which breaks their download URL but does not retroactively invalidate any consumer's already-ingested copy. The v2 draft [RFC-0006](https://github.com/kbtransfer/rfcs) introduces a signed revocation channel; this document will be updated when that lands.

## 8. Reporting problems

Open a GitHub issue on this repository with the label **`registry-report`**. Include the `pack_id@version` and the nature of the problem (malicious content, license violation, broken signature after rotate, etc.). Do not file security-sensitive reports publicly; the label description in the issue template links to a private disclosure channel for those.

## 9. What happens after merge

- Within roughly 5 minutes, `rebuild-index.yml` runs on the push to `main` and rewrites [index.json](index.json) and [stats.json](stats.json) with your new pack's metadata. The rebuild is idempotent: running it twice on the same git state produces byte-identical files.
- Your pack is immediately searchable from any KB client:
  ```
  kb/registry_search/0.1  query="circuit breaker"
  ```
  The MCP tool returns matches across every registry listed in the consumer's `.kb/policy.yaml`.
- The raw index is readable by any HTTP client (caches, CI, dashboards):
  ```
  https://registry.kbtransfer.dev/index.json
  ```
  `pack_count` at the top level is authoritative; `packs[].sha256` is what HTTPS consumers verify every tarball against before extraction.
