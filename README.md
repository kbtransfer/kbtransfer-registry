# kb-registry

[![packs](https://img.shields.io/badge/dynamic/json?url=https://registry.kbtransfer.dev/index.json&query=$.pack_count&label=packs)](https://registry.kbtransfer.dev/index.json)
[![publishers](https://img.shields.io/badge/dynamic/json?url=https://registry.kbtransfer.dev/index.json&query=$.publisher_count&label=publishers)](https://registry.kbtransfer.dev/index.json)

A git-hosted registry of signed, attested KBTransfer packs. Publishers
submit pack tarballs by pull request; every submission is
cryptographically verified before it can merge. Consumers fetch packs
by `pack_id` over HTTPS and re-verify every signature locally, so a
compromised registry cannot forge a valid pack.

## Publish a pack

See [REGISTRY_POLICY.md](REGISTRY_POLICY.md) for the seven validation
checks, the one-time publisher registration flow, and the worked
`kb init → kb/publish/0.1 → PR` example.

## Search packs

From any KBTransfer client:

```
kb/registry_search/0.1  query="circuit breaker"
```

The `kb/registry_search` MCP tool federates across every registry URL
listed in the consumer's `.kb/policy.yaml` and dedupes by `pack_id`.

Or directly over HTTPS — any `curl`, `jq`, CI job, or dashboard:

```
curl -s https://registry.kbtransfer.dev/index.json \
  | jq '.packs[] | select(.pack_id | contains("circuit-breaker"))'
```

The full index is at <https://registry.kbtransfer.dev/index.json>;
per-publisher aggregates live at
<https://registry.kbtransfer.dev/stats.json>.

## Run a mirror

`kb_registry.open_registry(url)` accepts `https://` and `git+https://`
URLs interchangeably — the `git+https://` prefix is a hint that the
URL is a git-backed HTTPS endpoint serving the registry tree. Both
fetch `index.json` over TLS and verify every tarball against its
index-declared `sha256` before extraction.

To stand up a mirror:

```
# 1. Clone this repo somewhere your users can reach.
git clone https://registry.kbtransfer.dev.git /srv/mirrors/kb-registry
# (keep it in sync on a cron: cd /srv/mirrors/kb-registry && git pull)

# 2. Serve the working tree over HTTPS. Anything works — nginx, Caddy,
#    an S3 static bucket, a GitHub Pages fork. All consumers need is
#    the index.json at the configured URL and the packs/*.tar files
#    at the paths the index references. Tarballs live FLAT directly
#    under packs/ as packs/<pack_id>-<version>.tar; there is no
#    per-pack subdirectory.

# 3. Point consumers at your mirror by adding it to .kb/policy.yaml:
#
#    registries:
#      - url: git+https://mirror.example.internal/kb-registry
#      - url: https://registry.kbtransfer.dev          # fallback
```

`kb/registry_search/0.1` queries every URL in order and merges the
results; the same pack_id showing up on multiple mirrors is returned
once. Mirrors inherit this repo's trust model — they are a
distribution layer, not a trust root. Every consumer still verifies
each pack against the publisher's `keys.json` on ingestion.

## License

Apache-2.0. See [LICENSE](LICENSE).
