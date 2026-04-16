# DEPLOY_CHECKLIST.md

One-time deploy sequence for standing up this registry on GitHub.
Tick boxes top to bottom; every `YOUR_ORG` is a placeholder you
must replace with your actual org or user handle before running
the surrounding command.

---

## Section 1 — Extract `registry-repo/` to a standalone git repo

- [ ] **1.1** Create a new directory outside the kbtransfer repo.
  ```bash
  mkdir ~/registry && cp -r registry-repo/. ~/registry/
  cd ~/registry
  ```

- [ ] **1.2** Init git and make the first commit.
  ```bash
  git init
  git add .
  git commit -m "chore: initial registry scaffold"
  ```

- [ ] **1.3** Add kbtransfer as a submodule.
  ```bash
  git submodule add https://github.com/YOUR_ORG/kbtransfer.git kbtransfer
  git commit -m "chore: add kbtransfer submodule"
  ```
  Note: replace `YOUR_ORG` with the real org/user when kbtransfer is
  pushed. Until then, use a local path:
  ```bash
  git submodule add /path/to/kbtransfer kbtransfer
  ```

---

## Section 2 — Create GitHub repository

- [ ] **2.1** Create the repo and wire up the remote.
  ```bash
  gh repo create kbtransfer-registry --public --source=. --remote=origin
  ```

- [ ] **2.2** Push.
  ```bash
  git push -u origin main
  ```

- [ ] **2.3** Confirm the repo page loads at
  `https://github.com/YOUR_ORG/kbtransfer-registry`.

---

## Section 3 — Create required labels

These must exist before any PR can be labeled by the bot. Every
`gh pr edit --add-label` call is `|| true`-guarded in the workflows,
but missing labels mean PRs merge without the taxonomy you rely on.

- [ ] **3.1** `registry-approved` (blue — passed validation, in auto-merge window).
  ```bash
  gh label create "registry-approved"   --color 0075ca --repo YOUR_ORG/kbtransfer-registry
  ```

- [ ] **3.2** `validation-failed` (red — Check 1-7 blocked the PR).
  ```bash
  gh label create "validation-failed"   --color d93f0b --repo YOUR_ORG/kbtransfer-registry
  ```

- [ ] **3.3** `invalid-submission` (yellow — PR scope rule broken).
  ```bash
  gh label create "invalid-submission"  --color e4e669 --repo YOUR_ORG/kbtransfer-registry
  ```

- [ ] **3.4** `registry-report` (purple — takedown / abuse issues).
  ```bash
  gh label create "registry-report"     --color 5319e7 --repo YOUR_ORG/kbtransfer-registry
  ```

---

## Section 4 — Bot token

The bot needs to post PR comments, add labels, merge PRs, and push
index commits. A fine-grained PAT scoped to just this repo is
enough — no `repo:*` on the whole account.

- [ ] **4.1** Mint the token.

  Open <https://github.com/settings/tokens?type=beta> and create a
  fine-grained PAT named `kbtransfer-registry-bot` with:

  - **Repository access:** only `kbtransfer-registry`
  - **Permissions:**
    - **Contents:** Read and write       (push `index.json` commits)
    - **Pull requests:** Read and write  (comment, label, merge)
    - **Metadata:** Read-only            (required by GitHub)

- [ ] **4.2** Install the token as a repo secret.
  ```bash
  gh secret set REGISTRY_BOT_TOKEN \
    --body "YOUR_TOKEN_HERE" \
    --repo YOUR_ORG/kbtransfer-registry
  ```

- [ ] **4.3** Verify both workflow files reference the secret consistently.
  ```bash
  grep -r "REGISTRY_BOT_TOKEN" .github/workflows/
  ```
  Expected: appears in `validate-pr.yml` (the `gh pr merge` step) and
  in `rebuild-index.yml` (the `git push` step). Currently both
  workflows use `secrets.GITHUB_TOKEN`; if you switch to the
  dedicated bot token, update those references in the same PR.

---

## Section 5 — Branch protection (repo-level ruleset, evaluate mode)

GitHub's classic branch protection API silently fails when a bot
needs to push directly to `main` (the rebuild-index workflow's
case): the four required PR-context status checks never run on
direct pushes, so they remain "expected" forever and block the
push. Repo-level rulesets have the same problem because they
cannot list `GitHub Actions` as a bypass actor — only org-level
rulesets can.

**Org-level rulesets require GitHub Team plan ($4/user/mo).**
On Free orgs the API returns
`Upgrade to GitHub Team to enable this feature. (HTTP 403)` for
`POST /orgs/{org}/rulesets`.

The workaround that ships in this checklist: a repo-level
ruleset in **`enforcement: "evaluate"` mode**. The four required
checks still appear on every PR (devs see green/red, the bot
comments still post and label), but the ruleset does NOT block
the bot's direct push. Trade-off: an org admin can technically
merge a failing PR via API. Acceptable for solo or small-team
deployments; revisit on Team upgrade.

- [ ] **5.1** Create the repo-level ruleset.
  ```bash
  gh api repos/YOUR_ORG/kbtransfer-registry/rulesets \
    --method POST \
    --input - <<'EOF'
  {
    "name": "main-protection-evaluate",
    "target": "branch",
    "enforcement": "evaluate",
    "conditions": {
      "ref_name": {
        "include": ["refs/heads/main"],
        "exclude": []
      }
    },
    "bypass_actors": [
      {
        "actor_id": 1,
        "actor_type": "OrganizationAdmin",
        "bypass_mode": "always"
      }
    ],
    "rules": [
      {"type": "deletion"},
      {"type": "non_fast_forward"},
      {
        "type": "required_status_checks",
        "parameters": {
          "strict_required_status_checks_policy": true,
          "required_status_checks": [
            {"context": "check_single_file"},
            {"context": "detect_submission_type"},
            {"context": "validate_publisher"},
            {"context": "validate_pack"}
          ]
        }
      }
    ]
  }
  EOF
  ```

  Notes on the JSON:
  - `enforcement: "evaluate"` — reports check status, does not
    block. Switch to `"active"` after upgrading to Team plan
    (and add a `GitHub Actions` bypass actor — see below).
  - `auto_merge` is intentionally NOT in the required list —
    it sleeps 30 min and would force every PR to wait that long
    before any required-check could complete.
  - `bypass_actors` includes only `OrganizationAdmin` so admins
    can merge or push when the bot can't. The bot itself doesn't
    need a bypass entry under `evaluate` mode.

  Context names must exactly match the top-level `jobs:` keys in
  `validate-pr.yml`. Verify with:
  ```bash
  grep -E "^  [a-z_]+:" .github/workflows/validate-pr.yml
  ```

- [ ] **5.2** Confirm the ruleset is active.
  ```bash
  gh api repos/YOUR_ORG/kbtransfer-registry/rulesets \
    --jq '.[] | {id, name, enforcement, target}'
  ```
  Expected output: one entry with `enforcement: "evaluate"` and
  `name: "main-protection-evaluate"`.

- [ ] **5.3** _After upgrading to Team plan (optional)._ Replace
  the repo-level ruleset with an org-level one in `active` mode
  with a `GitHub Actions` bypass actor:
  ```bash
  # Delete the repo-level ruleset:
  gh api repos/YOUR_ORG/kbtransfer-registry/rulesets/<RULESET_ID> \
    --method DELETE

  # Create the org-level ruleset (requires admin:org scope —
  # run `gh auth refresh -h github.com -s admin:org` first):
  gh api orgs/YOUR_ORG/rulesets --method POST --input - <<'EOF'
  { ... same body as 5.1 but enforcement: "active" and add to
        bypass_actors:
        {"actor_id": 15368, "actor_type": "Integration",
         "bypass_mode": "always"} ... }
  EOF
  ```

---

## Section 6 — GitHub Pages (optional — for `registry.kbtransfer.dev`)

Pages lets the registry serve `index.json` and `packs/*.tar` over
HTTPS without any extra infrastructure. Skip this section if you are
hosting the static files elsewhere (S3, Cloudflare Pages, nginx).

- [ ] **6.1** Enable Pages from the root of `main`.
  ```bash
  gh api repos/YOUR_ORG/kbtransfer-registry/pages \
    --method POST \
    --field source='{"branch":"main","path":"/"}'
  ```

- [ ] **6.2** Add the CNAME file.
  ```bash
  echo "registry.kbtransfer.dev" > CNAME
  git add CNAME && git commit -m "chore: add CNAME for Pages"
  git push
  ```

- [ ] **6.3** At your DNS provider, add the CNAME record.

  | Field | Value                 |
  |-------|-----------------------|
  | Type  | `CNAME`               |
  | Name  | `registry`            |
  | Value | `YOUR_ORG.github.io`  |
  | TTL   | `3600`                |

- [ ] **6.4** Verify after DNS propagation (up to 24h).
  ```bash
  curl https://registry.kbtransfer.dev/index.json | python -m json.tool
  ```
  Expected: valid JSON with `pack_count`, `publisher_count`, `packs`.

---

## Section 7 — Live pipeline smoke test

Pushes the E2E test pack we built earlier (in `/tmp/test-registry-kb/`)
through the real CI pipeline to confirm every job behaves as
expected on real GitHub infrastructure.

- [ ] **7.1** Copy the test pack produced by the earlier E2E run.
  ```bash
  mkdir -p packs/
  cp /tmp/test-registry-kb/published/test.patterns.circuit-breaker-1.0.0.tar \
     packs/
  mkdir -p publishers/did_web_test.example/
  cp /path/to/kbtransfer/registry-repo/publishers/did_web_test.example/keys.json \
     publishers/did_web_test.example/
  ```

- [ ] **7.2** Create a branch and open the PR.
  ```bash
  git checkout -b test/first-pack
  git add packs/ publishers/
  git commit -m "test: submit test.patterns.circuit-breaker 1.0.0"
  git push origin test/first-pack
  gh pr create --title "test: first pack submission" \
               --body "Smoke test for registry pipeline." \
               --base main
  ```

- [ ] **7.3** Watch the Actions run.
  ```bash
  gh run watch --repo YOUR_ORG/kbtransfer-registry
  ```
  Expected sequence:

  | Job                      | Status | Rough duration          |
  |--------------------------|--------|-------------------------|
  | `check_single_file`      | ✓      | ~10s                    |
  | `detect_submission_type` | ✓      | ~5s                     |
  | `validate_pack`          | ✓      | ~30s (pip install slow) |
  | `auto_merge`             | queued | waiting 30 min          |

- [ ] **7.4** Confirm the bot comment appears on the PR within 2 minutes.

  It must show all 7 checks green and the 30-minute merge notice
  ("This PR will be auto-merged in 30 minutes. To block merge,
  comment `/hold`.").

- [ ] **7.5** After 30 minutes, confirm the PR is merged and
  `index.json` was updated by the bot commit.
  ```bash
  gh pr list --state merged
  git pull && cat index.json | python -m json.tool
  ```
  Expected: `pack_count: 1`, `publisher_count: 1`, and a fresh
  `generated_at` timestamp. The merge commit is authored by
  `kbtransfer-bot`, followed by a second commit
  `chore: rebuild index [skip ci]` also authored by the bot.

---

## Section 8 — Cleanup

- [ ] **8.1** Delete the test pack from `main` after the pipeline check passes.
  ```bash
  git rm packs/test.patterns.circuit-breaker-1.0.0.tar
  git rm -r publishers/did_web_test.example/
  git commit -m "chore: remove smoke-test fixtures"
  git push
  ```

- [ ] **8.2** Note: `index.json` will show `pack_count: 0` after the
  post-merge rebuild runs. This is correct — the registry is now
  clean and ready for real publisher submissions.
