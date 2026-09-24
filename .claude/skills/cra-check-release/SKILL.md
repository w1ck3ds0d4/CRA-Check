---
name: cra-check-release
description: Cut a release of CRA-Check, the GitHub Action. Use when Daniel says "release CRA-Check", "cut a CRA-Check version", or "publish CRA-Check" - walks the tag-and-move-v1 sequence from RELEASING.md and hands off the Marketplace publish step he does himself.
---

# CRA-Check release

CRA-Check is distributed as a GitHub Action, published to the GitHub Marketplace by tag.
`action.yml` carries the Marketplace metadata (name, description, `branding`), and
`tests/` plus CI validate the report generator on every push. The whole procedure is in
`RELEASING.md`; this skill is that procedure with the exact commands filled in.

## 1. Check CI is green on main

```bash
gh pr checks --repo w1ck3ds0d4/CRA-Check main 2>/dev/null || gh run list --repo w1ck3ds0d4/CRA-Check --branch main --limit 1
```

Do not tag on top of a red `main`.

## 2. Pick the version

Ask Daniel for the version if it is not obvious from the change (semantic: patch for a
bugfix, minor for a new check or input, major for a breaking change to `action.yml`'s
inputs or outputs).

## 3. Tag and move the floating major tag

```bash
git tag -a v1.0.0 -m "CRA-Check v1.0.0"
git push origin v1.0.0
git tag -f v1 v1.0.0 && git push -f origin v1
```

Both tags matter: the semantic tag (`v1.0.0`) is the immutable release, and the floating
major tag (`v1`) is what every consumer's workflow actually points at
(`uses: w1ck3ds0d4/CRA-Check@v1`). Moving `v1` is a force-push of a tag, which is normal
here and expected by RELEASING.md, not a mistake to avoid.

## 4. Hand off the Marketplace step

Tell Daniel plainly that the rest is a manual GitHub-UI step tied to his account and
cannot be automated from here:

1. On GitHub: **Releases -> Draft a new release**, from the `v1.0.0` tag.
2. Tick **"Publish this Action to the GitHub Marketplace"**.
3. Accept the Marketplace Developer Agreement (first time only).
4. Choose the **Security** category.
5. Click **Publish release**.

## What proves it worked

- `git ls-remote --tags origin` shows both `v1.0.0` and `v1` pointing at the new commit.
- The GitHub release for `v1.0.0` exists and is marked published to Marketplace.
- A consumer pinned to `@v1` (see README) picks up the change on its next run without
  editing their workflow file.

## Traps

- Forgetting `-f` on the `v1` push leaves the floating tag stale, so every `@v1` consumer
  keeps running the old code silently. Always force-push `v1` after a release.
- Skipping the Marketplace tick-box still creates a valid tag and a working action for
  anyone pinning by SHA or tag, but it will not show up in Marketplace search or get the
  category badge. If Daniel only wants a code release (no Marketplace listing this time),
  say so and skip step 4 rather than doing it halfway.
- This is a GitHub Action repo, not a library: there is no build or publish step here for
  Claude to run. The tag itself is the artifact.
