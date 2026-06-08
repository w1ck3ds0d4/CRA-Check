# Releasing CRA-Check

CRA-Check is distributed as a GitHub Action, published to the **GitHub Marketplace** by tag.

`action.yml` already carries the Marketplace metadata (name, description, `branding`), and `tests/` + CI validate the report generator on every push.

## Cut a release

1. Make sure CI is green on `main`.
2. Tag a semantic version and move the floating major tag so `@v1` keeps working:
   ```bash
   git tag -a v1.0.0 -m "CRA-Check v1.0.0"
   git push origin v1.0.0
   git tag -f v1 v1.0.0 && git push -f origin v1
   ```
3. On GitHub: **Releases -> Draft a new release** from the `v1.0.0` tag.
4. Tick **"Publish this Action to the GitHub Marketplace"**, accept the agreement, choose the **Security** category, and **Publish release**.

Consumers then use:
```yaml
- uses: w1ck3ds0d4/CRA-Check@v1
  with:
    fail-on: 'off'   # or 'critical' to block releases on critical CVEs
```

> Marketplace publishing is a manual GitHub step (it needs your account and acceptance of the Marketplace Developer Agreement) - it cannot be automated from here.
