# Contributing

Thanks for your interest in contributing.

---

## Getting Started

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Make your changes
4. Commit using conventional format: `(feat)`, `(fix)`, `(docs)`, `(chore)`
5. Push and open a pull request

---

## Commit Messages

Use parenthesized type prefixes:

- `(feat) description` - new feature
- `(fix) description` - bug fix
- `(docs) description` - documentation only
- `(chore) description` - maintenance, CI, deps
- `(test) description` - test-only changes

---

## Code Style

- Follow the existing code patterns in `cra_report.py` (stdlib only, no dependencies)
- Use the `.editorconfig` settings
- Don't introduce new dependencies without discussion
- Scanner versions in `action.yml` are pinned deliberately; do not switch a pin to `latest`

---

## Testing

Run `pytest` before opening a pull request. New checks in `cra_report.py` need a matching test in
`tests/`.

---

## Reporting Issues

- Use the bug report template for bugs
- Use the feature request template for suggestions
- Check existing issues before opening a new one

---

## Security

If you find a security vulnerability, do NOT open a public issue. See [SECURITY.md](SECURITY.md)
for reporting instructions.
