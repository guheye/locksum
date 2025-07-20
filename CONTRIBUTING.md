# Contributing to Locksum

First off, thank you for taking the time to contribute!  The following is a
set of guidelines to help you get started.

## Development Environment

```bash
# Clone & set up
$ git clone https://github.com/guheye/locksum && cd locksum
$ python -m pip install -e .[dev]
$ pre-commit install    # run the same checks as CI
$ pytest -q             # run full test-suite (≈90 % coverage)
```

* Locksum supports Python 3.11+ only.
* All commits are automatically formatted by **Black** / **Ruff-format**.
* Type-hints must pass **MyPy** (`mypy .`).
* Security linters (**Bandit**, **Gitleaks**) should report no issues.

## Pull Request Process

1. Fork the repository and create your branch from `main`.
2. Follow conventional commit messages (`feat: ...`, `fix: ...` etc.).
3. If you add a feature, update the docs and `CHANGELOG.md`.
4. Ensure CI passes.  GitHub Actions will run lint, tests, type-checking and security scans.
5. Submit the PR – we squash-merge once approvals & green CI are in place.

## Coding Standards

* Keep functions <50 LOC where reasonable.
* Prefer `pathlib.Path` over `os.path`.
* Use `Final`, `Literal` and precise typing for public APIs.
* Avoid touching protected members in tests – if you need access, expose a
  dedicated helper or property.

## Documentation

Docs live under `docs/` and are built with **MkDocs Material** & **mkdocstrings**.
Run `mkdocs serve` to preview locally.

## Security

Locksum handles secrets – new crypto must be reviewed by at least two maintainers.
We follow the guidance in
[PyCA cryptography's API stability](https://cryptography.io/en/latest/api-stability/).

Please disclose vulnerabilities privately via security@guheye.com. 