# Maintaining

Tasks that need maintainer access. For working on the code and docs, see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Releases

Record changes under `## [Unreleased]` in `CHANGELOG.md` as they land. To release:

1. Rename that section to `## [X.Y.Z] - YYYY-MM-DD`, point its link at the tag, and start a new
   empty `## [Unreleased]` section.
2. Run `uv version X.Y.Z`, which updates both `pyproject.toml` and `uv.lock` (CI installs from
   the lock with `--locked`, so a stale lock fails it). Push these changes to `main`.
3. Tag the pushed commit `vX.Y.Z` and push the tag. `.github/workflows/release.yml` runs CI on
   it, checks that the tag matches the version and publishes to PyPI through trusted
   publishing. The `pypi` environment only accepts `v*` tags and waits for a maintainer to
   approve the deployment.

## pyevp.dev

A push to `main` that changes the site image deploys pyevp.dev and the demo provider; see
[Deployment](examples/site/README.md#deployment) for which paths count and how to check what is
running.

The site's stylesheet build pins Tailwind CSS and daisyUI, each download with a SHA256, at the
top of `examples/site/scripts/build-css.sh`. Renovate bumps the versions but not the hashes, so
after a bump the build fails with a SHA256 mismatch. From `examples/site`, run
`scripts/build-css.sh --print-hashes`, paste its output over the `*_SHA256` lines, then rebuild
with `scripts/build-css.sh static/site.css` and check the page.

## Japanese docs on Read the Docs

The Read the Docs project `pyevp-ja` builds the same repository with the language set to Japanese.
It serves <https://docs.pyevp.dev/ja/latest/> and is linked to `pyevp` as a translation.

## Dropping Python 3.11

Type aliases use `TypeAlias` instead of `type` statements while 3.11 is supported (marked
`TODO(py3.12)`). When 3.11 support is dropped, raise `requires-python` and run
`uv run ruff check --select UP040 --fix --unsafe-fixes` to convert them back
(the fix is "unsafe" only because `type` aliases are evaluated lazily).
