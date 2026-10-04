# Maintaining

Tasks that need maintainer access. For working on the code and docs, see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Releases

Record changes under `## [Unreleased]` in `CHANGELOG.md` as they land. To release:

1. Rename that section to `## [X.Y.Z] - YYYY-MM-DD`, point its link at the tag, and start a new
   empty `## [Unreleased]` section.
2. Bump `version` in `pyproject.toml`.
3. Push a `vX.Y.Z` tag. `.github/workflows/release.yml` checks that the tag matches the version
   and publishes to PyPI through trusted publishing. The `pypi` environment only accepts `v*`
   tags and waits for a maintainer to approve the deployment.

## Japanese docs on Read the Docs

The Read the Docs project `pyevp-ja` builds the same repository with the language set to Japanese.
It serves <https://docs.pyevp.dev/ja/latest/> and is linked to `pyevp` as a translation.

## Dropping Python 3.11

Type aliases use `TypeAlias` instead of `type` statements while 3.11 is supported (marked
`TODO(py3.12)`). When 3.11 support is dropped, raise `requires-python` and run
`uv run ruff check --select UP040 --fix --unsafe-fixes` to convert them back
(the fix is "unsafe" only because `type` aliases are evaluated lazily).
