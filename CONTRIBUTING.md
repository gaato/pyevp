# Contributing

## Issues and pull requests

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in a public
issue.

For a bug, open an issue with the PyEVP version, the issuer involved and a way to reproduce it.
`pyevp.testing.FakeIssuer` can build tokens without a real issuer. Do not paste real users'
tokens: they contain email addresses.

Open an issue before a pull request that changes behaviour or the public API, so that the
approach can be agreed first. Fixes and docs changes can go straight to a pull request.

A pull request should pass the checks below (CI runs them too), come with tests for what it
changes and, if it changes the English docs or a docstring, refresh the Japanese catalogs (see
[Translations](#translations)). You don't need to translate the new strings yourself.

Contributions are licensed under the [MIT License](LICENSE), like the rest of the project.

## Development

```sh
uv sync --all-packages --all-extras
uv run pytest              # library: unit + end-to-end with fakes
uv run pytest -m network   # live checks against deployed issuers (Gmail)
uv run ruff check && uv run ruff format --check && uv run ty check
```

The library supports Python 3.11, so write type aliases with `TypeAlias`, not `type` statements.

Each example under `examples/` is a member of the uv workspace with its own tests:

```sh
uv run --directory examples/fastapi pytest
uv run --directory examples/fastapi_spa pytest
uv run --directory examples/flask pytest
uv run --directory examples/fastapi_users pytest
uv run --directory examples/authx pytest
uv run --directory examples/django pytest
uv run --directory examples/django_allauth pytest
uv run --directory examples/issuer_fastapi pytest
uv run --directory examples/issuer_django pytest
uv run --directory examples/site pytest
```

To try one in a browser:

```sh
cd examples/fastapi && uv run uvicorn app:app --port 8000
cd examples/flask && uv run flask run --port 8000
cd examples/django_allauth && uv run manage.py migrate && uv run manage.py runserver
```

To start your own project from an example, copy it out and replace
`pyevp = { workspace = true }` with a normal dependency.

## Following the protocol

CI runs the network checks weekly (`.github/workflows/drift.yml`) and opens a `spec-drift` issue
when the deployed ecosystem diverges from the default profile. Behaviour changes usually go into a
new profile preset rather than changing an existing one, so that users can choose when to switch.

## Translations

The docs have a Japanese translation, kept as gettext catalogs in `docs/locales/ja/LC_MESSAGES/`.
After changing the English docs or a docstring, refresh the catalogs and commit the updated `.po`
files:

```sh
uv run sphinx-build -b gettext docs docs/_build/gettext
uv run sphinx-intl update -p docs/_build/gettext -l ja -d docs/locales
```

Entries that are untranslated or marked fuzzy (because their English text changed) show in
English until someone translates or reviews them and removes the `fuzzy` flag. Translations
follow the [Japanese style guide and glossary](docs/locales/ja/README.md).

`api.po` also holds the autodoc docstrings. Sphinx parses every translation for a page with that
page's parser, so even docstring entries are MyST there: write roles as ``{class}`Verifier` ``,
not ``:class:`Verifier` ``, and drop the `::` that introduces a literal block. The field labels
(Parameters, Raises, Return type) come from Sphinx's own catalog, not from `api.po`.

Link to sections with explicit labels (`(label-name)=` above the heading, then
`[text](#label-name)`), not with anchors derived from heading text. A heading that starts with a
number, like `3. Handle failures`, needs the dot escaped in its translation (`3\\. …` in the
`.po` file), or it is parsed as a list and the translation is dropped.

To build the Japanese docs locally and check progress:

```fish
uv sync --all-extras --group docs
uv run sphinx-build -W --keep-going -D language=ja -b html docs docs/_build/ja
xdg-open docs/_build/ja/index.html
uv run sphinx-intl stat -d docs/locales -l ja
```
