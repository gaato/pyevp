"""Sphinx configuration."""

from __future__ import annotations

import os
from importlib.metadata import version as _version

project = "PyEVP"
author = "Gakuto Furuya"
copyright = f"2026, {author}"
release = _version("pyevp")
version = ".".join(release.split(".")[:2])

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
]

source_suffix = {".md": "markdown", ".rst": "restructuredtext"}
exclude_patterns = ["_build", "locales"]

myst_enable_extensions = ["colon_fence", "deflist", "fieldlist"]
myst_heading_anchors = 3

# Translations (see CONTRIBUTING.md). Fuzzy entries are not used: changed strings fall back to
# English until a translator reviews them.
locale_dirs = ["locales"]
gettext_compact = False

autodoc_member_order = "bysource"
autodoc_typehints = "description"
autodoc_typehints_description_target = "documented_params"
autodoc_default_options = {"members": True, "show-inheritance": True}
autodoc_preserve_defaults = True

intersphinx_mapping = {"python": ("https://docs.python.org/3", None)}

html_theme = "furo"
# Read the Docs passes the canonical URL (https://docs.pyevp.dev/<lang>/<version>/) but
# no longer sets html_baseurl itself; without it Sphinx emits no rel="canonical".
html_baseurl = os.environ.get("READTHEDOCS_CANONICAL_URL", "")
html_title = f"PyEVP {release}"
html_theme_options = {
    "source_repository": "https://github.com/gaato/pyevp/",
    "source_branch": "main",
    "source_directory": "docs/",
}
