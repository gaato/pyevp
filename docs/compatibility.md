# Compatibility policy

PyEVP makes no compatibility promises yet. The protocol is still an Internet-Draft and browser
support is an origin trial, so any release may change or remove any part of the library,
including profile presets, error codes and the output of the command line. Every release lists
its changes, breaking ones included, in the [changelog].

Pin the minor version you tested with, for example `pyevp>=0.1,<0.2`, and read the changelog
before upgrading. Once the protocol settles, this page will say what stays stable.

Supported Pythons: 3.11 and newer.

[changelog]: https://github.com/gaato/pyevp/blob/main/CHANGELOG.md
