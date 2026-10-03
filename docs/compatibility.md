# Compatibility policy

- Before 1.0, minor releases may contain breaking changes. From 1.0 on, the project follows
  [Semantic Versioning].
- Profile presets are only ever added. An existing preset never changes behaviour; following the
  protocol means adding a new one.
- Switching `DEFAULT_PROFILE` to a newer preset is a breaking change, so after 1.0 it only happens
  in a major release.
- `ErrorCode` values are stable. New codes may be added in minor releases, so handle unknown
  codes.
- Supported Pythons: 3.11 and newer. A version is dropped only after its upstream end of life.

## Depending on PyEVP from a library

Libraries that still support Python 3.10 can offer EVP as an optional extra by gating it with an
environment marker:

```toml
[project.optional-dependencies]
pyevp = ["pyevp>=1,<2; python_version >= '3.11'"]
```

[Semantic Versioning]: https://semver.org/
