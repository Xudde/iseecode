This directory contains modified subsets of two upstream rule sets. No upstream
code is executed; these are vendored Semgrep snapshots.

## njsscan 1.0.2

Upstream: https://github.com/ajinabraham/njsscan
License: LGPL-3.0 (full text in LICENSE.njsscan)
Source archive sha256: 7d7361822e61cbf2ccab1999bd9596d71503f1042b270e1227989b40f9f69ddc
Rules were renamed with the oss-njsscan- prefix and had metadata/path excludes added.

## gosec 2.30.0

Upstream: https://github.com/securego/gosec
License: Apache-2.0 (full text in LICENSE.gosec)
Source archive sha256: 167dd29ac153ac5d61f4e69111c9fa0f8e18e4071273f04e6cc1c78e4e4dac9f
Rules were translated to Semgrep syntax, renamed with the oss-gosec- prefix,
and had metadata/path excludes added. Some data-flow checks are approximated
and are narrower than the upstream analyzers.
