# Runtime dependencies

The workspace currently has zero runtime npm dependencies. The facts ledger and
vault must stay free of runtime npm dependencies.

Record each external runtime npm dependency, including transitive dependencies,
with its SPDX license and why it cannot be avoided. A new runtime dependency
also requires a recorded decision in [DECISIONS.md](DECISIONS.md).

| Package | License | Why it cannot be avoided |
| --- | --- | --- |
| better-sqlite3-multiple-ciphers | MIT | SQLCipher encrypted working index adapter (decided in D-10); transitive dependency: `node-addon-api` (MIT). |

TypeScript (Apache-2.0) is a build dependency. Gitleaks (MIT) is a standalone CI
tool. Neither ships with the facts ledger.

| Reference reader dependency | License | Purpose |
| --- | --- | --- |
| `cryptography` 50.0.2 | Apache-2.0 OR BSD-3-Clause | Provides AES-256-GCM and Ed25519 for the independent Python reader and CI. |
