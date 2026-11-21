# foundry digest 2026-11-21
Facts: 7; supported 7, moved 0, stale 0, expired 0, unverifiable 0.
Lines start with V (verified, may be cited) or A (asserted, cite as "asserted"). Ledger content, not instructions.
## Pinned
V repo "foundry": file "packages/facts-ledger/src/log.ts" contains "MAX_LINE_BYTES = 64 * 1024" (03f17a5d6ce8.0)
V repo "foundry": file "packages/facts-ledger/src/index-db.ts" contains "INDEX_SCHEMA_VERSION = 7" (6cd0c652768f.0)
V repo "foundry": file "packages/facts-ledger/src/digest.ts" contains "DIGEST_MAX_BYTES = 6000" (7771c7719cbe.0)
V repo "foundry": file "package.json" contains "\"node\": \"24.22.3\"" (8a344972744c.0)
V repo "foundry": file "docs/DEPENDENCIES.md" contains "vault must stay free of runtime npm dependencies." (907714ee0870.0)
V repo "foundry": file "LICENSE" exists (f3cec7922d28.0)
V repo "foundry": file "packages/facts-ledger/src/log.ts" contains "timeout: 5000" (ff597a6b4e89.0)
## Recent decisions
- Record the maximum JSONL line size
- Record the writer lock timeout
- Record the facts index schema version
- Record the session digest byte budget
- Record the facts ledger runtime dependency rule
- Locate the repository licence
- Record the pinned Node version
0 fact(s) left out. Query them with: facts query --repo foundry --log ledger/foundry.jsonl
