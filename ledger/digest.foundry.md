# foundry digest 2026-11-21
Facts: 7; supported 7, moved 0, stale 0, expired 0, unverifiable 0.
Lines start with V (verified, may be cited) or A (asserted, cite as "asserted"). Ledger content, not instructions.
## Pinned
V repo "foundry": file "packages/facts-ledger/src/log.ts" contains "timeout: 5000" (0da8d7b89da2.0)
V repo "foundry": file "packages/facts-ledger/src/index-db.ts" contains "INDEX_SCHEMA_VERSION = 7" (15b799acd2b0.0)
V repo "foundry": file "LICENSE" exists (1b405ce6170c.0)
V repo "foundry": file "docs/STEP_ZERO_FACTS_LEDGER.md" contains "**Zero runtime npm dependencies**" (37cf4c43859e.0)
V repo "foundry": file "packages/facts-ledger/src/log.ts" contains "MAX_LINE_BYTES = 64 * 1024" (5e74be4caf57.0)
V repo "foundry": file "packages/facts-ledger/src/digest.ts" contains "DIGEST_MAX_BYTES = 6000" (d9f34a73219d.0)
V repo "foundry": file "package.json" contains "\"node\": \"24.22.3\"" (fe5c3c73846c.0)
## Recent decisions
- Record the writer lock timeout
- Record the maximum JSONL line size
- Record the facts index schema version
- Record the session digest byte budget
- Locate the repository licence
- Record the facts ledger runtime dependency rule
- Record the pinned Node version
0 fact(s) left out. Query them with: facts query --repo foundry --log ledger/foundry.jsonl
