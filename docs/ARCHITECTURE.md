# Foundry architecture

Status: architecture for build. V-1 freezes the record, manifest and keyring byte formats
with committed test vectors. See [A-31 in DECISIONS.md](DECISIONS.md).

Terms used throughout:

| Term | Meaning |
|---|---|
| Vault | The append-only, encrypted store of raw data. The source of truth. |
| Segment | A directory of vault files that is written, then closed, then never changed. |
| Close | Write a segment's manifest and extend the hash chain. Happens on the working device. |
| Seal | Copy a closed segment to the second copy, verify it there, mark it read-only, record the result. |
| Index | The derived SQLite database on the working device. Rebuildable from the vault. |
| Working device | The computer the user installs Foundry on. |
| Chain head | `(vault_id, segment number, manifest hash)` of the newest closed segment. |

## 1. System overview

```
 data exports ──► importers ──► VAULT (append-only, encrypted, hash-chained segments)
 (zip archives)                   │                         │
                                  │ replay                  │ vault session (Mode B)
                                  ▼                         ▼
                              INDEX (derived SQLite:    SECOND COPY (offline drive,
                              full text, vectors,       sealed segments, chain head)
                              places, graph, layout)
                                  │
                                  ▼
                        search / ask / map  ◄── `foundry` CLI and the loopback wizard
```

Three rules hold everywhere:

1. Only importers and annotation commands write to the vault, and only by appending.
2. Everything in the index can be deleted and rebuilt from the vault plus the keyring.
3. No process outlives its task. There is no daemon.

## 2. Packages

One repository, one workspace. Runtime target: Node.js 24 LTS or newer (pinned in
`package.json` `engines` and in the shipped bundle). TypeScript, ES modules.

| Package | Responsibility | May depend on |
|---|---|---|
| `packages/facts-ledger` | Step Zero. See [STEP_ZERO_FACTS_LEDGER.md](STEP_ZERO_FACTS_LEDGER.md). | Nothing in this repo |
| `packages/vault` | Segment format, record encryption, keyring, chain, verify, seal | Node built-ins only |
| `packages/index` | SQL driver port, schema, projections, search | `vault` |
| `packages/importers` | Archive reader and per-source importers and derivers | `vault`, `index` |
| `packages/profiles` | Profiles, collections, consent, sensitivity rules | `vault` |
| `packages/cli` | The `foundry` command | all of the above |
| `packages/wizard` | Loopback web UI: static assets plus a server that lives only while open | `cli` internals |

Dependency policy: `vault` and `facts-ledger` have zero runtime npm dependencies. Every
other runtime dependency needs a line in `docs/DEPENDENCIES.md` (name, license, why it
cannot be avoided). Licenses must be MIT, BSD, ISC or Apache-2.0.

## 3. What is in the vault and what is derived

| In the vault (append-only) | Derived in the index (rebuildable) |
|---|---|
| Original bytes of every imported file or message | Extracted text and chunks |
| One event per imported item: source, original path, type, size, timestamps, blob reference | Full-text index |
| Tags and labels known at write time | Embeddings |
| Later annotations, corrections and redactions, each as a new event | Places table and spatial index |
| Consent notes, key-destruction notices, seal and drill records | Graph nodes and edges |
| Map node ids and placements (`node.created`, `layout.placed`) | Graph positions table |

A parser improvement never touches the vault: bump the deriver version and re-derive.

## 4. Vault format

### 4.1 Layout on disk

```
<vault>/
  VAULT.json                 clear text, written once: format, vault_id, created_at, signing_public_key
  HEAD.json                  convenience copy of the chain head. Never trusted on its own.
  keyring/keyring.json       the only mutable file that holds key material (section 5.4)
  segments/
    000001/
      MANIFEST.json          clear text, written when the segment closes
      MANIFEST.sig           signature over MANIFEST.json (section 4.5)
      events-0001.fvr        record stream: events
      pack-0001.fvr          record stream: blobs
    000002/ ...
  open/                      the segment being written. Same files, no manifest yet.
```

- Use the exact literal names shown above. Record stream names use lowercase ASCII.
  Segment directories use the decimal segment number, zero-padded to six digits for
  1 through 999,999 and written without leading zeros from 1,000,000 onward.
- Root verification also allows the writer lock file `.writer.lock.sqlite` and its
  SQLite `-journal`, `-wal`, and `-shm` side files. It accepts `HEAD.json.pending`
  only for the interrupted head replacement described in section 4.6.
- A record stream file rolls over at 64 MiB. A blob never spans two files; a blob larger
  than 64 MiB gets a file to itself. (**Decided:** segment soft cap 512 MiB.)
- The cap is soft. A blob larger than the cap gets a segment to itself, and that segment is
  as large as the blob. Blobs are never split, so there is no part order to authenticate.
  The cost: a second-copy drive must use a file system without a 4 GiB file limit (exFAT,
  NTFS, ext4 and similar). The wizard refuses FAT32 and offers to explain reformatting.
- Small items are packed into shared files on purpose. One file per email would waste most
  of a flash drive to cluster slack and make copies slow.

### 4.2 Record

A stream concatenates complete version 1 records without delimiters or padding. Offsets
and lengths count bytes.

```
offset  size  field
0       4     ASCII magic "FVR1"
4       1     type: 0x01 = event, 0x02 = blob
5       16    key_id: raw bytes, matching a collection keyring entry
21      32    salt: fresh cryptographically random bytes for every record
53      8     ctx: u64 big-endian, 1 through 9,007,199,254,740,991 for an event, zero for a blob
61      8     total_len: u64 big-endian, bytes after the header in this record
69      ...   one or more frames: u32 big-endian ciphertext_len | ciphertext | 16-byte tag
```

- Use AES-256-GCM. Ciphertext length equals frame plaintext length. Every nonfinal frame
  has 1,048,576 bytes of plaintext. The final frame has 1 through 1,048,576 bytes.
  A zero-byte blob uses a single zero-length frame and its tag. An exact multiple of
  1,048,576 bytes ends with a full frame.
- Derive the 32-byte record key with HKDF-SHA256 using the collection encryption key
  (section 5.1), the header salt and ASCII info `foundry/record-key/v1`. Never reuse
  a salt with the same collection encryption key. The nonce is four zero bytes
  followed by the zero-based frame index as a big-endian u64, restarting at zero for
  each record.
- Frame AAD is the complete 69-byte header, the 16 raw vault ID bytes, the big-endian
  u64 frame index and one byte, `0x01` for the final frame or `0x00` otherwise,
  in that order. A frame is final exactly when its tag ends at offset
  `69 + total_len` relative to the record start.
- Check that the declared record fits in the stream and all frames fit exactly inside
  `total_len`. The minimum record size is 89 bytes. A reader without a key can verify
  structure and advance by `69 + total_len`. The signed manifest authenticates file
  placement and the order of complete records in a closed segment.
- FVR1 has its own HKDF labels and vault binding. See section 14.

### 4.3 Event plaintext

```json
{
  "seq": 48211,
  "ts": "2026-11-19T16:40:00Z",
  "kind": "item.imported",
  "profile": "me",
  "collection": "c_7f3a…",
  "sensitivity": "personal",
  "source": "google-takeout/mail",
  "tags": ["inbox"],
  "body": { "blob": "<blob id>", "path": "Takeout/Mail/All mail.mbox#1042", "mime": "message/rfc822", "size": 18233, "source_ts": "2019-03-02T08:15:00Z" }
}
```

Each event plaintext is a UTF-8 JSON object. Its top-level `seq` is a positive decimal
integer token without a fraction or exponent, at most 9,007,199,254,740,991, and equals
the header's `ctx`. Writers emit one `seq` member. JSON parsers that accept duplicate
members use the last occurrence. The vault-wide counter starts at 1 and has no gaps.
Event kinds in v1:

| Kind | Purpose |
|---|---|
| `vault.created`, `profile.created`, `collection.created` | Structure |
| `item.imported` | One stored item and its blob reference |
| `annotation.added` | Tag or label added after the fact |
| `correction.applied` | `target_ref`, `field`, `new_ref`, `reason`. Points at records, never carries the corrected content inline. |
| `redaction.applied` | Hide one item from every projection. Carries a tombstone (section 5.7) so a re-import of the same bytes is refused. |
| `consent.recorded`, `consent.withdrawn` | Section 5.7 and the product spec |
| `key.destroyed` | Notice that a key was erased: key id, date, reason. No content. |
| `node.created` | A person, place or topic entered the map: random node id, kind, canonical key. Recorded once so the id survives later changes to how names are normalised. |
| `edge.inferred` | A relationship proposed by a model: endpoints, evidence, confidence, model id and version. Recorded once so a rebuild never re-runs inference. |
| `layout.placed`, `layout.moved`, `layout.epoch`, `node.merged` | Section 11 |
| `copy.sealed`, `drill.completed` | Second-copy history: counts and hashes only |

Structural and history events use a `system` collection key.

### 4.4 Blob identity

`blob id = HMAC-SHA256(collection id key, plaintext)`, 64 lowercase hex characters. Identical content
inside one collection is stored once. The id key is per collection so that destroying a
collection's keys also destroys the ability to confirm what a given blob contained.
Content is not deduplicated across collections; that is the price.

The blob id is stored inside the encrypted event, not in the clear record header.

### 4.5 Manifest and chain

`VAULT.json`, the manifest and the keyring use UTF-8 without a BOM, trailing newline or other extra
whitespace, as specified by [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785). Sort object
members recursively by ascending UTF-16 code units and preserve array order. Use RFC 8785
string escaping and well-formed Unicode without normalization. Numbers are interoperable
integers with absolute value at most 9,007,199,254,740,991. Readers require exact canonical
bytes, unique member names and the exact named fields for each versioned object. Hex
strings are lowercase without a prefix. Base64 uses the RFC 4648 standard alphabet with
canonical padding and no whitespace. Format timestamps are Gregorian UTC with exactly
the form `YYYY-MM-DDTHH:MM:SSZ`, with years 0001 through 9999, hours 00 through 23,
and minutes and seconds 00 through 59.

```json
{
  "format": "foundry-segment/1",
  "vault_id": "<32 hex>",
  "epoch": 1,
  "segment": 12,
  "prev_manifest_sha256": "<64 hex>",
  "first_event_seq": 48211,
  "last_event_seq": 50977,
  "files": [
    { "name": "events-0001.fvr", "bytes": 1048576, "sha256": "<64 hex>" },
    { "name": "pack-0001.fvr", "bytes": 67108864, "sha256": "<64 hex>" }
  ],
  "key_ids": ["<32 hex>", "<32 hex>"],
  "closed_at": "2026-11-19T00:00:00Z",
  "writer": "foundry 0.1.0"
}
```

- `vault_id` encodes 16 bytes. `epoch` is the integer 1 in v1 and reserves space for
  later compaction. `writer` is a nonempty string identifying the writer version.
- Segment numbers start at 1 and increase by 1. The genesis link is 64 ASCII zeros.
  Each later link is lowercase hex SHA-256 of the preceding `MANIFEST.json` bytes.
  Event ranges are inclusive and contiguous across the chain, starting at 1. A segment
  without events uses JSON `null` for both range endpoints and preserves the last
  event sequence for the next link.
- `files` is a nonempty array of unique stream names sorted by ascending ASCII name.
  A name is `events-` or `pack-`, the positive decimal stream ordinal, and `.fvr`.
  Zero-pad ordinals 1 through 9,999 to four digits. Write ordinals from 10,000
  onward without leading zeros. The maximum ordinal is 9,007,199,254,740,991. Each file
  has at least one record and carries its exact byte count and lowercase hex SHA-256.
  An `events` stream contains events and a `pack` stream contains blobs. Check the
  event contexts in ascending event-stream ordinal and in byte order in each stream.
  `key_ids` is the nonempty set of all record key IDs in the segment, including erased
  IDs, rendered as 32 hex digits each, unique and sorted in ascending ASCII order.
- `MANIFEST.sig` is exactly the 64 raw bytes of a pure Ed25519 signature over the
  canonical `MANIFEST.json` bytes. `VAULT.json` has four fields. `format` is
  `foundry-vault/1`, `vault_id` is 16 bytes encoded as 32 lowercase hex digits,
  `created_at` is a canonical timestamp, and `signing_public_key` is the 32 raw
  public-key bytes encoded as canonical base64. The anchor's public-key
  fingerprint is lowercase hex SHA-256 of the 32 raw public-key bytes. The keyring
  wraps the 32-byte Ed25519 private seed (section 5.4). The signing key and its
  printed anchor are fixed for the life of a v1 vault. A later format version may
  add signing-key rotation. Version 1 readers need only support the fixed key.
- **Verification needs no secret.** Starting at segment 1, check the signatures, vault
  ID, chain links and event context ranges. Check the exact set of record stream names,
  file lengths, hashes, record structures and key ID inventory. Renaming a stream or
  changing the order of complete records changes this authenticated inventory or its
  hashes. Compare the verified head to an independent anchor to detect rollback or
  replacement (sections 8.1 and 8.2).
- Deep verification also unlocks the keyring, authenticates each frame and checks that
  each recovered event's plaintext sequence equals its context.
- Clear manifests reveal file counts and sizes, close times, event ranges and key IDs.
  They omit profile names, content, sources and blob IDs.

### 4.6 Closing and crash safety

- Appends go to `open/`. Each record is written with a single write call and fsynced at
  the end of an import batch. A short write fails the batch. A batch that crosses a
  segment boundary syncs and seals its completed segment before continuing.
- The writer holds the vault directory's SQLite writer lock until it releases the
  session or exits. The lock database carries no vault content.
- On start, a writer scans `open/`. A final record shorter than its header or
  declared length is truncated away and reported. Both stream types can have a
  short tail, each in its highest-ordinal file. A complete record with invalid
  framing or a failed authentication check fails recovery.
- Close: fsync files, write and sync the manifest and signature under temporary names,
  rename them into place in `open/`, and prepare and sync a temporary head. Rename
  `open/` to `segments/<n>/` before replacing `HEAD.json`. Sync affected directories
  on POSIX. Closed files are set read-only as a courtesy.
- The convenience head contains `segment` and `manifest_sha256` in canonical JSON,
  with segment zero and the genesis hash before the first seal. On startup a writer
  replaces a head that matches the verified predecessor only when the pending head
  matches the verified last segment and `open/` is absent. Verification accepts that
  interrupted state using the verified last segment as the head. If the segment
  rename never happened, the writer discards the pending close files and preserves
  the open records.
- Public verification checks framing and sequence in `open/`, whose records have
  no signed inventory until close. Deep verification authenticates active-key
  records. For a collection key marked destroyed in a MAC-verified keyring, deep
  verification, recovery and sealing check framing and sequence and hash the
  record without decrypting it. If all integrity and authentication checks pass,
  deep verification reports `ERASED` with the number of such records.
- A segment closes when it reaches the soft cap, when a vault session starts, or on demand.

### 4.7 Reading the vault without Foundry

The [Python reference reader](../packages/vault/reference/reader.py) uses the standard
library and `cryptography` in fewer than 200 lines. It validates signed segments and
decrypts records with a keyring and passphrase. Run the shared vectors with
`python -B packages/vault/reference/test_vectors.py`. The TypeScript codec and generator
live in [packages/vault/codec](../packages/vault/codec). Run the TypeScript tests
with `npm --prefix packages/vault/codec test` and check fixture reproducibility with
`npm --prefix packages/vault/codec run vectors -- --check`.

## 5. Keys, encryption and erasure

### 5.1 Hierarchy

```
passphrase ──scrypt──► KEK ─┐
                            ├─ unwraps ─► master key MK (random, 32 bytes)
recovery key ──HKDF──► RK ──┘                 │ wraps
                                              ▼
                                   profile key PK (random, one per profile)
                                              │ wraps
                                              ▼
                                   collection key CK (random, one per collection and epoch)
                                              │ HKDF
                              ┌───────────────┼────────────────┐
                              ▼               ▼                ▼
                     encryption key      id key (HMAC)    (reserved)
```

- "Wraps" means AES-256-GCM encryption of the child key under the parent, with the
  additional authenticated data in section 5.4. MK, PK, CK and index keys are 32 bytes.
- Collection keys are random, not derived from MK. That is what makes erasure possible:
  a derived key can always be re-derived.
- The index key is also random and wrapped by MK, one per index generation. Rebuilding the
  index after an erasure creates a new generation under a new key and destroys the old one,
  so leftover pages of the old index file are unreadable.
- The manifest signing key (Ed25519) is random and wrapped by MK.
- The collection encryption key and collection ID key are 32-byte HKDF-SHA256 outputs.
  Use raw CK as input key material, the 16 raw vault ID bytes as salt, and ASCII info
  `foundry/collection-encryption/v1` or `foundry/collection-id/v1`, respectively.
  Use each derived key only for its named purpose.
- Secrets are read from a terminal prompt or the wizard form. They are never accepted on
  the command line or from environment variables, and never written to logs.

### 5.2 Passphrase

Use scrypt to derive a 32-byte KEK from the passphrase's exact UTF-8 bytes and a fresh
32-byte cryptographically random salt. The prompt adds no normalization or newline.
Use the production defaults `N = 131072` (2^17), `r = 8`, `p = 1`. Version 1 readers
accept `N = 131072`, `r = 8`, and `p = 1` or `p = 2`. Readers reject other values
before calling scrypt and set an explicit memory limit of 268,435,456 bytes (256 MiB).
Parameters and salt are in the keyring header. A confirmed rewrite can raise p within
this range. Other KDFs or parameter ranges require a format revision and budget
verification. See section 9 and the V-0 measurements.

### 5.3 Recovery key

256 random bits, shown once as grouped base32 text and as a QR code for printing. It
unwraps MK independently of the passphrase. The wizard asks the user to type back four
groups before it continues. Changing the passphrase or KDF parameters leaves the same
recovery key valid. Either change uses a fresh salt, re-wraps MK under the new
passphrase-derived key, keeps `master.by_recovery` byte-identical, and recomputes the
keyring MAC. The rewrite can use the current passphrase to unlock MK and needs no recovery key.

- The printed text starts with the version character `1`. Encode the 32 recovery
  bytes as 52 uppercase, unpadded RFC 4648 base32 characters. Append the first four
  base32 characters of SHA-256 over the ASCII version character followed by those 52
  characters. Print the resulting 56 characters in groups of four, with a hyphen
  before each group. Check the text and checksum before attempting to unwrap MK.
- The wizard warns before printing: "print to PDF" saves the key as a file, and network
  or cloud printers keep copies of what they print. Writing it down by hand is offered first.
- The recovery key is useless without a keyring file. The restore drill proves the pair
  works using only what is on the second copy.
- Changing the passphrase does not revoke an old one. Anyone who copied an earlier keyring
  and knows the earlier passphrase can still unwrap the keys that keyring held. After a
  suspected passphrase leak, use `foundry vault rekey --all` with a fresh passphrase.
- `foundry vault rekey --all` rotates MK and the profile, collection and index keys
  for future writes. It issues a new recovery key, which is shown once. The new
  keyring keeps historical collection keys wrapped under the new hierarchy so it
  can read existing records by their original IDs. New writes use fresh collection
  IDs, and the index must be rebuilt under the new index key. Sealed segments stay
  byte-identical. It preserves the vault signing key and printed anchor. If
  the signing key may be compromised, create a new vault and import the old vault's
  contents. The new vault has its own vault ID, signing key and printed anchor.

### 5.4 Keyring file

A small JSON file. It is the only mutable file with key material and the only thing that
must be kept in step across copies.

```json
{
  "format": "foundry-keyring/1",
  "vault_id": "<32 hex>",
  "version": 41,
  "kdf": { "name": "scrypt", "N": 131072, "r": 8, "p": 1, "salt": "<base64>" },
  "master": { "by_passphrase": "<base64>", "by_recovery": "<base64>" },
  "keys": [
    { "key_id": "<32 hex>", "kind": "profile", "parent": "master", "label_enc": "<base64>", "wrapped": "<base64>", "state": "active", "created_at": "2026-11-19T00:00:00Z" },
    { "key_id": "<32 hex>", "kind": "collection", "parent": "<profile key id>", "wrapped": "<base64>", "state": "active", "created_at": "2026-11-19T00:00:00Z" },
    { "key_id": "<32 hex>", "kind": "collection", "parent": "<profile key id>", "wrapped": null, "state": "destroyed", "destroyed_at": "2026-11-20T00:00:00Z" }
  ],
  "mac": "<base64>"
}
```

- Use the canonical JSON and field encodings in section 4.5. The positive `version`
  starts at 1. Each rewrite increments it and uses a temp file, fsync and rename.
  `vault_id` must match the vault being opened.
- A sibling SQLite database holds a writer lock that the OS releases when a process
  exits. Under the lock, writers remove abandoned temp files for that keyring and
  compare the published keyring to the authenticated input. They sync a uniquely
  named temp file before renaming it over the keyring. POSIX writers also sync the
  parent directory. Windows writers retry transient rename failures.
- `keys` is sorted by ascending ASCII `key_id`. IDs are unique 16-byte identifiers.
  The kinds are `profile`, `collection`, `index` and `signing`. Profile, index and
  signing entries have parent `master`. A collection's parent is a profile entry ID,
  and that profile must be active if the collection is active. A destroyed entry keeps
  its identity and `destroyed_at` with `wrapped: null`. An active entry carries
  `created_at` and `wrapped`. Only an active profile has `label_enc`.
- Each encrypted field is base64 of `nonce[12] || ciphertext || GCM tag[16]` using
  AES-256-GCM. Use a fresh cryptographically random 12-byte nonce for each encryption.
  Never reuse a nonce under the same key, including across rewrites. A key wrap
  encrypts exactly 32 raw bytes (the Ed25519 seed for signing), giving 60 bytes before
  base64. A profile label encrypts nonempty UTF-8 text.
- AAD is the canonical JSON array
  `["foundry-keyring/1", vault_id, key_id, kind, parent, kdf_or_null]`. IDs in the
  array use their JSON string representation. Use these exact values.

  | Field | `key_id` | `kind` | `parent` | `kdf_or_null` | Encryption key |
  |---|---|---|---|---|---|
  | `master.by_passphrase` | `master` | `master` | `passphrase` | complete `kdf` object | scrypt KEK |
  | `master.by_recovery` | `master` | `master` | `recovery` | JSON null | recovery wrapping key |
  | `keys[].wrapped` | entry key ID | entry kind | entry parent | JSON null | MK or raw parent PK |
  | `keys[].label_enc` | profile key ID | `profile-label` | `master` | JSON null | profile label key |

- Both master wraps bind the format, vault ID and slot label in their AAD to prevent
  moving a wrap between vaults or slots. The passphrase slot also binds the complete
  KDF header (`name`, `N`, `r`, `p` and `salt`). The recovery slot's AAD is independent
  of the passphrase KDF header.
- Derive the 32-byte recovery wrapping, profile label and keyring MAC keys using
  HKDF-SHA256 with the 16 raw vault ID bytes as salt. For recovery, use the 32 raw
  recovery bytes and ASCII info `foundry/recovery-wrap/v1`. For the other two, use
  MK and ASCII info `foundry/profile-label/v1` and `foundry/keyring-mac/v1`,
  respectively.
- `mac` is base64 of raw HMAC-SHA256 over the canonical keyring object, including
  the KDF header, with only its `mac` member removed. Use the keyring MAC key. Check
  the format, KDF bounds and vault ID, unwrap MK using either credential, and verify
  the MAC with a constant-time comparison before using entry keys or accepting erasure
  states. Unwrap parents first.
- Size: keys exist per profile and per collection, never per item, so the file stays in
  the tens of kilobytes. A design with a random key per item was rejected for v1: it needs
  a transactional key store and makes every keyring backup a larger erasure liability.
- Default collection grain: one collection per profile, source and calendar year. That
  bounds the cost of re-keying after a single-item erasure to one source-year.
- Collection key IDs follow one fixed rule. The ID of the collection key for collection
  name `N` in the profile with key ID `P` is the first 16 bytes, as 32 lowercase hex
  characters, of HMAC-SHA256 under `NK` over the bytes of `P` (32 lowercase hex), one
  byte 0x0A and the exact UTF-8 bytes of `N`, with no case folding, normalization or
  trimming. `NK` is HKDF-SHA256 with MK as input key material, the 16 raw vault ID
  bytes as salt and ASCII info `foundry/collection-key-id/v1`. The collection key itself
  stays random. Names that start with `foundry:` are reserved. The rule finds only
  collections whose keys it allocated under the current MK: after a `rekeyAll`, bindings
  made under the old MK are no longer found, while a profile without collection entries
  can still get its first keys under the new MK; a
  marker entry (the ID derived from `foundry:collection-key-id-rule/v1`) turns a profile
  with collections but no active marker into a `KEY` failure. See
  [A-41 in DECISIONS.md](DECISIONS.md).
- The working device keeps a register of every keyring copy Foundry has written: which
  second copy, which keyring version, when. `foundry erase` prints the copies that still
  hold the old key.
- A destroyed key keeps its entry with `wrapped: null`, so a reader that meets a record
  under that key reports "erased on <date>" instead of "corrupt".
- Losing every copy of the keyring loses the data, even with the passphrase, because
  collection keys are random. Therefore: the keyring is written to every rewritable copy
  during each vault session, and the restore drill fails if the copy's keyring cannot open
  a sample record for every active key.
- The keyring is **not** written to write-once media by default. A key burned to a disc
  can never be destroyed, which would defeat erasure. A user who values durability over
  erasure can opt in; the wizard explains the trade.

### 5.5 Working index encryption (Decided: SQLCipher, option A)

The index holds extracted plaintext, so it is encrypted at rest.

- Access goes through a `SqlDriver` port with two adapters.
  1. `sqlcipher` (default): `better-sqlite3-multiple-ciphers`, opened with the raw index
     key (no per-open passphrase stretching), `temp_store = MEMORY`, `secure_delete = ON`.
  2. `plain`: the runtime's built-in `node:sqlite`. Allowed only when the operating system
     reports full-disk encryption for the index volume **and** the user accepts it explicitly.
- The cipher scheme and its parameters are selected explicitly and pinned in code, never
  left to the library's defaults, and are set before the first schema access. The scheme
  must authenticate pages. Compatibility with other SQLCipher tools is not promised.
- **Fail closed.** If the SQLCipher adapter cannot load, or the key or format is rejected,
  the product stops with an explanation. It never falls back to an unencrypted index on its own.
- Startup self-check: the opened database must have FTS5 and R-tree compiled in.
- Tests run against the **shipped** binary on each platform: a wrong key fails; a modified
  page is rejected; a process killed mid-write recovers with a live write-ahead log; and a
  planted marker string is absent from the database file, the write-ahead log, journals
  and any spill file.
- Operating-system disk encryption is recommended as well. It protects swap, crash dumps
  and temp files that the database layer does not control.
- The native addon is the main packaging risk. CI must prove prebuilt binaries load on
  win32-x64 and linux-x64 (and linux-arm64 before Mode A ships) for the pinned Node version.
  A Node major upgrade is a deliberate change with that CI proof, never automatic.

V-4 pins SQLCipher legacy 4 settings and reads back all 14 values listed in the V-0
measurement report. It checks the schema under the supplied key before enabling WAL.
The built-in adapter requires a caller-provided affirmative disk-encryption check.
Destruction of a generation key protects obsolete SQLCipher pages. Plain SQLite
relies on the platform for protection of any copies left by the filesystem.

### 5.6 Unlocking without a daemon

There is no agent process holding keys. A `KeyCache` port offers three behaviours:

| Adapter | Behaviour |
|---|---|
| `none` (default) | Ask for the passphrase on every command that needs to decrypt |
| `os-session` | Linux kernel keyring with a timeout; gone at logout |
| `os-protected` | Windows per-user data protection; survives reboot, tied to the user account |

Caching means anyone who can run code as the user can read the vault while the cache is
live. The wizard says this in one sentence when offering it. Scheduled jobs need no key:
they remind, and they verify ciphertext. The adapters are a spike (work package V-6);
`none` always works.

### 5.7 Erasure and its limits

Append-only storage and "delete my data" are reconciled by destroying keys.

| Request | Mechanism | Effect |
|---|---|---|
| Erase a profile | Destroy the profile key and all its collection keys in the keyring; append `key.destroyed`; purge the profile's rows from the index and vacuum | Every copy of that data, sealed or not, is unreadable once every keyring copy is updated |
| Erase a collection | Same, for one collection key | Same, narrower |
| Erase one item | Append `redaction.applied` (hidden from all projections at once). Physical removal needs `foundry vault rekey <collection>`: remaining items are re-encrypted under a new collection key into new segments and the old key is destroyed | Hidden immediately; unreadable after the re-key |

Order of operations. Each step is durable before the next starts, and an interrupted
erasure resumes from the first step not yet recorded:

1. Append the withdrawal (`consent.withdrawn`, `redaction.applied` or `key.destroyed`).
   From this point every read path refuses the data and the importer refuses to bring it back.
2. Destroy the keys in the working keyring.
3. Purge the index: text, full-text terms, vectors, places, graph evidence, inferred edges
   that rested on that evidence, and positions of nodes left with no evidence. Then
   rebuild into a new index generation and destroy the old index key.
4. At the next vault session for each second copy, update its keyring.

The interface reports three separate states per erasure and never merges them into one
word: **hidden** (step 1 done), **removed from the index** (step 3 done), and **key
destroyed on N of M copies** (steps 2 and 4).

**Restore rule.** A rebuild or restore first reads every withdrawal, redaction and
key-destruction event in the vault, and only then makes any item searchable. Restoring an
old copy can therefore never bring withdrawn data back into view. If a copy is older than
the newest withdrawal known to the working device, the product says so before it opens the copy.

**Tombstones.** `redaction.applied` stores `HMAC(tombstone key, original bytes)`, where the
tombstone key is derived from MK. The importer checks new items against the tombstones, so
re-importing the same archive does not restore a redacted item. The trade: the vault's
owner can later confirm that a given file was once redacted. Erasing a whole profile
records no per-item tombstones.

The V-2 library rotates keys at the keyring boundary. Before enabling vault-wide
rekey on a populated vault, the command must carry forward the ability to match
existing tombstones across the MK change and recover the switch to the new write
IDs and index generation. A later collection erasure must cover each historical
ID for that collection as well as its current ID.

**Items about more than one person.** A photo or a conversation is stored once, in the
collection of the profile that imported it. A per-profile key cannot erase it for one
person and keep it for another. When someone other than the importer withdraws, their
request is met item by item: redaction at once, then re-key of that collection.

Limits, to be printed in the docs and shown in the erase dialog:

1. Erasure is only as complete as the destruction of every copy of the key. An old keyring
   on a forgotten backup, or burned to write-once media, keeps the data readable to anyone
   who also has the passphrase or recovery key. Copies Foundry did not make are invisible
   to it: file-history and shadow-copy features of the operating system, and the version
   history of a cloud-sync folder. The wizard warns when the vault folder is inside one.
2. Flash storage may retain old blocks of an overwritten keyring. Someone with the
   passphrase and forensic tools is not ruled out. Erasure removes the data from the
   product's reach; it is not a forensic guarantee.
3. Ciphertext of erased data stays in sealed segments forever. Its size and the fact that
   it existed remain visible.
4. Data already copied out of Foundry (exports, screenshots, model prompts sent elsewhere
   by the user) is outside its control.
5. Erasing one item by re-key costs a rewrite of that collection.
6. The person who asked cannot check it. The vault's owner holds the keys, so erasure is
   the owner's act and the owner's word. Foundry provides a technical property. It does
   not provide proof to a third party or compliance with any particular law.

## 6. Index

### 6.1 Schema

The predecessor's proven tables carry over with generic names: `meta`, `items`, `chunks`,
`chunks_fts` (FTS5, `porter unicode61`, external content with insert and delete triggers),
`vectors` (int8-quantised, one row per chunk, with `model`, `dim`, `scale`). `items` gains
`profile`, `collection` and `event_seq`. New tables:

```sql
CREATE TABLE projection_state (          -- how far each projection has replayed the vault
  projection TEXT PRIMARY KEY,
  deriver_version INTEGER NOT NULL,
  last_event_seq INTEGER NOT NULL
) STRICT;

CREATE TABLE blob_locator (              -- where each blob lives; rebuilt by scanning segments
  blob_id TEXT NOT NULL, collection TEXT NOT NULL,
  segment INTEGER NOT NULL, file TEXT NOT NULL, offset INTEGER NOT NULL, length INTEGER NOT NULL,
  PRIMARY KEY (collection, blob_id)
) STRICT;

CREATE TABLE places (
  place_id INTEGER PRIMARY KEY, item_id TEXT NOT NULL, ts INTEGER NOT NULL,
  lat_e7 INTEGER NOT NULL, lng_e7 INTEGER NOT NULL, accuracy_m INTEGER
) STRICT;
CREATE VIRTUAL TABLE places_rtree USING rtree_i32(place_id, min_lat, max_lat, min_lng, max_lng);

CREATE TABLE graph_nodes (
  node_id TEXT PRIMARY KEY,              -- random, assigned by a `node.created` event
  kind TEXT NOT NULL, canonical_key TEXT NOT NULL, label TEXT NOT NULL, profile TEXT,
  merged_into TEXT REFERENCES graph_nodes(node_id),
  UNIQUE (kind, canonical_key)
) STRICT;
CREATE TABLE graph_edges (
  edge_id INTEGER PRIMARY KEY,
  src TEXT NOT NULL REFERENCES graph_nodes(node_id),
  dst TEXT NOT NULL REFERENCES graph_nodes(node_id),
  kind TEXT NOT NULL,
  evidence_event_seq INTEGER NOT NULL,   -- earliest surviving evidence. No evidence, no edge.
  inferred INTEGER NOT NULL DEFAULT 0 CHECK (inferred IN (0,1)),
  confidence REAL CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
  CHECK (inferred = 0 OR confidence IS NOT NULL)
) STRICT;
CREATE TABLE graph_edge_evidence (       -- every record that supports an edge
  edge_id INTEGER NOT NULL REFERENCES graph_edges(edge_id),
  event_seq INTEGER NOT NULL,
  PRIMARY KEY (edge_id, event_seq)
) STRICT;                                -- an edge whose last evidence row is removed is deleted
CREATE TABLE graph_positions (
  node_id TEXT PRIMARY KEY REFERENCES graph_nodes(node_id),
  epoch INTEGER NOT NULL, x INTEGER NOT NULL, y INTEGER NOT NULL, z INTEGER NOT NULL DEFAULT 0,
  placed_event_seq INTEGER NOT NULL
) STRICT;
```

### 6.2 Rebuild

`foundry index rebuild` builds a new index generation under a new key and replays the vault
in two passes. Pass one reads only withdrawals, redactions and key destructions and builds
the list of what must stay hidden (the restore rule in section 5.7). Pass two replays
everything else in `seq` order: events first, then derivers over blobs. The new generation
replaces the old one only when pass two has finished; the old index key is then destroyed.
Each projection records its progress, so an interrupted rebuild resumes. Records under a
destroyed key are skipped and counted. To shorten recovery after losing the working
device, a vault session may also write an encrypted index snapshot to the second copy; it
is a convenience, never a source of truth.

The generation catalog contains opaque key identifiers, replay stamps and progress
bounds. A separate writer lock serializes index refresh and publication. An
interrupted build resumes at committed projection checkpoints if its captured
boundary, keyring policy and deriver version still agree. Otherwise it starts a
fresh generation and retires the abandoned key. The catalog publishes the completed
generation and records the pending retirement in one transaction. An interrupted
retirement is retried before the next managed operation.

For V-4 replay, an import's item identifier comes from its event body or defaults
to the decimal event sequence. Its blob reference is resolved under the event's
collection key. The index records locators for visible referenced blobs. The
default deriver streams UTF-8 `text/plain`, with a limit of 1,024 chunks per item.
Importers can supply a versioned deriver for other formats. Withdrawal targets
can identify an item, event, collection, profile or key. Redaction tombstone
HMACs also exclude imported copies of the original bytes.

### 6.3 Search

1. Full text: FTS5 with BM25, filters on date, source, profile, collection, tier.
2. Semantic (Tier 1+): brute-force scan of int8 vectors. The predecessor measured roughly a
   third of a second over about fifty thousand chunks on a two-core low-power CPU; the
   number must be re-measured here before it is quoted anywhere.
3. Results always carry `item_id`, `event_seq`, source and import date so an answer can cite them.

Managed search checks the published generation against the verified vault boundary.
A stale generation requires a separate index update before it can serve results.
Full-text ranking keeps the best BM25 chunk per item. Date filters use the event's
import time, with an inclusive lower bound and an exclusive upper bound.

## 7. Importers

```ts
interface ArchiveEntry { path: string; size: number; open(): Readable }

interface Importer {
  id: string;                                   // "google-takeout/mail"
  matches(entry: ArchiveEntry): boolean;
  split(entry: ArchiveEntry): AsyncIterable<RawItem>;   // lossless: originals only
}
interface RawItem { bytes: Readable; path: string; mime: string; sourceTs?: string; tags: string[] }

interface Deriver {
  id: string; version: number;
  derive(item: StoredItem, bytes: Readable): AsyncIterable<Derived>;  // text, places, graph evidence
}
```

- **Two stages on purpose.** `split` only cuts an archive into original items (one email,
  one contact card, one calendar file). `derive` produces text and structure for the
  index (`calendar` yields each `VEVENT`, `GEO` place and participant graph evidence during
  `derive` while keeping `VTIMEZONE` intact in the stored `.ics` blob). Only stage one
  writes to the vault.
- **Archive reader.** Zip with zip64, entries opened as streams through the central
  directory, multi-part archives presented as one tree. The archive is never unpacked to
  disk. Implemented in `packages/importers` with Node built-ins only (`node:fs`,
  `node:stream`, `node:zlib`), adding zero external runtime dependencies (one vetted zip
  dependency remains permitted if ever needed, recorded in `DEPENDENCIES.md`).
- **Mail.** The mbox is split on message boundaries into individual messages while
  streaming. Memory stays flat regardless of mbox size. Each stored message keeps its
  leading `From ` separator line (and the event records `body.mbox_separator`), so
  concatenating stored messages reproduces the original file byte for byte.
- **Location history.** The predecessor's parser covers the older Takeout formats
  (`Records.json`, Semantic Location History). Newer accounts keep Timeline on the phone
  and export a different file from device settings. The location importer must handle
  both and is not part of the thin slice.
- Fixtures are generated by scripts in the repository. No fixture is copied from a real account.

## 8. Second copy

### 8.1 Mode B vault session

```
1. Detect the drive, read its VAULT.json. Refuse if vault_id differs or the
   file system has a 4 GiB file limit.
2. Verify the drive: every manifest and signature, every file hash, the whole
   chain.                                                                (no secret needed)
3. Compare the drive's chain head with the head recorded on the working device
   for this copy. Older than recorded, or a different hash at the same segment
   number: STOP and show a rollback or tamper warning.
4. Close the open segment on the working device.
5. Copy each missing segment: files first, manifest last, fsync.
6. Re-read and re-hash what was copied.
7. Mark the new segments read-only. Write keyring (if the medium is rewritable) and HEAD.json.
8. Record the new head for this copy on the working device. Append `copy.sealed`.
9. Show the anchor as text and QR for printing: vault id, epoch, segment number,
   manifest hash, public-key fingerprint. Tell the user to switch on write
   protection and disconnect.
```

- The session is the only time the drive is writable. With a write-protect switch the user
  flips it off at step 1 and on at step 9; the product checks at step 2 whether the drive
  is writable and says which state it expected.
- Any failure leaves the drive's previous segments untouched, reports loudly, and the
  session can be re-run. A partly copied segment has no manifest and is removed at the next session.
- Cadence (**Decided**): weekly default; daily, monthly, manual. Banner after 14 days.
- Optical export: `foundry vault export-iso` writes closed segments and manifests (no
  keyring by default) to an image for BD-R or M-DISC. The disc must be written as a
  single, finalised session: on a multi-session disc a later session can hide earlier files.
- Media facts the wizard states:
  1. The lock tab on an SD card is only a request to the card reader. It is not write
     protection. A USB drive whose switch is enforced by the drive's own controller, or a
     hardware write-blocker, is.
  2. Flash memory left unpowered for years can lose data. The scheduled verification
     exists to catch that while the other copy is still good.
  3. A keyring kept off a write-once disc means the disc alone cannot restore anything.
     It needs a keyring from another copy.

### 8.2 What the chain proves

A drive that simply lacks the newest segments is internally consistent. Rollback,
truncation at the end and whole-drive replacement are detectable **only** by comparing
against a chain head held somewhere else: the working device, the other copy, or the
printed code. The product stores the head in all three places and checks at every
session. The docs say "tamper-evident", never "tamper-proof" or "undeniable".

Two limits no design removes: an anchor that is itself out of date cannot reveal the loss
of segments written after it, and an exact copy of a drive is indistinguishable from the
original. A damaged copy is repaired from the other copy, which is why there are two.

### 8.3 Restore drill

The drill reads the second copy read-only, checks it against the anchor, verifies
manifests, signatures and file hashes, authenticates every record, replays withdrawals,
and builds a throwaway encrypted index. Nothing is published until all of that succeeds.
Decrypted content is held in memory or in the encrypted index only; the drill never
writes plaintext to a temp directory.
The drill's test suite must include: missing last segment, two segments swapped, one
flipped bit, a drive from a different vault, a copy older than the newest withdrawal, and
a drill interrupted halfway.

### 8.4 Mode A (later phase)

- Receiver is not a service. It is a command the sender starts over SSH, restricted by a
  forced command in `authorized_keys`, which accepts new segment files, verifies chain
  continuity, refuses any overwrite or delete, and exits. Memory ceiling 96 MiB.
- The pairing credential can do nothing except run that command.
- When the device is unreachable, the sender queues and shows a flag. It never drops data silently.
- First supported receiver OS: Linux. A Windows receiver depends on a spike.
- A1 (home network) uses a pinned host key. A2 (remote) requires a private overlay
  network; the wizard will not configure port-forwarding.

## 9. Resource budgets

Proposed ceilings for peak resident memory. Each is asserted in CI on Windows and Linux
from the process's own peak-usage counter. A ceiling may be raised only by a recorded decision.

| Command | Ceiling | Note |
|---|---|---|
| Facts ledger, any subcommand | 96 MiB | Step Zero |
| `vault verify` (no key) | 128 MiB | Streaming hashes |
| Any command that runs the passphrase KDF | 256 MiB | scrypt needs about 128 MiB for under two seconds |
| `import` | 256 MiB | Independent of archive size |
| `search` | 192 MiB | Full text; vectors scanned in batches |
| Wizard server | 192 MiB | Exits when the wizard closes |
| Mode A receiver | 96 MiB | |

How it is measured: the operating system's own peak counter for the process (peak working
set on Windows, peak resident set on Linux), read at exit, using the pinned runtime binary
that ships. Helper processes a command starts (for example `git`) are measured too and
count against a separate process-tree ceiling of twice the command's own. The ceilings are
proposals until the first measurement work package in each phase confirms them; if a
measured floor makes a ceiling impossible, the ceiling is changed by a recorded decision
before code is written against it.

Other rules: one heavy job at a time (a lock file, not a queue service); every command has
a wall-clock limit; no command starts a process that outlives it, except a model server
that exits after an idle timeout.

## 10. Threat model

| Threat | Covered? | How |
|---|---|---|
| Lost or stolen second-copy drive | Yes | Encrypted content and labels. Clear metadata includes sizes, dates, event ranges and key IDs (sections 4.5 and 5.4) |
| Stolen working device, powered off | Yes, if no `os-protected` key cache | Vault and index encrypted at rest |
| Malware running as the user while unlocked | No | It can read what the user can read. Stated plainly. |
| Ransomware or a bug rewriting the working copy | Detected and recoverable | Hash chain plus an offline sealed copy it could not reach |
| Silent edit of history on a sealed copy | Detected | Chain and manifests |
| Swap of a sealed drive for an older state | Detected if an independent chain head exists | Section 8.2 |
| Administrator on the same machine bypassing read-only flags | Not prevented by software | Hardware write-protect or write-once media |
| Drive failure, fire, loss | Not prevented | Two copies in two places, scheduled verify, restore drill |
| Forgotten passphrase | Recoverable with the recovery key only | Section 5.3 |
| A person asks for their data to be removed | Yes, with the limits in 5.7 | Key destruction |
| Supply-chain compromise of a dependency | Reduced | Minimal dependencies, pinned versions, hash-verified releases |

Network exposure in v1 is zero listening ports except the loopback wizard, which binds
`127.0.0.1` on a random port and requires a one-time token in the URL.

## 11. Relationship map and stable layout

- Nodes are people, places, topics and items. A node's id is random and is recorded in the
  vault by a `node.created` event the first time its kind and canonical key are seen. A
  rebuild replays those events, so the same entity keeps the same id. An id computed from
  the name would change, and lose its position, whenever name normalisation improved; with
  recorded ids a deriver upgrade that changes a key records a `node.merged` instead.
- Every ordering that affects ids or positions is by raw bytes with an explicit sort.
  Locale-aware comparison differs between machines.
- An edge exists only with an `evidence_event_seq`. Edges proposed by a model are stored
  with `inferred = 1` and a confidence, and are drawn differently. The map must not invent relationships.
- **Positions are recorded, not recomputed.** Re-running a force simulation gives
  different coordinates across runs and library versions. Instead:
  1. When a node first appears, a placement function chooses integer grid coordinates:
     near the integer median of its already-placed neighbours, spiralling outward to the
     first free cell, starting from a cell chosen by the node id hash when it has no
     neighbours. Integer arithmetic only.
  2. The function is fully specified so two machines agree: neighbours are taken in node-id
     order and capped at 32; the spiral order is fixed; the search stops after 4,096 cells
     and falls back to a fixed overflow row. The caps keep a node with thousands of
     neighbours from making an import slow. Only edges backed by stored records count as
     neighbours. Model-inferred edges never influence placement, because model output
     differs between machines.
  3. A large first import has no placed neighbours to start from, and placing nodes one by
     one would turn import order into geography. So nodes created by one import are placed
     together at the end of that import: grouped into regions by kind and source, then
     placed inside the region. Every placement event names the algorithm and its version.
  4. The result is appended to the vault as a `layout.placed` event and projected into
     `graph_positions`. A node is not shown until its placement is recorded.
  5. Rebuilding the index replays those events. The picture is the same on every device
     and after every rebuild.
  6. A user who wants a fresh arrangement triggers `layout.epoch`, which starts a new set
     of placements. Old epochs remain in history.
- Dragging a node appends one `layout.moved` when the drag ends. Merging two nodes appends
  `node.merged`, which names the survivor and maps the retired id to it. The survivor
  keeps a position the user chose by dragging, otherwise the earlier placement. The
  retired node's placement stays in history so undoing the merge restores it. Edges keep
  their evidence.
- Removing evidence removes the edges that depended on it and never moves the nodes that remain.
- A force simulation may be offered as an explicit "rearrange" action. Its result is
  committed as a new epoch of recorded positions; it is never the source of truth.
- The renderer may animate, but it starts from and returns to stored positions.
- Geographic coordinates (`places`) and map-layout coordinates are separate and never mixed.

## 12. Local models

- Models are optional and never required for Tier 0.
- Runtime: a permissively licensed local inference server, started on demand by the
  command that needs it and stopped by an idle timeout. Never resident.
- A model catalog file lists, for each model: download URL, SHA-256, license, file size,
  measured peak memory, and the tier it needs. The default catalog contains only models
  under MIT or Apache-2.0 terms. Downloads are started by the user and hash-verified.
- Candidates are chosen by benchmark on a Tier 1 reference machine during the models work
  package, not named in this document.
- One inference at a time.

## 13. Packaging

- v1 ships a directory bundle: the official, unmodified Node runtime binary, the bundled
  JavaScript, and the native SQLCipher addon for that platform. Single-file executables
  are avoided for three reasons: a native addon cannot be loaded from inside one without
  unpacking to disk, injecting an application into the runtime binary invalidates the
  runtime's own signature, and a program that unpacks a binary to a temp folder and loads
  it looks like malware to antivirus tools.
- A second channel for technical users: an npm package that runs on a Node 24 the user
  already has. Same code, same addon builds.
- The native addon is built per runtime major version, per platform. The project builds
  and publishes its own addon binaries in CI and does not depend on upstream release timing.
- Free integrity measures are used from the first release: build provenance attestations
  for release assets and npm provenance for the package.
- Windows: zip plus `install.ps1` that verifies SHA-256 and installs per-user; a WinGet
  manifest pointing at the release asset. No MSIX in v1, because MSIX requires a signed package.
- Linux: tarball plus `install.sh` into the user's home; `.deb` later. glibc-based
  distributions only in v1. The installer checks the platform, architecture and C library
  and stops with a clear message on anything untested.
- Each release names the exact runtime version and native-addon build it was tested with.
  Every advertised platform is tested on a clean machine image before release.
- Windows may warn about, or under some policies block, an unsigned download. A checksum
  proves the file is intact; it does not make Windows trust the publisher. On machines
  with Smart App Control switched on, the unsigned native addon may be refused outright;
  this must be tested on a clean Windows 11 image before the first release. If it is
  refused, the user's choices are the `plain` driver with disk encryption (section 5.5,
  explicit opt-in) or waiting for a signed build. See risk R-1 in [DECISIONS.md](DECISIONS.md).
- Windows on arm64 is not supported in v1.
- Schedulers: a per-user Task Scheduler entry on Windows, `systemd --user` timers on Linux,
  with a cron fallback.
- Releases are built in CI, with checksums published next to the assets.

## 14. Relationship to the private predecessor

Foundry is a clean extraction, not a fork. Components are re-homed file by file through a
scrub gate; no git history is carried. The record format here is deliberately not
byte-compatible with the predecessor's blob format: it adds a key id for erasure, binds
records to a vault, and uses new derivation labels. The predecessor adopts Foundry later
as a consumer, with a one-time migration that is planned separately and is not public.

## 15. Test gates that protect the architecture

| Gate | Fails the build when |
|---|---|
| Format vectors | Regenerated bytes differ from the committed vectors, or either reader differs from an expected plaintext or rejection |
| Tamper suite | A flipped bit, removed file, reordered record, swapped manifest or replayed record passes verification |
| Crash suite | A write killed at any point leaves a vault that cannot be opened or repaired automatically |
| Offline run | Import and search produce any network packet |
| Memory | Any command exceeds its ceiling in section 9 |
| Erasure | Data under a destroyed key is readable through any command, or remains in the index |
| Rebuild | Index after `rebuild` differs from the incrementally built index |
| Layout | Two rebuilds give different node positions |
| Withdrawal on restore | Restoring any older copy makes a withdrawn item searchable, or a redacted item can be re-imported |
| Restore drill | Any failure case in section 8.3 passes the drill |
| Fail closed | The index opens unencrypted without the explicit `plain` choice |
| Index at rest | A planted marker string is found in the index file, its write-ahead log, a journal or a spill file |
| Identifier scan | A personal name, hostname, home path, token or key appears in the tree **or in a release archive** |
