# Vendored upstream catalogs

These files are copied verbatim from Cynosure Prime and are **not** edited here.
They are vendored rather than fetched at build time so that every generated
inventory is reproducible from the repository alone, and so a contributor
without network access can still run the extractors and the seeder.

Refresh them with `tools/fetch-upstream.sh` and commit the result as its own
change, so the diff shows exactly what upstream altered.

| File | Source | Commit | Fetched |
|---|---|---|---|
| `hashpipe-HASH_TYPES.md` | [Cynosureprime/hashpipe](https://github.com/Cynosureprime/hashpipe) `HASH_TYPES.md` | `6ebf0069dac07b81a34177d160f88f51e6b809f6` (2026-09-02) | 2026-09-02 |
| `john_map.h` | [Cynosureprime/hashpipe](https://github.com/Cynosureprime/hashpipe) `john_map.h` | `6ebf0069dac07b81a34177d160f88f51e6b809f6` (2026-09-02) | 2026-09-02 |

## Why hashpipe's catalog and not mdxfind's

Both repositories ship a `HASH_TYPES.md`. They are not equally current:
measured 2026-08-29, mdxfind's copy is v1.76 / 988 types while hashpipe's is
v1.102 / 1000, and the local mdxfind binary is newer still at 1001 types
(RCS 1.540). On the 1000 shared indices hashpipe's copy agrees with the binary
on every name and every hashcat mapping; mdxfind's does not -- `e1` alone gives
`0,2600,5100` against the binary's `0,2600,3500,5100`.

mdxfind's copy is therefore deliberately **not** vendored. See
`tools/extract-mdxfind.pl`.

## Licence

Both projects are MIT licensed. See the LICENSE file in each upstream
repository; these copies are included under those terms.

## Known stale rows, and why they are not corrected here

These files are copied verbatim and are **not** edited, so a row upstream has
not caught up with stays wrong here on purpose: editing it would manufacture
exactly the drift `tools/fetch-upstream.sh` exists to detect. Where this
repository has established the correct value, it lives in `data/algorithms/`
with its working shown, and the entry says the catalog disagrees.

Re-fetched 2026-09-02 at commit `6ebf0069`: **both files came back
byte-identical to the 2026-08-29 copy** even though upstream HEAD had moved, so
what follows is upstream's current published state rather than a stale local
copy.

* **`e607 SHA1MD5SALTPASSPEPPER` publishes a pre-fix digest.** mdxfind 1.543
  (2026-08-29) repaired a buffer-layout bug in that type; its own revision log
  says "any hash cracked as e607 before this revision will not verify against
  it". The catalog still carries `786aab530907a783e9c25a2c7326ab7907ebf798`,
  which is the OLD construction `sha1(cut(salt . md5(salt . pass), 0, 32) .
  pepper)`. The repaired form `sha1(md5(salt . pass) . pepper)` gives
  `0992047fa349ac4e5abb3fef6c0f3f8f8bc6d679` for the same salt, pepper and
  plaintext, established three independent ways and recorded on the
  `sha1md5saltpasspepper` entry.

* **The catalog lags the binary by design.** Measured 2026-09-02: 1000 types at
  v1.102 here against 1002 in the local mdxfind (RCS 1.545). `e1002 RMD256` has no catalog row and
  therefore no example vector, which is why the extractor reports fewer example
  vectors than types.
