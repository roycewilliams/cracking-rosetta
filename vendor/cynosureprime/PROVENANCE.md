# Vendored upstream catalogs

These files are copied verbatim from Cynosure Prime and are **not** edited here.
They are vendored rather than fetched at build time so that every generated
inventory is reproducible from the repository alone, and so a contributor
without network access can still run the extractors and the seeder.

Refresh them with `tools/fetch-upstream.sh` and commit the result as its own
change, so the diff shows exactly what upstream altered.

| File | Source | Commit | Fetched |
|---|---|---|---|
| `hashpipe-HASH_TYPES.md` | [Cynosureprime/hashpipe](https://github.com/Cynosureprime/hashpipe) `HASH_TYPES.md` | `e528d881d96d81c97c57b88c7a0759ff6aec5770` (2026-09-04) | 2026-09-04 |
| `john_map.h` | [Cynosureprime/hashpipe](https://github.com/Cynosureprime/hashpipe) `john_map.h` | `e528d881d96d81c97c57b88c7a0759ff6aec5770` (2026-09-04) | 2026-09-04 |

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

**Each item below is also a record in `data/upstream-disagreements.yaml`,
which `tools/check-upstream.pl` executes and CI runs.** Until 2026-09-02 this
section was the only statement of the relationship and nothing read it, so
none of the three ways it can change state -- upstream moving, our side being
re-seeded back to upstream's value, or the two converging -- was detectable.
The prose here is the human account; the register is the part that fails.
**Delete an item from both when its record converges.**

Re-fetched 2026-09-02 at commit `6ebf0069`: **both files came back
byte-identical to the 2026-08-29 copy** even though upstream HEAD had moved, so
what follows is upstream's current published state rather than a stale local
copy.

* **`e607 SHA1MD5SALTPASSPEPPER` publishes a pre-fix digest.**
  Register record: `e607-example-vector`. mdxfind 1.543
  (2026-08-29) repaired a buffer-layout bug in that type; its own revision log
  says "any hash cracked as e607 before this revision will not verify against
  it". The catalog still carries `786aab530907a783e9c25a2c7326ab7907ebf798`,
  which is the OLD construction `sha1(cut(salt . md5(salt . pass), 0, 32) .
  pepper)`. The repaired form `sha1(md5(salt . pass) . pepper)` gives
  `0992047fa349ac4e5abb3fef6c0f3f8f8bc6d679` for the same salt, pepper and
  plaintext, established three independent ways and recorded on the
  `sha1md5saltpasspepper` entry.

* **The catalog lags the binary by design.**
  Register record: `mdxfind-catalog-lags-binary`, which also carries the
  assertion that makes hashpipe an alias of mdxfind rather than a fourth
  column: on every shared index the catalog and the local inventory agree on
  the name and on the hashcat mapping. Measured 2026-09-02: 1000 types at
  v1.102 here against 1002 in the local mdxfind (RCS 1.545). `e1002 RMD256` has no catalog row and
  therefore no example vector, which is why the extractor reports fewer example
  vectors than types.

* **`john_map.h` numbers ITERATIONS in hashpipe's scheme, not mdxfind's.**
  Register record: `hashpipe-john-map-agreement`. Measured 2026-09-02 with
  both binaries on this host, same hash and same plaintext, each pinned to the
  named type: mdxfind reports `SHA224RAWx01` for plain `sha224($p)` and
  `SHA224RAWx02` for `sha224(sha224_raw($p))`, while hashpipe calls the plain
  one `SHA224x01` and the raw-fed one `SHA224RAWx01`. The same offset holds for
  `SHA256RAW`, `SHA384RAW`, `SHA512RAW`, `MD5RAW` and `MD5CAP`. Four rows of
  `JohnMap[]` are affected (`dynamic_54`, `_64`, `_74`, `_84`), and a fifth,
  `dynamic_37`, publishes `SHA1SALTPASS` where john's own subformat listing
  says `sha1(lc($u).$p) (SMF)` -- hashpipe reports the first type that
  reproduces a digest, and those two coincide whenever the userid is already
  lower case. `tools/seed-upstream.pl` reads this register and refuses all
  five rather than seeding them.

* **`JohnMapLocal[]` must never be seeded from.** Not a disagreement and so
  not a register record, but the same class of hazard. hashpipe v1.189 added a
  second table of 51 config-defined dynamics; upstream's own comment says the
  NUMBERING IS LOCAL to the machine that ran the generator and the table is
  consulted on input only. Confirmed here 2026-09-02: upstream's
  `dynamic_1013` is `MD5PASSSALT` and its `dynamic_1014` is `POSTGRESQL`,
  while this host's john has the two the other way round. Both
  `tools/seed-upstream.pl` and `check_john_map` in `tools/check-upstream.pl`
  read the first table only, on purpose.
