# Vendored upstream catalogs

These files are copied verbatim from Cynosure Prime and are **not** edited here.
They are vendored rather than fetched at build time so that every generated
inventory is reproducible from the repository alone, and so a contributor
without network access can still run the extractors and the seeder.

Refresh them with `tools/fetch-upstream.sh` and commit the result as its own
change, so the diff shows exactly what upstream altered.

| File | Source | Commit | Fetched |
|---|---|---|---|
| `hashpipe-HASH_TYPES.md` | [Cynosureprime/hashpipe](https://github.com/Cynosureprime/hashpipe) `HASH_TYPES.md` | `81c3b8f8fb2678721d935ecfc8a6d2ebe2ad0ae0` (2026-08-29) | 2026-08-29 |
| `john_map.h` | [Cynosureprime/hashpipe](https://github.com/Cynosureprime/hashpipe) `john_map.h` | `81c3b8f8fb2678721d935ecfc8a6d2ebe2ad0ae0` (2026-08-29) | 2026-08-29 |

## Why hashpipe's catalog and not mdxfind's

Both repositories ship a `HASH_TYPES.md`. They are not equally current:
measured 2026-08-29, mdxfind's copy is v1.76 / 988 types while hashpipe's is
v1.102 / 1000, and the local mdxfind binary is newer still at 1001 types
(RCS 1.540). On the 1000 shared indices hashpipe's copy agrees with the binary
on every name and every hashcat mapping; mdxfind's does not — `e1` alone gives
`0,2600,5100` against the binary's `0,2600,3500,5100`.

mdxfind's copy is therefore deliberately **not** vendored. See
`tools/extract-mdxfind.pl`.

## Licence

Both projects are MIT licensed. See the LICENSE file in each upstream
repository; these copies are included under those terms.
