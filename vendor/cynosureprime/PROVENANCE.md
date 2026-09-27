# Vendored upstream catalogs

These files are copied verbatim from Cynosure Prime and are **not** edited here.
They are vendored rather than fetched at build time so that every generated
inventory is reproducible from the repository alone, and so a contributor
without network access can still run the extractors and the seeder.

Refresh them with `tools/fetch-upstream.sh` and commit the result as its own
change, so the diff shows exactly what upstream altered.

| File | Source | Commit | Fetched |
|---|---|---|---|
| `hashpipe-HASH_TYPES.md` | [Cynosureprime/hashpipe](https://github.com/Cynosureprime/hashpipe) `HASH_TYPES.md` | `5445f6fa0365eff9f6b36919a3870151e4c73dd2` (2026-09-27) | 2026-09-27 |
| `hx.8` | [Cynosureprime/hx](https://github.com/Cynosureprime/hx) `hx.8` | `93fcce559a98ae10c6f62ed08b7496f41c2b532c` (2026-09-27) | 2026-09-27 |
| `john_map.h` | [Cynosureprime/hashpipe](https://github.com/Cynosureprime/hashpipe) `john_map.h` | `5445f6fa0365eff9f6b36919a3870151e4c73dd2` (2026-09-27) | 2026-09-27 |

## What `hx.8` is

Appendix A of the hx Language Specification: one row per registered mdxfind
type, giving its index, its name and the expression it computes. It is the
authority behind every `denotation:` this repository sources to mdxfind, and
behind the expressions `seed-hx.pl` proposes.

`tools/extract-hx.pl` renders it into `data/hx-appendix-a.txt`, resolving the
troff font escapes and the multi-line `tbl` cells, which is the form
`RosettaHx::parse_appendix` reads. The troff is vendored rather than the
published PDF because the troff is the source, it diffs, and a specification
change is then visible in the same way a catalog change is.

The specification carries one version, the document's, printed in its running
header and bumped when the document is published; Appendix A is part of that
document and is identified by it. The commit in the table above is what pins
the exact bytes this repository read, which is what a check-upstream record
needs in order to run -- not a second version of the appendix.

## Why hashpipe's catalog and not mdxfind's

Both repositories ship a `HASH_TYPES.md`. They are not equally current:
measured 2026-08-29, mdxfind's copy is v1.76 / 988 types while hashpipe's is
v1.102 / 1000, and the local mdxfind binary is newer still at 1001 types
(RCS 1.540). On the 1000 shared indices hashpipe's copy agrees with the binary
on every name and every hashcat mapping; mdxfind's does not -- `e1` alone gives
`0,2600,5100` against the binary's `0,2600,3500,5100`.

mdxfind's copy is therefore deliberately **not** vendored. See
`tools/extract-mdxfind.pl`.

## License

All three projects are MIT licensed. See the LICENSE file in each upstream
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

Re-fetched 2026-09-05 at commit `deecd388`. `john_map.h` came back
byte-identical; `HASH_TYPES.md` did not, and the change is large and good:
upstream now GENERATES it from the hashpipe binary rather than maintaining it
by hand, so it goes from 1000 types at v1.102 to **1026 at v1.193**.

**`e607 SHA1MD5SALTPASSPEPPER` is no longer listed here.** It was, until
2026-09-05, and the record `e607-example-vector` is the reason it could be
dropped rather than forgotten: the catalog published the pre-fix digest
`786aab53...` for a construction mdxfind 1.543 had repaired, and the 2026-09-05
re-fetch brought back `0992047f...`, which is the value this repository had
established three independent ways and asserted on the
`sha1md5saltpasspepper` entry. `check-upstream.pl` reported `converged`, which
is the third failure mode -- the one that otherwise looks exactly like nothing
having happened -- and the record and this bullet were deleted together.

* **The catalog lags the binary by design, and as of 2026-09-05 by one index.**
  Register record: `mdxfind-catalog-lags-binary`, which also carries the
  assertion that makes hashpipe an alias of mdxfind rather than a fourth
  column: on every shared index the catalog and the local inventory agree on
  the name and on the hashcat mapping. Measured 2026-09-05: 1026 catalog rows
  at v1.193 against 1027 types in the inventory (mdxfind RCS 1.576). The one
  index upstream does not list is `e426 PARALLEL`, a control type rather than a
  hash, which the catalog SKIPS rather than renumbering around -- and that skip
  is what keeps the two index spaces comparable at all.

* **Eight shared indices now disagree on the hashcat mapping, and mdxfind did
  not move.** Same register record, `mode_differs:`. All 1026 shared indices
  agree on the NAME. The mode column changed when upstream started generating
  the catalog: it is the inverse of hashpipe's `Maphashcat[]`, which maps each
  hashcat mode to ONE canonical index, whereas mdxfind's `-h` prints every mode
  a type can serve. Measured 2026-09-05, mdxfind RCS 1.545 and RCS 1.576 answer
  identically on all eight, so the movement is entirely on the catalog side.
  Six are synonym pairs (6000 between `e17 RMD160` and `e118 RIPEMD`, 1000
  between `e369 NTLM` and `e786 NTLMH`, 4521/4522 between `e520` and `e579`)
  and two are a mode that is an ITERATION of a type (3500 = md5(md5(md5($p))),
  which mdxfind serves as `e1 MD5` at three iterations and hashpipe attributes
  to `e303 MD5-2xMD5`). Neither spelling is wrong, so this is recorded rather
  than repaired -- but an UNRECORDED mapping disagreement still fails, and a
  NAME disagreement has no exception path at all.

* **`john_map.h` disagrees on one row, and it is MASKING rather than
  numbering.** Register record: `hashpipe-john-map-agreement`. `dynamic_37`
  publishes `SHA1SALTPASS` where john's own subformat listing says
  `sha1(lc($u).$p) (SMF)`; hashpipe reports the first type that reproduces a
  digest, and those two coincide whenever the userid is already lower case.
  `tools/seed-upstream.pl` reads this register and refuses that row rather
  than seeding it.
  **Four rows were dropped on 2026-09-05 and the reason is worth keeping.**
  `dynamic_54`, `_64`, `_74` and `_84` were recorded on 2026-09-02 as an
  iteration-numbering convention difference, hashpipe publishing `SHA224RAWx01`
  where this repository asserted `SHA224RAW x02` and the same for the SHA256,
  384 and 512 siblings. That diagnosis was WRONG. mdxfind revision 1.290 had
  regressed the RAW family so that every RAW type became numerically identical
  to its plain sibling at x01, revision 1.549 restored it, and the installed
  RCS 1.545 of that day still carried the regression. Upstream's map was right
  the whole time. All four converged and were deleted.

* **`JohnMapLocal[]` must never be seeded from.** Not a disagreement and so
  not a register record, but the same class of hazard. hashpipe v1.189 added a
  second table of 51 config-defined dynamics; upstream's own comment says the
  NUMBERING IS LOCAL to the machine that ran the generator and the table is
  consulted on input only. Confirmed here 2026-09-02: upstream's
  `dynamic_1013` is `MD5PASSSALT` and its `dynamic_1014` is `POSTGRESQL`,
  while this host's john has the two the other way round. Both
  `tools/seed-upstream.pl` and `check_john_map` in `tools/check-upstream.pl`
  read the first table only, on purpose.
