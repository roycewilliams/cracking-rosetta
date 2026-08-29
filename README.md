# cracking-rosetta

A cross-reference of password-cracking algorithm identifiers across
**hashcat**, **John the Ripper**, **mdxfind**/**hashpipe**, and — for
historical reference — Alec Muffett's **Crack**.

It answers the question you actually have at 2am: *this thing is hashcat mode
2811; what does John call it, and can mdxfind do it?*

    tools:
      hashcat:  { modes: [2811],                 verified: vector }
      john:     { cpu: [dynamic_12],             verified: upstream }
      mdxfind:  { types: [MD5-MD5SALTMD5PASS],   verified: vector }

## The point: every mapping says how well it is known

Cross-references like this rot silently. A row that was right in 2021 still
*looks* right in 2026 after upstream renamed the format. So every mapping
carries a tier:

| Tier | Meaning |
|---|---|
| `vector` | This repo cracked the entry's own test vector with that tool, restricted to that exact identifier. **Proven.** |
| `upstream` | Asserted by a project that verifies by recomputation (mdxfind's own type table, hashpipe's `john_map.h`). |
| `asserted` | A human said so. No reproduction on record. |
| `absent` | That tool does not support this algorithm. |

Filter to `vector` if you are automating against this and want only what has
been demonstrated. Nothing is promoted without a round-trip, and a failed
round-trip never silently demotes — see `tools/verify-vectors.pl`.

## Layout

    data/algorithms/*.yaml   CURATED, one file per algorithm — the PR surface
    data/tools/*.yaml        GENERATED inventories — never hand-edited
    schema/                  entry shape, for editors and consumers
    tools/                   extractors, validator, verifier
    vendor/cynosureprime/    vendored upstream catalogs, with provenance

Inventory (what each tool supports, regenerated from the binaries) is kept
apart from mapping (human judgement about which identifiers denote the same
algorithm). A new hashcat release regenerates one layer and never touches the
other.

One file per algorithm rather than one big table is deliberate: a contributor
touches one small file, merge conflicts effectively vanish, `git blame` is
meaningful per algorithm, and CODEOWNERS can route review by path.

## Current state

Run `tools/validate.pl` for live numbers rather than trusting a README. As of
2026-08-29 the inventories held 593 hashcat modes, 552 John formats and 1001
mdxfind types, against 895 curated entries.

Coverage is deliberately partial and visible. Where a tool column is missing,
that is an open question, not a claim of absence — `absent` is a claim, and
it is stated explicitly.

## Regenerating

    tools/extract-hashcat.pl --binary /usr/local/bin/hashcat  > data/tools/hashcat.yaml
    tools/extract-john.pl    --binary .../john-latest/run/john > data/tools/john.yaml
    tools/extract-mdxfind.pl --binary /usr/local/bin/mdxfind \
        --catalog vendor/cynosureprime/hashpipe-HASH_TYPES.md  > data/tools/mdxfind.yaml

    tools/validate.pl                    # shape + cross-reference, gates PRs
    tools/verify-vectors.pl --tool all   # round-trip; needs the tools and a GPU

Extractors also accept `--from FILE` (or `stdin`), so captured output can be
diffed without the binaries present.

## Credits

The verified seed data is Cynosure Prime's. `mdxfind` ships a hashcat mapping
for 298 of its types, and `hashpipe`'s `john_map.h` maps 125 John dynamic
formats to mdxfind types, each confirmed by recomputation across 9672
harvested vectors — with the rows that would not verify omitted rather than
guessed. That practice is the model this repo follows.

The original rosetta was a Google Sheet maintained by the password-cracking
community; this repository migrates and continues it.

## Licence

MIT. See `LICENSE`.
