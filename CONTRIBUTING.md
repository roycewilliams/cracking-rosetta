# Contributing

## The short version

Edit exactly one file in `data/algorithms/`, run `tools/validate.pl`, open a PR.

## What you may and may not edit

**Edit:** `data/algorithms/*.yaml`. One algorithm per file; the filename stem
must equal the entry's `id`.

**Do not edit:** `data/tools/*.yaml`. Those are regenerated from the tools
themselves and every one carries a `GENERATED` banner. If a mode or format is
missing there, the fix is to re-run the extractor, not to hand-patch the file.

**Do not edit:** `vendor/`. Refresh it with `tools/fetch-upstream.sh` and
commit that as its own change, so the diff shows what upstream altered.

## Before you open a PR

    tools/validate.pl

It checks entry shape and then resolves every identifier you named against the
generated inventories: whether hashcat mode 2811 exists in this hashcat,
whether `dynamic_12` is really a CPU format, whether `MD5-MD5SALTMD5PASS`
exists in this mdxfind. Naming an identifier no installed tool has is the
likeliest defect in a repository like this and is exactly what the old
spreadsheet accumulated over three years.

## Tiers: please do not inflate them

`verified: vector` means **this repository cracked the vector with that tool**.
It is not a synonym for "I'm confident". If you have not round-tripped it, use
`asserted` and say where the claim came from in `note`. Someone will verify it
later and promote it, and an honest `asserted` is far more useful than a
`vector` that turns out to be hopeful.

`tools/verify-vectors.pl` does the promotion. It will refuse to promote a tool
block unless *every* identifier that block lists verified.

## Adding an algorithm

Minimum viable entry:

```yaml
id: "example-thing"
name: "Example Thing"
status: "needs-review"
tools:
  hashcat:
    modes: [12345]
    verified: "asserted"
vectors:
  - hash: "<a hash>"
    pass: "<its plaintext>"
    source: "where you got it"
```

A vector is the most valuable thing you can add — it is what lets anyone
promote the mapping to `vector` later, and it is what makes a disagreement
resolvable instead of an argument.

## One entry is one algorithm

If a hash you are adding is computed differently from the entry you were about
to put it in, it needs its own entry — even when the two share a name, a tool
identifier, or a mode.

- `aliases:` is for other **names** of the same computation. It is not a place
  to list related algorithms. One entry here reached five vectors falling to
  three different John dynamics that way, and no check caught it.
- Two entries **may** legitimately share an `expression:`. `joomla` and
  `md5-pass-salt` are both `md5($p.$s)`; hashcat gives them modes 11 and 10
  because the application is the distinction, and both rows earn their place.
  When you add such an entry, say in `note:` which axis differs — the
  application, the encoding of the digest, the encoding of the plaintext, an
  iteration count, or a truncation.
- If a tool cracks your vector but does not really implement your algorithm,
  do not record the mapping. `md5cap` is `cap(md5($p))`, which is a no-op
  whenever the digest has no letters, so John's `dynamic_2` recovers its
  vector while denoting something else. Put it in `note:` instead.
- `id` never changes once published — it is the filename stem, a URL fragment
  in the rendered page, and the key in `dist/rosetta.csv`. If a name is wrong,
  add the better one to `aliases:` on the entry that survives.

A richer, machine-readable form of all this — a typed `relations:` edge list,
so "same computation, differs by application" is data rather than prose — is
designed in `ACTION-PLAN.md` §11 and not built yet.

## Things worth knowing

- **The mdxfind iteration count is part of the identity.** `MD5` at `-i 2` is
  `md5(md5($pass))`, which is John's `dynamic_2`, not `dynamic_0`. Record it as
  `tools.mdxfind.iterations`.
- **John is inconsistent about case**: `Raw-MD5` on CPU, `raw-MD5-opencl` on
  GPU. Use the exact label the inventory lists.
- **Some John dynamics are disabled by default** in `dynamic_disabled.conf`.
  They are real formats and valid to reference; the validator will note them.
- **mdxfind's hashcat column lists *related* modes, not equivalents.** Type
  `MD5` names modes 0, 2600, 3500 and 5100 — four different algorithms it
  reaches by varying `-i` and truncation. Do not copy such a list wholesale
  into one entry.

## Disagreements

If your source contradicts what is already in an entry, do not overwrite it.
Add your claim in `note` and say so in the PR. Disagreements get settled by
verification, not by whoever edited last.
