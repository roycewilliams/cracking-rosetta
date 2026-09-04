# Tools this repository does not track, and why

Hand-written, not generated. Everything else in `docs/` carries a GENERATED
header and is rewritten by `tools/render.pl`; this file and `CRACK.md` do not.

The cross-reference names four tools -- hashcat, John the Ripper, mdxfind and
hashpipe -- plus Alec Muffett's `Crack` for historical reference. People
reasonably ask why not others. This is the standing answer, with the
measurements behind it, so the question does not have to be re-argued from
scratch each time.

## What earns a column

Two things, and a column needs both.

1. **An identifier namespace a reader arrives by.** Somebody has a hash and a
   tool's name for it -- `-m 2811`, `dynamic_12`, `MD5MD5SALTPASS` -- and needs
   the other tools' names for the same computation. A tool with no stable
   published identifier per algorithm has nothing to join on.
2. **A binary that can prove a mapping here.** The prime directive is that no
   mapping is asserted without a round-trip. A tool nobody can run against a
   vector on this host can only ever produce tier `asserted`, and a column of
   `asserted` is a rumour with a schema.

A tool that has the first and not the second can still be worth a **reference**
-- a paragraph here, an alias on a row -- which is what this file is for.

## Generators: cyclone-github/hashgen

`hashgen` is a Go hash *generator*: it reads a wordlist and writes hashes. Its
README published 132 mode names when this was written on 2026-09-04, each with
its hashcat mode number where one exists, and it accepts a bare hashcat mode
number as a mode name.

**It does not earn a column, and the reason is measured.** On 2026-09-04 all
132 published names were normalised by this repository's separator-drift rule
(upper-case, strip non-alphanumerics) and looked for among every identifier
this repository publishes -- id, name, aliases, legacy spellings, mdxfind and
hashpipe types, john cpu and gpu labels, hashcat modes:

* **81** reach a row by an identifier already published here.
* **37** match only as a substring. Nearly all are hashgen's convention for
  which operand keys an HMAC -- `hmacsha256pass` and `hmacsha256salt` against
  mdxfind's `HMAC-SHA256` and `HMAC-SHA256-KPASS`. A substring is a hint for a
  curator, never a mapping, so these are not counted as reached.
* **6** are encoders rather than hashes -- base32, base58 and Morse, each in
  both directions. A hash cross-reference is the wrong place for them.
* **3** reach a row once one obvious alias is allowed: `ldapsha` is
  `netscape-ldap` (hashcat 101), and `md5utf16passsalt` / `md5utf16saltpass`
  are `md5utf16lepasssalt` / `md5utf16lesaltpass` (hashcat 30 and 40).
* **3 are genuinely absent from this repository: MD6-224, MD6-384 and
  BLAKE2b-384.** MD6-128, MD6-256 and MD6-512 all have rows; BLAKE2b-512,
  BLAKE2b-256 and BLAKE2s-256 do. No hashcat mode, john format or mdxfind type
  covers the missing three, so a row for them would name no tool at all and
  could not be verified here. They are recorded as a gap rather than filed as
  three unverifiable rows.

So hashgen is a **naming convention**, not a namespace with its own algorithms,
and the convention already lands on rows this repository publishes.

**Its real interest is the other direction.** 57 live entries carry no usable
vector at all, which means no tool mapping on them can ever reach tier
`vector`. A generator is exactly the instrument for that: give it a plaintext
and it produces the hash, where a cracker has to be handed both. Nothing else
in this repository's toolbox does that -- hashpipe recomputes, but only to name
a type for a pair it is already given.

Two things stand in the way, and both are the repository owner's call rather
than a contributor's:

* hashgen is **GPL-2.0** and this repository is MIT throughout, including the
  data. Nothing of hashgen's would need to be vendored to *use* it -- a
  generated hash is a fact, not a copied table -- but the published contract
  says vendored material must be licence-compatible and recorded in
  `vendor/*/PROVENANCE.md`, and that line is worth not blurring.
* It is a Go program with no OS package. The house rule prefers
  OS-packaged software and asks that an external source be flagged with its
  trade-off rather than quietly installed.

## Identifiers: haiti, hashID, Name-That-Hash

These identify a hash type from the hash's *shape*. They are the closest prior
art to this repository's core join, and one of them is closer than the rest.

**`haiti`** (Orange-Cyberdefense / noraj, Ruby) claims 675+ hash types and, for
each, both a hashcat mode and a john format -- a hashcat-to-john rosetta stone
by any other name, and it is packaged (FreeBSD `security/rubygem-haiti-hash`).
Its repository is badged MIT.

**Do not treat that badge as settled provenance.** haiti's type database is
`data/prototypes.json`, which is the same filename and the same role as
hashID's `prototypes.json`, and **hashID is GPL-3.0** -- the licence is in its
`doc/LICENSE`, which is why GitHub reports none. Whether haiti's data is an
independent creation or a descendant of hashID's is a question about the file's
history, not about a badge, and it has to be answered before a line of it is
read, copied or compared against. That is the same care the repository already
took when it deleted its fetched copy of hashID's file in 2026-08.

**`Name-That-Hash`** (Python) appeared in 2021, after haiti, and covers fewer
types. Same class, smaller; nothing here has been measured against it.

**hashcat's own `--identify`** is already in use here: `tools/absence.pl` asks
it which modes can even parse a vector, so that an absence reads "of the modes
whose parser accepts this hash, none reproduced it" rather than "none of 592".
It is the one identifier in this list that is not prior art but a dependency.

The honest comparison: all three identify by regex over a hash's shape and
verify nothing. This repository verifies and does not identify. They are
complements, not competitors, and the identification capability is a queued
piece of work here -- to be written from this repository's own vector corpus,
for the licence reason above.

## Crackers with no general namespace

Not tracked because there is nothing to join on, not because they are bad.

* **Online / protocol crackers** -- hydra, medusa, ncrack, patator. They attack
  a login, not a stored digest; they have a protocol list, not a hash-type list.
* **Capture and conversion** -- aircrack-ng, hcxtools, the `*2john` family.
  These produce the input a cracker consumes. `hcxpcapngtool` output is already
  what a `WPA*01*` vector here IS.
* **Single-format tools** -- fcrackzip, pdfcrack, bkcrack, rarcrack. One
  format each, and the format already has a row.
* **Rainbow-table tools** -- ophcrack, RainbowCrack. LM, NTLM and a handful of
  raw digests. The namespace is a table set, not an algorithm list, and every
  algorithm in it already has a row.
* **Dead or Windows-only** -- Cain and Abel (last release 2014), L0phtCrack,
  MDCrack, BarsWF, IGHASHGPU.
* **Commercial** -- Passware Kit, Elcomsoft. Broad container coverage and no
  public per-algorithm identifier list to join on; the binaries are not here to
  prove anything with either.
* **Distribution layers** -- Hashtopolis, HashKitty. They schedule hashcat.
  The namespace they expose IS hashcat's, already a column.

## What would change any of this

* hashgen gaining a stable per-mode identifier that people cite in the way they
  cite `-m 2811` -- at which point its 130 names become a namespace and the
  measurement above should be re-run.
* haiti's data provenance being established as independent of hashID, which
  would make it an MIT third opinion on every hashcat-to-john pair published
  here, and disagreements would belong in
  `data/upstream-disagreements.yaml` like any other.
* Somebody wanting a generator badly enough to accept a GPL-2.0 Go dependency
  for the 57 vectorless rows.

Each of those is a decision with a cost, which is why none of them was taken
quietly.
