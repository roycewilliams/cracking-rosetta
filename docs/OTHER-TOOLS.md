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

**Its real interest is the other direction.** 54 live entries carried no
usable vector at all on 2026-09-04, which means no tool mapping on them can
ever reach tier `vector`. A generator is exactly the instrument for that: give
it a plaintext and it produces the hash, where a cracker has to be handed
both. Nothing else in this repository's toolbox does that -- hashpipe
recomputes, but only to name a type for a pair it is already given.

Where a tool already publishes a worked example the gap closes without a
generator, and `tools/seed-vectors.pl` does exactly that: it adopts the
example and verifies it before storing it. That is how `skein-256`,
`skein-512` and `tiger` stopped being vectorless the same day. What a
generator would reach is the rest -- the rows no tool here publishes an
example for.

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

**The repository badge is MIT and the database is not.** Asked and answered on
2026-09-04 by reading haiti's own `docs/legal.md`, without reading
`data/prototypes.json` itself. haiti states that its prototype file is under
**mixed licensing**, and names the mix: permissive for the sample hashes taken
from hashcat and John the Ripper modules, MIT for the nodes its author wrote,
and **"GPL3 for untouched hashID nodes"**. It argues Fair Use for reusing parts
of hashID's file without relicensing haiti as a whole, and that argument is
about haiti, not about anyone copying from haiti.

So the question this repository had is closed: `data/prototypes.json` cannot
be vendored here and cannot be diffed against, because a published contract
that says "both the code and the data are MIT" cannot absorb a file whose own
author says parts of it are GPL-3. The 2026-08-30 clean-room decision about
hashID covers haiti too.

**One thing haiti says is worth keeping**, because it is an argument this
repository can make from a stronger position: "the mapping between Hashcat or
John the Ripper references and the hash type name comes from Hashcat and John
the Ripper modules anyway". Quite so. That mapping is not anyone's original
work -- it is a fact about the tools, and this repository gets it by running
them rather than by transcribing a third party. It is also why haiti being off
limits costs nothing but a cross-check.

And a caution for the queued regex work: haiti's author claims that
re-implementing a regexp without knowledge of hashID's would produce the same
one more than 90% of the time, since there is often a minimal form. That is
probably true and it is exactly why the clean-room record matters -- similarity
is expected and proves nothing either way, so what has to be defensible is the
DERIVATION, from this repository's own vectors, and not the resemblance.

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
* ~~haiti's data provenance being established as independent of hashID~~
  **Answered 2026-09-04, and the answer is no**: haiti's own `docs/legal.md`
  puts its prototype file under mixed licensing including "GPL3 for untouched
  hashID nodes". Nothing there can be vendored or diffed against here. The
  only thing that would reopen it is haiti relicensing that file outright.
* Somebody wanting a generator badly enough to accept a GPL-2.0 Go dependency
  for the vectorless rows that no tool here publishes an example for.

Each of those is a decision with a cost, which is why none of them was taken
quietly.
