# Crack

Alec Muffett's `Crack` - the password cracker that predates every other tool
in this repository. Included for historical reference only. Nothing here is
verified against it: it is not installed on the machine that builds this data,
and its capability is taken from its own manual rather than from a round-trip.

The newest thing quoted below is the v5.0 manual of December 1996. Treat any
version or date claim beyond what is quoted as unchecked - I have not tried to
establish a release history.

## What it could actually attack

Crack implements no hash of its own. It calls the host's `crypt(3)`, and picks
which implementation to build against by looking for a directory - `libdes`,
`ufc_crypt` or GNU `crypt` - and falling back to the system library. So its
capability is really the capability of a 1996 Unix `crypt(3)`, which is three
things.

From the v5.0 manual (Alec Muffett, December 1996):

* **descrypt** - traditional DES `crypt(3)`. The default, and the one it ships
  ready for: *"For traditional crypt() users, I ship with libdes."* The bundled
  libdes is Eric Young's, of SSLeay fame.

* **md5crypt** - the FreeBSD/NetBSD MD5-based `crypt()`: *"if you're using a
  MD5-based version of crypt(), you must first do ... `cp elcid.c,bsd
  elcid.c`"* before building.

* **crypt16** - Ultrix, OSF and Digital Unix: *"edit src/util/elcid.c to use
  crypt16() (change #undef to #define)"*. No algorithm in this repository
  names crypt16, so it appears nowhere in the table.

## What it could not

The manual is unambiguous, under the heading *Weird Password Systems (Novell,
Kerberos Tickets, LAN-Manager, VMS)*:

> Crack v5.0 does not (as distributed) support cracking these sorts of
> systems, although I am aware that versions of Crack v4.1f were modified to
> support one or more of the above.

Worth knowing if you go reading the source: circulating trees include
`src/util/elcid.c,lanman` and `elcid.c,nt`, plus `scripts/lanman2spf` and
`nt2spf`. Those belong to Elias Levy's `crack-nt` fork, not to stock Crack,
and crediting Crack with LM or NTLM support on the strength of finding them is
a mistake this file exists to prevent.

## Why it is frozen rather than tracked

Because Crack delegates to `crypt(3)`, building it on a modern glibc would
inherit sha256crypt, sha512crypt and possibly bcrypt, and the answer would
then depend on which machine you asked. That is useless as a historical
record. This records what the shipped release could do on the systems it
shipped for.

## Algorithms here that Crack could attack

| Algorithm | hashcat | mdxfind | How |
|---|---|---|---|
| descrypt($plain) | `1500` (v) | `DESCRYPT` (v) | core algorithm; Eric Young's libdes ships with Crack and is its default |
| md5(unix) | `500` (v) | `MD5CRYPT` (v) | via src/util/elcid.c,bsd - the FreeBSD/NetBSD MD5 crypt() |

Marked with (c) in [ROSETTA.md](ROSETTA.md). The underlying field is
`tools.crack.supported` in `data/algorithms/`, and it is carried in
`dist/rosetta.csv` and `dist/rosetta.json` for anyone consuming those.

## References

* Manual, source and license as distributed with Crack v5.0a
* [Elias Levy's crack-nt fork](https://github.com/eliaslevy/crack-nt) - the NT
  and LAN-Manager additions described above
