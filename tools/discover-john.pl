#!/usr/bin/perl
#-----------------------------------------------------------------------
#
# Name: discover-john.pl
# Description: find which john formats crack entries that carry no john mapping
# Category: cracking-rosetta verifier
#
# Project: cracking-rosetta | Phase: 6 - close the john gap
#
#-----------------------------------------------------------------------
# METHODOLOGY AND WHY THESE CHOICES
#
# THE PROBLEM
#
# 635 of 784 curated entries name no john format at all. They are not missing
# because john cannot do them -- john ships ~440 CPU formats plus 518 dynamics
# that dynamic_disabled.conf switches off -- they are missing because nobody
# has sat down and matched identifier to identifier. This is the same job
# hashpipe's john_map.h did upstream, and it did it the only way that can be
# trusted: by running the hash.
#
# --loadable: WHICH FORMATS COULD EVEN HAVE ANSWERED
#
# A sweep's silence means nothing until you know the question was asked, and
# absence.pl says so at length: for hashcat it asks `--identify`, which lists
# every mode whose parser accepts an input. john has no --identify, which is
# the whole reason absence.pl has never had a --tool john and why 802 entries
# carry a john block at tier `none` -- measured 2026-09-04, against 623
# entries where hashcat's silence has been MEASURED as absent.
#
# john has something better than --identify: its own loader. `--show=left`
# prints the hashes that LOADED and were not cracked, and each line carries
# the synthetic login this tool already puts in front of every hash. So one
# invocation per format names exactly the corpus lines that format's valid()
# accepted -- not a heuristic about lengths, the real parser answering about
# itself. Measured 2026-09-04 on a three-line file: Raw-MD5 returned only the
# 32-hex line, Raw-SHA1 only the 40-hex one, md5crypt only the $1$ one, and
# bcrypt returned nothing at all.
#
# Two details it cost a measurement to learn, both handled below:
#
#   * john echoes its CANONICAL encoding, not what it was handed -- a bare
#     digest comes back "$dynamic_0$..." -- which is the same reason
#     attribution here is by login and never by searching for the hash.
#   * LM SPLITS one hash into two halves and gives them logins "v0:1" and
#     "v0:2". A trailing ":N" is stripped, or the format reads as loading
#     nothing.
#
# It is cheap enough to be uninteresting: 0.056s to load a 2.6MB corpus, so
# the whole inventory is well under a minute. The expensive half of a john
# absence pass is the CRACKING sweep, which is the rest of this file.
#
# SEARCH DIRECTION: ONE JOB PER FORMAT, NOT PER ENTRY
#
# The naive shape is "for each entry, try every format", which is ~650 x ~960
# john invocations. Inverted, it is ~960 invocations total: for each format,
# hand john EVERY unmapped vector at once and let its own valid() throw out
# the lines that are not its shape. john then cracks whichever of the survivors
# it can, and the pot file says which. The filtering that would have cost us
# 600k process starts is work john was going to do anyway on load.
#
# WHY A CRACK IS PROOF AND NOT A COINCIDENCE
#
# If john, pinned to exactly one format, recovers entry E's recorded plaintext
# from entry E's recorded hash, then that format computes E's algorithm on that
# input. That is the definition of tier 'vector' in CLAUDE.md, arrived at the
# same way verify-vectors.pl arrives at it. Nothing here is inferred from a
# name, a length, or a resemblance.
#
# The batching cannot manufacture a match. Feeding entry A's password next to
# entry B's hash only matters if B's hash actually falls to it, and then the
# two entries share an algorithm, which is a finding rather than an error.
#
# MATCHING IS ON HASH AND PLAINTEXT TOGETHER
#
# Every vector imported from the sheet carries the plaintext "rosetta", so a
# batch feeds hundreds of different hashes sharing one password. Matching on
# the plaintext alone would credit all of them the moment john cracked any one
# -- the false positive verify-vectors.pl documents having actually hit. So a
# pot line counts only when it carries the entry's OWN hash and its OWN
# plaintext.
#
# ATTRIBUTION IS BY LOGIN, NOT BY SEARCHING THE POT
#
# john echoes its own canonical encoding, not what it was handed: a bare digest
# comes back "$dynamic_213$...", bcrypt's "$2y$" comes back "$2a$", a Cisco
# type 8 comes back "$pbkdf2-sha256$...". Searching the pot for the hash we
# submitted therefore misses cracks that really happened, and every rewrite
# john grows needs another special case.
#
# So each line carries a synthetic login and the run is followed by "--show",
# which prints that login beside the plaintext. The login is ours; it survives
# every canonicalization, and the special cases go away.
#
# TAB IS THE FIELD SEPARATOR, WHICH BUYS TWO THINGS
#
# john's input is login:hash, so a vector recorded as "hash:salt" -- the shape
# every mdxfind salted self-test vector has -- gets misparsed as login "hash".
# --field-separator-char=tab moves the separator out of the way of the data,
# and lets each line carry the entry id as its login field for free. john then
# also writes the POT with tabs, so the pot parses unambiguously into exactly
# two fields instead of being split on a character the hash may contain.
#
# DISABLED DYNAMICS ARE IN SCOPE
#
# 518 dynamics are switched off by dynamic_disabled.conf. john's own comment
# there says they still run when named explicitly with --format, which is what
# this script does, and they are the densest source of composite formats
# (md5(md5($p).$s) and friends) -- exactly what the unmapped entries are. The
# data must not depend on host config, so the inventory records them as
# disabled and this script simply tries them.
#
# WHAT DOES NOT GET APPLIED AUTOMATICALLY
#
# A hash can honestly fall to several identifiers: raw MD5 is Raw-MD5 and
# dynamic_0 both, and that is worth recording. But an entry matched by a large
# number of formats usually means the vector is degenerate rather than that the
# algorithm has many names, so --max-per-entry holds those back for a human
# instead of writing a wall of identifiers into the file. Likewise a format
# that suddenly claims a large share of the corpus is reported, not applied.
#
# A SALTED VECTOR IS ALSO OFFERED IN JOHN'S OWN SHAPE
#
# The corpus records a salted vector the way mdxfind reads it, "<hash>:<salt>".
# john's dynamic_1009 wants "$dynamic_1009$<hash>$<salt>" and its valid()
# discards the colon form before computing anything, so every salted composite
# -- most of what was left unmapped -- was invisible to this search.
#
# So for a dynamic, each two-field vector is additionally written in that
# format's own encoding. The rewrite is mechanical and adds no claim: if the
# algorithms do not match, john simply fails to crack it, exactly as before.
# What it buys is that the mapping is then proven on THE ENTRY'S OWN vector.
#
# That matters more than it sounds. The other direction -- identify-john.pl,
# which asks mdxfind to name john's test vectors -- reported dynamic_1011,
# md5($p.md5($s)), as a match for MD5PASSMD5, md5($p.md5($p)). It is not one:
# two of dynamic_1011's four test vectors happen to use the password as the
# salt, so the two algorithms agree on them. An entry's own vector does not
# have that property, and the rewrite here refuses the pairing.
#
# AN ENTRY WHOSE VECTORS DISAGREE IS A DATA DEFECT, NOT A MAPPING
#
# md5-md5-plain-salt-2 is named md5(md5($p).$s) and carries two vectors that
# share a salt. One falls to dynamic_6, md5(md5($p).$s); the other to
# dynamic_9, md5($s.md5($p)). Both cracks are real, and they cannot both be
# this entry's algorithm: the second vector belongs to a different entry and
# was collated onto this one.
#
# So the label set is computed per vector, and an entry whose cracked vectors
# do not agree on it is held for review rather than having the union written
# in. Writing the union would put two contradictory algorithms in one row --
# and it is the row a reader trusts to say what to run.
#
# THE CANARY: SOME FORMATS DO NOT COMPARE THE WHOLE DIGEST
#
# This is not hypothetical and it is not hashcat's problem alone. john's
# Raw-SHA1-Linkedin reads the LinkedIn leak, whose hashes have their leading
# nibbles zeroed, so it ignores hash positions 0-7 exactly as hashcat's -m 100
# does -- measured position by position on 2026-08-31. An earlier run of THIS
# script duly wrote it onto aich and sha1uc, and it had to be withdrawn by
# hand. Raw-SHA1 and dynamic_26 compare the whole digest, so it is per-format,
# not universal.
#
# So every format that scored a hit is now challenged before anything is
# written: take each hash it cracked and, for every hex position in it, offer
# one copy with that character changed. A format that compares the whole digest
# refuses all of them. A format that accepts one has just proved it ignores
# that position.
#
# The challenge iterates, and the reason is a property of every cracker's
# target list rather than of any one of them: john deduplicates the hashes it
# loads by what it actually compares, so all the mutants of an ignored field
# collapse and only one is ever reported. Each round drops the mutants that
# fell and re-runs the rest, converging in as many rounds as the widest ignored
# field is wide.
#
#
# THE MUTATION IS CONFINED TO A LEADING HEX RUN, AND THAT IS NOT FUSSINESS
#
# Measured 2026-09-01: challenging john's Raw-SHA1 reported that it "ignores"
# position 31 of netscape-ldap's {SHA}0ijZPTcJXMa+t2XnEbEwSOkvQu0=. It does
# not. That position is the last base64 character before the padding, and a
# SHA-1 digest is 160 bits where 27 base64 characters carry 162, so its bottom
# two bits encode nothing. Changing '0' to '1' there produces a DIFFERENT
# STRING that decodes to the SAME DIGEST, and the crack that follows is not
# evidence about the format at all.
#
# The canary's mutation is defined on text; the claim it makes is about a
# digest. Those coincide only where the text IS the digest. So only a leading
# run of hex characters at least 16 long is mutated -- which covers the bare
# digests and the "<digest>:<salt>" shapes the masked and truncated families
# use -- and a vector in any other encoding is left unchallenged and counted as
# such. An unmeasured format is reported as unmeasured; it is not guessed at in
# either direction.
#
# The cost of having got this wrong is one-directional: a bogus ignored
# position can only ever WITHHOLD a claim, never invent one. So verdicts
# recorded before this rule existed cost coverage, not correctness.
#
# WHAT THE CANARY LICENSES, AND WHAT IT DOES NOT
#
# A format that skips part of the digest has NOT been shown to be wrong. Under
# Raw-SHA1-Linkedin john still proved 128 of the 160 bits match, which an
# unrelated hash manages with probability 2^-128. A false mapping arises only
# when the corpus holds a hash DELIBERATELY related to a true digest, which is
# exactly what mdxfind's masked and truncated families are.
#
# So a claim is withheld only where the corpus itself realizes the ambiguity:
# two DIFFERENT hashes in it that the format cannot tell apart. Excluding every
# format that skips a word would throw away correct mappings in order to refuse
# one that is not. This is the same rule discover-hashcat.pl arrived at, and it
# is stated once here rather than cross-referenced because the two tools must
# not drift.
#
# --mirror-gpu does not run the canary, and that is deliberate rather than an
# omission. A mirror adds no algorithmic claim: the row already names the CPU
# format, and the GPU twin is the same format on another device. Withdrawing
# the GPU label while leaving the CPU one would leave the data saying something
# nobody believes.
#
# ONE FORMAT IS NEVER RECORDED: crypt
#
# john's "crypt" format is a wrapper around the host's crypt(3), so what it
# cracks is a property of this machine's libc rather than of john. It duly
# claimed bcrypt, sha1crypt, sha256crypt, sha512crypt and bsdicrypt here, all
# of which john also has native formats for. Recording it would put a mapping
# in the table that a reader on another host cannot reproduce, which is the
# same reason john.yaml keeps the disabled dynamics as data rather than
# depending on this host's dynamic_disabled.conf.
#
# --mirror-gpu: THE GPU COLUMN IS A NARROWER CLAIM AND GETS A NARROWER SEARCH
#
# john ships 113 -opencl/-ztex builds beside its CPU formats, and until now
# nothing populated tools.john.gpu, so 103 of john's 552 formats were counted
# against this repository as uncovered while being nothing more than the same
# formats on another device.
#
# They are NOT discovered the way a CPU format is. --mirror-gpu writes a GPU
# label onto an entry only when BOTH of these hold:
#
#   (a) the entry already names the CPU format the GPU label mirrors -- label
#       with '-opencl'/'-ztex' stripped, matched case-insensitively against the
#       inventory's own CPU labels; and
#   (b) the entry's own vector round-trips under the GPU label here.
#
# (b) alone is the ordinary standard and would be tempting, since it is a
# genuine round-trip. It is not enough. 22 hashcat modes and john's own
# Raw-SHA1-Linkedin do not compare the whole digest, so a crack under such a
# format is not by itself evidence about a truncated or masked entry, and the
# canary that measures this (discover-hashcat.pl) has not been ported here.
# Requiring (a) keeps the incremental claim to "the format this row already
# names also exists for the GPU", which inherits whatever scrutiny the CPU
# mapping already had rather than minting a new one.
#
# A GPU format with no CPU counterpart -- diskcryptor-aes-opencl, which is an
# AES-XTS-only build, KeePass-Argon2-opencl, ethereum-presale-opencl -- is
# therefore reported and never written. Those are curation: they may deserve
# their own entry, and that is a person's call.
#
# THE DEVICE DECIDES THE LIST, NOT THE CALLER
#
# tools.john.cpu and tools.john.gpu are separate lists and validate.pl rejects
# a label filed under the wrong one. So every applied label is routed by the
# inventory's own device field. Before this, --include-gpu --apply would have
# written opencl labels into cpu: a search that could only ever produce an
# invalid tree.
#
# FAILURE NEVER DEMOTES, AND NEITHER DOES SILENCE
#
# An entry no format cracks is left exactly as it was. It may be a format john
# lacks, a vector john wants wrapped differently (*2john.py output rather than
# a bare digest), or a wrong plaintext from the sheet. None of those are
# distinguishable here, so none of them are written down as a claim.
#
#-----------------------------------------------------------------------
# Generated by Claude Opus 5 on 2026-08-29

use strict;
use warnings;

use File::Basename qw(basename);
use File::Path qw(make_path);
use FindBin qw($RealBin);
use Getopt::Long qw(GetOptions);
use POSIX qw(strftime);
use Time::HiRes qw(time);
use YAML::XS ();

use lib "$RealBin/lib";
use RosettaEmit qw(emit_entry);
use RosettaTools qw(tool_path tool_env_help tool_version
                    share_measurable share_unmeasurable_reason);

my $PROG = basename($0);
my $ROOT = "$RealBin/..";

sub usage {
    print STDERR <<"END_USAGE";

Usage: $PROG [options]

   --john PATH       john binary (default: @{[tool_env_help('john')]})
   --algorithms DIR  curated entries  (default: data/algorithms)
   --inventory PATH  john inventory   (default: data/tools/john.yaml)
   --work DIR        scratch          (default: tmp/discover-john)
   --timeout SECS    per john run     (default: 60)
   --limit N         stop after N formats; for smoke tests
   --format REGEX    only formats whose label matches (repeatable)
   --only ID         only consider this entry
   --exclude ID      never write a mapping for this entry (repeatable); it is
                     still measured and reported, so the reason stays visible
   --all             target every entry with a vector, not just the unmapped
   --include-gpu     also try opencl/ztex formats
   --mirror-gpu      populate tools.john.gpu only: try each opencl/ztex format
                     against the entries that already name the CPU format it
                     mirrors. Implies --include-gpu --all --skip-disabled.
   --skip-disabled   do not try the dynamics disabled by dynamic_disabled.conf
   --no-canary       skip the whole-digest challenge (see the methodology
                     note; it only ever WITHDRAWS claims)
   --canary-rounds N how many refinement rounds the challenge may take
                     (default 12)
   --canary-span N   how far into a hash to mutate (default 512 characters)
   --max-per-entry N hold back entries matched by more than N formats
                     (default 6; they are reported, never written)
   --max-share PCT   hold back a format matching more than PCT% of the corpus
                     (default 20). The corpus is the TARGET set, so a narrow
                     run narrows the denominator: under --only it is one entry
                     and every format that matched scores 100%. The guard still
                     withholds, but reports the share as UNMEASURABLE rather
                     than calling the format over-broad.
   --loadable        do NOT crack: for each candidate format, record which
                     corpus lines its own valid() accepts, and write the
                     matrix to <work>/loadable.tsv for absence.pl --tool
                     john. Fast, and needs no GPU.
   --resume          reuse per-format results already in the work dir
   --apply           write the discovered mappings into data/algorithms
   -n, --dry-run     show the plan; run nothing, write nothing
   -v, --verbose     per-format result (repeatable)
   -h, --help        this help

   Without --apply nothing is written: the run reports what it found and the
   work dir keeps the evidence. Exit 0 success, 1 error, 2 usage.

END_USAGE
    return;
}

my ($john, $algdir, $inventory, $workdir, $only, $help, $dry, $apply);
my ($all, $include_gpu, $skip_disabled, $resume, $mirror_gpu);
my @fmt_re;
my @exclude;
my $timeout       = 60;
my $limit         = 0;
my $verbose       = 0;
my $had_args      = scalar @ARGV;   # house rule: no arguments means show usage
my $max_per_entry = 6;
my $max_share     = 20;
my $canary_rounds = 12;
my $canary_span   = 512;
my $no_canary;
my $loadable;

GetOptions(
    'john=s'          => \$john,
    'algorithms=s'    => \$algdir,
    'inventory=s'     => \$inventory,
    'work=s'          => \$workdir,
    'timeout=i'       => \$timeout,
    'limit=i'         => \$limit,
    'format=s'        => \@fmt_re,
    'only=s'          => \$only,
    'exclude=s'       => \@exclude,
    'all'             => \$all,
    'include-gpu'     => \$include_gpu,
    'mirror-gpu'      => \$mirror_gpu,
    'skip-disabled'   => \$skip_disabled,
    'no-canary'       => \$no_canary,
    'canary-rounds=i' => \$canary_rounds,
    'canary-span=i'   => \$canary_span,
    'max-per-entry=i' => \$max_per_entry,
    'max-share=i'     => \$max_share,
    'loadable'        => \$loadable,
    'resume'          => \$resume,
    'apply'           => \$apply,
    'n|dry-run'       => \$dry,
    'v|verbose+'      => \$verbose,
    'h|help'          => \$help,
) or do { usage(); exit 2 };

if ($help) { usage(); exit 0 }
# --mirror-gpu is a narrower search wearing the same machinery: GPU builds only,
# against entries chosen by what they already name rather than by what they lack.
if ($mirror_gpu) { $include_gpu = $all = $skip_disabled = 1 }
# No arguments at all: show usage rather than silently starting an hour of work.
if (!$had_args) { usage(); exit 2 }

$john = tool_path('john', $john);
$algdir    //= "$ROOT/data/algorithms";
$inventory //= "$ROOT/data/tools/john.yaml";
$workdir   //= "$ROOT/tmp/discover-john";

# john is run from its own run/ directory -- it resolves john.conf against the
# cwd -- so a RELATIVE --work would be resolved there, where this user cannot
# write, and every pot file would silently fail to appear. That happened
# 2026-08-31: 957 formats "ran" in 35s and found nothing. Make it absolute
# once, here.
$workdir = "$ROOT/$workdir" unless $workdir =~ m{^/};

make_path($workdir) unless -d $workdir;
my $today = strftime('%Y-%m-%d', localtime);

#-----------------------------------------------------------------------
# Inventory: the candidate identifiers.

my $inv = eval { YAML::XS::LoadFile($inventory) }
    or do { print STDERR "$PROG: cannot load $inventory: $@\n"; exit 1 };

# The version of the binary that will actually RUN, not the one the
# inventory was generated from. Those coincided until 2026-09-05, when
# data/tools/mdxfind.yaml went to RCS 1.576 against an installed RCS 1.545 and
# the sibling tool would have credited the wrong build with every claim. The
# inventory is the fallback and it is marked as one.
my $john_version = RosettaTools::tool_version('john', $john);
if (!defined $john_version) {
    $john_version = ($inv->{version} // 'unknown') . ' (per the inventory; the '
                  . 'binary would not state a version)';
}
elsif (($inv->{version} // '') ne $john_version) {
    printf STDERR "- NOTE: john binary reports %s; the inventory was built "
                . "from %s. verified_with records the binary.\n",
                $john_version, $inv->{version} // '(unset)';
}

# The device of every label, so an applied mapping is filed under the list
# validate.pl expects instead of under the one the caller happened to be in.
my %device = map { $_->{label} => ($_->{device} // 'cpu') } @{ $inv->{formats} || [] };
$device{$_} //= 'cpu' for @{ $inv->{disabled_dynamic} || [] };

# gpu label -> the CPU label it mirrors. The join is the label with the device
# suffix stripped, matched case-insensitively because john spells the pair
# inconsistently: Raw-MD5 has raw-MD5-opencl, xsha512 has XSHA512-opencl.
my %cpu_by_lc = map  { lc($_) => $_ }
                grep { $device{$_} eq 'cpu' } keys %device;
my %mirrors;
for my $l (grep { $device{$_} ne 'cpu' } keys %device) {
    (my $base = $l) =~ s/-(?:opencl|ztex)$//;
    my $cpu = $cpu_by_lc{ lc $base } or next;
    $mirrors{$l} = $cpu;
}

my @candidates;
for my $f (@{ $inv->{formats} || [] }) {
    my $dev = $f->{device} // 'cpu';
    next if $dev ne 'cpu' && !$include_gpu;
    next if $mirror_gpu && ($dev eq 'cpu' || !$mirrors{ $f->{label} });
    push @candidates, $f->{label};
}
push @candidates, @{ $inv->{disabled_dynamic} || [] } unless $skip_disabled;

# The GPU builds with no CPU counterpart are not failures and not candidates;
# say so once, because "103 of 113" otherwise looks like something went wrong.
if ($mirror_gpu) {
    my @orphan = sort grep { $device{$_} ne 'cpu' && !$mirrors{$_} } keys %device;
    printf STDERR "- %d GPU build(s) mirror a CPU format; %d have none and are "
                . "left for curation: %s\n",
        scalar(keys %mirrors), scalar @orphan, join(' ', @orphan) if @orphan;
}

if (@fmt_re) {
    my @re = map { qr/$_/i } @fmt_re;
    @candidates = grep { my $l = $_; grep { $l =~ $_ } @re } @candidates;
}

# Deterministic order, so --limit takes a reproducible prefix.
my %seen_fmt;
@candidates = grep { !$seen_fmt{$_}++ } sort @candidates;

#-----------------------------------------------------------------------
# Entries. A target needs a vector; by default it also needs to be missing a
# proven john mapping, since re-proving what verify-vectors.pl already proved
# costs the same time and tells us nothing.

opendir(my $dh, $algdir) or do { print STDERR "$PROG: cannot read $algdir: $!\n"; exit 1 };
my @files = sort grep { /\.yaml$/ } readdir $dh;
closedir $dh;

my (%entry, %path);
for my $f (@files) {
    my $p = "$algdir/$f";
    my $e = eval { YAML::XS::LoadFile($p) };
    next unless $e && $e->{id};
    next if defined $only && $e->{id} ne $only;
    $entry{ $e->{id} } = $e;
    $path{  $e->{id} } = $p;
}

# In mirror mode: entry id -> gpu label -> 1, for every gpu build whose CPU
# format this entry ALREADY names. Nothing outside this map may be written; see
# the methodology note on why (b) alone is not the standard here.
my %wants;
if ($mirror_gpu) {
    my %entries_of;                      # lc cpu label -> [ entry ids ]
    for my $id (keys %entry) {
        push @{ $entries_of{ lc $_ } }, $id
            for @{ $entry{$id}{tools}{john}{cpu} || [] };
    }
    for my $g (sort keys %mirrors) {
        $wants{$_}{$g} = 1 for @{ $entries_of{ lc $mirrors{$g} } || [] };
    }
}

my @vectors;   # { id, hash, pass }
my %targets;
for my $id (sort keys %entry) {
    my $e = $entry{$id};
    next if $mirror_gpu && !$wants{$id};
    unless ($all) {
        my $j = $e->{tools}{john};
        next if $j && ($j->{verified} // '') eq 'vector';
    }
    for my $v (@{ $e->{vectors} || [] }) {
        next unless defined $v->{hash} && defined $v->{pass};
        next if $v->{hash} =~ /\t/ || $v->{pass} =~ /\t/;   # would break the field split
        push @vectors, { id => $id, hash => $v->{hash}, pass => $v->{pass},
                         vid => "$id\0" . scalar(@vectors) };
        $targets{$id} = 1;
    }
}

if (!@vectors) {
    print STDERR "$PROG: nothing to do -- no target entry carries a vector.\n";
    exit 0;
}

printf STDERR "- %d format(s) x %d vector(s) from %d entry/entries\n",
    scalar @candidates, scalar @vectors, scalar keys %targets;

#-----------------------------------------------------------------------
# Helpers.

# write_matrix($path, $header, \%by_label, \%hash_of) - a (format, vector)
# matrix, one pair per line: format, entry id, and the vector's HASH.
#
# Not the vid. Internally that is "$id\0<n>" where n is a GLOBAL sequence
# number, so it identifies a vector only within one run and resolves to
# nothing a reader or a later tool can look up. The hash is what absence.pl
# needs anyway: a crack credited to a SIBLING row carrying the same hash
# under a different plaintext is the trap that would otherwise publish as
# this row's absence, and only the hash makes that visible.
sub write_matrix {
    my ($path, $header, $by_label, $hash_of) = @_;
    open my $mf, '>', $path or die "$PROG: cannot write $path: $!\n";
    print {$mf} $header;
    my $pairs = 0;
    for my $label (sort keys %$by_label) {
        for my $vid (sort keys %{ $by_label->{$label} }) {
            my ($id) = split /\0/, $vid, 2;
            printf {$mf} "%s\t%s\t%s\n", $label, $id, $hash_of->{$vid} // '';
            $pairs++;
        }
    }
    close $mf or die "$PROG: cannot close $path: $!\n";
    return $pairs;
}

sub write_file {
    my ($p, @lines) = @_;
    open my $fh, '>', $p or die "cannot write $p: $!\n";
    print {$fh} "$_\n" for @lines;
    close $fh;
    return $p;
}

# run_capture($timeout, @argv) - run without a shell, return (exit, output).
# Nothing derived from a hash ever reaches a shell metacharacter this way.
sub run_capture {
    my ($secs, @argv) = @_;
    my $out = '';
    my $pid = open(my $fh, '-|');
    defined $pid or return (-1, '');
    if (!$pid) {
        open STDERR, '>&', \*STDOUT;
        exec { $argv[0] } @argv or exit 127;
    }
    my $killed = 0;
    eval {
        local $SIG{ALRM} = sub { $killed = 1; kill 'KILL', $pid; die "timeout\n" };
        alarm $secs;
        local $/;
        $out = <$fh> // '';
        alarm 0;
    };
    alarm 0;
    close $fh;
    return ($killed ? -2 : ($? >> 8), $out);
}

#-----------------------------------------------------------------------
# The corpus is identical for every format, so it is written once. john reads
# the hash file as "<id>TAB<hash>"; the id is only along for the ride, but it
# makes john's own progress output readable while a long run is going.

my $wordfile = "$workdir/corpus.word";

my %uniq_word;
my @words = grep { !$uniq_word{$_}++ } map { $_->{pass} } @vectors;

write_file($wordfile, @words);

#-----------------------------------------------------------------------
# One john run per format.

my $jdir = $john; $jdir =~ s{/[^/]+$}{};
my $jbin = basename($john);
die "$PROG: john not executable at $john\n" unless -x $john;

my %hits;          # entry id -> format -> 1
my %loads;         # --loadable: format -> vector id -> 1, which lines
                   # that format's own valid() accepted
my %hash_of_vid;   # vector id -> the hash, for the evidence matrices
$hash_of_vid{ $_->{vid} } = $_->{hash} for @vectors;
my %per_fmt;       # format -> vector id -> 1, the transpose of %per_vector
                   # and what the evidence file is written from
my %per_vector;    # vector id -> format -> 1, so an entry whose vectors
                   # disagree can be spotted rather than merged
my %fmt_hits;      # format -> count of entries
my (%timed_out, %ran);
my $started = time;
my $n = 0;

FORMAT: for my $label (@candidates) {
    last if $limit && $n >= $limit;
    $n++;

    if ($dry) {
        print STDERR "-   would run --format=$label\n" if $verbose;
        next;
    }

    (my $safe = $label) =~ s/[^A-Za-z0-9]/_/g;
    my $pot  = "$workdir/pot/$safe.pot";
    make_path("$workdir/pot") unless -d "$workdir/pot";

    # A dynamic gets the salted vectors rewritten into its own encoding as
    # well; both lines carry the same login, so a crack of either credits the
    # vector. See the methodology note on attribution.
    my (@lines, %login_of);
    my $seq = 0;
    for my $v (@vectors) {
        my $login = 'v' . $seq++;
        $login_of{$login} = $v;
        push @lines, "$login\t$v->{hash}";
        next unless $label =~ /^dynamic_\d+$/;
        my ($h, $salt) = split /:/, $v->{hash}, 2;
        push @lines, "$login\t\$$label\$$h\$$salt"
            if defined $salt && length $salt && $salt !~ /:/;
    }
    my $hf = write_file("$workdir/hash.$safe", @lines);

    # --loadable asks john's LOADER what it accepts and stops there. No
    # cracking, no wordlist, no session: --show is incompatible with
    # --session, which is an "Invalid options combination", not a warning.
    if ($loadable) {
        # A SCRATCH pot, deliberately not $pot. --show still wants one, and
        # writing an empty file into pot/ would make a later --resume crack
        # run read `-e $pot` as "this format ran and cracked nothing".
        my $lpot = "$workdir/loadable.pot";
        unlink $lpot;
        my (undef, $left) = run_capture($timeout, '/bin/sh', '-c',
            sprintf('cd %s && exec ./%s --format=%s --field-separator-char=tab '
                  . '--pot=%s --show=left %s 2>/dev/null',
                    quotemeta($jdir), quotemeta($jbin), quotemeta($label),
                    quotemeta($lpot), quotemeta($hf)));
        my $accepted = 0;
        for my $line (split /\n/, $left // '') {
            my ($login) = split /\t/, $line, 2;
            next unless defined $login;
            # LM splits a hash into halves and suffixes the login ":1"/":2".
            $login =~ s/:\d+$//;
            my $v = $login_of{$login} or next;
            next if $loads{$label}{ $v->{vid} }++;
            $accepted++;
        }
        printf STDERR "-   [%4d/%4d] %-28s %4d line(s) load\n",
            $n, scalar @candidates, $label, $accepted
            if $verbose && ($accepted || $verbose > 1);
        next FORMAT;
    }

    my $code = 0;
    if ($resume && -e $pot) {
        # Evidence from an earlier run; re-read it rather than re-cracking.
    }
    else {
        unlink $pot;
        ($code, undef) = run_capture($timeout, '/bin/sh', '-c',
            sprintf('cd %s && exec ./%s --format=%s --field-separator-char=tab '
                  . '--wordlist=%s --pot=%s --session=%s %s >/dev/null 2>&1',
                    quotemeta($jdir), quotemeta($jbin), quotemeta($label),
                    quotemeta($wordfile), quotemeta($pot),
                    quotemeta("$workdir/s.$safe"), quotemeta($hf)));
        $timed_out{$label} = 1 if $code == -2;
    }
    $ran{$label} = 1;

    my $found = 0;
    if (-s $pot) {
        my (undef, $shown) = run_capture($timeout, '/bin/sh', '-c',
            sprintf('cd %s && exec ./%s --show --format=%s '
                  . '--field-separator-char=tab --pot=%s %s 2>/dev/null',
                    quotemeta($jdir), quotemeta($jbin), quotemeta($label),
                    quotemeta($pot), quotemeta($hf)));
        my %won;
        for my $line (split /\n/, $shown // '') {
            my ($login, $pw) = split /\t/, $line, 2;
            next unless defined $login && defined $pw;
            my $v = $login_of{$login} or next;
            next unless $pw eq $v->{pass};
            $won{"$v->{hash}\0$v->{pass}"} = 1;
        }
        # A hash john deduplicated on load is shown once, so the crack is
        # spread to every vector carrying the same hash and plaintext.
        for my $v (@vectors) {
            next unless $won{"$v->{hash}\0$v->{pass}"};
            $per_vector{ $v->{vid} }{$label} = 1;
            $per_fmt{$label}{ $v->{vid} }  = 1;
            next if $hits{ $v->{id} }{$label}++;
            $found++;
        }
    }
    $fmt_hits{$label} = $found if $found;

    printf STDERR "-   [%4d/%4d] %-28s %3d hit(s)%s\n",
        $n, scalar @candidates, $label, $found,
        ($timed_out{$label} ? ' [TIMEOUT]' : '')
        if $verbose && ($found || $verbose > 1);
}

my $elapsed = time - $started;

#-----------------------------------------------------------------------
# The evidence files. absence.pl --tool john reads these three and nothing
# else, because they are the only record of what the sweep actually did:
#
#   hits.tsv   the ATTRIBUTED cracks. A pot line cannot be attributed after
#              the fact -- john echoes its canonical encoding, so the pot
#              never holds the hash that was submitted -- so the attribution
#              is written here by the run that performed it.
#   ran        every format the sweep actually asked. A format absent from
#              this file was never tried, which is not the same as one that
#              tried and found nothing, and only this file tells them apart.
#   timeouts   the formats killed at --timeout. Their pot exists and looks
#              like a completed run that cracked little, so absence.pl
#              treats anything listed here as never run.

unless ($dry || $loadable) {   # --loadable measures the LOADER, not the sweep:
                                 # writing an empty hits.tsv beside a real
                                 # loadable.tsv is a trap, not a record
    my $stamp = sprintf(
          "# GENERATED by tools/discover-john.pl -- %s\n"
        . "# john %s\n"
        . "# %d format(s) run over %d vector(s) from %d entry/entries in %.1fs\n",
            strftime('%Y-%m-%d', localtime), $john_version,
            scalar(keys %ran), scalar @vectors, scalar(keys %targets), $elapsed);

    my $npairs = write_matrix("$workdir/hits.tsv",
        $stamp . "# format\tentry id\thash"
               . "  -- this format reproduced this vector\n",
        \%per_fmt, \%hash_of_vid);

    open my $rf, '>', "$workdir/ran" or die "$PROG: cannot write ran: $!\n";
    print {$rf} $stamp, "# one format label per line: the sweep asked it\n";
    print {$rf} "$_\n" for sort keys %ran;
    close $rf or die "$PROG: cannot close ran: $!\n";

    open my $tf, '>', "$workdir/timeouts" or die "$PROG: cannot write timeouts: $!\n";
    print {$tf} $stamp, "# one format label per line: killed at --timeout,\n"
              . "# so its silence is not a measurement\n";
    print {$tf} "$_\n" for sort keys %timed_out;
    close $tf or die "$PROG: cannot close timeouts: $!\n";

    printf STDERR "- evidence: %d attributed hit(s), %d format(s) run, "
                . "%d timed out\n", $npairs, scalar(keys %ran),
                  scalar(keys %timed_out);
}

#-----------------------------------------------------------------------
# --loadable stops here: it has measured what each format can READ, which is
# a different question from what it can crack, and it must never write a
# mapping. The file is the john half of what <work>/identify.tsv is for
# hashcat, and absence.pl --tool john refuses to run without it.

if ($loadable) {
    my $path  = "$workdir/loadable.tsv";
    my $fmts  = scalar keys %loads;
    my $pairs = write_matrix($path, sprintf(
          "# GENERATED by tools/discover-john.pl --loadable -- %s\n"
        . "# john %s\n"
        . "# %d format(s) asked, %d vector(s) offered\n"
        . "# format\tentry id\thash"
        . "  -- a line this format's own valid() accepted\n",
            strftime('%Y-%m-%d', localtime), $john_version,
            scalar @candidates, scalar @vectors), \%loads, \%hash_of_vid);
    printf STDERR "- %d format(s) accepted at least one line; %d (format, "
                . "vector) pair(s) in %.1fs\n", $fmts, $pairs, $elapsed;
    printf STDERR "- wrote %s\n", $path;
    # A format that accepted nothing is not an error: bcrypt reads no bare
    # digest. A run where NOTHING accepted anything is, because that is what
    # a broken corpus or a wrong john path looks like.
    if (!$pairs) {
        print STDERR "$PROG: no format accepted any line -- that is not a "
                   . "measurement, it is a broken run\n";
        exit 1;
    }
    exit 0;
}

#-----------------------------------------------------------------------
# The canary. Challenge every format that scored a hit with digests differing
# from the ones it cracked by exactly one hex character; see the methodology
# note. --mirror-gpu skips it, also per that note.

my %vec_of    = map { $_->{vid}     => $_ } @vectors;
my %uniq_hash = map { lc $_->{hash} => 1 } @vectors;
my %ignored_pos;     # format label -> { position => 1 }
my %unmeasured;      # format label -> vectors whose encoding cannot be mutated

# The challenge costs far more than replaying the cracks it is challenging, so
# its verdict is written beside the pot files and reused by --resume like any
# other evidence in the work dir. Delete canary.positions to re-measure, which
# is what a new john release calls for: it is a property of the formats.
my $canary_cache = "$workdir/canary.positions";
if ($resume && -s $canary_cache && open my $cfh, '<', $canary_cache) {
    while (my $line = <$cfh>) {
        chomp $line;
        my ($label, @pos) = split /\s+/, $line;
        next unless defined $label && @pos;
        $ignored_pos{$label}{$_} = 1 for @pos;
    }
    close $cfh;
    printf STDERR "- canary: %d format(s) read from %s\n",
        scalar keys %ignored_pos, $canary_cache;
}
elsif (!$dry && !$no_canary && !$mirror_gpu && %fmt_hits) {
    my $canary_started = time;
    my $rounds_total   = 0;

    for my $label (sort keys %fmt_hits) {
        (my $safe = $label) =~ s/[^A-Za-z0-9]/_/g;

        # Every (hash, plaintext) this format was credited with.
        my %credited;
        for my $vid (keys %per_vector) {
            next unless $per_vector{$vid}{$label};
            my $v = $vec_of{$vid} or next;
            $credited{ $v->{hash} . "\0" . $v->{pass} } = $v;
        }
        next unless %credited;

        my (%mutant_pos, @pending, %words);
        my $unmeasurable = 0;
        for my $v (values %credited) {
            $words{ $v->{pass} } = 1;
            my $h = $v->{hash};
            # Only the leading hex run, and only if it is long enough to BE a
            # digest; see the methodology note on base64 padding bits.
            my ($hex) = $h =~ /^([0-9a-fA-F]{16,})/;
            unless (defined $hex) { $unmeasurable++; next }
            my $max = length($hex) < $canary_span ? length($hex) : $canary_span;
            for my $i (0 .. $max - 1) {
                my $c = substr($h, $i, 1);
                my $m = $h;
                # Any different hex digit will do; '0' unless it already is.
                substr($m, $i, 1) = ($c eq '0') ? '1' : '0';
                next if $uniq_hash{ lc $m };     # a real corpus hash, not a mutant
                next if exists $mutant_pos{ lc $m };
                $mutant_pos{ lc $m } = $i;
                push @pending, $m;
            }
        }
        $unmeasured{$label} = $unmeasurable if $unmeasurable;
        next unless @pending;

        my $mw = write_file("$workdir/canary.$safe.word", sort keys %words);

        for my $round (1 .. $canary_rounds) {
            last unless @pending;
            $rounds_total++;

            # Same shape the search itself used, including the dynamic rewrite:
            # a mapping proven only in john's own encoding must be challenged
            # in that encoding too, or the canary is silent exactly where it
            # was needed.
            my (@lines, %mutant_of);
            my $seq = 0;
            for my $m (@pending) {
                my $login = 'c' . $seq++;
                $mutant_of{$login} = $m;
                push @lines, "$login\t$m";
                next unless $label =~ /^dynamic_\d+$/;
                my ($h, $salt) = split /:/, $m, 2;
                push @lines, "$login\t\$$label\$$h\$$salt"
                    if defined $salt && length $salt && $salt !~ /:/;
            }
            my $mf = write_file("$workdir/canary.$safe.hash", @lines);
            my $mp = "$workdir/pot/canary.$safe.pot";
            unlink $mp;

            run_capture($timeout, '/bin/sh', '-c',
                sprintf('cd %s && exec ./%s --format=%s --field-separator-char=tab '
                      . '--wordlist=%s --pot=%s --session=%s %s >/dev/null 2>&1',
                        quotemeta($jdir), quotemeta($jbin), quotemeta($label),
                        quotemeta($mw), quotemeta($mp),
                        quotemeta("$workdir/c.$safe"), quotemeta($mf)));
            last unless -s $mp;

            my (undef, $shown) = run_capture($timeout, '/bin/sh', '-c',
                sprintf('cd %s && exec ./%s --show --format=%s '
                      . '--field-separator-char=tab --pot=%s %s 2>/dev/null',
                        quotemeta($jdir), quotemeta($jbin), quotemeta($label),
                        quotemeta($mp), quotemeta($mf)));

            my %fell;
            for my $line (split /\n/, $shown // '') {
                my ($login, $pw) = split /\t/, $line, 2;
                next unless defined $login && defined $pw && $words{$pw};
                my $m   = $mutant_of{$login} or next;
                my $pos = $mutant_pos{ lc $m };
                next unless defined $pos;
                $ignored_pos{$label}{$pos} = 1;
                $fell{ lc $m } = 1;
            }
            last unless %fell;
            @pending = grep { !$fell{ lc $_ } } @pending;
        }
    }

    printf STDERR "- canary: challenged %d format(s) in %d round(s), %.1fs; "
                . "%d do not compare the whole digest\n",
        scalar keys %fmt_hits, $rounds_total, time - $canary_started,
        scalar keys %ignored_pos;
    printf STDERR "-   %d format(s) had cracked vector(s) in an encoding this "
                . "cannot safely mutate\n-   and are reported unmeasured rather "
                . "than clean: %s\n", scalar keys %unmeasured,
        join(' ', map { "$_=$unmeasured{$_}" } sort keys %unmeasured)
        if %unmeasured;
    if (open my $cfh, '>', $canary_cache) {
        print {$cfh} join(' ', $_, sort { $a <=> $b } keys %{ $ignored_pos{$_} }), "\n"
            for sort keys %ignored_pos;
        close $cfh;
    }
}

# range_summary(@positions) - "0-7,32" rather than a wall of numbers.
sub range_summary {
    my @p = sort { $a <=> $b } @_;
    my @runs;
    for (my $i = 0; $i <= $#p; ) {
        my $j = $i;
        $j++ while $j < $#p && $p[$j + 1] == $p[$j] + 1;
        push @runs, $i == $j ? $p[$i] : "$p[$i]-$p[$j]";
        $i = $j + 1;
    }
    return join ',', @runs;
}

# Where the corpus itself realizes the ambiguity: two DIFFERENT hashes this
# format cannot tell apart. Only there is a claim withheld.
my %ambiguous;    # "label\0id" -> the other ids the format cannot distinguish
for my $label (keys %ignored_pos) {
    my @pos = keys %{ $ignored_pos{$label} };
    my %group;
    for my $v (@vectors) {
        my $k = lc $v->{hash};
        substr($k, $_, 1) = '.' for grep { $_ < length $k } @pos;
        # Keyed by the masked hash so two entries carrying the SAME hash are
        # not ambiguity; valued by every id carrying it, so neither is lost
        # when they do collide with a third.
        $group{$k}{ lc $v->{hash} }{ $v->{id} } = 1;
    }
    for my $k (keys %group) {
        next if keys %{ $group{$k} } < 2;
        my @ids = sort keys %{ { map { %$_ } values %{ $group{$k} } } };
        for my $id (@ids) {
            $ambiguous{"$label\0$id"} = join ' ', grep { $_ ne $id } @ids;
        }
    }
}

#-----------------------------------------------------------------------
# Decide what may be written. Two guards, both about not letting one
# degenerate vector or one over-permissive format spray identifiers around.

my $corpus = scalar keys %targets;
my %noisy_fmt = map { $_ => 1 }
                grep { $fmt_hits{$_} * 100 > $max_share * $corpus }
                keys %fmt_hits;

# Whether a share verdict on this corpus says anything about the FORMAT. Under
# --only the corpus is one entry, so every format that matched scores 100% and
# the guard has measured its own denominator; see RosettaTools. The guard still
# withholds -- withholding is safe -- but it must not report what it did not
# establish.
my $share_ok = share_measurable($corpus, $max_share);

my %excluded = map { $_ => 1 } @exclude;

# See the methodology note: what "crypt" cracks is a fact about this host's
# libc, not about john.
my %host_dependent = map { $_ => 1 } qw(crypt crypt-opencl);

my (@apply_list, @held);
for my $id (sort keys %hits) {
    my @f = sort keys %{ $hits{$id} };
    my @clean = grep { !$noisy_fmt{$_} && !$host_dependent{$_}
                       && !$ambiguous{"$_\0$id"} } @f;
    my @amb   = grep { $ambiguous{"$_\0$id"} } @f;

    # A GPU build that cracked this entry's vector without being the twin of a
    # format the entry already names is a discovery, not a mirror. It is
    # reported so it is not lost, and never written: see the methodology note.
    if ($mirror_gpu) {
        my @stray = grep { !$wants{$id}{$_} } @clean;
        @clean = grep { $wants{$id}{$_} } @clean;
        push @held, [$id, \@stray, 'cracked but mirrors no CPU format this '
                                 . 'entry names'] if @stray;
    }

    # Every vector of this entry that cracked at all must have cracked under
    # the same formats; see the methodology note.
    my @sets = map  { join ' ', sort grep { !$noisy_fmt{$_} && !$host_dependent{$_}
                                            && (!$mirror_gpu || $wants{$id}{$_}) }
                                     keys %{ $per_vector{$_} } }
               grep { %{ $per_vector{$_} } }
               grep { (split /\0/)[0] eq $id } keys %per_vector;
    my %distinct = map { $_ => 1 } grep { length } @sets;

    if (keys %distinct > 1) {
        push @held, [$id, \@clean,
                     'this entry\'s vectors disagree: ' .
                     join(' | ', sort keys %distinct)];
    }
    elsif ($excluded{$id}) {
        push @held, [$id, \@f, 'named in --exclude'];
    }
    elsif (!@clean && @amb) {
        push @held, [$id, \@amb, join('; ', map {
            sprintf('%s skips hash position(s) %s and so cannot tell this row '
                  . 'from %s', $_, range_summary(keys %{ $ignored_pos{$_} }),
                    $ambiguous{"$_\0$id"}) } @amb)];
    }
    elsif (!@clean) {
        # In mirror mode the stray hits were already reported above with the
        # reason that actually applies; do not report them again as over-broad.
        push @held, [$id, \@f, $share_ok
                       ? 'every matching format is over-broad'
                       : share_unmeasurable_reason('format', $corpus, $max_share)]
            unless $mirror_gpu;
    }
    elsif (@clean > $max_per_entry) {
        push @held, [$id, \@clean, sprintf('%d formats > --max-per-entry %d',
                                           scalar @clean, $max_per_entry)];
    }
    else {
        push @apply_list, [$id, \@clean];
    }
}

#-----------------------------------------------------------------------
# Report. Data on stdout so it can be redirected into a review file; progress
# and counts on stderr per the house convention.

for my $r (@apply_list) {
    my ($id, $f) = @$r;
    printf "%-40s %s\n", $id, join(' ', @$f);
}
if (@held) {
    print "\n# held back for review\n";
    for my $r (@held) {
        my ($id, $f, $why) = @$r;
        printf "# %-38s %s  (%s)\n", $id, join(' ', @$f), $why;
    }
}

printf STDERR "- ran %d format(s) in %.1fs%s\n", $n, $elapsed,
    ($dry ? ' (dry run)' : '');
printf STDERR "-   entries matched %d of %d target(s); applicable %d, held %d\n",
    scalar(keys %hits), $corpus, scalar @apply_list, scalar @held;
if (%noisy_fmt && $share_ok) {
    printf STDERR "-   %d over-broad format(s) ignored (> %d%% of the corpus): %s\n",
        scalar keys %noisy_fmt, $max_share,
        join(' ', map { "$_=$fmt_hits{$_}" } sort keys %noisy_fmt);
}
elsif (%noisy_fmt) {
    printf STDERR "-   %d format(s) held, share UNMEASURABLE: the corpus is %d "
                . "%s, so a\n-   single hit is %g%% and trips --max-share %d by "
                . "itself. That is a fact\n-   about this run, not about the "
                . "format -- re-run against the whole corpus\n-   (--all, without "
                . "--only) to measure it: %s\n",
        scalar keys %noisy_fmt, $corpus, ($corpus == 1 ? 'entry' : 'entries'),
        ($corpus ? 100 / $corpus : 100), $max_share,
        join(' ', map { "$_=$fmt_hits{$_}" } sort keys %noisy_fmt);
}
if (%timed_out) {
    printf STDERR "-   %d format(s) hit the %ds timeout: %s\n",
        scalar keys %timed_out, $timeout, join(' ', sort keys %timed_out);
}
if (%ignored_pos) {
    printf STDERR "-   %d format(s) do not compare the whole digest. That is not "
                . "by itself\n-   a wrong mapping -- see the methodology note -- "
                . "but a claim is withheld\n-   wherever the corpus holds two "
                . "hashes the format cannot tell apart:\n", scalar keys %ignored_pos;
    printf STDERR "-     %-28s skips hash position(s) %s\n",
        $_, range_summary(keys %{ $ignored_pos{$_} })
        for sort keys %ignored_pos;
    my %amb_ids = map { (split /\0/)[1] => 1 } keys %ambiguous;
    printf STDERR "-     %d entry/entries are affected: %s\n",
        scalar keys %amb_ids, join(' ', sort keys %amb_ids) if %amb_ids;
}

#-----------------------------------------------------------------------
# Apply. A discovered mapping is tier 'vector' because it was round-tripped
# here; the note records that a machine found it rather than a human.

if ($apply && !$dry) {
    my $changed = 0;
    for my $r (@apply_list) {
        my ($id, $f) = @$r;
        my $e = $entry{$id} or next;
        my $blk = $e->{tools}{john} ||= {};

        # Keep identifiers a human already recorded even if this run did not
        # reach or prove them; dropping them would be a silent demotion. Each
        # label goes to the list its DEVICE says it belongs in -- validate.pl
        # rejects an opencl build filed under cpu, and the caller does not get
        # to decide which it was.
        for my $key (qw(cpu gpu)) {
            my @mine = grep { ($key eq 'gpu') == ($device{$_} ne 'cpu') } @$f;
            next unless @mine || @{ $blk->{$key} || [] };
            my %set = map { $_ => 1 } @{ $blk->{$key} || [] }, @mine;
            $blk->{$key} = [ sort keys %set ];
        }
        delete $blk->{supported};

        # Only a block whose every identifier cracked here may claim tier
        # 'vector'; a block that gained one proven identifier alongside an
        # unproven one keeps the tier and the date it already had, because
        # nothing about that older claim was tested. In mirror mode that is
        # always the case -- the CPU labels were deliberately not re-run -- so
        # the tier and its note are left exactly as they were.
        my $proven = !grep { !$hits{$id}{$_} }
                      (@{ $blk->{cpu} || [] }, @{ $blk->{gpu} || [] });
        if ($proven) {
            $blk->{verified}      = 'vector';
            $blk->{verified_at}   = $today;
            $blk->{verified_with} = "john $john_version";
            $blk->{note} = 'format discovered by round-trip search, not by name';
        }
        else {
            $blk->{verified} //= 'asserted';
        }

        $changed += emit_entry($path{$id}, $e);
    }
    printf STDERR "-   files rewritten: %d\n", $changed;
}
elsif (@apply_list) {
    printf STDERR "-   nothing written; re-run with --apply to record these\n";
}

exit 0;
