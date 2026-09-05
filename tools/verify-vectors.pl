#!/usr/bin/perl
#-----------------------------------------------------------------------
#
# Name: verify-vectors.pl
# Description: prove mappings by round-tripping test vectors through the tools
# Category: cracking-rosetta verifier
#
# Project: cracking-rosetta | Phase: 5 - promote mappings to tier 'vector'
#
#-----------------------------------------------------------------------
# METHODOLOGY AND WHY THESE CHOICES
#
# WHAT 'PROVEN' MEANS HERE
#
# A mapping is proven when the named tool, restricted to the named identifier,
# recovers the entry's known plaintext from the entry's known hash. Nothing
# else counts: not a plausible name, not agreement between two tools, not an
# upstream assertion. That is the only difference between tier 'vector' and
# tier 'upstream', and it is the whole reason the tier column exists.
#
# WORK IS BATCHED BY IDENTIFIER, AND THAT IS SAFE
#
# One invocation per entry would mean ~900 process starts, and for hashcat each
# one pays GPU init and possibly a kernel compile. So all vectors sharing a
# hashcat mode (or mdxfind type, or john format) are cracked in ONE run, with
# every candidate plaintext in one wordlist.
#
# Feeding entry A's password alongside entry B's hash cannot create a false
# positive: the tool reports which hash it cracked, and a hash only falls to
# the plaintext that actually produces it. If B's hash falls to A's password
# the two entries really are the same algorithm, which is a discovery worth
# having rather than an error.
#
# THE john CHECK MATCHES THE HASH, NOT THE PLAINTEXT
#
# john's pot line is "$dynamic_0$<hash>TAB<plain>", and the obvious check --
# does the plaintext appear in the pot -- is WRONG in exactly the case that
# matters. Every vector imported from the sheet carries the plaintext
# "rosetta", so a batched job feeds five different hashes sharing one
# password; john cracks one of them and a plaintext test credits all five.
# Observed 2026-08-29: md5(md5($pass)) was briefly credited to dynamic_0,
# which is plain MD5.
#
# So a crack counts only when the entry's OWN hash and its OWN plaintext
# appear on the same pot line. Where the stored hash carries a salt in a form
# john rewrites, this fails to match and the block is reported unverified --
# a false negative, which is reported and harmless, rather than a false
# positive, which would be a lie in the one column people trust.
#
# TAB IS THE FIELD SEPARATOR
#
# john's default input shape is "login:hash", so a vector that legitimately
# contains a colon -- netntlmv2, krb5tgs, a JWT, or any mdxfind "<hash>:<salt>"
# -- is read as a login plus a truncated hash and never loads.
# --field-separator-char=tab moves the separator out of the way of the data,
# lets the entry id ride along as the login field, and makes john write the pot
# with tabs too, so the pot parses into exactly two fields instead of being
# split on a character the ciphertext may contain.
#
# A SALTED VECTOR IS ALSO OFFERED IN JOHN'S OWN SHAPE
#
# The corpus stores a salted vector as mdxfind reads it, "<hash>:<salt>".
# john's dynamic_9 wants "$dynamic_9$<hash>$<salt>" and discards the colon
# form in valid(), so every salted composite came back unverified even where
# the mapping is right. discover-john.pl proved those mappings by rewriting the
# vector into the format's own encoding; this does the same, so that what that
# search found can be re-derived here from the entry file alone.
#
# The rewrite adds no claim of its own: a wrong mapping still fails to crack.
#
# PROMOTION IS ALL-OR-NOTHING PER TOOL BLOCK
#
# tools.john.cpu can list several formats. The block is promoted only when
# EVERY listed identifier verified, because "verified" on the block would
# otherwise mean "at least one of these is right", which is not a claim anyone
# can act on. Partial results are reported so the failing identifier can be
# fixed or removed.
#
# AN IDENTIFIER THAT WAS NOT RUN IS NOT AN IDENTIFIER THAT FAILED
#
# --limit stops after N jobs, and jobs run in sorted order, so a block naming
# both Raw-MD4 and dynamic_30 can have the first run and the second never
# reached. Counting the un-run one as a failure reported md4 as only partly
# verified when dynamic_30 cracks its vector perfectly well. So promotion is
# evaluated only for blocks whose every identifier actually executed;
# everything else is left completely alone, neither promoted nor reported.
#
# FAILURE NEVER DEMOTES
#
# A vector that does not crack means the mapping is wrong, OR the plaintext is
# wrong, OR the hash needs a salt this script did not supply, OR the format
# wants a wrapper it did not add. Those are not distinguishable from the exit
# status, so a failure is reported and the existing tier is left exactly as it
# was. Silently demoting on an unproven negative would be the same sin as
# silently promoting on an unproven positive.
#
# ITERATION COUNTS ARE RECOVERED, NOT GUESSED
#
# The sheet recorded mdxfind types without the -i value, so md5(md5($pass))
# arrived as type MD5 with the iteration count silently lost. Those entries
# cannot verify at -i 1 and 25 of them duly failed.
#
# mdxfind computes every iteration up to -i N and names the one that matched
# in its output suffix: "MD5x02 <hash>:<plain>". So --discover-iterations
# re-runs a FAILED block once at a high -i and reads the true count off the
# result. That is a measurement, not an inference: if MD5 at iteration 3
# reproduces the digest then the algorithm is md5 applied three times, and no
# other count would have matched.
#
# It runs only against blocks that already failed at their declared count, so
# it can never quietly redefine an entry that was verifying correctly.
#
# ...AND THE COUNT IS CHECKED, NOT JUST THE CRACK
#
# The same suffix that recovers a lost count is also the only thing that says
# a crack belongs to THIS entry. This script originally accepted any suffix,
# so a vector that fell at x01 satisfied an entry declaring x02, and 42 such
# entries reached tier 'vector' on a proof of the wrong algorithm. The suffix
# is now pinned to the declared count. tools/audit-iterations.pl found that
# and repairs the data; this is the check that stops it recurring.
#
# SALTED mdxfind TYPES NEED -F, NOT -f
#
# mdxfind's -f reads bare hashes; -F reads hashes with the salt embedded in the
# line, which is the shape every salted type's self-test vector actually has.
# Feeding an APFS vector to -f gives "No final hash type found"; the same line
# through -F cracks immediately. The inventory already records which types are
# salted -- flag 's' in mdxfind -h -- so the flag is chosen from the data
# rather than from a list maintained here.
#
# Flag 'u' is the same situation wearing a different name: the extra field is a
# userid rather than a salt, which is how mdxfind's HMAC types take their key.
# 47 types carry it, and reading them with -f is why the whole HMAC-* family
# sat in the failure list.
#
# THE SHEET'S PLAINTEXT IS A GUESS
#
# Imported vectors carry pass "rosetta" because the sheet's column header said
# so. Where that is wrong the vector simply will not crack, which is why the
# report separates "failed" from "wrong tool" -- a whole tool failing points at
# this script, a scattering of failures points at the data.
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
use YAML::XS ();

use lib "$RealBin/lib";
use RosettaEmit qw(emit_entry);
use RosettaTools qw(tool_path tool_env_help tool_version);

my $PROG = basename($0);
my $ROOT = "$RealBin/..";

sub usage {
    print STDERR <<"END_USAGE";

Usage: $PROG --tool hashcat|mdxfind|john|all [options]

   --tool NAME       which tool to verify (repeatable; 'all' for every one)
   --hashcat PATH    hashcat binary   (default: @{[tool_env_help('hashcat')]})
   --mdxfind PATH    mdxfind binary   (default: @{[tool_env_help('mdxfind')]})
   --john PATH       john binary      (default: @{[tool_env_help('john')]})
   --algorithms DIR  curated entries  (default: data/algorithms)
   --work DIR        scratch for hash/word/pot files (default: tmp/verify)
   --timeout SECS    per invocation   (default: 120)
   --limit N         stop after N identifiers; for smoke tests
   --only ID         verify just this entry (repeatable)
   --john-gpu        also verify john's opencl/ztex formats (needs a GPU)
   --discover-iterations N
                     for mdxfind blocks that failed, re-run once at -i N and
                     record the iteration count that actually matched
   -n, --dry-run     show the plan; run nothing, write nothing
   -v, --verbose     per-identifier result (repeatable)
   -h, --help        this help

   Promotes a tool block to tier 'vector' only when every identifier it lists
   recovers the entry's plaintext from the entry's hash. Failures are reported
   and never demote an existing tier.

   Exit 0 success, 1 error, 2 usage.

END_USAGE
    return;
}

my (@tools, $hashcat, $mdxfind, $john, $algdir, $workdir, @only, $help);
# (entry, mode) pairs whose crack was attributed by a solo run because
# hashcat echoed a different spelling of the hash than it was given.
my %reserialized;
my ($dry, $john_gpu);
my $discover = 0;
my $timeout = 120;
my $limit   = 0;
my $verbose = 0;

GetOptions(
    'tool=s'       => \@tools,
    'hashcat=s'    => \$hashcat,
    'mdxfind=s'    => \$mdxfind,
    'john=s'       => \$john,
    'algorithms=s' => \$algdir,
    'work=s'       => \$workdir,
    'timeout=i'    => \$timeout,
    'limit=i'      => \$limit,
    'only=s'       => \@only,
    'john-gpu'     => \$john_gpu,
    'discover-iterations=i' => \$discover,
    'n|dry-run'    => \$dry,
    'v|verbose+'   => \$verbose,
    'h|help'       => \$help,
) or do { usage(); exit 2 };

if ($help)  { usage(); exit 0 }
if (!@tools) { usage(); exit 2 }

$hashcat = tool_path('hashcat', $hashcat);
$mdxfind = tool_path('mdxfind', $mdxfind);
$john = tool_path('john', $john);

# WHAT verified_with RECORDS, AND WHY IT IS NOT JUST THE TOOL'S NAME
#
# This promoter wrote the bare strings 'hashcat', 'mdxfind' and 'john' for
# months, which is where 1473 of them in the corpus come from. A tier says
# "proven by this tool" and, without a version, cannot say by which build --
# and WHICH build has twice decided whether a mapping was true here: the RAW
# family repair of 2026-09-05 turned on mdxfind 1.545 against 1.576, and the
# same day the mdxfind inventory and the installed binary stopped being the
# same release at all. So ask each binary, and if one will not say, record
# that rather than a guess.
my %TOOL_VER = map { $_->[0] => (tool_version($_->[0], $_->[1])
                                 // 'version not stated by the binary') }
               ( ['hashcat', $hashcat], ['mdxfind', $mdxfind], ['john', $john] );
$algdir  //= "$ROOT/data/algorithms";
$workdir //= "$ROOT/tmp/verify";

@tools = map { lc } @tools;
@tools = qw(hashcat mdxfind john) if grep { $_ eq 'all' } @tools;
my %want = map { $_ => 1 } @tools;
# --only is repeatable: a delta from review-delta.pl or seed-vectors.pl names
# the entries it changed, and verifying just those is minutes rather than a
# whole-corpus run.
my %only = map { $_ => 1 } @only;
for my $t (@tools) {
    next if $t =~ /^(hashcat|mdxfind|john)$/;
    print STDERR "$PROG: unknown tool '$t'.\n";
    exit 2;
}

make_path($workdir) unless -d $workdir;
my $today = strftime('%Y-%m-%d', localtime);

# TRANSCODES: the type's own serialization of a vector the entry stores in
# some other tool's. john writes RVARY as "$rvary$<hex>" and mdxfind wants the
# bare hex; dynamic_1602 wraps hash and salt and appends a user field that
# QAS-VASAUTH ignores. Those vectors cannot verify as stored, and the row then
# says NOT REPRODUCED about a mapping that reproduces perfectly well.
#
# A line here is a hint about SPELLING and never a claim: it is used only as
# the LAST fallback, only for an (entry, type) pair that has nothing yet, and
# it still has to survive a pinned run. Its plaintext must also be one the
# entry itself stores, so a line cannot quietly introduce a different vector.
my %TRANSCODE;
if ($want{mdxfind}) {
    my $tf = "$ROOT/data/mdxfind-transcodes.tsv";
    if (open my $fh, '<', $tf) {
        while (<$fh>) {
            next if /^\s*(#|$)/;
            chomp;
            my ($ty, $id, $line) = split /\t/, $_, 3;
            next unless defined $line && length $line;
            $TRANSCODE{"$ty\0$id"} = $line;
        }
        close $fh;
    }
}

# Which mdxfind types carry a salt, so -f or -F is chosen from the inventory.
my (%MX_SALTED, %MX_PEPPER);
if ($want{mdxfind}) {
    my $mx = eval { YAML::XS::LoadFile("$ROOT/data/tools/mdxfind.yaml") };
    if ($mx) {
        for my $t (@{ $mx->{types} }) {
            # 's' is a salt carried in the hash line; 'u' is a userid field
            # carried the same way -- mdxfind's HMAC types take their key that
            # way, and 47 types are flagged 'u'. Both need -F rather than -f.
            $MX_SALTED{ $t->{name} } = 1
                if grep { $_ eq 's' || $_ eq 'u' } @{ $t->{flags} || [] };
            # 'j' is a PEPPER type: it takes a site-wide secret that is not in
            # the hash line and cannot be derived from it, so mdxfind reads it
            # from a file (-j, the global pepper array). 13 types carry the
            # flag.
            $MX_PEPPER{ $t->{name} } = 1
                if grep { $_ eq 'j' } @{ $t->{flags} || [] };
        }
    }
    else {
        print STDERR "$PROG: cannot load the mdxfind inventory; assuming no type is salted.\n";
    }
}

# Which john formats are CASE-INSENSITIVE, from john's own FMT_CASE flag.
#
# john returns the plaintext it actually found, and for a case-insensitive
# format that is not the string the wordlist held: netlm's own test array says
# "hiyagerge" and john --show says "HIYAGERGE". A byte-equal comparison reads
# that as a failure, which is how LM, netlm and nethalflm sat unverified while
# every one of them cracks its own vector on the first try.
#
# formats.h line 55: FMT_CASE is bit 0, SET when the format IS case-sensitive.
# So the relaxation is applied only where john says the bit is clear, and only
# to case; nothing else about the comparison moves.
my %JOHN_NOCASE;
if ($want{john}) {
    my $jn = eval { YAML::XS::LoadFile("$ROOT/data/tools/john.yaml") };
    if ($jn) {
        for my $f (@{ $jn->{formats} }) {
            next unless defined $f->{flags} && $f->{flags} =~ /^[0-9a-fA-F]+$/;
            $JOHN_NOCASE{ lc $f->{label} } = 1 unless hex($f->{flags}) & 0x1;
        }
    }
    else {
        print STDERR "$PROG: cannot load the john inventory; every format is treated as case-sensitive.\n";
    }
}

#-----------------------------------------------------------------------
# Load entries.

opendir(my $dh, $algdir) or do { print STDERR "$PROG: cannot read $algdir: $!\n"; exit 1 };
my @files = sort grep { /\.yaml$/ } readdir $dh;
closedir $dh;

my (%entry, %path);
for my $f (@files) {
    my $p = "$algdir/$f";
    my $e = eval { YAML::XS::LoadFile($p) };
    next unless $e && $e->{id};
    next if %only && !$only{ $e->{id} };
    $entry{ $e->{id} } = $e;
    $path{  $e->{id} } = $p;
}

#-----------------------------------------------------------------------
# Build work: one job per (tool, identifier), carrying every entry that
# names it and has a vector.

my %job;   # tool -> identifier -> { entries => {id=>1}, iterations => n }
my %read;  # tool -> entry id -> vector index -> 1, when that tool read THAT
           # string. %cracked answers "did this entry verify", which is what a
           # tier needs; this answers "which serialization did each tool
           # accept", which is what a reader holding one of them needs, and it
           # was already being computed and thrown away.

for my $id (sort keys %entry) {
    my $e = $entry{$id};
    my $vecs = $e->{vectors} or next;
    next unless ref $vecs eq 'ARRAY' && @$vecs;

    if ($want{hashcat} && $e->{tools}{hashcat}{modes}) {
        $job{hashcat}{$_}{entries}{$id} = 1 for @{ $e->{tools}{hashcat}{modes} };
    }
    if ($want{mdxfind} && $e->{tools}{mdxfind}{types}) {
        my $it = $e->{tools}{mdxfind}{iterations} // 1;
        for my $t (@{ $e->{tools}{mdxfind}{types} }) {
            $job{mdxfind}{"$t\0$it"}{entries}{$id} = 1;
            $job{mdxfind}{"$t\0$it"}{iterations} = $it;
        }
    }
    if ($want{john} && $e->{tools}{john}) {
        my @labels = @{ $e->{tools}{john}{cpu} || [] };
        push @labels, @{ $e->{tools}{john}{gpu} || [] } if $john_gpu;
        $job{john}{$_}{entries}{$id} = 1 for @labels;
    }
}

#-----------------------------------------------------------------------
# Helpers.

sub write_file {
    my ($p, @lines) = @_;
    open my $fh, '>', $p or die "cannot write $p: $!\n";
    print {$fh} "$_\n" for @lines;
    close $fh;
    return $p;
}

# run_capture($timeout, @argv) - run, return (exit, output). Never a shell, so
# a hash containing $ or ` cannot be interpreted as anything.
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
    my $code = $killed ? -2 : ($? >> 8);
    return ($code, $out);
}

# vectors_for(@ids) - the (hash, pass) pairs those entries carry.
sub vectors_for {
    my (@ids) = @_;
    my @v;
    for my $id (@ids) {
        my $i = -1;
        for my $vec (@{ $entry{$id}{vectors} || [] }) {
            $i++;
            next unless defined $vec->{hash} && defined $vec->{pass};
            # vi is the vector's position in its entry's list. Without it a
            # result can be attributed only to the ENTRY, which is all a tier
            # needs and not enough to say which SERIALIZATION a tool read.
            push @v, { id => $id, vi => $i,
                       hash => $vec->{hash}, pass => $vec->{pass} };
        }
    }
    return @v;
}

# mx_echo_is($rest, $vec) - does mdxfind's "<hash>:<plain>" tail name THIS
# vector? The plaintext must match exactly. The digest must too, except for
# hex case: mdxfind normalizes hex on read and echoes its OWN lowercase form,
# so an entry whose vector is recorded in uppercase -- which is how the
# vendored catalog renders 15 types, and how the *UC types are published --
# had its own successful round-trip rejected by a string compare and was left
# saying "NOT REPRODUCED HERE" on rows that reproduce fine. Measured
# 2026-08-31: mdxfind -h '^MD4UTF16UC$' on A9FDFA...F0DA prints
# a9fdfa...f0da:password123.
#
# The fold is deliberately narrow. It applies only when the recorded digest is
# pure hex, so a salted "<hash>:<salt>" line -- where the salt is a string and
# its case is part of the algorithm's input -- is still compared exactly. Two
# hex strings differing only in case are the same digest, so nothing that was
# a failure becomes a pass.
sub mx_echo_is {
    my ($rest, $vec) = @_;
    my $want = "$vec->{hash}:$vec->{pass}";
    return 1 if $rest eq $want;
    return 0 unless $vec->{hash} =~ /^[0-9A-Fa-f]+$/;
    my $tail = ":$vec->{pass}";
    return 0 unless length($rest) > length($tail);
    return 0 unless substr($rest, -length($tail)) eq $tail;
    return lc(substr($rest, 0, length($rest) - length($tail))) eq lc($vec->{hash});
}

my (%cracked, %attempted, %failed_job, %mx_job_ids, %ran_ident);
# (entry, type) pairs whose round trip used a line from
# data/mdxfind-transcodes.tsv rather than the vector as stored. The block's
# note says so, because otherwise the promotion reads as though the stored
# string verified and a later reader would try it and be baffled.
my %transcoded;
my $ran = 0;

# hc_plain_is($said, $want) - is the plaintext hashcat printed the plaintext
# the vector records?
#
# The two do not always spell it the same way. hashcat writes a non-printable
# password as $HEX[<hex>], and a vector may store either spelling: mode 9710's
# vector here is "$HEX[91b2e062b9]" and hashcat's crack line ends
# ":91b2e062b9". Both are the same five bytes. So one $HEX wrapper on either
# side is unwrapped and nothing else is: a comparison that normalized harder
# than that would start accepting different plaintexts.
sub hc_plain_is {
    my ($said, $want) = @_;
    return 0 unless defined $said && defined $want;
    return 1 if $said eq $want;
    for my $p ([$said, $want], [$want, $said]) {
        my ($a, $b) = @$p;
        next unless $a =~ /^\$HEX\[([0-9a-fA-F]*)\]$/;
        return 1 if lc($1) eq lc($b);              # the inner hex, as text
        return 1 if pack('H*', $1) eq $b;          # the inner hex, as bytes
    }
    return 0;
}

#-----------------------------------------------------------------------
# hashcat.

if ($want{hashcat} && $job{hashcat}) {
    for my $mode (sort { $a <=> $b } keys %{ $job{hashcat} }) {
        last if $limit && $ran >= $limit;
        my @ids = sort keys %{ $job{hashcat}{$mode}{entries} };
        my @v   = vectors_for(@ids) or next;
        $ran++;

        $attempted{hashcat}{$_} = 1 for @ids;
        $ran_ident{hashcat}{$mode} = 1;
        next if $dry;

        my $solo_cracked = 0;
        my $hf = write_file("$workdir/hc.$mode.hash", map { $_->{hash} } @v);
        my $wf = write_file("$workdir/hc.$mode.word", map { $_->{pass} } @v);

        my ($code, $out) = run_capture($timeout, $hashcat,
            '-m', $mode, '-a', '0', '--quiet', '--potfile-disable',
            '--self-test-disable', '--backend-ignore-opencl', $hf, $wf);

        # hashcat prints "<hash>:<plain>" for each crack, and the two facts
        # that line carries are NOT the same claim.
        #
        # READ is about the string: hashcat loaded this exact serialization,
        # whatever plaintext came back. That is what reads_in records, so the
        # hash appearing is the whole test.
        #
        # CRACKED is about the tier, which promises that the tool "recovers
        # the entry's plaintext from the entry's hash", so it checks the
        # plaintext -- as the john and mdxfind branches already do. The
        # wordlist for a mode holds every plaintext of every entry mapped to
        # it, and CLAUDE.md records modes that compare only part of a digest,
        # so hashcat reporting hash A cracked by entry B's plaintext is a
        # shape this branch could not see. Tightening here can only ever
        # WITHHOLD a promotion, never invent one, because verify-vectors does
        # not demote.
        # %read_here is THIS identifier's reads. %read is the tool's, across
        # every identifier in the run, because that is what reads_in means --
        # "which tools were proven to read this string". Counting the report
        # line off %read credited an identifier with vectors an earlier one had
        # read: measured 2026-09-05, md5-md5-pass-salt printed
        # "dynamic_6  5 hash(es) -> 5 cracked" when dynamic_6 took 4 and
        # dynamic_2006, which ran before it, took the fifth. Promotion is
        # unaffected -- it is per identifier, off %cracked -- but this line is
        # the human check on a tier, so it has to answer the question it asks.
        my %read_here;
        for my $vec (@v) {
            next unless index($out, $vec->{hash}) >= 0;
            next unless $out =~ /^\Q$vec->{hash}\E:(.*)$/m;
            my $said = $1;
            $read{hashcat}{ $vec->{id} }{ $vec->{vi} } = 1;
            $read_here{ $vec->{id} }{ $vec->{vi} } = 1;
            $cracked{hashcat}{ $vec->{id} }{$mode} = 1
                if hc_plain_is($said, $vec->{pass});
        }
        # SOLO FALLBACK. hashcat does not always echo the string it was
        # GIVEN. Measured 2026-09-05 on v7.1.2-549-g8a15e210b: -m 26900 strips
        # the trailing zero padding from the SNMPv3 engine-id field, so it is
        # handed ...db57fd6000000000 and prints ...db57fd60 -- same credential,
        # a line eight characters shorter. Attribution above is an exact match
        # on the hash, which is exactly what makes a GROUPED run safe, since
        # output lines do not correspond to input lines. So a re-serializing
        # mode reads as "did not reproduce" and the block keeps a note saying
        # hashcat failed to reproduce its own published example. That note was
        # wrong about hashcat, and nothing in the data could tell it from a
        # mode that genuinely does not crack.
        #
        # One hash and one candidate per invocation removes the attribution
        # question rather than loosening it: there is no other hash the crack
        # could belong to and no other plaintext it could have used, so the
        # echoed spelling stops mattering. It fires only for a (vector, mode)
        # pair the grouped run left with nothing, so the grouped run stays
        # primary, a regression is structurally impossible, and the cost is
        # bounded by what is still unexplained.
        for my $vec (@v) {
            next if $cracked{hashcat}{ $vec->{id} }{$mode};
            next if $read{hashcat}{ $vec->{id} }{ $vec->{vi} };
            my $sf = write_file("$workdir/hc.$mode.solo.hash", $vec->{hash});
            my $sw = write_file("$workdir/hc.$mode.solo.word", $vec->{pass});
            my ($c2, $o2) = run_capture($timeout, $hashcat,
                '-m', $mode, '-a', '0', '--quiet', '--potfile-disable',
                '--self-test-disable', '--backend-ignore-opencl', $sf, $sw);
            next unless defined $o2;
            my $hit = 0;
            for my $line (split /\n/, $o2) {
                # "<whatever hashcat calls the hash>:<plain>". The plaintext is
                # still checked, because the tier promises the tool recovered
                # THIS entry's plaintext; only the hash spelling is conceded.
                next unless $line =~ /^(.+?):(.*)$/;
                next unless length $1;
                next unless hc_plain_is($2, $vec->{pass});
                $hit = 1;
                last;
            }
            next unless $hit;
            $read{hashcat}{ $vec->{id} }{ $vec->{vi} } = 1;
            $read_here{ $vec->{id} }{ $vec->{vi} } = 1;
            $cracked{hashcat}{ $vec->{id} }{$mode} = 1;
            # Two different causes send a pair here and they are not the same
            # sentence. If the grouped run COMPLETED, it read this hash and
            # echoed a spelling that did not match, which is a fact about the
            # mode's serialization. If it did not complete, hashcat rejected
            # the FILE and we learned nothing about the spelling at all. Saying
            # the first when the second happened is a wrong reason attached to
            # a right tier.
            $reserialized{ $vec->{id} }{$mode} =
                ($code == 0 || $code == 1) ? 'echo' : 'batch';
            $solo_cracked = 1;
        }

        # A run that did not COMPLETE is not evidence of anything, and the
        # reads_in rule below turns "did not run" into "does not read" unless
        # it is told. hashcat's own include/types.h: RC_FINAL_OK is 0 and
        # RC_FINAL_EXHAUSTED is 1; RC_FINAL_ERROR and the aborts are not runs
        # that finished. Measured 2026-09-04, after two concurrent jobs
        # contended for the GPU and the loser stripped "hashcat" from three
        # vectors that hashcat demonstrably reads.
        unless ($code == 0 || $code == 1) {
            $failed_job{hashcat}{$mode} = $code;
            delete $ran_ident{hashcat}{$mode};
            # ... unless a SOLO run of this same identifier cracked. hashcat
            # exits 255 when ANY line of the hash file fails to parse, which
            # throws away what every line that DID parse established. Measured
            # 2026-09-05: qnx7-sha512 carries one vector in mdxfind's
            # serialization and one in hashcat's; -m 19210 exits 255 on the
            # pair, and cracks the mdxfind one on its own. Treating the
            # identifier as unrun there is the batch's fault, not the mode's.
            # A crack is a completed run by definition, so this can only ever
            # convert "no verdict" into a verdict, and only on evidence that
            # actually exists -- a solo run that merely finished proves
            # nothing and does not qualify.
            if ($solo_cracked) {
                $ran_ident{hashcat}{$mode} = 1;
                delete $failed_job{hashcat}{$mode};
            }
        }
        # The count is VECTORS THIS IDENTIFIER READ, not vectors belonging to
        # an entry that cracked. An entry can carry one vector per tool -- a
        # sheet-era mdxfind serialization beside hashcat's own example -- and
        # counting per entry printed "2 hash(es) -> 2 cracked" where hashcat
        # read one of them. Promotion is unaffected: it is per identifier, and
        # the per-vector fact is what reads_in already records.
        printf STDERR "-   hashcat -m %-6s %d hash(es) -> %d cracked%s\n",
            $mode, scalar @v,
            scalar(grep { $read_here{ $_->{id} }{ $_->{vi} } } @v),
            ($code == -2 ? ' [TIMEOUT]' : '') if $verbose;
    }
}

#-----------------------------------------------------------------------
# mdxfind. -h anchors the type so a broader type cannot claim the crack.

if ($want{mdxfind} && $job{mdxfind}) {
    for my $key (sort keys %{ $job{mdxfind} }) {
        last if $limit && $ran >= $limit;
        my ($type, $it) = split /\0/, $key;
        my @ids = sort keys %{ $job{mdxfind}{$key}{entries} };
        my @v   = vectors_for(@ids) or next;
        $ran++;

        $attempted{mdxfind}{$_} = 1 for @ids;
        $ran_ident{mdxfind}{$type} = 1;
        next if $dry;

        (my $safe = $type) =~ s/[^A-Za-z0-9]/_/g;
        my $hf = write_file("$workdir/mx.$safe.$it.hash", map { $_->{hash} } @v);
        my $wf = write_file("$workdir/mx.$safe.$it.word", map { $_->{pass} } @v);

        # -F for a salted type: its vector carries the salt in the line.
        my $readflag = $MX_SALTED{$type} ? '-F' : '-f';

        my ($code, $out) = run_capture($timeout, $mdxfind,
            '-h', "^\Q$type\E\$", $readflag, $hf, '-i', $it, $wf);

        # PEPPER TYPES TAKE THEIR SECRET TWO DIFFERENT WAYS, AND THE FLAGS DO
        # NOT SAY WHICH
        #
        # A pepper is a site-wide secret that appears in no hash and cannot be
        # derived from one, so mdxfind reads it from a file: -j, the global
        # pepper array. The catalog writes it as the SECOND space-separated
        # field of the salt, "<hash>:<salt> <pepper>", which the run above
        # hands to -F as one long salt -- so the pepper never reaches the array
        # and the type computes nothing it can match. That is why ten of these
        # entries sat at tier upstream: not a wrong vector, an unaskable
        # question.
        #
        # But it is not universal, and the inventory cannot tell them apart:
        # SHA1-SALT-UTF16-PEPPER and SHA1SALTMD5PASSPEPPER both carry flags
        # f,s,j and need OPPOSITE handling. The reason is in mdxfind's source,
        # in the default_salts[] table -- SHA1_SALT_UTF16_PEPPER has a built-in
        # salt of "f5g= of8=", one string the type splits itself, so it wants
        # the field whole and splitting it breaks a vector that was verifying.
        # Measured 2026-09-02 against RCS 1.545.
        #
        # So the whole-field run above stays PRIMARY and this is a fallback,
        # which makes a regression structurally impossible: anything that
        # verified before still verifies on the first run. Note what this is
        # NOT -- it is not the re-casing pitfall of "try variants until one
        # passes". The hash and the plaintext are fixed; only the plumbing by
        # which the tool is handed its own published fields varies, and both
        # forms ask the identical question of the identical type.
        if ($MX_PEPPER{$type} && ($out // '') !~ /^\Q$type\E/m) {
            my (@hashes, @peppers);
            for my $vec (@v) {
                my ($h, $rest) = split /:/, $vec->{hash}, 2;
                if (defined $rest && $rest =~ /^(.*?) (.+)$/) {
                    push @hashes,  "$h:$1";
                    push @peppers, $2;
                }
                else { push @hashes, $vec->{hash} }
            }
            if (@peppers) {
                my %u; my @uniq = grep { !$u{$_}++ } @peppers;
                my $hf2 = write_file("$workdir/mx.$safe.$it.hash2", @hashes);
                my $jf  = write_file("$workdir/mx.$safe.$it.pep",   @uniq);
                ($code, $out) = run_capture($timeout, $mdxfind,
                    '-h', "^\Q$type\E\$", $readflag, $hf2, '-i', $it,
                    '-j', $jf, $wf);
            }
        }

        # %read_here is THIS identifier's reads. %read is the tool's, across
        # every identifier in the run, because that is what reads_in means --
        # "which tools were proven to read this string". Counting the report
        # line off %read credited an identifier with vectors an earlier one had
        # read: measured 2026-09-05, md5-md5-pass-salt printed
        # "dynamic_6  5 hash(es) -> 5 cracked" when dynamic_6 took 4 and
        # dynamic_2006, which ran before it, took the fifth. Promotion is
        # unaffected -- it is per identifier, off %cracked -- but this line is
        # the human check on a tier, so it has to answer the question it asks.
        my %read_here;

        # Output lines look like "MD5x01 <hash>:<plain>". The suffix is the
        # iteration that actually matched and is part of the identity, so a
        # vector that falls at x01 does NOT verify an entry declaring x02 --
        # accepting any suffix here is how 42 single-iteration vectors were
        # promoted under twice-iterated entries (see audit-iterations.pl).
        # The plaintext is matched too, for the reason the john block gives.
        for my $line (split /\n/, $out) {
            next unless $line =~ /^\Q$type\E(?:x(\d+))?\s+(.+)$/;
            my $got = defined $1 ? $1 + 0 : $it;   # no suffix: cannot tell
            next unless $got == $it;
            my $rest = $2;
            for my $vec (@v) {
                next unless mx_echo_is($rest, $vec);
                $cracked{mdxfind}{ $vec->{id} }{$type} = 1;
                $read{mdxfind}{ $vec->{id} }{ $vec->{vi} } = 1;
                $read_here{ $vec->{id} }{ $vec->{vi} } = 1;
            }
        }
        # SOLO FALLBACK: mdxfind does not always echo the string it was GIVEN,
        # and mx_echo_is attributes a crack by comparing the echo.
        #
        # Two ways it differs, both measured 2026-09-04:
        #
        #   * IT RE-SERIALIZES. Handed grub-2's
        #     "grub.pbkdf2.sha512.1024.<salt>.<digest>" mdxfind recovers the
        #     plaintext and prints "$ml$1024$<salt>$<digest>" -- macOS's
        #     spelling of the same PBKDF2-SHA512 material.
        #   * IT ADDS A FIELD. The TRUNC family sweeps a truncation length and
        #     reports the one that matched, so SHA1SHA1TRUNC handed
        #     "360621c68ac8101809a7a66d5a2c2469" prints
        #     "360621c68ac8101809a7a66d5a2c2469:40:password123". That is 20 of
        #     the 24 blocks this fallback promotes, and every one of them had
        #     been sitting at tier 'upstream' saying "the tool pinned to this
        #     identifier did not reproduce its own published example".
        #
        # In both cases the round trip succeeded and the attribution failed, so
        # the row said NOT REPRODUCED about a row that reproduces.
        #
        # The echo is only load-bearing because several hashes share a run. So
        # each still-unverified vector is re-run ALONE, pinned, at the same
        # iteration count: with ONE hash in the file, a report line naming the
        # pinned type and ending in that vector's plaintext cannot be anything
        # else, and the echoed spelling stops mattering.
        #
        # Same shape and same guarantee as the PEPPER fallback above: the
        # grouped run stays primary and this only ever ADDS a verification, so
        # nothing that verified before can stop verifying.
        # Only where the (entry, type) pair has NOTHING yet, which is the pair
        # that would otherwise be reported as failing. A vector that is another
        # tool's serialization is not expected to verify under mdxfind and does
        # not need a run of its own to say so; reads_in already carries the
        # per-vector fact. Measured 2026-09-04: without this guard the fallback
        # fires for every unverified vector and the pass takes hours.
        for my $vec (@v) {
            next if $cracked{mdxfind}{ $vec->{id} }{$type};
            next if $read{mdxfind}{ $vec->{id} }{ $vec->{vi} };
            my $sf = write_file("$workdir/mx.$safe.$it.solo.hash", $vec->{hash});
            my $sw = write_file("$workdir/mx.$safe.$it.solo.word", $vec->{pass});
            my ($c2, $o2) = run_capture($timeout, $mdxfind,
                '-h', "^\Q$type\E\$", $readflag, $sf, '-i', $it, $sw);
            next unless defined $o2;
            my $found = 0;
            for my $line (split /\n/, $o2) {
                next unless $line =~ /^\Q$type\E(?:x(\d+))?\s+(.+)$/;
                my $g = defined $1 ? $1 + 0 : $it;
                next unless $g == $it;
                my $tail = ":$vec->{pass}";
                next unless length($2) > length($tail)
                         && substr($2, -length($tail)) eq $tail;
                $found = 1;
                last;
            }
            next unless $found;
            $cracked{mdxfind}{ $vec->{id} }{$type} = 1;
            $read{mdxfind}{ $vec->{id} }{ $vec->{vi} } = 1;
            $read_here{ $vec->{id} }{ $vec->{vi} } = 1;
        }

        # TRANSCODE FALLBACK, third and last. Same shape and same guarantee as
        # the two above: the earlier runs stay primary, this only ever ADDS a
        # verification, and it fires only for an (entry, type) pair that has
        # nothing at all. What it changes is that the hash line comes from
        # data/mdxfind-transcodes.tsv rather than from the entry, because the
        # entry stores that vector in another tool's spelling and mdxfind
        # cannot read it. The plaintext is checked against the entry's own
        # vectors first, so a transcode line cannot smuggle in a different
        # vector, and the block is marked so its note can say the round trip
        # used the transcribed form -- ONE piece of evidence written twice,
        # not two agreeing vectors.
        for my $id (@ids) {
            next if $cracked{mdxfind}{$id}{$type};
            my $line = $TRANSCODE{"$type\0$id"} or next;
            my ($tp) = $line =~ /:([^:]*)$/;
            next unless defined $tp;
            (my $th = $line) =~ s/:\Q$tp\E$//;
            # the plaintext must be one this entry actually stores
            next unless grep { ($_->{pass} // '') eq $tp }
                        @{ $entry{$id}{vectors} || [] };
            my $rf = ($th =~ /:/) ? '-F' : '-f';
            my $hf = write_file("$workdir/mx.$safe.$it.tr.hash", $th);
            my $wf = write_file("$workdir/mx.$safe.$it.tr.word", $tp);
            my ($c3, $o3) = run_capture($timeout, $mdxfind,
                '-h', "^\Q$type\E\$", $rf, $hf, '-i', $it, $wf);
            next unless defined $o3;
            my $hit = 0;
            for my $line2 (split /\n/, $o3) {
                next unless $line2 =~ /^\Q$type\E(?:x(\d+))?\s+\Q$th\E:\Q$tp\E\s*$/;
                my $g = defined $1 ? $1 + 0 : $it;
                next unless $g == $it;
                $hit = 1;
                last;
            }
            next unless $hit;
            $cracked{mdxfind}{$id}{$type} = 1;
            $transcoded{$id}{$type} = $line;
        }

        # Accumulate: one type has a separate job per declared iteration
        # count, and assigning here would leave discovery seeing only the
        # entries of whichever iteration ran last.
        push @{ $mx_job_ids{$type} }, @ids;
        if ($code == -2) {
            $failed_job{mdxfind}{$type} = $code;
            delete $ran_ident{mdxfind}{$type};   # see the hashcat note above
        }
        printf STDERR "-   mdxfind %-24s i=%s %d hash(es) -> %d cracked%s\n",
            $type, $it, scalar @v,
            scalar(grep { $read_here{ $_->{id} }{ $_->{vi} } } @v),
            ($code == -2 ? ' [TIMEOUT]' : '') if $verbose;
    }
}

#-----------------------------------------------------------------------
# john. Run from run/ -- john resolves john.conf against the cwd -- and keep
# pot and session in the work dir, which is writable when run/ is not.

if ($want{john} && $job{john}) {
    my $jdir = $john; $jdir =~ s{/[^/]+$}{};
    my $jbin = basename($john);

    for my $label (sort keys %{ $job{john} }) {
        last if $limit && $ran >= $limit;
        my @ids = sort keys %{ $job{john}{$label}{entries} };
        my @v   = vectors_for(@ids) or next;
        $ran++;

        $attempted{john}{$_} = 1 for @ids;
        $ran_ident{john}{$label} = 1;
        next if $dry;

        (my $safe = $label) =~ s/[^A-Za-z0-9]/_/g;

        # Each line carries a synthetic login, and john's --show prints that
        # login back beside the plaintext. That is what makes the attribution
        # exact: john echoes its OWN canonical encoding into the pot -- a bare
        # digest comes back "$dynamic_213$...", bcrypt's "$2y$" comes back
        # "$2a$", a Cisco type 8 comes back as "$pbkdf2-sha256$..." -- so
        # searching the pot for the hash we submitted misses cracks that really
        # happened. The login is ours and survives every rewrite.
        #
        # A dynamic also gets each two-field vector in john's own encoding,
        # under the SAME login, so a crack of either form credits the vector.
        my (@lines, %login_of);
        my $seq = 0;
        for my $vec (@v) {
            my $login = 'v' . $seq++;
            $login_of{$login} = $vec;
            push @lines, "$login\t$vec->{hash}";
            next unless $label =~ /^dynamic_\d+$/;
            my ($h, $salt) = split /:/, $vec->{hash}, 2;
            push @lines, "$login\t\$$label\$$h\$$salt"
                if defined $salt && length $salt && $salt !~ /:/;
        }

        my $hf  = write_file("$workdir/jn.$safe.hash", @lines);
        my $wf  = write_file("$workdir/jn.$safe.word", map { $_->{pass} } @v);
        my $pot = "$workdir/jn.$safe.pot";
        unlink $pot;

        # john.c refuses to run a format flagged FMT_UNICODE but not FMT_ENC
        # unless the configured encoding is raw or ISO-8859-1, and this host's
        # john.conf sets DefaultEncoding = UTF-8. The refusal goes to stderr
        # and is otherwise INDISTINGUISHABLE from a format that did not crack,
        # which is why stderr is kept here rather than discarded. The retry is
        # made only when john actually printed it, and it credits only vectors
        # whose plaintext is pure ASCII, where the two encodings feed the
        # format identical bytes and the flag therefore cannot change what was
        # proven. A non-ASCII plaintext under the flag would be a claim about a
        # different string, so it is left unproven.
        my ($code, $shown, $enc_used, $enc_refused);
        for my $enc ('', '--input-encoding=iso-8859-1 ') {
            unlink $pot;
            my ($c, $out) = run_capture($timeout, '/bin/sh', '-c',
                sprintf('cd %s && ./%s --format=%s --field-separator-char=tab '
                      . '%s--wordlist=%s --pot=%s --session=%s %s 2>&1 >/dev/null',
                        quotemeta($jdir), quotemeta($jbin), quotemeta($label), $enc,
                        quotemeta($wf), quotemeta($pot), quotemeta("$workdir/jn.$safe"),
                        quotemeta($hf)));
            $code = $c;
            last if $code == -2;
            if (index($out, 'does not yet support other encodings') >= 0) {
                next unless length $enc;
                # Refused even with the flag: john never ran, so this job is a
                # FAILURE and not a silent zero. Treating it as "ran and found
                # nothing" would strike john from reads_in and demote a mapping
                # on evidence that was never gathered.
                $enc_refused = 1;
                last;
            }

            (undef, $shown) = run_capture($timeout, '/bin/sh', '-c',
                sprintf('cd %s && ./%s --show --format=%s --field-separator-char=tab '
                      . '%s--pot=%s %s 2>/dev/null',
                        quotemeta($jdir), quotemeta($jbin), quotemeta($label), $enc,
                        quotemeta($pot), quotemeta($hf)));
            $enc_used = length $enc ? 1 : 0;
            last;
        }

        # "<login>TAB<plaintext>"; a hash john deduplicated on load is shown
        # once, so a crack is spread to every vector carrying the same pair.
        my %won;
        for my $line (split /\n/, $shown // '') {
            my ($login, $pw) = split /\t/, $line, 2;
            next unless defined $login && defined $pw;
            my $vec = $login_of{$login} or next;
            next unless $pw eq $vec->{pass}
                     || ($JOHN_NOCASE{ lc $label } && lc $pw eq lc $vec->{pass});
            next if $enc_used && $vec->{pass} =~ /[^\x20-\x7e]/;
            $won{"$vec->{hash}\0$vec->{pass}"} = 1;
        }
        # %read_here is THIS identifier's reads. %read is the tool's, across
        # every identifier in the run, because that is what reads_in means --
        # "which tools were proven to read this string". Counting the report
        # line off %read credited an identifier with vectors an earlier one had
        # read: measured 2026-09-05, md5-md5-pass-salt printed
        # "dynamic_6  5 hash(es) -> 5 cracked" when dynamic_6 took 4 and
        # dynamic_2006, which ran before it, took the fifth. Promotion is
        # unaffected -- it is per identifier, off %cracked -- but this line is
        # the human check on a tier, so it has to answer the question it asks.
        my %read_here;
        for my $vec (@v) {
            next unless $won{"$vec->{hash}\0$vec->{pass}"};
            $cracked{john}{ $vec->{id} }{$label} = 1;
            $read{john}{ $vec->{id} }{ $vec->{vi} } = 1;
            $read_here{ $vec->{id} }{ $vec->{vi} } = 1;
        }
        if ($code == -2 || $enc_refused) {
            $failed_job{john}{$label} = $enc_refused ? -3 : $code;
            delete $ran_ident{john}{$label};     # see the hashcat note above
        }
        printf STDERR "-   john --format=%-22s %d hash(es) -> %d cracked%s\n",
            $label, scalar @v,
            scalar(grep { $read_here{ $_->{id} }{ $_->{vi} } } @v),
            ($code == -2 ? ' [TIMEOUT]' : '') if $verbose;
    }
}

#-----------------------------------------------------------------------
# Recover lost iteration counts. Only for mdxfind blocks that failed at the
# count they declare; see methodology.

my @discovered;

if ($discover && $want{mdxfind} && !$dry) {
    for my $type (sort keys %mx_job_ids) {
        my %seen;
        for my $id (grep { !$seen{$_}++ } @{ $mx_job_ids{$type} }) {
            next if $cracked{mdxfind}{$id}{$type};
            my $blk = $entry{$id}{tools}{mdxfind} or next;
            my @v = vectors_for($id) or next;

            (my $safe = $type) =~ s/[^A-Za-z0-9]/_/g;
            my $hf = write_file("$workdir/dx.$safe.hash", map { $_->{hash} } @v);
            my $wf = write_file("$workdir/dx.$safe.word", map { $_->{pass} } @v);
            my $readflag = $MX_SALTED{$type} ? '-F' : '-f';

            my ($code, $out) = run_capture($timeout, $mdxfind,
                '-h', "^\Q$type\E\$", $readflag, $hf, '-i', $discover, $wf);

            for my $vec (@v) {
                next unless $out =~ /^\Q$type\Ex(\d+)\s+\Q$vec->{hash}\E:/m;
                my $found = $1 + 0;
                my $was   = $blk->{iterations} // 1;
                next if $found == $was;

                $blk->{iterations} = $found;
                $cracked{mdxfind}{$id}{$type} = 1;
                push @discovered, "$id: mdxfind $type needs -i $found (was $was)";
                last;
            }
        }
    }
}

#-----------------------------------------------------------------------
# Promote. All identifiers in a block must have verified.

my (%promoted, @partial, @failed);
my $changed = 0;

if (!$dry) {
    for my $id (sort keys %entry) {
        my $e = $entry{$id};
        my $touched = 0;

        for my $tool (qw(hashcat mdxfind john)) {
            next unless $want{$tool};
            my $blk = $e->{tools}{$tool} or next;
            next unless $attempted{$tool}{$id};

            my @idents = $tool eq 'hashcat' ? @{ $blk->{modes} || [] }
                       : $tool eq 'mdxfind' ? @{ $blk->{types} || [] }
                       :                      (@{ $blk->{cpu} || [] },
                                               $john_gpu ? @{ $blk->{gpu} || [] } : ());
            next unless @idents;

            my $all_ran = !grep { !$ran_ident{$tool}{$_} } @idents;

            # reads_in: which tools were proven to READ this exact string.
            # Three states, and the third is the point -- a tool that did not
            # run tells us nothing, and recording that as "does not read" would
            # invent a negative. So: a read sets it; a complete run that read
            # nothing clears it; anything else leaves the vector alone.
            #
            # This is what makes a divergent serialization visible. Where one
            # string reads in hashcat and john both, they agree on the format;
            # where an entry needs one string per tool, they do not, and until
            # now that was only ever stated in prose on three entries.
            my $vi = -1;
            for my $vec (@{ $e->{vectors} || [] }) {
                $vi++;
                my %in = map { $_ => 1 } @{ $vec->{reads_in} || [] };
                my $was = join ',', sort keys %in;
                if ($read{$tool}{$id}{$vi})  { $in{$tool} = 1 }
                elsif ($all_ran)             { delete $in{$tool} }
                else                         { next }
                my @now = sort keys %in;
                next if join(',', @now) eq $was;
                if (@now) { $vec->{reads_in} = \@now }
                else      { delete $vec->{reads_in} }
                $touched = 1;
            }

            # Every identifier must have actually run; see methodology.
            next unless $all_ran;

            my @ok  = grep {  $cracked{$tool}{$id}{$_} } @idents;
            my @bad = grep { !$cracked{$tool}{$id}{$_} } @idents;

            if (!@bad) {
                # A clean run always withdraws a machine-written note that
                # says the opposite of the tier, INCLUDING on a block that
                # was already at 'vector'. The early return used to skip
                # this, so a block promoted in one run kept seed-orphans'
                # marker from the run before it: measured 2026-09-02, 24
                # blocks stood at tier 'vector' while their own note read
                # "NOT REPRODUCED HERE ... the claim is upstream's, not this
                # repository's". A reader of that row cannot tell which half
                # to believe, and the tier is the load-bearing one.
                # The last alternative is NOT anchored, on purpose.
                # attach-mdxfind-ahead.pl writes "<TYPE> added <date> by
                # attach-mdxfind-ahead.pl. NOT ROUND-TRIPPED BY mdxfind
                # HERE...", so the marker is mid-string; seed-orphans
                # --via-hashpipe writes the same sentence at the start.
                # Measured 2026-09-05: 16 blocks reached tier `vector` under
                # mdxfind RCS 1.576 while still carrying a note saying mdxfind
                # had not run them, which is the exact contradiction the
                # anchored list above was added to stop.
                if (($blk->{note} // '') =~ /^(hashcat mapping shipped|from hashpipe|vector replaced|NOT REPRODUCED HERE)/
                    || ($blk->{note} // '') =~ /NOT ROUND-TRIPPED BY mdxfind HERE/) {
                    delete $blk->{note};
                    $touched = 1;
                }
                next if ($blk->{verified} // '') eq 'vector';
                $blk->{verified}      = 'vector';
                $blk->{verified_at}   = $today;
                $blk->{verified_with} = "$tool $TOOL_VER{$tool}";
                # Say when the string that verified is not the string stored.
                if ($tool eq 'mdxfind' && $transcoded{$id}) {
                    my @t = map { "$_ as \"$transcoded{$id}{$_}\"" }
                            sort keys %{ $transcoded{$id} };
                    $blk->{note} =
                        "Round-tripped on the TRANSCRIBED form, not on the "
                      . "vector as stored: this entry keeps its vector in "
                      . "another tool's serialization, which mdxfind's reader "
                      . "does not parse. mdxfind pinned with -h reproduced "
                      . join('; ', @t)
                      . ", from data/mdxfind-transcodes.tsv. The plaintext is "
                      . "one this entry already stores, and the two strings "
                      . "are ONE piece of evidence written twice -- not two "
                      . "agreeing vectors.";
                }
                # Same idea, the other tool: the vector is the one stored, but
                # hashcat prints a different spelling of it, so the crack was
                # attributed by a run holding this hash and nothing else.
                if ($tool eq 'hashcat' && $reserialized{$id}) {
                    my $r = $reserialized{$id};
                    my @echo  = sort { $a <=> $b } grep { $r->{$_} eq 'echo'  } keys %$r;
                    my @batch = sort { $a <=> $b } grep { $r->{$_} eq 'batch' } keys %$r;
                    my @why;
                    push @why,
                        "hashcat echoed a different spelling of this hash than "
                      . "it was given under mode(s) " . join(', ', @echo)
                      . ", and the grouped run attributes a crack by matching "
                      . "the hash string -- its output lines do not correspond "
                      . "to its input lines -- so it could not credit one"
                        if @echo;
                    push @why,
                        "the grouped run under mode(s) " . join(', ', @batch)
                      . " did not complete: hashcat exits 255 when ANY line of "
                      . "the hash file fails to parse, which discards what the "
                      . "lines that DID parse established"
                        if @batch;
                    $blk->{note} =
                        "Round-tripped, but attributed by a SOLO run, because "
                      . join('; and ', @why)
                      . ". One hash and one candidate per invocation leaves "
                      . "nothing else the crack could belong to. The stored "
                      . "vector is unchanged and is the form hashcat was fed.";
                }
                $promoted{$tool}++;
                $touched = 1;
            }
            elsif (@ok) {
                push @partial, "$id/$tool: verified [@ok], not [@bad]";
            }
            else {
                push @failed, "$id/$tool: [@bad]";
            }
        }

        $changed += emit_entry($path{$id}, $e) if $touched;
    }
}

#-----------------------------------------------------------------------
# Report.

printf STDERR "- Verified %s across %d identifier job(s)%s\n",
    join('/', @tools), $ran, ($dry ? ' (dry run)' : '');

for my $tool (@tools) {
    next unless $attempted{$tool};
    printf STDERR "-   %-8s entries attempted %4d, promoted to tier 'vector' %4d\n",
        $tool, scalar(keys %{ $attempted{$tool} }), $promoted{$tool} // 0;
}
printf STDERR "-   files rewritten: %d\n", $changed unless $dry;

if (@discovered) {
    printf STDERR "- %d iteration count(s) recovered from failed blocks:\n", scalar @discovered;
    my $n = 0;
    for (@discovered) { print STDERR "-   $_\n"; last if ++$n >= ($verbose ? @discovered : 10) }
}

if (@partial) {
    printf STDERR "- %d block(s) verified only in part (tier unchanged):\n", scalar @partial;
    my $n = 0;
    for (@partial) { print STDERR "-   $_\n"; last if ++$n >= ($verbose ? @partial : 8) }
}
if (@failed) {
    printf STDERR "- %d block(s) did not verify (tier unchanged; see methodology):\n", scalar @failed;
    my $n = 0;
    for (@failed) { print STDERR "-   $_\n"; last if ++$n >= ($verbose ? @failed : 8) }
}
# A job here did not complete -- the ${timeout}s cap, or for hashcat an exit
# outside {0,1}. Its identifier is withheld from $all_ran, so nothing it
# touched was promoted and no reads_in was cleared on its account.
for my $tool (sort keys %failed_job) {
    my @j = sort keys %{ $failed_job{$tool} };
    my @to = grep { $failed_job{$tool}{$_} == -2 } @j;
    printf STDERR "- %s: %d job(s) did not complete (%d at the %ds timeout);"
                . " their identifiers are treated as unrun\n",
        $tool, scalar @j, scalar @to, $timeout;
    for my $ident (grep { $failed_job{$tool}{$_} != -2 } @j) {
        # -3 is john's FMT_UNICODE/FMT_ENC encoding refusal, which prints on
        # stderr and otherwise reads exactly like a format that did not crack.
        printf STDERR "-   %s %s\n", $ident,
            $failed_job{$tool}{$ident} == -3
                ? 'refused: the format takes only ISO-8859-1 and the plaintext is not ASCII'
                : sprintf('exited %d', $failed_job{$tool}{$ident});
    }
}

exit 0;
