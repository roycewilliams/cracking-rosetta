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
use RosettaTools qw(tool_path tool_env_help);

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
# hex case: mdxfind normalises hex on read and echoes its OWN lowercase form,
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
my $ran = 0;

# hc_plain_is($said, $want) - is the plaintext hashcat printed the plaintext
# the vector records?
#
# The two do not always spell it the same way. hashcat writes a non-printable
# password as $HEX[<hex>], and a vector may store either spelling: mode 9710's
# vector here is "$HEX[91b2e062b9]" and hashcat's crack line ends
# ":91b2e062b9". Both are the same five bytes. So one $HEX wrapper on either
# side is unwrapped and nothing else is: a comparison that normalised harder
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
        for my $vec (@v) {
            next unless index($out, $vec->{hash}) >= 0;
            next unless $out =~ /^\Q$vec->{hash}\E:(.*)$/m;
            my $said = $1;
            $read{hashcat}{ $vec->{id} }{ $vec->{vi} } = 1;
            $cracked{hashcat}{ $vec->{id} }{$mode} = 1
                if hc_plain_is($said, $vec->{pass});
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
        }
        # The count is VECTORS THIS IDENTIFIER READ, not vectors belonging to
        # an entry that cracked. An entry can carry one vector per tool -- a
        # sheet-era mdxfind serialization beside hashcat's own example -- and
        # counting per entry printed "2 hash(es) -> 2 cracked" where hashcat
        # read one of them. Promotion is unaffected: it is per identifier, and
        # the per-vector fact is what reads_in already records.
        printf STDERR "-   hashcat -m %-6s %d hash(es) -> %d cracked%s\n",
            $mode, scalar @v,
            scalar(grep { $read{hashcat}{ $_->{id} }{ $_->{vi} } } @v),
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
            }
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
            scalar(grep { $read{mdxfind}{ $_->{id} }{ $_->{vi} } } @v),
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

        my ($code, undef) = run_capture($timeout, '/bin/sh', '-c',
            sprintf('cd %s && ./%s --format=%s --field-separator-char=tab '
                  . '--wordlist=%s --pot=%s --session=%s %s >/dev/null 2>&1',
                    quotemeta($jdir), quotemeta($jbin), quotemeta($label),
                    quotemeta($wf), quotemeta($pot), quotemeta("$workdir/jn.$safe"),
                    quotemeta($hf)));

        my (undef, $shown) = run_capture($timeout, '/bin/sh', '-c',
            sprintf('cd %s && ./%s --show --format=%s --field-separator-char=tab '
                  . '--pot=%s %s 2>/dev/null',
                    quotemeta($jdir), quotemeta($jbin), quotemeta($label),
                    quotemeta($pot), quotemeta($hf)));

        # "<login>TAB<plaintext>"; a hash john deduplicated on load is shown
        # once, so a crack is spread to every vector carrying the same pair.
        my %won;
        for my $line (split /\n/, $shown // '') {
            my ($login, $pw) = split /\t/, $line, 2;
            next unless defined $login && defined $pw;
            my $vec = $login_of{$login} or next;
            next unless $pw eq $vec->{pass};
            $won{"$vec->{hash}\0$vec->{pass}"} = 1;
        }
        for my $vec (@v) {
            next unless $won{"$vec->{hash}\0$vec->{pass}"};
            $cracked{john}{ $vec->{id} }{$label} = 1;
            $read{john}{ $vec->{id} }{ $vec->{vi} } = 1;
        }
        if ($code == -2) {
            $failed_job{john}{$label} = $code;
            delete $ran_ident{john}{$label};     # see the hashcat note above
        }
        printf STDERR "-   john --format=%-22s %d hash(es) -> %d cracked%s\n",
            $label, scalar @v,
            scalar(grep { $read{john}{ $_->{id} }{ $_->{vi} } } @v),
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
                if (($blk->{note} // '') =~ /^(hashcat mapping shipped|from hashpipe|vector replaced|NOT REPRODUCED HERE)/) {
                    delete $blk->{note};
                    $touched = 1;
                }
                next if ($blk->{verified} // '') eq 'vector';
                $blk->{verified}      = 'vector';
                $blk->{verified_at}   = $today;
                $blk->{verified_with} = $tool eq 'hashcat' ? 'hashcat'
                                      : $tool eq 'mdxfind' ? 'mdxfind'
                                      :                      'john';
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
    printf STDERR "-   %s exited %d\n", $_, $failed_job{$tool}{$_}
        for grep { $failed_job{$tool}{$_} != -2 } @j;
}

exit 0;
