#!/usr/bin/perl
#-----------------------------------------------------------------------
#
# Name: absence.pl
# Description: decide, from a completed discovery sweep, which entries a tool
#              provably has no identifier for -- and refuse to guess on the
#              ones the sweep could not decide
# Category: cracking-rosetta upstream deliverable
#
# Project: cracking-rosetta | Phase: 7 - pre-publication readiness
#
#-----------------------------------------------------------------------
# METHODOLOGY AND WHY THIS EXISTS
#
# WHAT AN EMPTY COLUMN DOES NOT SAY
#
# 500 entries name no mdxfind type and docs/GAPS.md presents all of them as
# "nobody has said". That is true of this repository and useless to the one
# reader who could act on it: an upstream maintainer wants the other sentence,
# which algorithms the other tools name and theirs does not. Measured
# 2026-09-03, 498 of those 500 are named by hashcat or john, so nearly the
# whole set is a real algorithm somebody supports.
#
# Turning "we did not say" into "this tool has no identifier for it" is a
# claim, and tier 'absent' is where claims of that shape go.
#
# AND WHAT A BARE 'absent' DOES NOT SAY EITHER
#
# Measured 2026-09-03: 415 of the 417 entries carrying tools.hashcat.verified
# 'absent' have no note, no verified_at and no verified_with. They arrived
# with the sheet import, where an empty hashcat column became the tier that
# sounds strongest. Under the tier definitions that is the weakest data in the
# repository wearing the second strongest label, and dist/rosetta.csv
# publishes it as "no".
#
# --reearn is for exactly those. A BARE verdict is a checkable condition, not
# a judgement: tier 'absent' with no verified_at, no verified_with and no
# note. Nothing else is touched, and the replacement can only ever be the
# same verdict with evidence attached -- absent for absent. Where the sweep
# DISAGREES with a bare claim, by cracking the vector or by matching a name,
# the entry is reported and left exactly as it was: a machine may not promote
# an unevidenced absence into a mapping, because the mapping would inherit
# the confidence of a claim nobody ever checked. That is a curator's call and
# discover-<tool>.pl --apply is where it belongs.
#
# WHY IT READS A SWEEP RATHER THAN RUNNING ONE
#
# discover-mdxfind.pl and discover-hashcat.pl already drive a whole inventory
# and keep their evidence. Re-implementing either loop would be another
# partial copy of an engine this repository already has two of, which is on
# the complexity review's list. So the sweeps stay where they are:
#
#     tools/discover-mdxfind.pl --all -v         # writes out/*.txt
#     tools/absence.pl --tool mdxfind --from tmp/discover-mdxfind
#
#     tools/discover-hashcat.pl --all -v         # writes pot/*.pot
#     tools/absence.pl --tool hashcat --from tmp/discover-hashcat
#
# THE MEASUREMENT THAT MAKES THIS HARD
#
# A sweep can only fail to find what it actually searched. Measured
# 2026-09-03 on mdxfind: a 524-line corpus, and the binary reported
# "Searching through 111 unique hex hashes". Four fifths of it was never in
# the search. mdxfind's loader takes hex digests for its raw-digest types and
# drops the rest, while a named container type still cracks such a hash when
# it is selected explicitly -- which is why mdxfind pinned to 7ZIP reproduces
# a vector that the same vector in a chunked sweep is never tested against.
#
# Two rules for predicting which vectors get searched were tried and both are
# wrong: "hex and at least 16 characters" predicted 145 where the binary's own
# count peaked at 112, and "hex whose length is a digest length of some type
# in that chunk" agreed with the binary on 1 chunk out of 51.
#
# So the tool stops predicting and uses POSITIVE CONTROLS. Sweep with --all
# and the corpus holds every entry that has a vector, including the ones the
# tool already maps. If the sweep reported a hit on some vector whose hash
# portion is N characters, then lines of that shape were in the search, in
# this run, by this binary. An unmapped entry of that same shape that drew no
# hit was therefore tested and not reproduced, which is the only thing
# 'absent' is allowed to mean here. A shape with no control decides nothing
# and the entry is reported as unsearched.
#
# THE WIDTH THE mdxfind SWEEP ACTUALLY COMPARED AT
#
# mdxfind cracks TRUNCATED hashes by design -- a capability hashcat does not
# have -- so it compares at the length of the shortest hash it LOADED and
# honours that for every hash in the file. Two numbers matter and both are
# measured, 2026-09-03:
#
#   * It DROPS anything shorter than 16 hex characters. Stubs of 4, 8 and 12
#     give "Searching through 0 unique hex hashes"; 16, 20 and 24 load and
#     each matches at its own length. So the short non-digest fields in
#     discover-mdxfind's corpus -- IPMI2-SHA1 at 2 characters, NETNTLMv2 at 4
#     to 13 -- are discarded and set no width at all.
#   * On the 2026-08-31 evidence the width was therefore 16, not the 4 a naive
#     read of the corpus file suggests, and mdxfind states it in every chunk:
#     "Minimum hash length is 16 characters". That line is read below rather
#     than the number being inferred.
#
# The two directions are not symmetric. A loose comparison OVER-reports, and a
# spurious hit only withholds an absence -- an entry that drew no hit even at
# four characters really has nothing computing it, so absence survives. What
# does not survive is MASKING: where two corpus hashes share their first
# min-length characters they are, at that width, the same hash, so mdxfind
# reports one and not the other and the silent one looks unswept when it was
# only eclipsed. Those entries are named and held back rather than the run
# being discarded.
#
# The control also validates the EVIDENCE PARSER, which matters more for
# hashcat than for mdxfind: a potfile stores the hash as hashcat loaded it,
# and for some modes that is not the string that was submitted. A parser that
# silently failed to attribute cracks would turn every entry into a false
# absence -- unless no control parses either, which is exactly what the
# control test detects.
#
# WHICH IDENTIFIERS EVEN APPLY
#
# An identifier that could never have loaded the vector is not one whose
# silence means anything, and counting it as untested holds back every entry
# for no reason: nine VeraCrypt modes timed out in the 2026-09-03 sweep, and
# a length-based applicability test made them relevant to a 56-hex BLAKE224
# digest, which they cannot parse.
#
# For hashcat there is no need to reason about it. --identify lists every mode
# whose parser accepts an input, which is hashcat answering the question about
# itself. Measured 2026-09-03: 12 modes for a 32-hex digest, and 19 for a file
# holding a 32-hex and a 40-hex one, so it reports the UNION over the file and
# each hash is asked separately. A run is under a second and the answers are
# cached in <from>/identify.tsv, which also makes this testable without a GPU.
#
# So a hashcat absence reads "of the modes whose parser accepts this hash,
# every one was swept and none reproduced it" rather than "none of 592", most
# of which were never candidates. An EMPTY list is not an absence: it means no
# mode can read this serialization, so this vector cannot ask the question at
# all, and the entry is reported as unsearched.
#
# mdxfind has no equivalent -- it selects types by its own rules and reports
# what it loaded, not what it could have -- so there the identifier set stays
# the whole inventory.
#
# hashpipe IS THE INSTRUMENT FOR THE mdxfind QUESTION
#
# mdxfind has no --identify, but it has something better: hashpipe, built from
# the same catalog, is handed <hash>:<plaintext> and names the type that
# reproduces it. That is the absence question asked directly, where a sweep
# asks it sideways -- the sweep must CRACK, so it needs the -F/-S/-U/-j
# plumbing to be right and its loader drops anything that is not a hex digest,
# while hashpipe is given the plaintext and simply recomputes.
#
# The difference is not marginal. Measured 2026-09-03 over the 454
# mdxfind-silent entries carrying a vector: hashpipe resolved 84 vectors
# across 58 entries in 7.5 seconds; the chunked sweep found one in twenty
# minutes. FIFTEEN of those 58 are hex-shaped, so the shape-control test would
# not have withheld them and they would have been written as false absences --
# hmac-sha256-key-salt is HMAC-SHA256, oracle-11g is ORACLE11, ripemd256 is
# RMD256, punbb and redmine are SHA1SALTSHA1PASS. Fifteen published claims
# that mdxfind does not support something it does.
#
# So an mdxfind absence requires hashpipe to have found nothing either, and
# --no-hashpipe is the only way to skip that, loudly.
#
# A hashpipe HIT MEANS TWO OPPOSITE THINGS
#
# It is never an mdxfind mapping -- hashpipe proposes, mdxfind proves -- but
# which way it cuts depends on whether mdxfind has the type at all. Measured
# 2026-09-03: 25 names hashpipe has and mdxfind does not, against 1 the other
# way (PARALLEL).
#
#   * A type BOTH have. hashpipe reproduced the vector, so mdxfind plausibly
#     can too and the sweep merely failed to arrange it -- wrong plumbing, or
#     a line its loader dropped. That CONTRADICTS an absence: the entry is
#     reported as a candidate mapping and nothing is written.
#   * A type only hashpipe has. mdxfind genuinely does not have it, so the
#     hit CORROBORATES the absence rather than contradicting it. Ten entries
#     here are in this position -- ORACLE11, SUNMD5, H3C, MONGODB,
#     GOST94CRYPT, GOST12256CRYPT and the four DRAGONFLY variants.
#
# The second case is also where this repository stops being a superset. The
# absence is true and gets written, and the note says which hashpipe type
# covers the algorithm, because there is nowhere else to put it: there is no
# hashpipe column. That note is the placeholder for a decision, not a
# substitute for one.
#
# A NAME MATCH VETOES
#
# Before any verdict, the entry's own tool-neutral identifiers -- id, name,
# aliases, legacy spellings -- are normalised by the separator-drift rule
# (upper-case, strip non-alphanumerics) and looked for among the tool's
# identifier names. An exact match is a CANDIDATE MAPPING, not an absence.
#
# The vocabulary is deliberately NOT widened to the other tools' identifiers,
# and that is a measured decision rather than caution. Doing so on the hashcat
# side produced 8 matches, and they are collisions between two naming
# conventions rather than mappings: mdxfind's MD5MD5PASS is md5(md5(pass).pass)
# and hashcat mode 2600 is named md5(md5($pass)), and stripping "$ . ( )"
# makes both MD5MD5PASS. Same for SHA1MD5PASS against mode 4700. Normalisation
# is safe within one tool's convention and unsafe across two that both write
# expressions with different implicit operands.
#
# WHAT IT WILL NOT DO
#
# It never touches an entry that already names an identifier for the tool,
# never overwrites an existing verdict, and never writes a tier stronger than
# 'absent'. Discovering a mapping is the discover-* tools' job and promoting
# one is verify-vectors.pl's.
#
# USAGE
#   tools/absence.pl --tool mdxfind|hashcat --from DIR [--apply] [-v]
#
# DEPENDENCIES
#   perl, YAML::XS, tools/lib/RosettaEmit.pm
#
#-----------------------------------------------------------------------
# Generated by Claude Opus 5 on 2026-09-03

use strict;
use warnings;

use File::Basename qw(basename);
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
Usage: $PROG --tool mdxfind|hashcat --from DIR [options]

   --tool NAME       which tool's column to decide
   --from DIR        a completed discover-<tool>.pl work directory
                     (default: tmp/discover-<tool>)
   --algorithms DIR  curated entries (default: data/algorithms)
   --inventory PATH  that tool's inventory (default: data/tools/<tool>.yaml)
   --hashcat PATH    hashcat binary, for --identify (default: hashcat on PATH)
   --hashpipe PATH   hashpipe binary (default: @{[tool_env_help('hashpipe')]})
   --no-hashpipe     do not corroborate an mdxfind absence with hashpipe.
                     Measured 2026-09-03, that corroboration is what stops 15
                     entries being called absent for a type hashpipe names.
   --no-identify     do not run hashcat; use only the cached identify answers
                     already in <from>/identify.tsv
   --timeouts PATH   identifiers the sweep could not finish, one per line;
                     they are treated as never run (default: <from>/timeouts
                     when it exists). A run killed at the timeout looks
                     exactly like one that cracked nothing.
   --apply           write 'absent' onto the entries the sweep decided
   --reearn          also target entries whose verdict is 'absent' with no
                     date, version or note -- a claim nobody ever checked.
                     They are replaced only by the same verdict with the
                     evidence attached; a disagreement is reported, never
                     written.
   -v, --verbose     list every entry in every class (repeatable)
   -h, --help        this help

   Without --apply nothing is written. Exit 0 success, 1 error, 2 usage.
END_USAGE
    return;
}

my ($tool, $from, $algdir, $invpath, $apply, $reearn, $timeouts, $hashcat,
    $no_identify, $hashpipe, $no_hashpipe, $verbose, $help);
GetOptions(
    'tool=s'        => \$tool,
    'from=s'        => \$from,
    'hashcat=s'     => \$hashcat,
    'hashpipe=s'    => \$hashpipe,
    'no-hashpipe'   => \$no_hashpipe,
    'no-identify'   => \$no_identify,
    'timeouts=s'    => \$timeouts,
    'algorithms=s' => \$algdir,
    'inventory=s'  => \$invpath,
    'apply'        => \$apply,
    'reearn'       => \$reearn,
    'verbose+'     => \$verbose,
    'help|h'       => \$help,
) or do { usage(); exit 2 };

if ($help) { usage(); exit 0 }
# House rule: no arguments prints usage and exits rather than blocking.
unless (defined $tool) { usage(); exit 2 }
unless ($tool =~ /^(mdxfind|hashcat)$/) {
    print STDERR "$PROG: --tool must be mdxfind or hashcat, not '$tool'.\n";
    exit 2;
}

$from    //= "$ROOT/tmp/discover-$tool";
$algdir  //= "$ROOT/data/algorithms";
$invpath //= "$ROOT/data/tools/$tool.yaml";

#-----------------------------------------------------------------------
# The separator-drift rule, stated once. The source sheet wrote HAV128_4
# where mdxfind writes HAV128-4. Compare on this; store the tool's spelling.
sub norm {
    my ($s) = @_;
    return '' unless defined $s;
    $s = uc $s;
    $s =~ s/[^A-Z0-9]//g;
    return $s;
}

# shape($hash) - what a control speaks for: the hash portion before the first
# colon, reduced to "hex:<length>" or the literal "nonhex".
sub shape {
    my ($h) = @_;
    return 'nonhex' unless defined $h;
    my ($head) = split /:/, $h, 2;
    return 'nonhex' unless $head =~ /^[0-9A-Fa-f]+$/;
    return 'hex:' . length($head);
}

#-----------------------------------------------------------------------
# The tool's inventory: its identifiers, and how an entry names them.

my $inv = eval { YAML::XS::LoadFile($invpath) }
    or die "$PROG: cannot load $invpath: $@\n";

my (%ident_by_norm, %ident_name, @ident, %len_min, %len_max);
if ($tool eq 'mdxfind') {
    for my $t (@{ $inv->{types} }) {
        push @ident, $t->{index_num};
        $ident_name{ $t->{index_num} } = $t->{name};
        push @{ $ident_by_norm{ norm($t->{name}) } }, $t->{name};
    }
}
else {
    for my $m (@{ $inv->{modes} }) {
        push @ident, $m->{mode};
        $ident_name{ $m->{mode} } = $m->{name};
        push @{ $ident_by_norm{ norm($m->{name}) } }, $m->{mode};
        # hashcat rejects a plaintext outside a mode's stated range, and
        # discover-hashcat skips such a mode rather than running it. That is a
        # legitimate non-test, so it is applied per entry below rather than
        # counted as missing coverage.
        $len_min{ $m->{mode} } = $m->{password_len_min} // 0;
        $len_max{ $m->{mode} } = $m->{password_len_max} // 256;
    }
}

# how an entry names this tool's identifiers
sub entry_ids {
    my ($e) = @_;
    my $b = $e->{tools}{$tool} || {};
    return $tool eq 'mdxfind' ? @{ $b->{types} || [] } : @{ $b->{modes} || [] };
}

#-----------------------------------------------------------------------
# Entries.

opendir(my $dh, $algdir) or die "$PROG: cannot read $algdir: $!\n";
my @files = sort grep { /\.yaml$/ } readdir $dh;
closedir $dh;

my (%entry, %path, %target, %bare_target);
for my $f (@files) {
    my $e = eval { YAML::XS::LoadFile("$algdir/$f") } or next;
    next unless $e->{id};
    next if ($e->{status} // '') eq 'merged';   # a tombstone claims nothing
    $entry{ $e->{id} } = $e;
    $path{  $e->{id} } = "$algdir/$f";
    next if entry_ids($e);                     # already mapped
    my $b = $e->{tools}{$tool} || {};
    if (defined $b->{verified}) {
        # bare(): a verdict carrying no evidence at all. Anything with a date,
        # a version or a note was written by somebody who checked, and is not
        # this tool's to revisit.
        my $bare = $b->{verified} eq 'absent'
                && !defined $b->{verified_at}
                && !defined $b->{verified_with}
                && !defined $b->{note};
        next unless $reearn && $bare;
        $bare_target{ $e->{id} } = 1;
    }
    $target{ $e->{id} } = 1;
}

# Case-folded index of every vector, so a report line can be attributed back.
my (%by_fold, %words);
for my $id (sort keys %entry) {
    my $v = $entry{$id}{vectors};
    next unless ref $v eq 'ARRAY';
    for my $vec (@$v) {
        next unless defined $vec->{hash} && defined $vec->{pass};
        push @{ $by_fold{ lc($vec->{hash}) . "\0" . $vec->{pass} } }, $id;
        $words{ $vec->{pass} } = 1;
    }
}
# Longest first: a report line is split from the right, and "pass" must not
# win over "pass:word" where the corpus holds both.
my @words_by_len = sort { length($b) <=> length($a) || $a cmp $b } keys %words;

# split_report($rest) - "<hash>:<plain>", or a longer line ending that way,
# split into its two halves. The plaintext is matched against the corpus's own
# set longest-first because a plaintext may itself contain a colon, so there is
# no fixed occurrence to split on.
sub split_report {
    my ($rest) = @_;
    for my $w (@words_by_len) {
        my $tail = ":$w";
        next unless length($rest) > length($tail);
        next unless substr($rest, -length($tail)) eq $tail;
        return (substr($rest, 0, length($rest) - length($tail)), $w);
    }
    return ();
}

# attribute($rest) - the entries whose vector this report line is. The hex fold
# is narrow on purpose: it applies only where the recorded digest is pure hex,
# so a salted line whose salt case is part of the input is still compared
# exactly.
sub attribute {
    my ($rest) = @_;
    my ($printed, $w) = split_report($rest);
    return () unless defined $printed;
    # The index is keyed on lc(hash), so this lookup already folds the case
    # mdxfind and hashcat both normalise on read and echo back.
    return @{ $by_fold{ lc($printed) . "\0" . $w } || [] };
}

# Every HASH the sweep reproduced, without regard to which plaintext followed
# it. See the "SAME HASH, ANOTHER PLAINTEXT" note at the classifier.
my %cracked_hash;   # lc(hash portion) -> identifier -> 1

# record_hash($ident, $rest) - the bookkeeping both evidence readers do.
sub record_hash {
    my ($ident, $rest) = @_;
    my ($printed) = split_report($rest);
    $cracked_hash{ lc $printed }{$ident} = 1 if defined $printed;
    return;
}

#-----------------------------------------------------------------------
# The sweep's evidence, one reader per tool.

my (%hits, %covered);

# Types whose hits mdxfind reported and this parser could not read. Empty is
# the only acceptable value: see the report_type note below.
my %parser_blind;

# How many mdxfind invocations the evidence for a range holds. mdxfind prints
# "Minimum hash length is N characters" once per run, so this is its own
# record rather than an inference. It matters because a sweep's silence is
# weaker the bigger its corpus was -- see the salt-pool note at the report.
my $runs_per_chunk;

if ($tool eq 'mdxfind') {
    # Raw output per chunk, named eLOW-eHIGH.txt. A report line is
    # "TYPExNN <hash>[:<salt>]:<plain>".
    opendir(my $eh, "$from/out") or die
        "$PROG: cannot read $from/out: $!\n"
      . "  Run tools/discover-mdxfind.pl --all first; it writes that directory.\n";
    my @chunks = sort grep { /\.txt$/ } readdir $eh;
    closedir $eh;
    die "$PROG: no chunk output under $from/out\n" unless @chunks;

    my %is_type = map { $_ => 1 } values %ident_name;

    # report_type($token) - the type a report line's first field names, or
    # undef.
    #
    # HALF OF mdxfind's REPORT LINES CARRY NO ITERATION SUFFIX. The print is
    # guarded by "if (x > 0)" (mdxfind.c, every emitter around lines
    # 10264-10703): a type whose internal iteration counter never leaves zero
    # prints its bare name, and only a type that counts prints "NAMExNN". The
    # value is not lost -- the same block does
    # TOTALFOUND(op)[x > 0 ? x - 1 : 0]++ and the end-of-run summary prints
    # slot 0 as "x01" -- so a bare line IS the first iteration, stated by the
    # binary in its own totals.
    #
    # Measured 2026-09-03 on tmp/mx-sweep-fresh: 917 suffixed report lines and
    # 235 bare ones, the bare ones covering 163 entries. 141 of those entries
    # appear ONLY in a bare line, and 13 of the 141 are entries this tool
    # targets -- drupal-7, both episerver rows, four hmac-*-key-salt rows,
    # lotus-notes-domino-5, mac-os-x-10-4-10-6, three scrypt rows and sha1-cx.
    # Every one of them was cracked by an mdxfind type in the sweep, and every
    # one would have been published as 'absent' by a parser that reads only
    # the suffixed form.
    #
    # No type in the inventory ends in x<digits> (measured 2026-09-03), so
    # stripping a trailing suffix cannot eat a name.
    my $report_type = sub {
        my ($tok) = @_;
        return $tok if $is_type{$tok};
        (my $bare = $tok) =~ s/x\d+$//;
        return $is_type{$bare} ? $bare : undef;
    };

    for my $c (@chunks) {
        $covered{$_} = 1 for ($c =~ /^e(\d+)-e(\d+)\.txt$/ ? ($1 .. $2) : ());
        open my $fh, '<', "$from/out/$c" or next;
        my (%saw, %claimed);
        my $runs = 0;
        while (my $line = <$fh>) {
            chomp $line;

            # mdxfind prints this once per invocation, so counting them is its
            # own record of how many runs this range's evidence holds.
            $runs++ if $line =~ /Minimum hash length is \d+ characters/;

            # mdxfind's own tally, one line per (type, iteration) it found
            # something for: "4 MD5MD5SALTx01 hashes found", commified. It is
            # the binary's account of its own run and it is what this parser
            # is reconciled against.
            if ($line =~ /^\s*[\d,]+\s+(\S+)x\d+\s+hashes found$/) {
                my $t = $report_type->($1);
                $claimed{$t} = 1 if defined $t;
                next;
            }

            next unless $line =~ /^(\S+)\s+(.+)$/;
            my ($tok, $rest) = ($1, $2);
            my $type = $report_type->($tok) // next;
            $saw{$type} = 1;
            record_hash($type, $rest);
            $hits{$_}{$type} = 1 for attribute($rest);
        }
        close $fh;

        # A type mdxfind counted but whose report lines this parser never
        # recognised means the output format moved. Every entry that type
        # cracked would look unswept, which is exactly a false absence, so it
        # is recorded and the run refuses to write.
        $parser_blind{$_} = $c for grep { !$saw{$_} } sort keys %claimed;

        # The weakest range decides: an absence is only as good as the
        # least-swept identifier it rests on.
        $runs_per_chunk = $runs
            if $runs && (!defined $runs_per_chunk || $runs < $runs_per_chunk);
    }
}
else {
    # One potfile per mode. The file EXISTING is the record that the mode ran;
    # discover-hashcat.pl creates an empty one when nothing loaded or nothing
    # cracked, precisely so that "tried" is distinguishable from "skipped".
    opendir(my $eh, "$from/pot") or die
        "$PROG: cannot read $from/pot: $!\n"
      . "  Run tools/discover-hashcat.pl --all first; it writes that directory.\n";
    my @pots = grep { /^\d+\.pot$/ } readdir $eh;
    closedir $eh;
    die "$PROG: no potfiles under $from/pot\n" unless @pots;

    for my $p (@pots) {
        my ($mode) = $p =~ /^(\d+)\.pot$/;
        $covered{$mode} = 1;
        open my $fh, '<', "$from/pot/$p" or next;
        while (my $line = <$fh>) {
            chomp $line;
            next unless length $line;
            record_hash($mode, $line);
            $hits{$_}{$mode} = 1 for attribute($line);
        }
        close $fh;
    }
}

#-----------------------------------------------------------------------
# Controls, and coverage.

# An identifier the sweep could not finish is not one it tested. The potfile
# or chunk file exists either way -- the discovery tools write it so --resume
# can tell "tried" from "not tried" -- so the list has to come from outside.
$timeouts //= "$from/timeouts" if -r "$from/timeouts";
if (defined $timeouts) {
    open my $tf, '<', $timeouts
        or die "$PROG: cannot read $timeouts: $!\n";
    my $n = 0;
    while (<$tf>) {
        chomp;
        s/^\s+|\s+$//g;
        next unless length && !/^#/;
        delete $covered{$_};
        $n++;
    }
    close $tf;
    printf STDERR "- %d identifier(s) listed as unfinished; treated as never run\n", $n;
}

my %searched_shape;
for my $id (sort keys %hits) {
    my $v = $entry{$id}{vectors};
    next unless ref $v eq 'ARRAY';
    $searched_shape{ shape($_->{hash}) } = $id for @$v;
}

my %target_shape;
for my $id (sort keys %target) {
    my $v = $entry{$id}{vectors};
    next unless ref $v eq 'ARRAY';
    $target_shape{ shape($_->{hash}) }++ for @$v;
}
my @no_control = grep { !$searched_shape{$_} } sort keys %target_shape;

printf STDERR "- %s: %d shape(s) proven searched by a control; %d target shape(s) with none\n",
    $tool, scalar keys %searched_shape, scalar @no_control;
printf STDERR "-   no control: %s\n", join(' ', @no_control) if @no_control && $verbose;

my $controls_ok = (scalar keys %searched_shape) > 0;
unless ($controls_ok) {
    print STDERR <<"END_WARN";
- The sweep reported no hit on any vector, so no shape has a control and
  nothing can be written. That is what a sweep of ONLY the unmapped entries
  looks like: it finds nothing by construction, and finding nothing is then
  not evidence. Re-run the sweep with --all, so the entries this tool already
  maps are in the corpus and act as controls for their own shapes.
END_WARN
}

# Masked hashes: mdxfind compares at the width the shortest hash in the corpus
# file sets, so two hashes sharing that prefix are the same hash to it and
# only one is ever reported. That follows from truncated matching being a
# feature. hashcat loads per mode with its own parser and does not do this, so
# the check is measured only where it applies.
my %masked;
if ($tool eq 'mdxfind' && -r "$from/corpus.hash") {
    # mdxfind's own floor, measured: shorter than this and the line is not
    # loaded, so it cannot mask anything and cannot be masked.
    my $MDXFIND_MIN_HASH = 16;

    my (@h, $min);
    open my $cf, '<', "$from/corpus.hash" or die "$PROG: $!\n";
    while (<$cf>) {
        chomp;
        my ($head) = split /:/, $_, 2;
        next unless defined $head && $head =~ /^[0-9A-Fa-f]+$/;
        next if length($head) < $MDXFIND_MIN_HASH;
        push @h, lc $head;
        $min = length $head if !defined $min || length($head) < $min;
    }
    close $cf;

    # mdxfind states the width it used. Prefer it: it is the binary's answer
    # about its own run, where the line above is this tool's reconstruction.
    if (opendir(my $oh, "$from/out")) {
        for my $c (sort grep { /\.txt$/ } readdir $oh) {
            open my $fh2, '<', "$from/out/$c" or next;
            while (<$fh2>) {
                next unless /Minimum hash length is (\d+) characters/;
                $min = $1 if !defined $min || $1 < $min;
            }
            close $fh2;
        }
        closedir $oh;
    }
    if (defined $min) {
        my %pre;
        my %seen;
        for my $x (grep { !$seen{$_}++ } @h) { push @{ $pre{ substr($x, 0, $min) } }, $x }
        for my $p (keys %pre) {
            next unless @{ $pre{$p} } > 1;
            $masked{$_} = 1 for @{ $pre{$p} };
        }
        printf STDERR "- sweep comparison width was %d hex character(s); "
                    . "%d hash(es) are indistinguishable at it\n",
            $min, scalar keys %masked;
    }
}

#-----------------------------------------------------------------------
# hashpipe: the second oracle on the mdxfind question.

my %hp_type;    # entry id -> type hashpipe named
my %hp_asked;   # entry id -> 1 when hashpipe was actually given its vectors
my %hp_only;    # type name -> 1 when hashpipe has it and mdxfind does not
if ($tool eq 'mdxfind' && !$no_hashpipe) {
    my $cache = "$from/hashpipe.tsv";
    my %known;  # "<hash>:<plain>" -> type, '' meaning asked and unresolved
    if (-r $cache) {
        open my $cf, '<', $cache or die "$PROG: $!\n";
        while (<$cf>) {
            chomp;
            next unless length && !/^#/;
            my ($line, $t) = split /\t/, $_, 2;
            $known{$line} = $t // '';
        }
        close $cf;
    }

    # Everything a target carries, asked in ONE pass: hashpipe reads a file
    # and takes 7.5 seconds over the whole set, so there is no reason to
    # batch it any more cleverly than this.
    my (%line_of, @ask);
    for my $id (sort keys %target) {
        for my $v (ref $entry{$id}{vectors} eq 'ARRAY'
                   ? @{ $entry{$id}{vectors} } : ()) {
            next unless defined $v->{hash} && defined $v->{pass};
            my $line = "$v->{hash}:$v->{pass}";
            push @{ $line_of{$line} }, $id;
            push @ask, $line unless exists $known{$line};
        }
    }

    if (@ask) {
        my $bin = tool_path('hashpipe', $hashpipe);
        my $in  = "$from/.hp.in.$$";
        my $out = "$from/.hp.out.$$";
        open my $ih, '>', $in or die "$PROG: cannot write $in: $!\n";
        print {$ih} "$_\n" for @ask;
        close $ih;
        # -L is hashpipe's own guard: above that estimate an expensive verify
        # is DECLINED and the line is reported unresolved, which its help says
        # "looks exactly like a genuine miss". Raised well past the default so
        # a slow KDF is measured rather than silently declined.
        system("$bin -L 5000 -O '$out' -E /dev/null '$in' >/dev/null 2>&1");
        my %got;
        if (open my $oh, '<', $out) {
            while (<$oh>) {
                chomp;
                next unless /^(\S+)\s+(.+)$/;
                $got{$2} = $1;
            }
            close $oh;
        }
        unlink $in, $out;
        # Record the misses too: "asked and found nothing" is the evidence,
        # and without it a re-run cannot tell it from "never asked".
        open my $af, '>>', $cache or die "$PROG: cannot append $cache: $!\n";
        for my $line (@ask) {
            $known{$line} = $got{$line} // '';
            print {$af} join("\t", $line, $known{$line}), "\n";
        }
        close $af;
        printf STDERR "- hashpipe asked about %d line(s)\n", scalar @ask;
    }

    for my $line (sort keys %line_of) {
        next unless exists $known{$line};
        for my $id (@{ $line_of{$line} }) {
            $hp_asked{$id} = 1;
            $hp_type{$id} = $known{$line} if length $known{$line};
        }
    }

    # Which of hashpipe's types mdxfind does not have. Read from a list
    # alongside the cache rather than derived: producing it needs the hashpipe
    # binary (-T lists its registered types) and this tool must run without
    # one. Absent, every hit is treated as a contradiction, which is the
    # conservative reading.
    my $only = "$from/hashpipe-only.txt";
    if (-r $only) {
        open my $of, '<', $only or die "$PROG: $!\n";
        while (<$of>) { chomp; s/^\s+|\s+$//g; $hp_only{$_} = 1 if length && !/^#/ }
        close $of;
        printf STDERR "- %d type(s) hashpipe has and mdxfind does not\n",
            scalar keys %hp_only;
    }
    printf STDERR "- hashpipe: %d entry/entries asked, %d named a type\n",
        scalar keys %hp_asked, scalar keys %hp_type;
}

#-----------------------------------------------------------------------
# Which modes can even parse a given hash, from hashcat itself.

my %identify;            # hash -> [ modes ], '' meaning "no mode accepts it"
my $identify_path = "$from/identify.tsv";
if ($tool eq 'hashcat' && -r $identify_path) {
    open my $if, '<', $identify_path or die "$PROG: $!\n";
    while (<$if>) {
        chomp;
        next unless length && !/^#/;
        my ($h, $m) = split /\t/, $_, 2;
        next unless defined $h;
        $identify{$h} = [ grep { length } split /,/, ($m // '') ];
    }
    close $if;
    printf STDERR "- %d cached --identify answer(s)\n", scalar keys %identify
        if $verbose;
}

# identify_modes($hash) - hashcat's own list, cached. Returns an arrayref, or
# undef when it is not known and cannot be found out.
sub identify_modes {
    my ($h) = @_;
    return $identify{$h} if exists $identify{$h};
    return undef if $no_identify;

    $hashcat //= 'hashcat';
    my $tmpf = "$from/.identify.$$";
    open my $th, '>', $tmpf or return undef;
    print {$th} "$h\n";
    close $th;
    my $out = `$hashcat --identify '$tmpf' 2>&1`;
    unlink $tmpf;

    my @m;
    push @m, $1 while $out =~ /^\s*(\d+)\s*\|/mg;
    $identify{$h} = \@m;

    # Append rather than rewrite: the cache is evidence accumulated across
    # runs, and a partial run must not discard what an earlier one measured.
    if (open my $af, '>>', $identify_path) {
        print {$af} join("\t", $h, join(',', @m)), "\n";
        close $af;
    }
    return \@m;
}

# applicable_for($e) - the identifiers whose silence about this entry means
# anything. For hashcat that is hashcat's own answer; for mdxfind it is the
# whole inventory, because mdxfind has no equivalent question to ask.
sub applicable_for {
    my ($e) = @_;
    return @ident unless $tool eq 'hashcat';
    my (%m, $asked);
    for my $v (ref $e->{vectors} eq 'ARRAY' ? @{ $e->{vectors} } : ()) {
        my $list = identify_modes($v->{hash} // '') or next;
        $asked = 1;
        $m{$_} = 1 for @$list;
    }
    return $asked ? (sort { $a <=> $b } keys %m) : @ident;
}

# uncovered_for($e) - the tool's identifiers that this entry needed tested and
# the sweep did not run. For hashcat a mode whose plaintext-length range
# excludes every plaintext the entry carries could never have applied, and
# discover-hashcat skips it for that reason; that is not missing coverage.
sub uncovered_for {
    my ($e, @applicable) = @_;
    my @plen = map { length($_->{pass} // '') }
               (ref $e->{vectors} eq 'ARRAY' ? @{ $e->{vectors} } : ());
    my @out;
    for my $i (@applicable) {
        next if $covered{$i};
        # hashcat also refuses a plaintext outside a mode's stated range, and
        # discover-hashcat skips such a mode rather than running it. That is a
        # legitimate non-test, not missing coverage.
        if ($tool eq 'hashcat') {
            next unless grep { $_ >= $len_min{$i} && $_ <= $len_max{$i} } @plen;
        }
        push @out, $i;
    }
    return @out;
}

my @globally_uncovered = grep { !$covered{$_} } @ident;
if ($tool eq 'mdxfind' && defined $runs_per_chunk) {
    printf STDERR "- evidence holds %d mdxfind run(s) of every range\n",
        $runs_per_chunk;
    print STDERR <<'END_ONE' if $runs_per_chunk < 2;
-   ONE run only. Measured 2026-09-04: mdxfind can miss under -m over a range
-   what it finds in a second under -h pinned, because the salt pool is the
-   union over every type selected and a large one suppresses the match. A
-   lean-corpus sweep of all 1002 types took 21.5s and found eight mappings a
-   full-corpus sweep had missed. Run the other one and union the chunk files:
-     tools/discover-mdxfind.pl --lean --untyped -v --work <dir2>
END_ONE
}

printf STDERR "- sweep ran %d of this tool's %d identifier(s)\n",
    scalar(grep { $covered{$_} } @ident), scalar @ident;

#-----------------------------------------------------------------------
# Classify.

my $today   = strftime('%Y-%m-%d', localtime);
my $version = $inv->{version} // 'unknown';

my (@absent, @candidate, @unsearched, @novector, @swept_hit, @partial,
    @maskrisk, @hp_hit, @othertext, %napplicable);

for my $id (sort keys %target) {
    my $e = $entry{$id};
    my @v = ref $e->{vectors} eq 'ARRAY' ? @{ $e->{vectors} } : ();

    # A name match is a candidate mapping, not an absence.
    my @ids = ($e->{id}, $e->{name}, @{ $e->{aliases} || [] });
    push @ids, values %{ $e->{legacy} || {} };
    my (@exact, %seen);
    for my $cand (grep { defined && length } @ids) {
        my $n = norm($cand) or next;
        push @exact, grep { !$seen{$_}++ } @{ $ident_by_norm{$n} || [] };
    }
    if (@exact) { push @candidate, [ $id, join(', ', @exact) ]; next }

    unless (@v)        { push @novector,  [ $id, '' ]; next }
    if ($hits{$id})    { push @swept_hit, [ $id, join(', ', sort keys %{ $hits{$id} }) ]; next }

    # SAME HASH, ANOTHER PLAINTEXT.
    #
    # Two entries can record the same hash and disagree about what the tool is
    # fed as the password. hashcat mode 2100 takes the password and mode 31600
    # takes the NT hash of it, and both describe DCC2; the same split gives
    # this repository a "-nt" row beside the ordinary one for MSCACHE,
    # NETNTLMv1, NETNTLMv2 and Kerberos TGS-REP etype 23. The sweep then cracks
    # the hash under the OTHER row's plaintext, this row draws no hit of its
    # own, and the literal reading -- no identifier of this tool reproduced
    # this (hash, plaintext) pair -- is true and publishes as "mdxfind does not
    # support NetNTLMv2", which it does.
    #
    # Measured 2026-09-03 on the mdxfind sweep: five entries in exactly this
    # position, all of them the NT-hash-input variant of an algorithm the tool
    # names. It is an input-encoding relation waiting to be curated, so it is
    # reported and never written.
    my %othertype;
    for my $v (@v) {
        next unless defined $v->{hash};
        my $t = $cracked_hash{ lc $v->{hash} } or next;
        $othertype{$_} = 1 for keys %$t;
    }
    if (%othertype) {
        push @othertext, [ $id, join(', ', sort keys %othertype) ];
        next;
    }

    # hashpipe names a type the sweep did not find. If mdxfind has that type
    # too, the sweep merely failed to arrange the question and this
    # contradicts an absence. If it does not, mdxfind really has no such type
    # and the hit corroborates -- see the methodology note.
    if ($hp_type{$id} && !$hp_only{ $hp_type{$id} }) {
        push @hp_hit, [ $id, $hp_type{$id} ];
        next;
    }

    my @applicable = applicable_for($e);
    unless (@applicable) {
        push @unsearched, [ $id, sprintf('no %s identifier can parse this '
            . 'vector, so it cannot ask the question', $tool) ];
        next;
    }

    my @miss = uncovered_for($e, @applicable);
    if (@miss) {
        push @partial, [ $id, sprintf('%d identifier(s) never run, first %s',
            scalar @miss, $miss[0]) ];
        next;
    }

    # A vector the sweep could not tell apart from another corpus hash was
    # perhaps reported as that other hash and not as itself. Held back.
    my @eclipsed = grep {
        my ($head) = split /:/, ($_->{hash} // ''), 2;
        defined $head && $masked{ lc $head };
    } @v;
    if (@eclipsed && @eclipsed == @v) {
        push @maskrisk, [ $id, sprintf('%d vector(s) indistinguishable from '
            . 'another corpus hash at the sweep comparison width', scalar @v) ];
        next;
    }

    my @s = grep { $searched_shape{ shape($_->{hash}) } } @v;
    unless (@s) {
        push @unsearched, [ $id, sprintf('%d vector(s), shape(s) %s, no control',
            scalar @v, join('/', map { shape($_->{hash}) } @v)) ];
        next;
    }
    # No absence without the second oracle having been asked.
    if ($tool eq 'mdxfind' && !$no_hashpipe && !$hp_asked{$id}) {
        push @unsearched, [ $id, 'hashpipe was not asked about this entry, '
            . 'and an mdxfind absence is not written without it' ];
        next;
    }

    push @absent, [ $id, sprintf('%d of %d vector(s) in a searched shape (%s); '
        . '%d applicable %s', scalar @s, scalar @v, shape($s[0]{hash}),
        scalar @applicable, $tool eq 'hashcat' ? 'mode(s)' : 'type(s)') ];
    $napplicable{$id} = scalar @applicable;
}

#-----------------------------------------------------------------------
# Report, then optionally write.

printf STDERR "- %d target(s): %d with no %s verdict, %d re-earning a bare one\n",
    scalar keys %target,
    (scalar keys %target) - (scalar keys %bare_target), $tool,
    scalar keys %bare_target;
printf STDERR "-   %-28s %d\n", $_->[0], scalar @{ $_->[1] } for
    [ 'absent (swept, nothing)'   => \@absent     ],
    [ 'candidate (name match)'    => \@candidate  ],
    [ 'unsearched (no control)'   => \@unsearched ],
    [ 'partial (identifier unrun)'=> \@partial    ],
    [ 'masked (width collision)'  => \@maskrisk   ],
    [ 'no vector at all'          => \@novector   ],
    [ 'sweep found an identifier' => \@swept_hit  ],
    [ 'same hash, other plaintext'=> \@othertext  ],
    [ 'hashpipe names a type'     => \@hp_hit     ];

# A bare claim the evidence CONTRADICTS is the outcome worth a reader's time,
# and it is never written: see the methodology note.
my @contradicted = grep { $bare_target{ $_->[0] } } @candidate, @swept_hit;
if (@contradicted) {
    printf STDERR "\n- %d bare 'absent' claim(s) the evidence CONTRADICTS."
                . " Not written; a curator decides:\n", scalar @contradicted;
    printf STDERR "    %-52s %s\n", @$_ for @contradicted;
}

if ($verbose) {
    for my $g ([ 'ABSENT'     => \@absent     ], [ 'CANDIDATE' => \@candidate  ],
               [ 'UNSEARCHED' => \@unsearched ], [ 'PARTIAL'   => \@partial    ],
               [ 'MASKED'     => \@maskrisk   ],
               [ 'NO VECTOR'  => \@novector   ], [ 'SWEEP HIT' => \@swept_hit  ],
               [ 'SAME HASH, ANOTHER PLAINTEXT' => \@othertext ],
               [ 'HASHPIPE NAMES A TYPE' => \@hp_hit ]) {
        next unless @{ $g->[1] };
        print STDERR "\n- $g->[0]\n";
        printf STDERR "    %-52s %s\n", @$_ for @{ $g->[1] };
    }
}

if (%parser_blind) {
    print STDERR <<"END_WARN";

- mdxfind's own summary names @{[ scalar keys %parser_blind ]} type(s) it found hashes for whose report
  lines this parser did not recognise. Every entry such a type cracked reads
  as unswept, and an unswept entry is one step from a false 'absent'. Nothing
  is written until the parser is fixed.
END_WARN
    printf STDERR "    %-28s first seen in %s\n", $_, $parser_blind{$_}
        for sort keys %parser_blind;
}

unless ($controls_ok && !%parser_blind) { exit 1 }
unless ($apply) {
    print STDERR "\n- dry run; nothing written. Add --apply to write the 'absent' class.\n";
    exit 0;
}

my $what = $tool eq 'mdxfind' ? 'type' : 'mode';

# note_for($id) - the evidence, in the entry's own terms. The denominator is
# per entry for hashcat: "none of 592 modes" is true and misleading, since
# most could never have parsed the hash, and hashcat's own --identify says
# which could.
sub note_for {
    my ($id) = @_;
    my $scope = $tool eq 'hashcat' && $napplicable{$id}
        ? "the $napplicable{$id} mode(s) whose parser accepts this entry's own "
        . "vector, as hashcat --identify lists them,"
        : "all " . scalar(@ident) . " $tool ${what}s";
    my $howmany = ($tool eq 'mdxfind' && defined $runs_per_chunk)
                ? ($runs_per_chunk > 1
                   ? ", in $runs_per_chunk separate runs over different corpora,"
                   : ", in a single run,")
                : '';
    return "no $what. Swept $scope on $today$howmany "
         . "(a tools/discover-$tool.pl sweep, evidence read by tools/absence.pl): "
         . "not one reproduced this entry's own vector. That the vector was IN "
         . "the search is not assumed -- the same sweep reported a hit on "
         . "another vector of the same shape, a positive control measured in "
         . "the same run by the same binary, and without it finding nothing "
         . "would not be evidence. Every applicable $what ran to completion; a "
         . "$what killed at the timeout is counted as untested and withholds "
         . "this verdict. No $tool $what name matches any identifier this entry "
         . "publishes either, normalised by the separator-drift rule. "
         . ($tool eq 'mdxfind' && !$no_hashpipe
            ? ($hp_type{$id}
               ? "hashpipe DOES cover this algorithm, as type $hp_type{$id}, "
               . "which mdxfind has no equivalent of -- so that is corroboration "
               . "rather than contradiction, and it is recorded here because "
               . "there is no hashpipe column to record it in. "
               : "Corroborated by hashpipe, a second binary built from the same "
               . "catalog: handed this entry's own hash and plaintext it names "
               . "no type at all. It is the more direct instrument -- it "
               . "recomputes rather than cracking -- and on this corpus it named "
               . "a type for 58 entries the sweep alone called silent. ")
            : "")
         . "This is "
         . "the absence of an IDENTIFIER, not of the algorithm: if $tool gains "
         . "one, this becomes a mapping.";
}

my $written = 0;
for my $row (@absent) {
    my ($id) = @$row;
    my $e = $entry{$id};
    my $note = note_for($id);
    $e->{tools}{$tool} = {
        verified      => 'absent',
        verified_at   => $today,
        verified_with => "$tool $version",
        note          => $note,
    };
    $written++ if emit_entry($path{$id}, $e);
}
printf STDERR "- wrote 'absent' onto %d entry(ies)\n", $written;
exit 0;
