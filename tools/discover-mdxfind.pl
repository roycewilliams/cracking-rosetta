#!/usr/bin/perl
#-----------------------------------------------------------------------
#
# Name: discover-mdxfind.pl
# Description: find which mdxfind types crack entries that carry no mdxfind mapping
# Category: cracking-rosetta verifier
#
# Project: cracking-rosetta | Phase: 10 - make the rows cross-reference
#
#-----------------------------------------------------------------------
# METHODOLOGY AND WHY THESE CHOICES
#
# THE PROBLEM
#
# 467 entries carry a vector and name no mdxfind type at all -- almost all of
# them rows seeded from a hashcat mode or a john format, which is the shape
# the tenth session exists to fix. discover-john.pl and discover-hashcat.pl
# answer the same question for their own columns; this is the third.
#
# IT IS NOT A SEARCH, AND THAT IS THE WHOLE POINT
#
# The other two tools try one identifier at a time because that is the only
# way hashcat and john will answer. mdxfind will test MANY types in one run
# and PRINTS THE NAME of the type that matched -- "MD5x01 <hash>:<plain>" --
# so the answer comes back directly rather than being inferred from which
# invocation happened to succeed. Looping 1001 types one at a time would be
# both far slower and strictly less informative.
#
# So the corpus goes in once per CHUNK of types, and the chunk exists only
# because of cost, not semantics: a handful of type families (BCRYPT, SCRYPT,
# ARGON2, the PBKDF2s, the *CRYPTs) are thousands of times slower than the
# rest, and in one 1001-type run they set the pace for everything. Chunked by
# internal index with a per-chunk timeout, a slow family times out alone and
# is reported by name, and the other 950 types still answer. Measured
# 2026-08-31: a single full-catalog run over TWO hashes had not finished in
# ten minutes.
#
# -F, NOT -f, FOR THE WHOLE CORPUS
#
# verify-vectors.pl picks -f or -F from the TYPE's flags, because it already
# knows the type. Discovery does not. Measured here: -F reads a plain
# unsalted line and a "<hash>:<salt>" line correctly IN THE SAME FILE -- the
# plain hash still fell to MD5x01 while the salted one fell to MD5MD5USERx01
# -- so one corpus file read with -F covers both and no second sweep is
# needed. -f cannot do the reverse: it read the salted line as an opaque
# string and found nothing.
#
# WHY A CRACK IS PROOF AND NOT A COINCIDENCE
#
# If mdxfind reports type T reproducing entry E's recorded hash from E's
# recorded plaintext, then T computes E's algorithm on that input. That is
# tier 'vector' in CLAUDE.md. Nothing is inferred from a name or a length.
#
# THE PRINTED HASH MUST BE THE ENTRY'S OWN, CHARACTER FOR CHARACTER
#
# This is the guard that matters here, and it is not the same one the other
# two tools need. mdxfind matches on the RAW DIGEST, after decoding whatever
# representation the input was in -- so a bare hex SHA-1 in the corpus is
# also matched by APACHE-SHA, whose digests are "{SHA}"+base64. Measured
# 2026-08-31: the corpus line was hex and mdxfind duly printed
# "APACHE-SHAx01 {SHA}y/2sYAj5yrQIN4TL0YdPdmGNKpc=:password123".
#
# Recording APACHE-SHA on a raw-SHA-1 row would be false: the tool folded an
# encoding difference that the row is precisely about. So a report counts only
# when the hash mdxfind echoes is the hash the entry carries, compared
# case-folded and nothing else. Case is folded because mdxfind normalises hex
# on read and echoes its own case; every other rewrite is a different
# representation and is refused.
#
# MATCHING IS ON HASH AND PLAINTEXT TOGETHER
#
# Every vector imported from the sheet carries the plaintext "rosetta", so a
# batch holds hundreds of hashes sharing one password; crediting on the
# plaintext alone is a false positive verify-vectors.pl has actually hit.
#
# THE ITERATION SUFFIX IS PART OF THE IDENTITY
#
# MD5x01 is not MD5x02: CLAUDE.md records 42 entries that reached tier
# 'vector' on a verifier that accepted any suffix. The run pins -i, and only
# a report whose printed suffix equals that value is counted. Since the schema
# carries `iterations` once per mdxfind BLOCK rather than per type, a run at
# one iteration count can only ever write a block at that count, which is why
# --iterations is a single value and defaults to 1.
#
# AN ENTRY THAT ALREADY NAMES AN MDXFIND TYPE IS HELD, NEVER EXTENDED
#
# This is where this tool is deliberately more conservative than its two
# siblings. For most rows here the mdxfind type IS the row's identity -- the
# id was derived from it -- so a SECOND type appearing on the row is a
# curation question rather than a fact: is it the same computation, or the
# collides-on-subset relation that MD5 and MD5CAP have, or the encoding
# relation that MD5 and MD5UC have? CLAUDE.md reserves that judgement for a
# person. So the finding is reported and never written, and the 156 rows the
# ninth session flagged as "NOT REPRODUCED HERE" keep their note intact
# instead of quietly acquiring a different type beside it.
#
# A MULTI-EMIT TYPE IS NEVER WRITTEN, ONLY REPORTED
#
# At least 48 of mdxfind's types compute SEVERAL candidate digests per
# candidate password and match if ANY of them reproduces the stored hash
# (CLAUDE.md; hx specification rev 1.15 Appendix A, note [24] plus the rows
# that spell emit() themselves). So "SHA1MD5USER reproduced this row's vector"
# does not say the row's algorithm is SHA1MD5USER -- it says the row's
# algorithm is ONE OF the several things that type emits, and which one is
# curation. This is the same defect md5-md5-plain-salt-3 carries in its notes,
# arrived at from the other direction. RosettaHx::is_multi_emit() is the
# authority, because it reads both halves of the population; the note alone is
# not the whole list.
#
# WHAT DOES NOT GET APPLIED AUTOMATICALLY
#
# --max-per-entry holds back an entry claimed by more types than an algorithm
# plausibly has names; --max-share holds back a type claiming a large share of
# the corpus. Both exist because at this scale a permissive identifier
# produces confident nonsense. An entry whose vectors disagree on the type set
# is held too: that is either a collation error or a MULTI-EMIT type, and the
# union would put two algorithms in one row.
#
# FAILURE NEVER DEMOTES, AND NEITHER DOES SILENCE
#
# An entry no type reproduces is left exactly as it was.
#
# DEPENDENCIES: perl, YAML::XS, an mdxfind binary.
#
#-----------------------------------------------------------------------
# Generated by Claude Opus 5 on 2026-08-31

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
use RosettaHx qw(is_multi_emit);
use RosettaTools qw(tool_path tool_env_help);

my $PROG = basename($0);
my $ROOT = "$RealBin/..";

sub usage {
    print STDERR <<"END_USAGE";

Usage: $PROG [options]

   --mdxfind PATH    mdxfind binary  (default: @{[tool_env_help('mdxfind')]})
   --algorithms DIR  curated entries (default: data/algorithms)
   --inventory PATH  mdxfind inventory (default: data/tools/mdxfind.yaml)
   --work DIR        scratch         (default: tmp/discover-mdxfind)
                     MUST be absolute if you override it
   --chunk N         types per mdxfind run (default 50)
   --timeout SECS    per chunk       (default 300)
   --iterations N    mdxfind -i value (default 1); only a report whose
                     printed suffix is exactly this counts
   --limit N         stop after N chunks; for smoke tests
   --type REGEX      only types whose name matches (repeatable)
   --index LO-HI     only types whose internal index is in this range
   --lean            trim the corpus to the target vectors plus ONE
                     already-proven vector per hash shape (not with --all)
   --only ID         only consider this entry
   --exclude ID      never write a mapping for this entry (repeatable); it is
                     still measured and reported, so the reason stays visible
   --all             target every entry with a vector, not just the unmapped
   --untyped         target ONLY entries naming no mdxfind type at all; this
                     is the set absence.pl publishes about (not with --all)
   --extend          also write onto entries that already name a type
                     (off by default; see the methodology note)
   --multi-emit      also write types that emit several digests per candidate
                     (off by default; see the methodology note)
   --max-per-entry N hold back entries matched by more than N types
                     (default 6; they are reported, never written)
   --max-share PCT   hold back a type matching more than PCT% of the corpus
                     (default 20)
   --resume          reuse per-chunk results already in the work dir
   --apply           write the discovered mappings into data/algorithms
   -n, --dry-run     show the plan; run nothing, write nothing
   -v, --verbose     per-chunk result (repeatable)
   -h, --help        this help

   Without --apply nothing is written: the run reports what it found and the
   work dir keeps the evidence. Exit 0 success, 1 error, 2 usage.

END_USAGE
    return;
}

my ($mdxfind, $algdir, $inventory, $workdir, $only, $help, $dry, $apply);
my ($all, $resume, $extend, $want_multi, $lean, $index_range, $untyped);
my (@type_re, @exclude);
my $chunk         = 50;
my $timeout       = 300;
my $iterations    = 1;
my $limit         = 0;
my $verbose       = 0;
my $had_args      = scalar @ARGV;   # house rule: no arguments means show usage
my $max_per_entry = 6;
my $max_share     = 20;

GetOptions(
    'mdxfind=s'       => \$mdxfind,
    'algorithms=s'    => \$algdir,
    'inventory=s'     => \$inventory,
    'work=s'          => \$workdir,
    'chunk=i'         => \$chunk,
    'timeout=i'       => \$timeout,
    'iterations=i'    => \$iterations,
    'limit=i'         => \$limit,
    'type=s'          => \@type_re,
    'index=s'         => \$index_range,
    'lean'            => \$lean,
    'only=s'          => \$only,
    'exclude=s'       => \@exclude,
    'all'             => \$all,
    'untyped'         => \$untyped,
    'extend'          => \$extend,
    'multi-emit'      => \$want_multi,
    'max-per-entry=i' => \$max_per_entry,
    'max-share=i'     => \$max_share,
    'resume'          => \$resume,
    'apply'           => \$apply,
    'n|dry-run'       => \$dry,
    'v|verbose+'      => \$verbose,
    'h|help'          => \$help,
) or do { usage(); exit 2 };

if ($help) { usage(); exit 0 }
if (!$had_args) { usage(); exit 2 }

$mdxfind = tool_path('mdxfind', $mdxfind);
$algdir    //= "$ROOT/data/algorithms";
$inventory //= "$ROOT/data/tools/mdxfind.yaml";
$workdir   //= "$ROOT/tmp/discover-mdxfind";
$workdir = "$ROOT/$workdir" unless $workdir =~ m{^/};

make_path($workdir) unless -d $workdir;
my $today = strftime('%Y-%m-%d', localtime);

die "$PROG: mdxfind not executable at $mdxfind\n" unless -x $mdxfind;
die "$PROG: --chunk must be at least 1\n" if $chunk < 1;

#-----------------------------------------------------------------------
# Inventory: the candidate identifiers, in internal-index order because that
# is the order -m eA-eB selects them in.

my $inv = eval { YAML::XS::LoadFile($inventory) }
    or do { print STDERR "$PROG: cannot load $inventory: $@\n"; exit 1 };

my $mx_version = $inv->{version} // 'mdxfind';

my @types = grep { defined $_->{index_num} && defined $_->{name} }
            @{ $inv->{types} || [] };
@types = sort { $a->{index_num} <=> $b->{index_num} } @types;

if (@type_re) {
    my @re = map { qr/$_/i } @type_re;
    @types = grep { my $t = $_->{name}; grep { $t =~ $_ } @re } @types;
}

# --index selects the same way -m eLO-eHI does, which is what makes a chunk
# re-runnable on its own: the work dir's file is named for the range, so
# "--index 901-950" rewrites exactly out/e901-e950.txt and nothing else.
if (defined $index_range) {
    my ($lo, $hi) = $index_range =~ /^(\d+)-(\d+)$/;
    unless (defined $lo && $lo <= $hi) {
        print STDERR "$PROG: --index wants LO-HI with LO <= HI, not '$index_range'\n";
        exit 2;
    }
    @types = grep { $_->{index_num} >= $lo && $_->{index_num} <= $hi } @types;
    unless (@types) {
        print STDERR "$PROG: --index $index_range selects no type\n";
        exit 1;
    }
}

my %is_type = map { $_->{name} => 1 } @types;

# Chunks are contiguous runs of internal index, so each is one -m eA-eB.
my @chunks;
for (my $i = 0; $i < @types; $i += $chunk) {
    my $end = $i + $chunk - 1;
    $end = $#types if $end > $#types;
    push @chunks, [ @types[$i .. $end] ];
}

#-----------------------------------------------------------------------
# Entries.

opendir(my $dh, $algdir) or do { print STDERR "$PROG: cannot read $algdir: $!\n"; exit 1 };
my @files = sort grep { /\.yaml$/ } readdir $dh;
closedir $dh;

my (%entry, %path);
for my $f (@files) {
    my $p = "$algdir/$f";
    my $e = eval { YAML::XS::LoadFile($p) };
    next unless $e && $e->{id};
    next if ($e->{status} // '') eq 'merged';     # a tombstone is not an algorithm
    next if defined $only && $e->{id} ne $only;
    $entry{ $e->{id} } = $e;
    $path{  $e->{id} } = $p;
}

# WHY --lean EXISTS, AND WHAT IT COSTS
#
# mdxfind pools the salt field of every line it reads, so a salted type costs
# words x salts and the corpus's own size is the multiplier. Measured
# 2026-09-03 on the --all corpus -- 1668 lines, 485 of them salted, 126 unique
# plaintexts -- the e901-e950 chunk of slow KDF and container types (DCC2,
# ECRYPTFS, ANDROIDFDE, PWSAFE3, APFS, the SAP family) did not finish at 300
# seconds, did not finish at 3600, and had still not finished at 900 with the
# thirteen longest salts removed. mdxfind reported "found 189 unique salts"
# for a typical salted type.
#
# The salt pool is almost entirely NOT the targets: of 444 unique target
# hashes only 39 carry a salt. Dropping the already-proven vectors that are
# not needed as shape controls therefore takes the pool from 189 to 10 and
# leaves the question intact -- the same chunk then runs in ONE second.
#
# What survives is what the question needs. Every target vector is present
# with its own hash, its own salt and its own plaintext, so any type that can
# reproduce a target has everything required to do so; and one already-proven
# vector per hash shape is kept so a sweep still reports a hit at each shape,
# which is what absence.pl requires before it will call a shape searched.
#
# What is lost, and it is real: with the full corpus a bare digest whose entry
# records no salt could still fall to some OTHER entry's salt. Under --lean
# there are fewer foreign salts to fall to. That trades discovery sensitivity
# for a chunk that terminates, so --lean is a deliberate flag and not the
# default.
#
# --all makes every entry a target, so there is nothing left to trim; the two
# together are a contradiction rather than a no-op, and are refused.
if ($untyped && $all) {
    print STDERR "$PROG: --untyped and --all contradict: one narrows the target\n"
               . "  set to the entries with no mapping, the other widens it to all.\n";
    exit 2;
}

if ($lean && $all) {
    print STDERR "$PROG: --lean and --all contradict: --all makes every entry\n"
               . "  a target, so there are no already-proven vectors to trim.\n";
    exit 2;
}

# shape($hash) - absence.pl's definition, deliberately identical: a control
# only speaks for a shape if the two tools agree on what a shape is.
sub shape {
    my ($h) = @_;
    my ($head) = split /:/, $h, 2;
    return 'nonhex' unless $head =~ /^[0-9A-Fa-f]+$/;
    return 'hex:' . length($head);
}

my @vectors;   # { id, hash, pass, vid }
my %targets;
my %already_typed;
my %ctl_by_shape;   # shape -> [ vectors of entries this run is NOT targeting ]
for my $id (sort keys %entry) {
    my $e = $entry{$id};
    my $m = $e->{tools}{mdxfind};
    $already_typed{$id} = 1 if $m && @{ $m->{types} || [] };
    # Three points on one axis: --all targets everything, --untyped targets
    # only what has no mapping at all, and the default sits between them at
    # "not yet proven". Only --untyped matches the question absence.pl asks,
    # which is why an absence sweep uses it -- see the --lean note.
    my $skip = $all     ? 0
             : $untyped ? (($m && @{ $m->{types} || [] }) ? 1 : 0)
             :            (($m && ($m->{verified} // '') eq 'vector') ? 1 : 0);
    for my $v (@{ $e->{vectors} || [] }) {
        next unless defined $v->{hash} && defined $v->{pass};
        next if $v->{hash} =~ /\n/ || $v->{pass} =~ /\n/;   # one hash per line
        if ($skip) {
            push @{ $ctl_by_shape{ shape($v->{hash}) } },
                 { id => $id, hash => $v->{hash}, pass => $v->{pass} };
            next;
        }
        push @vectors, { id => $id, hash => $v->{hash}, pass => $v->{pass},
                         vid => "$id\0" . scalar(@vectors) };
        $targets{$id} = 1;
    }
}

# One control per shape, unsalted for preference: a control costs a corpus
# line either way, and only a salted one costs a salt.
my @control;
if ($lean) {
    for my $s (sort keys %ctl_by_shape) {
        my ($pick) = grep { $_->{hash} !~ /:/ } @{ $ctl_by_shape{$s} };
        $pick //= $ctl_by_shape{$s}[0];
        push @control, $pick;
    }
    my $pool = 0;
    $pool += scalar @{ $ctl_by_shape{$_} } for keys %ctl_by_shape;
    printf STDERR "- lean corpus: %d shape control(s) kept, %d proven vector(s) dropped\n",
        scalar @control, $pool - scalar @control;
}

if (!@vectors) {
    print STDERR "$PROG: nothing to do -- no target entry carries a vector.\n";
    exit 0;
}

printf STDERR "- %d type(s) in %d chunk(s) x %d vector(s) from %d entry/entries\n",
    scalar @types, scalar @chunks, scalar @vectors, scalar keys %targets;

#-----------------------------------------------------------------------
# Helpers.

sub write_file {
    my ($p, @lines) = @_;
    open my $fh, '>', $p or die "cannot write $p: $!\n";
    print {$fh} "$_\n" for @lines;
    close $fh;
    return $p;
}

sub slurp {
    my ($p) = @_;
    open my $fh, '<', $p or return '';
    local $/;
    my $t = <$fh> // '';
    close $fh;
    return $t;
}

# mode_spec(\@types) - the -m argument naming exactly these types and no
# others. Contiguous internal indices compress to a range (mdxfind accepts
# "e10-e59"), and the runs are joined with commas ("e1,e5-e8"). Emitting a
# bare lo-hi range instead would silently pull in every type BETWEEN the ones
# selected, which is wrong the moment --type filters the list -- and expensive,
# since the slow KDF families are what a filter is usually excluding.
sub mode_spec {
    my ($list) = @_;
    my @idx = sort { $a <=> $b } map { $_->{index_num} } @$list;
    my @parts;
    my $i = 0;
    while ($i <= $#idx) {
        my $j = $i;
        $j++ while $j < $#idx && $idx[$j + 1] == $idx[$j] + 1;
        push @parts, $i == $j ? "e$idx[$i]" : "e$idx[$i]-e$idx[$j]";
        $i = $j + 1;
    }
    return join ',', @parts;
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
# The corpus is identical for every chunk, so it is written once. -F reads
# both the plain and the "<hash>:<salt>" lines; see the methodology note.

my $hashfile = "$workdir/corpus.hash";
my $wordfile = "$workdir/corpus.word";

my %uniq_hash;
write_file($hashfile, grep { !$uniq_hash{$_}++ }
                      map { $_->{hash} } (@vectors, @control));

# A control's plaintext has to be in the wordlist or the control cannot fall,
# but it is deliberately NOT in @words_by_len: that list is how a report line
# is split back into hash and plaintext, and only a TARGET's plaintext may win
# that split.
my %uniq_word;
my @words     = grep { !$uniq_word{$_}++ } map { $_->{pass} } @vectors;
my @ctl_words = grep { !$uniq_word{$_}++ } map { $_->{pass} } @control;
write_file($wordfile, @words, @ctl_words);

# Longest first: a report line is split from the right against this set, and
# "pass" must not win over "pass:word" where the corpus holds both.
my @words_by_len = sort { length($b) <=> length($a) || $a cmp $b } @words;

# Case-folded index of the corpus. mdxfind normalises hex on read and echoes
# its own case; anything it rewrites further is a different representation and
# must not match. The value is a list because two entries may carry the same
# vector.
my %by_fold;
push @{ $by_fold{ lc($_->{hash}) . "\0" . $_->{pass} } }, $_ for @vectors;

#-----------------------------------------------------------------------
# One mdxfind run per chunk of types.

my %hits;          # entry id -> type -> 1
my %per_vector;    # vector id -> type -> 1
my %type_hits;     # type -> count of entries
my (%timed_out, %ran_chunk);
my $started = time;
my $n = 0;

make_path("$workdir/out") unless -d "$workdir/out";

CHUNK: for my $c (@chunks) {
    last if $limit && $n >= $limit;
    $n++;

    my $spec = mode_spec($c);
    my $outf = "$workdir/out/" . sprintf('e%d-e%d', $c->[0]{index_num},
                                                    $c->[-1]{index_num}) . ".txt";

    if ($dry) {
        printf STDERR "-   would run -m %s (%s .. %s)\n",
            $spec, $c->[0]{name}, $c->[-1]{name} if $verbose;
        next;
    }

    my $out;
    if ($resume && -e $outf) {
        # Evidence from an earlier run; re-read it rather than re-cracking.
        $out = slurp($outf);
    }
    else {
        my $code;
        ($code, $out) = run_capture($timeout, $mdxfind,
            '-m', $spec, '-F', $hashfile, '-i', $iterations, $wordfile);
        $timed_out{$spec} = 1 if $code == -2;
        write_file($outf, split /\n/, $out // '');
    }
    $ran_chunk{$spec} = 1;

    # A report is "TYPExNN <hash>[:<salt>]:<plain>", or "TYPE <hash>...:<plain>"
    # where the type does not iterate. The suffix is printed under "if (x > 0)"
    # (mdxfind.c, every emitter around lines 10264-10703) and the same block
    # tallies the find at TOTALFOUND(op)[x > 0 ? x - 1 : 0], whose slot 0 the
    # end-of-run summary prints as "x01" -- so a BARE line is iteration 1,
    # stated by the binary in its own totals rather than assumed here.
    # Requiring the suffix hid 235 of the 1152 report lines of the 2026-09-03
    # sweep, among them every HMAC, SCRYPT, MSSQL and NETNTLM hit.
    #
    # No type in the inventory ends in x<digits>, so stripping a trailing
    # suffix cannot eat a name.
    #
    # The plaintext may itself contain a colon, so the tail is matched against
    # the known set rather than split on a fixed occurrence.
    my $found = 0;
    LINE: for my $line (split /\n/, $out // '') {
        next unless $line =~ /^(\S+)\s+(.+)$/;
        my ($tok, $rest) = ($1, $2);
        my ($type, $it) = ($tok, 1);
        unless ($is_type{$type}) {
            ($type, $it) = ($1, $2 + 0) if $tok =~ /^(\S+)x(\d+)$/;
        }
        next unless $is_type{$type};        # not a type name: a progress line
        next unless $it == $iterations;     # the suffix is part of the identity
        for my $w (@words_by_len) {
            my $tail = ":$w";
            next unless length($rest) > length($tail);
            next unless substr($rest, -length($tail)) eq $tail;
            my $printed = substr($rest, 0, length($rest) - length($tail));
            for my $v (@{ $by_fold{ lc($printed) . "\0" . $w } || [] }) {
                $per_vector{ $v->{vid} }{$type} = 1;
                next if $hits{ $v->{id} }{$type}++;
                $found++;
            }
            next LINE;
        }
    }

    printf STDERR "-   [%3d/%3d] -m %-13s %3d hit(s)%s\n",
        $n, scalar @chunks, $spec, $found,
        ($timed_out{$spec} ? " [TIMEOUT ${timeout}s]" : '')
        if $verbose && ($found || $verbose > 1 || $timed_out{$spec});
}

my $elapsed = time - $started;

# Per-type entry counts, for the --max-share guard.
for my $id (keys %hits) { $type_hits{$_}++ for keys %{ $hits{$id} } }

#-----------------------------------------------------------------------
# Decide what may be written.

my $corpus = scalar keys %targets;
my %noisy_type = map { $_ => 1 }
                 grep { $type_hits{$_} * 100 > $max_share * $corpus }
                 keys %type_hits;

# A multi-emit type reproducing a vector does not identify the vector; see the
# methodology note. It rides in the same %noisy_type set because the decision
# is the same one -- report it, never write it -- and the held-back line then
# names it like any other over-broad identifier.
my %multi_emit;
unless ($want_multi) {
    for my $t (keys %type_hits) {
        next unless is_multi_emit($t);
        $multi_emit{$t} = 1;
        $noisy_type{$t} = 1;
    }
}

my %excluded = map { $_ => 1 } @exclude;

my (@apply_list, @held);
for my $id (sort keys %hits) {
    my @t = sort keys %{ $hits{$id} };
    my @clean = grep { !$noisy_type{$_} } @t;

    my @sets = map  { join ' ', sort grep { !$noisy_type{$_} } keys %{ $per_vector{$_} } }
               grep { %{ $per_vector{$_} } }
               grep { (split /\0/)[0] eq $id } keys %per_vector;
    my %distinct = map { $_ => 1 } grep { length } @sets;

    if (keys %distinct > 1) {
        push @held, [$id, \@clean,
                     'this entry\'s vectors disagree: ' .
                     join(' | ', sort keys %distinct)];
    }
    elsif ($excluded{$id}) {
        push @held, [$id, \@t, 'named in --exclude'];
    }
    elsif ($already_typed{$id} && !$extend) {
        push @held, [$id, \@clean,
                     'entry already names ' .
                     join(' ', @{ $entry{$id}{tools}{mdxfind}{types} }) .
                     '; a second type is curation, not a fact'];
    }
    elsif (!@clean) {
        push @held, [$id, \@t, 'every matching type is over-broad'];
    }
    elsif (@clean > $max_per_entry) {
        push @held, [$id, \@clean, sprintf('%d types > --max-per-entry %d',
                                           scalar @clean, $max_per_entry)];
    }
    else {
        push @apply_list, [$id, \@clean];
    }
}

#-----------------------------------------------------------------------
# Report. Data on stdout, progress and counts on stderr.

for my $r (@apply_list) {
    my ($id, $t) = @$r;
    printf "%-40s %s\n", $id, join(' ', @$t);
}
if (@held) {
    print "\n# held back for review\n";
    for my $r (@held) {
        my ($id, $t, $why) = @$r;
        printf "# %-38s %s  (%s)\n", $id, join(' ', @$t), $why;
    }
}

printf STDERR "- ran %d chunk(s) in %.1fs%s\n", $n, $elapsed,
    ($dry ? ' (dry run)' : '');
printf STDERR "-   entries matched %d of %d target(s); applicable %d, held %d\n",
    scalar(keys %hits), $corpus, scalar @apply_list, scalar @held;
if (%noisy_type) {
    printf STDERR "-   %d over-broad type(s) ignored (> %d%% of the corpus): %s\n",
        scalar keys %noisy_type, $max_share,
        join(' ', map { "$_=$type_hits{$_}" } sort keys %noisy_type);
}
if (%multi_emit) {
    printf STDERR "-   %d multi-emit type(s) reported but never written: %s\n",
        scalar keys %multi_emit, join(' ', sort keys %multi_emit);
}
if (%timed_out) {
    printf STDERR "-   %d chunk(s) hit the %ds timeout, so the types in them "
                . "were NOT tested: %s\n",
        scalar keys %timed_out, $timeout, join(' ', sort keys %timed_out);
}

#-----------------------------------------------------------------------
# Apply.

if ($apply && !$dry) {
    my $changed = 0;
    for my $r (@apply_list) {
        my ($id, $t) = @$r;
        my $e = $entry{$id} or next;
        my $blk = $e->{tools}{mdxfind} ||= {};

        my %ty = map { $_ => 1 } @{ $blk->{types} || [] }, @$t;
        $blk->{types} = [ sort keys %ty ];
        $blk->{iterations} = $iterations if $iterations > 1;
        delete $blk->{supported};

        my $proven = !grep { !$hits{$id}{$_} } @{ $blk->{types} };
        if ($proven) {
            $blk->{verified}      = 'vector';
            $blk->{verified_at}   = $today;
            $blk->{verified_with} = "mdxfind $mx_version";
            $blk->{note} = 'type discovered by round-trip search, not by name';
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
