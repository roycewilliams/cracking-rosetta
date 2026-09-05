#!/usr/bin/perl
#-----------------------------------------------------------------------
#
# Name: discover-hashcat.pl
# Description: find which hashcat modes crack entries that carry no hashcat mapping
# Category: cracking-rosetta verifier
#
# Project: cracking-rosetta | Phase: 10 - make the rows cross-reference
#
#-----------------------------------------------------------------------
# METHODOLOGY AND WHY THESE CHOICES
#
# THE PROBLEM
#
# The ninth session made the repository FINDABLE: every hashcat mode, mdxfind
# type and john format now lands a reader on some row. It did not make those
# rows a CROSS-REFERENCE -- two thirds of them name exactly one tool, and a
# row that names one tool cannot tell anybody what to call the thing anywhere
# else, which is what they came here for.
#
# discover-john.pl answers "does any john format crack this entry's vector?"
# by running them. There was no symmetric tool, so a row seeded from john or
# mdxfind could never acquire a hashcat mode. This is that tool. It is
# deliberately a near-transcription of discover-john.pl: same search
# direction, same proof standard, same guards, so that a reader who has
# audited one has audited both.
#
# SEARCH DIRECTION: ONE JOB PER MODE, NOT PER ENTRY
#
# "For each entry try every mode" is ~1000 x ~590 process starts. Inverted it
# is ~590: hand hashcat EVERY unmapped vector at once and let its own parser
# throw out the lines that are not that mode's shape -- it prints a "Token
# length exception" per rejected line and cracks whichever survivors it can.
# That rejection is work hashcat does on load anyway, and it is why hashcat is
# the right column to do first: a mode either parses a hash or refuses it in
# milliseconds, so most of the matrix costs nothing.
#
# WHY A CRACK IS PROOF AND NOT A COINCIDENCE
#
# If hashcat, pinned to exactly one mode with -m, recovers entry E's recorded
# plaintext from entry E's recorded hash, then that mode computes E's
# algorithm on that input. That is tier 'vector' in CLAUDE.md, reached the
# same way verify-vectors.pl reaches it. Nothing here is inferred from a name,
# a digest length or a resemblance.
#
# Batching cannot manufacture a match: feeding entry A's password beside entry
# B's hash only matters if B's hash actually falls to it, and then the two
# entries share an algorithm, which is a finding rather than an error.
#
# MATCHING IS ON HASH AND PLAINTEXT TOGETHER
#
# Every vector imported from the sheet carries the plaintext "rosetta", so one
# batch holds hundreds of different hashes sharing a password. Matching on the
# plaintext alone would credit all of them the moment hashcat cracked any one
# -- a false positive verify-vectors.pl has actually hit. A cracked line
# counts only when it carries the entry's OWN hash and its OWN plaintext.
#
# ATTRIBUTION IS BY --show, AND THE HASH IS COMPARED CASE-FOLDED
#
# hashcat does not echo the line it was handed: it echoes its own canonical
# form, and for every hex-digest mode that form is LOWERCASE. Feed it
# 5F4DCC...CF99 and the crack comes back 5f4dcc...cf99, so a literal string
# search of the output misses cracks that really happened. Measured here on
# 2026-08-31.
#
# john's answer to the same problem was a synthetic login field, and hashcat
# has one: --username with -p TAB prints "login<TAB>hash<TAB>plain". It is not
# usable, and the reason is worth writing down so nobody "fixes" this later.
# hashcat's separator char is ONE setting shared by the username split and the
# hash:salt split, so -p TAB simultaneously declares that mode 10's input is
# "hash<TAB>salt" -- and the corpus records salted vectors as "hash:salt",
# which is the majority of what is still unmapped. The login field would cost
# exactly the vectors this run exists to reach.
#
# So attribution is: crack into a per-mode potfile, then re-read it with
# --show against the same hash file, and match each output line back by
# case-folded hash plus exact plaintext. Folding case is safe because it is
# hashcat's own normalization of its own input; it is not a search for
# something that passes. Where hashcat rewrites a hash by more than case the
# line simply fails to match and no claim is made, which is the safe
# direction.
#
# THE PLAINTEXT IS SPLIT OFF FROM THE RIGHT, AGAINST THE KNOWN SET
#
# A salted line comes back "hash:salt:plain" and a plaintext may itself
# contain a colon, so the split cannot be "first colon" or "last colon".
# Every candidate suffix is tested against the set of plaintexts the corpus
# actually carries, longest first; anything else is not a line we can
# attribute and is dropped rather than guessed at.
#
# MODES THAT CANNOT BE TESTED ARE SKIPPED, NOT FAILED
#
# hashcat's inventory records password_len_min/max per mode, and validate.pl
# already refuses to believe a mapping whose mode cannot accept any plaintext
# the entry carries. The same filter is applied here up front: a mode that
# accepts only 5-character passwords cannot be exercised by a corpus of
# 7-character ones, so running it would burn a process start to learn nothing.
#
# ONE MODE IS NEVER RECORDED: 2000
#
# -m 2000 is STDOUT, hashcat's candidate printer rather than a hash type. It
# is in the inventory because it is in --hash-info; it denotes no algorithm
# and cannot appear in a cross-reference. This is the same exclusion
# discover-john.pl makes for john's "crypt", and for the same reason: what it
# "cracks" is not a property of the algorithm.
#
# DEPRECATED MODES ARE IN SCOPE
#
# Four modes are flagged deprecated and hashcat refuses them without
# --deprecated-check-disable. They are still identifiers a reader will arrive
# by -- that is precisely what a rosetta stone is for -- so the flag is passed
# and they are tried like any other.
#
# THE CANARY: SOME MODES DO NOT COMPARE THE WHOLE DIGEST
#
# Measured here on hashcat v7.1.2-549-g8a15e210b, 2026-08-31, and it is the
# single most important thing in this file. **-m 100 ignores the FIRST 32-BIT
# WORD of the SHA-1 digest.** Hand it deadbeefe046af0e12d3c38472792cd5f081c39f
# with the candidate "rosetta" and it reports a crack, although
# sha1("rosetta") is d21af7ec e046af0e ... -- the first eight hex characters
# were never checked. Change any LATER word and it correctly refuses. -m 0
# (MD5) compares all four words, so this is per-mode, not universal; it is
# what the SHA-1 kernel's reversal of the final round costs.
#
# That is fatal to a discovery tool taken on trust. sha1lsb35 is
# and(sha1($p), 0x00000fff..ff) -- a SHA-1 digest with exactly the first five
# nibbles masked to zero -- and -m 100 duly "cracked" it, which would have
# written "SHA1lsb35 == hashcat mode 100" into a cross-reference. It is not.
#
# So every mode that scored a hit is challenged with a CANARY before anything
# is written: take each hash it cracked, and for every hex position in it emit
# one copy with that character changed. A mode that compares the whole digest
# refuses all of them. A mode that accepts any of them has just proved it
# ignores that position, and every claim it made is withheld and reported by
# name, along with the positions it ignored.
#
# This costs one extra run per mode that had hits -- 34 of 577 on the first
# full sweep -- and it is a direct empirical test of the actual defect rather
# than a list of modes someone remembered. Mutants that collide with a real
# corpus hash are skipped, so a "crack" can never be a legitimate one. The
# test only ever WITHDRAWS claims, so it cannot invent a mapping. Positions
# beyond 512 characters into a hash are not mutated, which matters only for
# the container formats whose example hashes run to thousands of hex
# characters.
#
#
# THE MUTATION IS CONFINED TO A LEADING HEX RUN
#
# Measured 2026-09-01 while porting this canary to discover-john.pl: mutating
# a BASE64 digest reports positions the format does not actually ignore. john's
# Raw-SHA1 "ignored" position 31 of {SHA}0ijZPTcJXMa+t2XnEbEwSOkvQu0=, which is
# the last base64 character before the padding -- 27 base64 characters carry
# 162 bits and a SHA-1 digest is 160, so its bottom two bits encode nothing.
# The mutant is a different STRING that decodes to the SAME DIGEST.
#
# The mutation is defined on text; the claim is about a digest. Those coincide
# only where the text IS the digest, so only a leading run of at least 16 hex
# characters is mutated -- the bare digests and the "<digest>:<salt>" shapes
# the masked and truncated families use -- and any other encoding is left
# unchallenged and reported as unmeasured rather than as clean.
#
# Getting this wrong is one-directional: a bogus ignored position can only ever
# WITHHOLD a claim, never invent one. Verdicts cached before this rule existed
# therefore cost coverage, not correctness -- but delete canary.positions so
# the next run re-measures.
#
# WHAT DOES NOT GET APPLIED AUTOMATICALLY
#
# A hash can honestly fall to several modes: a bare MD5 digest is mode 0 and
# nothing else, but a raw SHA-1 is 100 and also the input of several composite
# modes. An entry matched by a large number of modes usually means its vector
# is degenerate rather than that the algorithm has many names, so
# --max-per-entry holds it back for a human. Likewise a mode that suddenly
# claims a large share of the corpus is reported, never applied: a permissive
# mode at this scale produces confident nonsense.
#
# AN ENTRY WHOSE VECTORS DISAGREE IS A DATA DEFECT, NOT A MAPPING
#
# The mode set is computed per vector. If an entry's cracked vectors do not
# agree on it, the union is two contradictory algorithms in the one row a
# reader trusts to say what to run, so the entry is held for review instead.
# This is also where a multi-emit mdxfind type shows up (CLAUDE.md): two
# vectors of one multi-emit type are both correct and need not share a mode.
#
# FAILURE NEVER DEMOTES, AND NEITHER DOES SILENCE
#
# An entry no mode cracks is left exactly as it was. It may be a mode hashcat
# lacks, a vector hashcat wants wrapped differently (a *2hashcat.pl envelope
# rather than a bare digest), or a wrong plaintext from the sheet. None of
# those are distinguishable here, so none is written down as a claim.
#
# DEPENDENCIES: perl, YAML::XS, a hashcat binary. A GPU is not required --
# hashcat falls back to the CPU backend -- but one is present here and the
# nvmlInit warning it prints is benign.
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
use RosettaTools qw(tool_path tool_env_help tool_version
                    share_measurable share_unmeasurable_reason);

my $PROG = basename($0);
my $ROOT = "$RealBin/..";

sub usage {
    print STDERR <<"END_USAGE";

Usage: $PROG [options]

   --hashcat PATH    hashcat binary  (default: @{[tool_env_help('hashcat')]})
   --algorithms DIR  curated entries (default: data/algorithms)
   --inventory PATH  hashcat inventory (default: data/tools/hashcat.yaml)
   --work DIR        scratch         (default: tmp/discover-hashcat)
                     MUST be absolute if you override it
   --timeout SECS    per hashcat run (default: 60)
   --limit N         stop after N modes; for smoke tests
   --mode N          only this mode (repeatable)
   --only ID         only consider this entry
   --exclude ID      never write a mapping for this entry (repeatable); it is
                     still measured and reported, so the reason stays visible
   --all             target every entry with a vector, not just the unmapped
   --no-canary       skip the whole-digest challenge (see the methodology
                     note); only do this to reproduce an older run
   --canary-rounds N how many refinement rounds the challenge may take
                     (default 12; one round finds one ignored position per
                     digest, because hashcat indexes by what it compares)
   --canary-span N   how far into a hash to mutate (default 512 characters)
   --max-per-entry N hold back entries matched by more than N modes
                     (default 6; they are reported, never written)
   --max-share PCT   hold back a mode matching more than PCT% of the corpus
                     (default 20). The corpus is the TARGET set, so a narrow
                     run narrows the denominator: under --only it is one entry
                     and every mode that matched scores 100%. The guard still
                     withholds, but reports the share as UNMEASURABLE rather
                     than calling the mode over-broad.
   --resume          reuse per-mode results already in the work dir
   --apply           write the discovered mappings into data/algorithms
   -n, --dry-run     show the plan; run nothing, write nothing
   -v, --verbose     per-mode result (repeatable)
   -h, --help        this help

   Without --apply nothing is written: the run reports what it found and the
   work dir keeps the evidence. Exit 0 success, 1 error, 2 usage.

END_USAGE
    return;
}

my ($hashcat, $algdir, $inventory, $workdir, $only, $help, $dry, $apply);
my ($all, $resume, $no_canary);
my $canary_rounds = 12;
my $canary_span   = 512;
my (@mode_want, @exclude);
my $timeout       = 60;
my $limit         = 0;
my $verbose       = 0;
my $had_args      = scalar @ARGV;   # house rule: no arguments means show usage
my $max_per_entry = 6;
my $max_share     = 20;

GetOptions(
    'hashcat=s'       => \$hashcat,
    'algorithms=s'    => \$algdir,
    'inventory=s'     => \$inventory,
    'work=s'          => \$workdir,
    'timeout=i'       => \$timeout,
    'limit=i'         => \$limit,
    'mode=i'          => \@mode_want,
    'only=s'          => \$only,
    'exclude=s'       => \@exclude,
    'all'             => \$all,
    'max-per-entry=i' => \$max_per_entry,
    'max-share=i'     => \$max_share,
    'no-canary'       => \$no_canary,
    'canary-rounds=i' => \$canary_rounds,
    'canary-span=i'   => \$canary_span,
    'resume'          => \$resume,
    'apply'           => \$apply,
    'n|dry-run'       => \$dry,
    'v|verbose+'      => \$verbose,
    'h|help'          => \$help,
) or do { usage(); exit 2 };

if ($help) { usage(); exit 0 }
# No arguments at all: show usage rather than silently starting half an hour
# of work.
if (!$had_args) { usage(); exit 2 }

$hashcat = tool_path('hashcat', $hashcat);
$algdir    //= "$ROOT/data/algorithms";
$inventory //= "$ROOT/data/tools/hashcat.yaml";
$workdir   //= "$ROOT/tmp/discover-hashcat";

# hashcat is run from this process's cwd, but a relative --work would still be
# resolved against whatever the caller's cwd happens to be at the time; make
# it absolute once, here, so every path written below is unambiguous.
$workdir = "$ROOT/$workdir" unless $workdir =~ m{^/};

make_path($workdir) unless -d $workdir;
my $today = strftime('%Y-%m-%d', localtime);

die "$PROG: hashcat not executable at $hashcat\n" unless -x $hashcat;

#-----------------------------------------------------------------------
# Inventory: the candidate identifiers.

my $inv = eval { YAML::XS::LoadFile($inventory) }
    or do { print STDERR "$PROG: cannot load $inventory: $@\n"; exit 1 };

# See the note in discover-john.pl: this is the binary that RUNS.
my $hc_version = RosettaTools::tool_version('hashcat', $hashcat);
if (!defined $hc_version) {
    $hc_version = ($inv->{version} // 'unknown') . ' (per the inventory; the '
                . 'binary would not state a version)';
}
elsif (($inv->{version} // '') ne $hc_version) {
    printf STDERR "- NOTE: hashcat binary reports %s; the inventory was built "
                . "from %s. verified_with records the binary.\n",
                $hc_version, $inv->{version} // '(unset)';
}

# -m 2000 is STDOUT, a candidate printer rather than a hash type; see the
# methodology note.
my %never = (2000 => 1);

my %mode_info;
for my $m (@{ $inv->{modes} || [] }) {
    next unless defined $m->{mode};
    next if $never{ $m->{mode} };
    $mode_info{ $m->{mode} } = $m;
}

if (@mode_want) {
    my %want = map { $_ => 1 } @mode_want;
    %mode_info = map { $_ => $mode_info{$_} } grep { $want{$_} } keys %mode_info;
}

#-----------------------------------------------------------------------
# Entries. A target needs a vector; by default it also needs to be missing a
# proven hashcat mapping, since re-proving what verify-vectors.pl already
# proved costs the same time and tells us nothing.

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

my @vectors;   # { id, hash, pass, vid }
my %targets;
for my $id (sort keys %entry) {
    my $e = $entry{$id};
    unless ($all) {
        my $h = $e->{tools}{hashcat};
        next if $h && ($h->{verified} // '') eq 'vector';
    }
    for my $v (@{ $e->{vectors} || [] }) {
        next unless defined $v->{hash} && defined $v->{pass};
        next if $v->{hash} =~ /\n/ || $v->{pass} =~ /\n/;   # one hash per line
        push @vectors, { id => $id, hash => $v->{hash}, pass => $v->{pass},
                         vid => "$id\0" . scalar(@vectors) };
        $targets{$id} = 1;
    }
}

if (!@vectors) {
    print STDERR "$PROG: nothing to do -- no target entry carries a vector.\n";
    exit 0;
}

# Length filter: a mode that cannot accept any plaintext in the corpus cannot
# be exercised by it. Same rule validate.pl applies to a recorded mapping.
my %len = map { length($_->{pass}) => 1 } @vectors;
my @candidates;
my $skipped_len = 0;
for my $mode (sort { $a <=> $b } keys %mode_info) {
    my $m   = $mode_info{$mode};
    my $min = $m->{password_len_min} // 0;
    my $max = $m->{password_len_max} // 256;
    if (!grep { $_ >= $min && $_ <= $max } keys %len) {
        $skipped_len++;
        next;
    }
    push @candidates, $mode;
}

printf STDERR "- %d mode(s) x %d vector(s) from %d entry/entries"
            . " (%d mode(s) skipped: no plaintext of an acceptable length)\n",
    scalar @candidates, scalar @vectors, scalar keys %targets, $skipped_len;

#-----------------------------------------------------------------------
# Helpers.

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
# The corpus is identical for every mode, so it is written once.

my $hashfile = "$workdir/corpus.hash";
my $wordfile = "$workdir/corpus.word";

my %uniq_hash;
write_file($hashfile, grep { !$uniq_hash{$_}++ } map { $_->{hash} } @vectors);

my %uniq_word;
my @words = grep { !$uniq_word{$_}++ } map { $_->{pass} } @vectors;
write_file($wordfile, @words);

# Plaintexts longest first: a --show line is split from the right against this
# set, and "pass" must not win over "pass:word" where both are in the corpus.
my @words_by_len = sort { length($b) <=> length($a) || $a cmp $b } @words;

# Case-folded index of the corpus, since hashcat echoes its own lowercase
# canonical form of every hex digest. The value is a list because two entries
# may legitimately carry the same vector.
my %by_fold;
push @{ $by_fold{ lc($_->{hash}) . "\0" . $_->{pass} } }, $_ for @vectors;

# parse_show($text) - the (hash, plain) pairs hashcat says it cracked.
# A line is "hash:plain" or "hash:salt:plain"; the plaintext may itself
# contain a colon, so the suffix is matched against the known set rather than
# being split on a fixed occurrence. See the methodology note.
sub parse_show {
    my ($text) = @_;
    my @pairs;
    LINE: for my $line (split /\n/, $text // '') {
        next unless length $line;
        for my $w (@words_by_len) {
            my $tail = ":$w";
            next unless length($line) > length($tail);
            next unless substr($line, -length($tail)) eq $tail;
            push @pairs, [ substr($line, 0, length($line) - length($tail)), $w ];
            next LINE;
        }
    }
    return @pairs;
}

#-----------------------------------------------------------------------
# One hashcat run per mode.

my %hits;          # entry id -> mode -> 1
my %per_vector;    # vector id -> mode -> 1, so an entry whose vectors
                   # disagree can be spotted rather than merged
my %mode_hits;     # mode -> count of entries
my (%timed_out, %ran);
my $started = time;
my $n = 0;

make_path("$workdir/pot") unless -d "$workdir/pot";

MODE: for my $mode (@candidates) {
    last if $limit && $n >= $limit;
    $n++;

    if ($dry) {
        print STDERR "-   would run -m $mode\n" if $verbose;
        next;
    }

    my $pot = "$workdir/pot/$mode.pot";

    my $code = 0;
    if ($resume && -e $pot) {
        # Evidence from an earlier run; re-read it rather than re-cracking.
    }
    else {
        unlink $pot;
        ($code, undef) = run_capture($timeout, $hashcat,
            '-m', $mode, '-a', '0', '--quiet', '--self-test-disable',
            '--deprecated-check-disable', '--backend-ignore-opencl',
            '--potfile-path', $pot, $hashfile, $wordfile);
        $timed_out{$mode} = 1 if $code == -2;
        # hashcat creates no potfile when nothing loaded or nothing cracked;
        # make the "already tried" mark unambiguous for --resume.
        unless (-e $pot) {
            if (open my $fh, '>', $pot) { close $fh }
        }
    }
    $ran{$mode} = 1;

    my $found = 0;
    if (-s $pot) {
        my (undef, $shown) = run_capture($timeout, $hashcat,
            '-m', $mode, '--show', '--quiet', '--self-test-disable',
            '--deprecated-check-disable', '--backend-ignore-opencl',
            '--potfile-path', $pot, $hashfile);
        my %won;
        for my $p (parse_show($shown)) {
            my ($h, $pw) = @$p;
            $won{ lc($h) . "\0" . $pw } = 1;
        }
        # A hash hashcat deduplicated on load is shown once, so the crack is
        # credited to every vector carrying the same hash and plaintext.
        for my $key (keys %won) {
            for my $v (@{ $by_fold{$key} || [] }) {
                $per_vector{ $v->{vid} }{$mode} = 1;
                next if $hits{ $v->{id} }{$mode}++;
                $found++;
            }
        }
    }
    $mode_hits{$mode} = $found if $found;

    printf STDERR "-   [%4d/%4d] -m %-7s %3d hit(s)%s\n",
        $n, scalar @candidates, $mode, $found,
        ($timed_out{$mode} ? ' [TIMEOUT]' : '')
        if $verbose && ($found || $verbose > 1);
}

my $elapsed = time - $started;

#-----------------------------------------------------------------------
# The canary. Challenge every mode that scored a hit with digests that differ
# from the ones it cracked by exactly one hex character; see the methodology
# note.
#
# It has to iterate, and the reason is itself a hashcat behavior worth
# knowing: hashcat indexes its target list by the digest words it actually
# COMPARES, so all eight one-nibble mutants of an ignored 32-bit word collapse
# to one entry and only one of them is ever reported. Handing them over in a
# single run therefore finds one ignored position and stops. So each round
# removes the mutants that cracked and runs what is left, until a round finds
# nothing new -- which converges in as many rounds as the widest ignored field
# is wide.

my %vec_of = map { $_->{vid} => $_ } @vectors;
my %ignored_pos;       # mode -> { position => 1 }, the digest it never checks
my %unmeasured;        # mode -> vectors whose encoding cannot be mutated

# The challenge costs an order of magnitude more than replaying the cracks it
# is challenging -- 731s against 10s on the first full sweep -- so its verdict
# is written beside the pot files and reused by --resume like any other
# evidence in the work dir. Delete canary.positions to force it again.
my $canary_cache = "$workdir/canary.positions";
if ($resume && -s $canary_cache && open my $fh, '<', $canary_cache) {
    while (my $line = <$fh>) {
        chomp $line;
        my ($mode, @pos) = split /\s+/, $line;
        next unless defined $mode && @pos;
        $ignored_pos{$mode}{$_} = 1 for @pos;
    }
    close $fh;
    printf STDERR "- canary: %d mode(s) read from %s\n",
        scalar keys %ignored_pos, $canary_cache;
}
elsif (!$dry && !$no_canary && %mode_hits) {
    my $canary_started = time;
    my $rounds_total = 0;
    for my $mode (sort { $a <=> $b } keys %mode_hits) {

        # Every (hash, plaintext) this mode was credited with.
        my %credited;
        for my $vid (keys %per_vector) {
            next unless $per_vector{$vid}{$mode};
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
                next if $uniq_hash{$m};          # a real corpus hash: not a mutant
                next if exists $mutant_pos{ lc $m };
                $mutant_pos{ lc $m } = $i;
                push @pending, $m;
            }
        }
        $unmeasured{$mode} = $unmeasurable if $unmeasurable;
        next unless @pending;

        my $mw = write_file("$workdir/canary.$mode.word", sort keys %words);

        for my $round (1 .. $canary_rounds) {
            last unless @pending;
            $rounds_total++;
            my $mf = write_file("$workdir/canary.$mode.hash", @pending);
            my $mp = "$workdir/pot/canary.$mode.pot";
            unlink $mp;
            run_capture($timeout, $hashcat,
                '-m', $mode, '-a', '0', '--quiet', '--self-test-disable',
                '--deprecated-check-disable', '--backend-ignore-opencl',
                '--potfile-path', $mp, $mf, $mw);
            last unless -s $mp;

            my (undef, $shown) = run_capture($timeout, $hashcat,
                '-m', $mode, '--show', '--quiet', '--self-test-disable',
                '--deprecated-check-disable', '--backend-ignore-opencl',
                '--potfile-path', $mp, $mf);

            my %fell;
            for my $pr (parse_show($shown)) {
                my $pos = $mutant_pos{ lc $pr->[0] };
                next unless defined $pos;
                $ignored_pos{$mode}{$pos} = 1;
                $fell{ lc $pr->[0] } = 1;
            }
            last unless %fell;
            @pending = grep { !$fell{ lc $_ } } @pending;
        }
    }
    printf STDERR "- canary: challenged %d mode(s) in %d round(s), %.1fs; "
                . "%d do not compare the whole digest\n",
        scalar keys %mode_hits, $rounds_total, time - $canary_started,
        scalar keys %ignored_pos;
    printf STDERR "-   %d mode(s) had cracked vector(s) in an encoding this "
                . "cannot safely mutate\n-   and are reported unmeasured rather "
                . "than clean: %s\n", scalar keys %unmeasured,
        join(' ', map { "$_=$unmeasured{$_}" } sort { $a <=> $b } keys %unmeasured)
        if %unmeasured;
    if (open my $fh, '>', $canary_cache) {
        print {$fh} join(' ', $_, sort { $a <=> $b } keys %{ $ignored_pos{$_} }), "\n"
            for sort { $a <=> $b } keys %ignored_pos;
        close $fh;
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

#-----------------------------------------------------------------------
# What the canary licenses, and what it does not.
#
# A mode that skips part of the digest has NOT been shown to be wrong. Under
# -m 100 hashcat still proved that the last 128 bits of sha1($p) equal the
# last 128 bits of this hash, and a hash that is merely UNRELATED passes that
# with probability 2^-128. The only way a false mapping arises is when the
# corpus contains a hash DELIBERATELY related to a true digest -- which is
# exactly what mdxfind's masked and truncated families are, and exactly how
# -m 100 "cracked" sha1lsb35, and(sha1($p), 0x00000fff..ff).
#
# So the claim is withheld only where the corpus itself realizes the
# ambiguity: two DIFFERENT hashes in it that this mode cannot tell apart.
# Blanket-excluding every mode that skips a word would have thrown away
# twenty-odd mappings that are correct in order to refuse one that is not.

my %ambiguous;    # "mode\0id" -> the other ids the mode cannot distinguish
for my $mode (keys %ignored_pos) {
    my @pos = keys %{ $ignored_pos{$mode} };
    my %group;
    for my $v (@vectors) {
        my $k = lc $v->{hash};
        substr($k, $_, 1) = '.' for grep { $_ < length $k } @pos;
        # Keyed by the hash so that two entries carrying the SAME hash are
        # not ambiguity; valued by every id that carries it, so neither of
        # them is lost when they do collide with a third.
        $group{$k}{ lc $v->{hash} }{ $v->{id} } = 1;
    }
    for my $k (keys %group) {
        next if keys %{ $group{$k} } < 2;   # same hash twice is not ambiguity
        my @ids = sort keys %{ { map { %$_ } values %{ $group{$k} } } };
        for my $id (@ids) {
            $ambiguous{"$mode\0$id"} = join ' ', grep { $_ ne $id } @ids;
        }
    }
}

#-----------------------------------------------------------------------
# Decide what may be written. Two guards, both about not letting one
# degenerate vector or one over-permissive mode spray identifiers around.

my $corpus = scalar keys %targets;
my %noisy_mode = map { $_ => 1 }
                 grep { $mode_hits{$_} * 100 > $max_share * $corpus }
                 keys %mode_hits;

# Whether a share verdict on this corpus says anything about the MODE. Under
# --only the corpus is one entry, so every mode that matched scores 100% and
# the guard has measured its own denominator; see RosettaTools. The guard still
# withholds -- withholding is safe -- but it must not report what it did not
# establish.
my $share_ok = share_measurable($corpus, $max_share);



my %excluded = map { $_ => 1 } @exclude;

my (@apply_list, @held);
for my $id (sort keys %hits) {
    my @m = sort { $a <=> $b } keys %{ $hits{$id} };
    my @clean = grep { !$noisy_mode{$_} && !$ambiguous{"$_\0$id"} } @m;
    my @amb   = grep { $ambiguous{"$_\0$id"} } @m;

    # Every vector of this entry that cracked at all must have cracked under
    # the same modes; see the methodology note.
    my @sets = map  { join ' ', sort { $a <=> $b }
                                grep { !$noisy_mode{$_} } keys %{ $per_vector{$_} } }
               grep { %{ $per_vector{$_} } }
               grep { (split /\0/)[0] eq $id } keys %per_vector;
    my %distinct = map { $_ => 1 } grep { length } @sets;

    if (keys %distinct > 1) {
        push @held, [$id, \@clean,
                     'this entry\'s vectors disagree: ' .
                     join(' | ', sort keys %distinct)];
    }
    elsif ($excluded{$id}) {
        push @held, [$id, \@m, 'named in --exclude'];
    }
    elsif (!@clean && @amb) {
        push @held, [$id, \@amb, join('; ', map {
            sprintf('-m %s skips hash position(s) %s and so cannot tell this '
                  . 'row from %s', $_, range_summary(keys %{ $ignored_pos{$_} }),
                    $ambiguous{"$_\0$id"}) } @amb)];
    }
    elsif (!@clean) {
        push @held, [$id, \@m, $share_ok
                       ? 'every matching mode is over-broad'
                       : share_unmeasurable_reason('mode', $corpus, $max_share)];
    }
    elsif (@clean > $max_per_entry) {
        push @held, [$id, \@clean, sprintf('%d modes > --max-per-entry %d',
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
    my ($id, $m) = @$r;
    # How many of the entry's vectors actually fell. The repository's standard
    # -- verify-vectors.pl's -- is that one is enough to prove the identifier,
    # and a row can legitimately carry vectors for shapes this mode does not
    # read. But "1 of 5" is worth a human's eye, so it is printed rather than
    # left for someone to reconstruct from the work dir.
    my @vids = grep { (split /\0/)[0] eq $id } map { $_->{vid} } @vectors;
    my $fell = grep { my $v = $_; grep { $per_vector{$v}{$_} } @$m } @vids;
    printf "%-40s %-18s %s\n", $id, join(' ', @$m),
        (@vids > 1 ? sprintf('(%d of %d vectors)', $fell, scalar @vids) : '');
}
if (@held) {
    print "\n# held back for review\n";
    for my $r (@held) {
        my ($id, $m, $why) = @$r;
        printf "# %-38s %s  (%s)\n", $id, join(' ', @$m), $why;
    }
}

printf STDERR "- ran %d mode(s) in %.1fs%s\n", $n, $elapsed,
    ($dry ? ' (dry run)' : '');
printf STDERR "-   entries matched %d of %d target(s); applicable %d, held %d\n",
    scalar(keys %hits), $corpus, scalar @apply_list, scalar @held;
if (%noisy_mode && $share_ok) {
    printf STDERR "-   %d over-broad mode(s) ignored (> %d%% of the corpus): %s\n",
        scalar keys %noisy_mode, $max_share,
        join(' ', map { "$_=$mode_hits{$_}" } sort { $a <=> $b } keys %noisy_mode);
}
elsif (%noisy_mode) {
    printf STDERR "-   %d mode(s) held, share UNMEASURABLE: the corpus is %d "
                . "%s, so a\n-   single hit is %g%% and trips --max-share %d by "
                . "itself. That is a fact\n-   about this run, not about the "
                . "mode -- re-run against the whole corpus\n-   (--all, without "
                . "--only) to measure it: %s\n",
        scalar keys %noisy_mode, $corpus, ($corpus == 1 ? 'entry' : 'entries'),
        ($corpus ? 100 / $corpus : 100), $max_share,
        join(' ', map { "$_=$mode_hits{$_}" } sort { $a <=> $b } keys %noisy_mode);
}
if (%ignored_pos) {
    printf STDERR "-   %d mode(s) do not compare the whole digest. That is not by "
                . "itself\n-   a wrong mapping -- see the methodology note -- but a "
                . "claim is withheld\n-   wherever the corpus holds two hashes the "
                . "mode cannot tell apart:\n", scalar keys %ignored_pos;
    printf STDERR "-     -m %-7s skips hash position(s) %s\n",
        $_, range_summary(keys %{ $ignored_pos{$_} })
        for sort { $a <=> $b } keys %ignored_pos;
    my %amb_ids = map { (split /\0/)[1] => 1 } keys %ambiguous;
    printf STDERR "-   %d claim(s) withheld as ambiguous, over %d entry/entries\n",
        scalar keys %ambiguous, scalar keys %amb_ids if %ambiguous;
}
if (%timed_out) {
    printf STDERR "-   %d mode(s) hit the %ds timeout: %s\n",
        scalar keys %timed_out, $timeout,
        join(' ', sort { $a <=> $b } keys %timed_out);
}

#-----------------------------------------------------------------------
# Apply. A discovered mapping is tier 'vector' because it was round-tripped
# here; the note records that a machine found it rather than a human.

if ($apply && !$dry) {
    my $changed = 0;
    for my $r (@apply_list) {
        my ($id, $m) = @$r;
        my $e = $entry{$id} or next;
        my $blk = $e->{tools}{hashcat} ||= {};

        # Keep identifiers a human already recorded even if this run did not
        # reach or prove them; dropping them would be a silent demotion.
        my %modes = map { $_ => 1 } @{ $blk->{modes} || [] }, @$m;
        $blk->{modes} = [ sort { $a <=> $b } keys %modes ];
        delete $blk->{supported};

        # Only a block whose every mode cracked here may claim tier 'vector';
        # a block that gained one proven mode alongside an unproven one keeps
        # the tier and the date it already had, because nothing about that
        # older claim was tested.
        my $proven = !grep { !$hits{$id}{$_} } @{ $blk->{modes} };
        if ($proven) {
            $blk->{verified}      = 'vector';
            $blk->{verified_at}   = $today;
            $blk->{verified_with} = "hashcat $hc_version";
            $blk->{note} = 'mode discovered by round-trip search, not by name';
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
