#!/usr/bin/perl
#-----------------------------------------------------------------------
#
# Name: mdxfind-corpus.pl
# Description: export this repository's proven vectors as a regression corpus
#              in mdxfind's OWN serialization, and re-check that corpus
#              against a binary
# Category: cracking-rosetta upstream deliverable
#
# Project: cracking-rosetta | Phase: 7 - pre-publication readiness
#
#-----------------------------------------------------------------------
# METHODOLOGY AND WHY THIS EXISTS
#
# WHO IT IS FOR
#
# mdxfind's maintainer, not this repository's readers. dist/rosetta.csv is a
# cross-reference keyed on OUR ids; it cannot be fed to anything. This writes
# the same evidence as a file mdxfind can be driven with: one row per (type,
# vector), carrying the hash line in the shape the binary reads, the iteration
# count, the reader flag, and the pepper where there is one.
#
# THE PROBLEM IT SOLVES UPSTREAM
#
# mdxfind revision 1.543 repaired a buffer-layout bug in e607
# SHA1MD5SALTPASSPEPPER, and upstream's own note says "any hash cracked as e607
# before this revision will not verify against it". That is a behaviour change
# discovered by reading a revision log. With this file and --check it is a
# command: 993 pinned jobs, and the ones that stopped reproducing are named.
#
# WHY IT RUNS EVERYTHING RATHER THAN TRANSCRIBING THE YAML
#
# Every row here is at tier 'vector' in data/algorithms already, so a
# transcription would look identical on the day it was written. It would also
# be a claim about a binary nobody ran. The corpus is published as a
# MEASUREMENT: --export drives mdxfind for every job and writes only the rows
# that reproduced, so the file's header can name the binary and the date and
# mean it. That is the same rule the tiers themselves follow.
#
# THE PLUMBING IS THE PAYLOAD
#
# The vectors are the cheap part. What upstream's own HASH_TYPES.md does not
# carry, and what this file does:
#
#   * WHICH READER. A type flagged 's' (salt) or 'u' (userid) carries its
#     extra field in the hash line and needs -F; everything else needs -f.
#     Feeding a salted vector to -f gives "No final hash type found", which
#     reads like a wrong vector.
#   * THE ITERATION COUNT. MD5x01 and MD5x02 are different identities, and
#     mdxfind labels its first emitted value x02 for the types whose loop
#     starts at 2. The suffix is checked on the way back, not stripped.
#   * WHERE THE PEPPER GOES. A pepper is a site-wide secret that appears in no
#     hash. The catalog writes it as the second space-separated field of the
#     salt, which -F alone parses as one long salt, so the type computes
#     nothing it can match. It has to reach the array through -j.
#   * ONE HASH LENGTH PER RUN, BECAUSE TRUNCATED MATCHING IS A FEATURE.
#     mdxfind cracks truncated hashes on purpose -- that is a capability
#     hashcat does not have, and it is why whole families here are truncations
#     -- so it sets its comparison width from the SHORTEST hash in the file
#     and honours it for every hash in that file. Measured 2026-09-03:
#     md5("rosetta") and its own 16-hex truncation together, pinned to MD5,
#     print "Minimum hash length is 16 characters" and report ONLY the
#     truncation, because at 16 characters the two ARE the same hash. Alone,
#     the full digest reports fine.
#
#     Nothing is wrong with that. What is wrong is handing mdxfind a file that
#     mixes lengths and then reading the result as though it had compared
#     whole digests. So every job here is split by the length of the hash
#     portion: a few more invocations, and the collapse becomes impossible
#     rather than unlikely. 33 of 993 jobs mix lengths, and the ones that
#     matter are exactly the truncated families this repository models on
#     purpose -- MD5 (16,32), SHA1 (32,40), SQL5 (32,40), LM (16,32).
#   * EXCEPT WHERE IT DOES NOT. SHA1-SALT-UTF16-PEPPER and
#     SHA1SALTMD5PASSPEPPER both carry flags f,s,j and need OPPOSITE handling:
#     the first has a built-in salt of "f5g= of8=" in mdxfind's own
#     default_salts[] table, one string the type splits itself, so splitting
#     the field breaks a vector that was verifying. The flags do not say which.
#     This tool does not guess: it runs the whole-field form FIRST, falls back
#     to the split only where that found nothing, and RECORDS WHICH ONE WORKED
#     in the pepper column. A regression is therefore structurally impossible
#     and the published file states the answer the flags cannot.
#
# WHAT --check MEANS
#
# It reads the corpus and re-runs it. A row that no longer reproduces is a
# behaviour change in the binary, not a defect in the file, so it exits 1 and
# names the type. It writes nothing and touches no entry: promoting or
# demoting a tier is verify-vectors.pl's job, and keeping the two apart is
# what stops a regression run quietly rewriting the evidence it disagrees
# with.
#
# THE hashcat_mode COLUMN
#
# Free, and directly useful to the one reader this file is for: mdxfind
# carries its own Maphashcat[] table, and this repository has round-tripped a
# hashcat mode against the SAME vector for many of these types. The column is
# populated only where the entry's hashcat block is itself at tier 'vector',
# and is empty otherwise -- an empty cell is "we have not proven one", never
# "there is none".
#
# SCALE
#
# 993 jobs, about a second each because mdxfind has a fixed startup floor, so
# roughly 17 minutes for a full pass. Nothing here is worth making faster;
# this is run on an upstream release, not in a loop.
#
# USAGE
#   tools/mdxfind-corpus.pl --export [--out PATH] [-v]
#   tools/mdxfind-corpus.pl --check  [--in  PATH] [-v]
#
# DEPENDENCIES
#   perl, YAML::XS, tools/lib/RosettaTools.pm, an mdxfind binary
#
#-----------------------------------------------------------------------
# Generated by Claude Opus 5 on 2026-09-03

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
use RosettaTools qw(tool_path tool_env_help);

my $PROG = basename($0);
my $ROOT = "$RealBin/..";

my $DEFAULT_OUT = "$ROOT/dist/mdxfind-corpus.tsv";

sub usage {
    print STDERR <<"END_USAGE";
Usage: $PROG --export | --check [options]

   --export          run every job and write the corpus (only proven rows)
   --check           re-run the corpus against the binary; write nothing
   --out PATH        where --export writes  (default: dist/mdxfind-corpus.tsv,
                     '-' for stdout)
   --in PATH         what --check reads     (default: dist/mdxfind-corpus.tsv)
   --mdxfind PATH    mdxfind binary         (default: @{[tool_env_help('mdxfind')]})
   --algorithms DIR  curated entries        (default: data/algorithms)
   --work DIR        scratch for hash and word files (default: tmp/mdxcorpus)
   --timeout SECS    per invocation         (default: 120)
   --limit N         stop after N jobs; for smoke tests
   --only TYPE       just this mdxfind type (repeatable)
   -v, --verbose     per-job result to stderr
   -h, --help        this help

   Exit 0 success, 1 a row did not reproduce (or an error), 2 usage.
END_USAGE
    return;
}

my ($export, $check, $out, $in, $mdxfind, $algdir, $workdir, $timeout,
    $limit, @only, $verbose, $help);
$timeout = 120;

GetOptions(
    'export'       => \$export,
    'check'        => \$check,
    'out=s'        => \$out,
    'in=s'         => \$in,
    'mdxfind=s'    => \$mdxfind,
    'algorithms=s' => \$algdir,
    'work=s'       => \$workdir,
    'timeout=i'    => \$timeout,
    'limit=i'      => \$limit,
    'only=s'       => \@only,
    'verbose+'     => \$verbose,
    'help|h'       => \$help,
) or do { usage(); exit 2 };

if ($help) { usage(); exit 0 }
# House rule: no arguments prints usage and exits, rather than blocking.
if (!$export && !$check) { usage(); exit 2 }
if ($export && $check) {
    print STDERR "$PROG: --export and --check are separate runs.\n";
    exit 2;
}

$mdxfind = tool_path('mdxfind', $mdxfind);
$algdir //= "$ROOT/data/algorithms";
$workdir //= "$ROOT/tmp/mdxcorpus";
$out //= $DEFAULT_OUT;
$in  //= $DEFAULT_OUT;
my %only = map { $_ => 1 } @only;

make_path($workdir) unless -d $workdir;

#-----------------------------------------------------------------------
# Running mdxfind.

# run_capture($secs, @cmd) - run, returning (exit code, combined output).
# A timeout returns -2 so the caller can say TIMEOUT rather than silently
# recording "did not reproduce", which is a different claim.
sub run_capture {
    my ($secs, @cmd) = @_;
    my $tmp = "$workdir/.out.$$";
    my $pid = fork();
    die "$PROG: fork failed: $!\n" unless defined $pid;
    if (!$pid) {
        open STDOUT, '>', $tmp or exit 127;
        open STDERR, '>&', \*STDOUT;
        exec { $cmd[0] } @cmd;
        exit 127;
    }
    my $code;
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm $secs;
        waitpid $pid, 0;
        $code = $? >> 8;
        alarm 0;
        1;
    } or do { kill 'KILL', $pid; waitpid $pid, 0; alarm 0; $code = -2 };
    my $text = '';
    if (open my $fh, '<', $tmp) { local $/; $text = <$fh> // ''; close $fh }
    unlink $tmp;
    return ($code, $text);
}

# mx_echo_is($rest, $hash, $plain) - does mdxfind's "<hash>:<plain>" tail name
# THIS row?
#
# The plaintext must match exactly. The digest must too, except for hex case:
# mdxfind normalises hex on read and echoes its own lower-case form, so a
# vector recorded in upper case -- which is how the *UC types are published --
# would have its own successful round trip rejected by a string compare. The
# fold is narrow on purpose: it applies only when the recorded digest is pure
# hex, so a salted "<hash>:<salt>" line, where the salt's case is part of the
# algorithm's input, is still compared exactly. Lifted from verify-vectors.pl,
# which measured the case on 2026-08-31.
sub mx_echo_is {
    my ($rest, $hash, $plain) = @_;
    my $want = "$hash:$plain";
    return 1 if $rest eq $want;
    return 0 unless $hash =~ /^[0-9A-Fa-f]+$/;
    my $tail = ":$plain";
    return 0 unless length($rest) > length($tail);
    return 0 unless substr($rest, -length($tail)) eq $tail;
    return lc(substr($rest, 0, length($rest) - length($tail))) eq lc($hash);
}

# write_file($path, @lines) - one line each, newline-terminated.
sub write_file {
    my ($path, @lines) = @_;
    open my $fh, '>', $path or die "$PROG: cannot write $path: $!\n";
    print {$fh} "$_\n" for @lines;
    close $fh or die "$PROG: cannot close $path: $!\n";
    return $path;
}

# split_pepper($hash) - the catalog's "<hash>:<salt> <pepper>" shape, split
# into the line mdxfind should read and the pepper that belongs in -j.
# Returns (line, pepper) or (line, undef) when there is nothing to split.
sub split_pepper {
    my ($hash) = @_;
    my ($h, $rest) = split /:/, $hash, 2;
    return ($hash, undef) unless defined $rest && $rest =~ /^(.*?) (.+)$/;
    return ("$h:$1", $2);
}

# run_job($type, $iterations, $read_flag, $rows, $use_split) - one pinned
# mdxfind invocation over every row of one job. Returns (exit code, hashref of
# row index => 1 for the rows that reproduced).
#
# Every row of a job shares the type, so they share one hash file and one word
# file; that is the whole reason jobs exist rather than one run per vector.
sub run_job {
    my ($type, $it, $flag, $rows, $use_split, $tag) = @_;

    (my $safe = $type) =~ s/[^A-Za-z0-9]/_/g;
    $safe .= '.' . ($tag // 0);
    my (@hashes, @peppers, @lines);
    for my $r (@$rows) {
        if ($use_split) {
            my ($line, $pep) = split_pepper($r->{hash});
            push @hashes, $line;
            push @peppers, $pep if defined $pep;
        }
        else { push @hashes, $r->{hash} }
        # ALWAYS the original, never the submitted line. mdxfind reassembles
        # the salt field with the pepper appended before it echoes, so the
        # string to expect back is the one the catalog publishes -- see the
        # note on this patch and the header's pepper section.
        push @lines, $r->{hash};
    }
    my %u; my @uniq = grep { defined $_ && !$u{$_}++ } @peppers;

    my $hf = write_file("$workdir/$safe.$it.hash", @hashes);
    my $wf = write_file("$workdir/$safe.$it.word", map { $_->{plain} } @$rows);
    my @cmd = ($mdxfind, '-h', "^\Q$type\E\$", $flag, $hf, '-i', $it);
    push @cmd, '-j', write_file("$workdir/$safe.$it.pep", @uniq) if @uniq;
    push @cmd, $wf;

    my ($code, $text) = run_capture($timeout, @cmd);

    # Output lines look like "MD5x01 <hash>:<plain>". The suffix is the
    # iteration that actually matched and is part of the identity, so a value
    # that falls at x01 does not satisfy a row declaring x02.
    my %hit;
    for my $line (split /\n/, $text) {
        next unless $line =~ /^\Q$type\E(?:x(\d+))?\s+(.+)$/;
        my $got = defined $1 ? $1 + 0 : $it;
        next unless $got == $it;
        my $rest = $2;
        for my $i (0 .. $#$rows) {
            $hit{$i} = 1 if mx_echo_is($rest, $lines[$i], $rows->[$i]{plain});
        }
    }
    return ($code, \%hit);
}

#-----------------------------------------------------------------------
# Columns. Stated once; the header, the writer and the reader all use this.

my @COLS = qw(type index iterations read_flag pepper hash plain
              hashcat_mode entry);

my %COL_DOC = (
    type         => 'mdxfind type name, exactly as the binary spells it',
    index        => 'the eN index, which is the stable identity across renames',
    iterations   => 'the -i value; the xNN suffix is part of the identity',
    read_flag    => '-f for a bare hash, -F where the line carries a salt or userid',
    pepper       => 'the pepper for -j, empty when the type takes none',
    hash         => 'the line to put in the hash file, exactly as written',
    plain        => 'the plaintext that must come back',
    hashcat_mode => 'a hashcat mode this repository proved on the SAME vector; '
                  . 'empty means unproven here, never "there is none"',
    entry        => "cracking-rosetta entry id, so a disagreement has an address",
);

#-----------------------------------------------------------------------
# Build the jobs from the curated entries.

# load_jobs() - every (type, iterations) whose mdxfind block is at tier
# 'vector' and whose entry carries a vector. Returns a hashref keyed
# "type\0iterations".
sub load_jobs {
    my $inv = eval { YAML::XS::LoadFile("$ROOT/data/tools/mdxfind.yaml") }
        or die "$PROG: cannot load the mdxfind inventory: $@";
    my (%flags, %index);
    for my $t (@{ $inv->{types} }) {
        $flags{ $t->{name} } = { map { $_ => 1 } @{ $t->{flags} || [] } };
        $index{ $t->{name} } = $t->{index};
    }

    opendir(my $dh, $algdir) or die "$PROG: cannot read $algdir: $!\n";
    my @files = sort grep { /\.yaml$/ } readdir $dh;
    closedir $dh;

    my %job;
    for my $f (@files) {
        my $e = eval { YAML::XS::LoadFile("$algdir/$f") } or next;
        next if ($e->{status} // '') eq 'merged';   # a tombstone claims nothing
        my $mx = $e->{tools}{mdxfind} or next;
        next unless ($mx->{verified} // '') eq 'vector';
        my @types = @{ $mx->{types} || [] } or next;
        my @vecs  = ref $e->{vectors} eq 'ARRAY' ? @{ $e->{vectors} } : ();
        next unless @vecs;

        my $it = $mx->{iterations} // 1;
        my $hc = '';
        if (($e->{tools}{hashcat}{verified} // '') eq 'vector') {
            my @m = @{ $e->{tools}{hashcat}{modes} || [] };
            $hc = join(' ', @m) if @m;
        }

        for my $t (@types) {
            next if %only && !$only{$t};
            next unless exists $flags{$t};   # a type the binary no longer has
            for my $v (@vecs) {
                # The hash portion's length is part of the job key: mdxfind
                # compares to the shortest hash in the file, so a truncated
                # vector in with a full-length one hides the full-length one.
                my ($head) = split /:/, $v->{hash}, 2;
                my $len = length $head;
                my $key = "$t\0$it\0$len";
                $job{$key}{type}        = $t;
                $job{$key}{index}       = $index{$t};
                $job{$key}{iterations}  = $it;
                $job{$key}{hashlen}     = $len;
                $job{$key}{read_flag}   = ($flags{$t}{s} || $flags{$t}{u}) ? '-F' : '-f';
                $job{$key}{pepper_type} = $flags{$t}{j} ? 1 : 0;
                push @{ $job{$key}{rows} }, {
                    hash         => $v->{hash},
                    plain        => $v->{pass},
                    hashcat_mode => $hc,
                    entry        => $e->{id},
                };
            }
        }
    }
    return \%job;
}

#-----------------------------------------------------------------------
# --export

sub do_export {
    my $job = load_jobs();
    my @keys = sort keys %$job;
    my $started = time;
    my (@written, @failed);
    my $n = 0;

    for my $key (@keys) {
        last if $limit && $n >= $limit;
        $n++;
        my $j = $job->{$key};
        my ($code, $hit) = run_job($j->{type}, $j->{iterations},
                                   $j->{read_flag}, $j->{rows}, 0,
                                   $j->{hashlen});

        # The pepper fallback. Whole-field stays PRIMARY, so anything that
        # verified before still verifies; the split is tried only where the
        # whole field found nothing, and the form that worked is what gets
        # written. See the header: the flags cannot tell these apart.
        my $split = 0;
        if ($j->{pepper_type} && !keys %$hit) {
            my ($c2, $h2) = run_job($j->{type}, $j->{iterations},
                                    $j->{read_flag}, $j->{rows}, 1,
                                    $j->{hashlen});
            if (keys %$h2) { ($code, $hit, $split) = ($c2, $h2, 1) }
        }

        for my $i (0 .. $#{ $j->{rows} }) {
            my $r = $j->{rows}[$i];
            unless ($hit->{$i}) {
                push @failed, sprintf('%-28s i=%d %s [%s]%s',
                    $j->{type}, $j->{iterations}, $r->{entry},
                    substr($r->{hash}, 0, 40),
                    ($code == -2 ? ' TIMEOUT' : ''));
                next;
            }
            my ($line, $pep) = $split ? split_pepper($r->{hash})
                                      : ($r->{hash}, undef);
            push @written, {
                type         => $j->{type},
                index        => $j->{index},
                iterations   => $j->{iterations},
                read_flag    => $j->{read_flag},
                pepper       => $pep // '',
                hash         => $line,
                plain        => $r->{plain},
                hashcat_mode => $r->{hashcat_mode},
                entry        => $r->{entry},
            };
        }
        printf STDERR "-   %-28s i=%d %d row(s) -> %d reproduced%s\n",
            $j->{type}, $j->{iterations}, scalar @{ $j->{rows} },
            scalar(keys %$hit), ($split ? ' [pepper split]' : '')
            if $verbose;
    }

    my $version = mdxfind_version();
    my $fh;
    if ($out eq '-') { $fh = \*STDOUT }
    else {
        make_path($1) if $out =~ m{^(.*)/[^/]+$} && !-d $1;
        open $fh, '>', $out or die "$PROG: cannot write $out: $!\n";
    }
    print {$fh} corpus_header($version, scalar @written, $n);
    print {$fh} join("\t", @COLS), "\n";
    for my $r (sort { $a->{type} cmp $b->{type}
                   || $a->{iterations} <=> $b->{iterations}
                   || $a->{hash} cmp $b->{hash} } @written) {
        print {$fh} join("\t", map { $r->{$_} // '' } @COLS), "\n";
    }
    close $fh unless $out eq '-';

    printf STDERR "- %d job(s), %d row(s) written, %d row(s) did not reproduce, %.1fs\n",
        $n, scalar @written, scalar @failed, time - $started;
    if (@failed) {
        print STDERR "- did not reproduce, and so are NOT in the corpus:\n";
        print STDERR "    $_\n" for @failed;
    }
    printf STDERR "- wrote %s\n", $out unless $out eq '-';
    return 0;   # a row that will not reproduce is reported, not fatal, on export
}

# mdxfind_version() - the binary's own RCS header, for the corpus header.
sub mdxfind_version {
    my (undef, $text) = run_capture(30, $mdxfind, '-V');
    return $1 if $text =~ /mdxfind\.c,v\s+(\S+\s+\S+)/;
    return 'unknown';
}

sub corpus_header {
    my ($version, $rows, $jobs) = @_;
    my $today = strftime('%Y-%m-%d', localtime);
    my $doc = join '', map { sprintf("#   %-13s %s\n", $_, $COL_DOC{$_}) } @COLS;
    return <<"END_HEADER";
# mdxfind regression corpus
#
# GENERATED by tools/mdxfind-corpus.pl on $today -- do not edit; regenerate.
# From github.com/roycewilliams/cracking-rosetta, MIT, data and code both.
#
# Every row below was REPRODUCED, not transcribed: mdxfind $version
# was run pinned to the named type at the named iteration count and echoed
# this hash and this plaintext back. $rows row(s) across $jobs job(s).
#
# TAB-separated. Columns:
$doc#
# To re-run a single row:
#
#     mdxfind -h '^<type>\$' <read_flag> hashes -i <iterations> wordlist
#
# where hashes holds the hash column and wordlist the plain column. Add
# -j peppers where the pepper column is not empty, with the pepper on its own
# line -- it is a site-wide secret that appears in no hash and cannot be
# derived from one, so it reaches the type through the array and not through
# the salt. A pepper column that IS empty on a type flagged 'j' is not an
# omission: it means this vector verifies with the field left whole, which is
# what a type with a built-in salt in default_salts[] requires.
#
# Success is the type name with the iteration suffix, then the hash and the
# plaintext: "MD5x01 <hash>:<plain>". The suffix is part of the identity --
# a value that falls at x01 does not satisfy a row that says 2.
#
# ON A PEPPER ROW, EXPECT BACK MORE THAN YOU SENT. Measured 2026-09-03:
# mdxfind reassembles the salt field with the pepper appended before it
# echoes, so submitting "<hash>:<salt>" with the pepper in a -j file reports
#
#     SHA1SALTMD5PASSPEPPERx01 <hash>:<salt> <pepper>:password123
#
# A runner that compares against the line it wrote to the hash file will call
# every pepper row a failure. Compare against the hash column with the pepper
# column appended after a space, which is the catalog's own spelling.
END_HEADER
}

#-----------------------------------------------------------------------
# --check

sub do_check {
    open my $fh, '<', $in or do {
        print STDERR "$PROG: cannot read $in: $!\n";
        return 1;
    };
    my (@hdr, %job, $rows);
    while (<$fh>) {
        chomp;
        next if /^#/ || !length;
        if (!@hdr) { @hdr = split /\t/, $_, -1; next }
        my @f = split /\t/, $_, -1;
        unless (@f == @hdr) {
            printf STDERR "%s: %s line %d has %d field(s), header has %d\n",
                $PROG, $in, $., scalar @f, scalar @hdr;
            return 1;
        }
        my %r; @r{@hdr} = @f;
        next if %only && !$only{ $r{type} };
        # Split by hash length here too: a check that pooled the lengths
        # would report the full-length rows as regressions.
        my ($head) = split /:/, $r{hash}, 2;
        my $key = join("\0", $r{type}, $r{iterations}, $r{read_flag},
                       length $head);
        push @{ $job{$key} }, \%r;
        $rows++;
    }
    close $fh;

    unless ($rows) {
        print STDERR "$PROG: no rows in $in\n";
        return 1;
    }

    my $started = time;
    my (@bad, $n) = ();
    $n = 0;
    for my $key (sort keys %job) {
        last if $limit && $n >= $limit;
        $n++;
        my ($type, $it, $flag, $hlen) = split /\0/, $key;
        my $rs = $job{$key};

        # The corpus already states the resolved plumbing, so --check never
        # falls back: a row that needed the split carries its pepper, and a
        # row that did not carries none. Re-deciding here would let a
        # regression hide behind the other form.
        # submit: the hash column. expect back: the hash column with the
        # pepper reattached, because that is what mdxfind echoes.
        my @rows = map { {
            hash   => $_->{hash},
            expect => (length($_->{pepper} // '')
                        ? "$_->{hash} $_->{pepper}" : $_->{hash}),
            plain  => $_->{plain},
        } } @$rs;
        my %u; my @peps = grep { length && !$u{$_}++ } map { $_->{pepper} } @$rs;

        (my $safe = $type) =~ s/[^A-Za-z0-9]/_/g;
        $safe .= ".$hlen";
        my $hf = write_file("$workdir/chk.$safe.$it.hash", map { $_->{hash} } @rows);
        my $wf = write_file("$workdir/chk.$safe.$it.word", map { $_->{plain} } @rows);
        my @cmd = ($mdxfind, '-h', "^\Q$type\E\$", $flag, $hf, '-i', $it);
        push @cmd, '-j', write_file("$workdir/chk.$safe.$it.pep", @peps) if @peps;
        push @cmd, $wf;

        my ($code, $text) = run_capture($timeout, @cmd);
        my %hit;
        for my $line (split /\n/, $text) {
            next unless $line =~ /^\Q$type\E(?:x(\d+))?\s+(.+)$/;
            my $got = defined $1 ? $1 + 0 : $it;
            next unless $got == $it;
            for my $i (0 .. $#rows) {
                $hit{$i} = 1 if mx_echo_is($2, $rows[$i]{expect}, $rows[$i]{plain});
            }
        }
        for my $i (0 .. $#rows) {
            next if $hit{$i};
            push @bad, sprintf('%-28s e=%s i=%-2s %s%s', $type,
                $rs->[$i]{index}, $it, $rs->[$i]{entry},
                ($code == -2 ? '  TIMEOUT' : ''));
        }
        printf STDERR "-   %-28s i=%s %d row(s) -> %d reproduced\n",
            $type, $it, scalar @rows, scalar keys %hit if $verbose;
    }

    printf STDERR "- %d job(s), %d row(s), %d did not reproduce, %.1fs\n",
        $n, $rows, scalar @bad, time - $started;
    if (@bad) {
        print STDERR "- REGRESSION: these rows no longer reproduce.\n";
        print STDERR "  The corpus is evidence, not a wish: a row here means the\n";
        print STDERR "  named type reproduced this vector when the file was written.\n";
        print STDERR "    $_\n" for @bad;
        return 1;
    }
    print STDERR "- OK: every row still reproduces\n";
    return 0;
}

exit($export ? do_export() : do_check());
