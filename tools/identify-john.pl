#!/usr/bin/perl
#-----------------------------------------------------------------------
#
# Name: identify-john.pl
# Description: name each john format by having mdxfind identify john's own
#              test vectors, then join those names to the curated entries
# Category: cracking-rosetta verifier
#
# Project: cracking-rosetta | Phase: 6 - close the john gap
#
#-----------------------------------------------------------------------
# METHODOLOGY AND WHY THESE CHOICES
#
# WHY A SECOND SEARCH DIRECTION IS NEEDED
#
# discover-john.pl asks "which john format cracks this entry's vector?". That
# only reaches entries whose recorded vector john will load. It cannot reach a
# salted composite: the entry stores mdxfind's shape, "<hash>:<salt>", and
# john's dynamic_6 wants "$dynamic_6$<hash>$<salt>", so john's valid() throws
# the line out before a single hash is computed. Roughly 570 entries were left,
# and the salted dynamics are most of what is missing.
#
# So this runs the join the other way round. john ships its own regression
# corpus -- "john --format=X --list=format-tests" prints label, index,
# ciphertext and plaintext for every format, disabled dynamics included, about
# 13,700 vectors over 763 formats. Each of those vectors is already in the
# shape john wants. The open question is what algorithm it is, and mdxfind
# answers that by cracking it.
#
# THE TYPE IS PINNED, NEVER GUESSED FROM A FREE-FOR-ALL
#
# Running mdxfind with every type at once and reading off the winner would run
# straight into the masking pitfall CLAUDE.md documents: mdxfind reports the
# FIRST internal type that reproduces a digest, so MD5CAP comes back as MD5 and
# a whole family of composites collapses onto their base. It is also slow --
# e1-e1001 over this corpus did not finish in ten minutes.
#
# Instead the question is asked one type at a time, and only for the types the
# curated entries actually name: "pinned to HAV160-5 at -i 2, which of john's
# 13,700 vectors do you reproduce?". That is the same discipline the rest of
# the project uses, it is ~610 runs of about a second, and a hit is unambiguous
# because nothing else was in the running.
#
# THE ITERATION COUNT COMES BACK IN THE SAME ANSWER
#
# mdxfind computes every iteration up to -i N and names the one that matched in
# its output suffix, so one run per type at the highest count any entry declares
# buckets the hits by iteration for free. dynamic_213's vector coming back as
# "HAV160-5x02" says both which type and how many applications, which is the
# whole identity of an entry like hav160-5-x2.
#
# WHAT GETS WRITTEN, AND WHY IT IS NOT AN ASSERTION
#
# A match makes two locally reproduced statements: john computes this digest
# under format F (it is john's own regression vector), and mdxfind pinned to T
# at iteration I reproduces it. The entry already claims T at I. So F is added
# to the entry AND john's vector is added alongside the entry's own, which lets
# verify-vectors.pl re-derive the john leg directly from the entry file without
# consulting this script or john's test corpus again.
#
# That is why the block is written at tier 'asserted' and not at 'vector':
# proving it is verify-vectors.pl's job and it will do it from the data, on the
# next run, or refuse to. Nothing here promotes anything.
#
# THE CORPUS IS OFFERED TO mdxfind IN EVERY SHAPE IT MIGHT READ
#
# john's encoding is not mdxfind's. A vector arrives as "$dynamic_6$<hash>$<salt>"
# and mdxfind wants "<hash>:<salt>" through -F, or a bare digest through -f. So
# each john vector contributes several candidate lines -- as printed, with the
# "$dynamic_N$" tag stripped, the leading field on its own, and the two-part
# form rejoined with a colon -- and every line remembers which vector it came
# from. A shape mdxfind cannot read simply never matches; there is no way for a
# wrong shape to produce a wrong answer.
#
# ONE REPRODUCED VECTOR IS NOT ENOUGH
#
# "mdxfind pinned to T reproduces this digest" is literally true, but on a
# degenerate input it can be true of two different algorithms at once. MD5revp
# -- md5(reverse($p)) -- reproduces john's Raw-MD5 vector for the plaintext
# "1", because a one-character string is its own reverse. Exactly the masking
# CLAUDE.md warns about, arriving through the data rather than through the
# type list.
#
# So a label must be reproduced on --min-vectors distinct test vectors before
# it is written, two by default. A wrong pairing has to survive a second,
# usually longer plaintext, which the degenerate cases do not. Labels that hit
# on only one vector are reported and held: for a format with a single usable
# vector -- Argon2, scrypt, krb5tgs -- one hit is all there is to have, and
# accepting it is a judgment a human can make from the report with
# --min-vectors 1 on that type.
#
# FORMATS NO ENTRY COVERS ARE REPORTED, NOT INVENTED
#
# The same measurement names john formats for mdxfind types the corpus has no
# entry for at all. Those are printed as candidates and nothing more: creating
# entries is a curation decision about scope, not something a verifier does.
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
use RosettaTools qw(tool_path tool_env_help);

my $PROG = basename($0);
my $ROOT = "$RealBin/..";

sub usage {
    print STDERR <<"END_USAGE";

Usage: $PROG [options]

   --mdxfind PATH    mdxfind binary   (default: @{[tool_env_help('mdxfind')]})
   --john PATH       john binary      (default: @{[tool_env_help('john')]})
   --algorithms DIR  curated entries  (default: data/algorithms)
   --work DIR        scratch          (default: tmp/identify-john)
   --timeout SECS    per mdxfind run  (default: 120)
   --limit N         stop after N types; for smoke tests
   --type REGEX      only mdxfind types matching this (repeatable)
   --only ID         only consider this entry
   --exclude ID      never write a mapping for this entry (repeatable)
   --all             consider every entry, not just those without a proven
                     john mapping
   --min-iterations N  floor for the -i ceiling per type (default 3), so a
                     type whose entries all declare x1 still reports x2/x3
   --max-per-entry N hold back an entry matched by more than N formats
                     (default 4; reported, never written)
   --min-vectors N   a format must be reproduced on at least N of its own test
                     vectors (default 2); see the masking note in the header
   --refresh         re-dump john's test corpus even if the cache is present
   --apply           write the candidate mappings into data/algorithms
   -n, --dry-run     show the plan; run nothing, write nothing
   -v, --verbose     per-type result (repeatable)
   -h, --help        this help

   Writes candidates at tier 'asserted' with john's own vector attached; run
   tools/verify-vectors.pl --tool john afterwards to prove or reject them.
   Exit 0 success, 1 error, 2 usage.

END_USAGE
    return;
}

my ($mdxfind, $john, $algdir, $workdir, $only, $help, $dry, $apply, $all, $refresh);
my (@type_re, @exclude);
my $timeout       = 120;
my $limit         = 0;
my $verbose       = 0;
my $min_iter      = 3;
my $max_per_entry = 4;
my $min_vectors   = 2;
my $had_args      = scalar @ARGV;

GetOptions(
    'mdxfind=s'        => \$mdxfind,
    'john=s'           => \$john,
    'algorithms=s'     => \$algdir,
    'work=s'           => \$workdir,
    'timeout=i'        => \$timeout,
    'limit=i'          => \$limit,
    'type=s'           => \@type_re,
    'only=s'           => \$only,
    'exclude=s'        => \@exclude,
    'all'              => \$all,
    'min-iterations=i' => \$min_iter,
    'max-per-entry=i'  => \$max_per_entry,
    'min-vectors=i'    => \$min_vectors,
    'refresh'          => \$refresh,
    'apply'            => \$apply,
    'n|dry-run'        => \$dry,
    'v|verbose+'       => \$verbose,
    'h|help'           => \$help,
) or do { usage(); exit 2 };

if ($help)      { usage(); exit 0 }
if (!$had_args) { usage(); exit 2 }

$mdxfind = tool_path('mdxfind', $mdxfind);
$john = tool_path('john', $john);
$algdir  //= "$ROOT/data/algorithms";
$workdir //= "$ROOT/tmp/identify-john";

make_path($workdir) unless -d $workdir;
my $today = strftime('%Y-%m-%d', localtime);

#-----------------------------------------------------------------------
# Helpers.

sub write_file {
    my ($p, @lines) = @_;
    open my $fh, '>', $p or die "cannot write $p: $!\n";
    print {$fh} "$_\n" for @lines;
    close $fh;
    return $p;
}

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
# john's regression corpus. Cached: 957 process starts for ~30 seconds of
# work that does not change unless john does.

my $corpus_file = "$workdir/format-tests.tsv";

if ($refresh || !-s $corpus_file) {
    my $inv = eval { YAML::XS::LoadFile("$ROOT/data/tools/john.yaml") }
        or do { print STDERR "$PROG: cannot load the john inventory: $@\n"; exit 1 };
    my @labels = ( (map { $_->{label} } grep { ($_->{device} // 'cpu') eq 'cpu' }
                        @{ $inv->{formats} || [] }),
                   @{ $inv->{disabled_dynamic} || [] } );
    my %seen; @labels = grep { !$seen{$_}++ } sort @labels;

    my $jdir = $john; $jdir =~ s{/[^/]+$}{};
    my $jbin = basename($john);
    printf STDERR "- dumping john's test corpus for %d format(s)\n", scalar @labels;

    open my $out, '>', $corpus_file or die "cannot write $corpus_file: $!\n";
    for my $label (@labels) {
        my (undef, $txt) = run_capture($timeout, '/bin/sh', '-c',
            sprintf('cd %s && exec ./%s --format=%s --list=format-tests 2>/dev/null',
                    quotemeta($jdir), quotemeta($jbin), quotemeta($label)));
        print {$out} $txt;
    }
    close $out;
}

my @tests;      # { label, ct, pass }
{
    open my $fh, '<', $corpus_file or die "cannot read $corpus_file: $!\n";
    my %seen;
    while (my $line = <$fh>) {
        chomp $line;
        my ($label, undef, $ct, $pass) = split /\t/, $line, 4;
        next unless defined $label && defined $ct && defined $pass;
        next unless length $ct && length $pass;
        next if $pass =~ /:/;               # would break the mdxfind line split
        next if $seen{"$label\0$ct\0$pass"}++;
        push @tests, { label => $label, ct => $ct, pass => $pass };
    }
    close $fh;
}
printf STDERR "- john corpus: %d vector(s) over %d format(s)\n",
    scalar @tests, scalar keys %{ { map { $_->{label} => 1 } @tests } };

#-----------------------------------------------------------------------
# Candidate lines. Each john vector is offered in every shape mdxfind might
# read; "$line:$pass" is the key mdxfind's output will present back.

my (%by_line, %bare, %salted);
for my $t (@tests) {
    my @forms = ($t->{ct});
    (my $untagged = $t->{ct}) =~ s/^\$dynamic_\d+\$//;
    push @forms, $untagged if $untagged ne $t->{ct};

    for my $f (@forms[0 .. $#forms]) {
        my @part = split /\$/, $f;
        next unless @part == 2 && length $part[0] && length $part[1];
        push @forms, "$part[0]:$part[1]";   # mdxfind's -F shape
        push @forms, $part[0];              # the digest on its own
    }

    my %seen;
    for my $f (grep { !$seen{$_}++ } @forms) {
        next if $f =~ /\s/;
        push @{ $by_line{"$f:$t->{pass}"} }, $t;
        if ($f =~ /:/) { $salted{$f} = 1 }
        else           { $bare{$f}   = 1 }
    }
}

# A colon-free line is also legal input to -F, and some salted types encode
# the salt inside the string itself, so -F gets both sets.
my $bare_file   = write_file("$workdir/bare.hash",   sort keys %bare);
my $salted_file = write_file("$workdir/salted.hash", sort(keys %salted), sort keys %bare);
my $word_file   = write_file("$workdir/corpus.word",
                             sort keys %{ { map { $_->{pass} => 1 } @tests } });

printf STDERR "- candidate lines: %d bare, %d salted; %d distinct plaintext(s)\n",
    scalar keys %bare, scalar keys %salted,
    scalar keys %{ { map { $_->{pass} => 1 } @tests } };

#-----------------------------------------------------------------------
# Which mdxfind types to ask about, and how far to iterate.

my $inv = eval { YAML::XS::LoadFile("$ROOT/data/tools/mdxfind.yaml") }
    or do { print STDERR "$PROG: cannot load the mdxfind inventory: $@\n"; exit 1 };
my %is_salted = map { $_->{name} => 1 }
                grep { grep { $_ eq 's' || $_ eq 'u' } @{ $_->{flags} || [] } }
                @{ $inv->{types} || [] };

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

my (%want_type, %entries_for);   # type -> ceiling ; "type\0it" -> [ids ]
for my $id (sort keys %entry) {
    my $e = $entry{$id};
    unless ($all) {
        my $j = $e->{tools}{john};
        next if $j && ($j->{verified} // '') eq 'vector';
    }
    my $m = $e->{tools}{mdxfind} or next;
    my $it = $m->{iterations} // 1;
    for my $t (@{ $m->{types} || [] }) {
        $want_type{$t} = $it if ($want_type{$t} // 0) < $it;
        push @{ $entries_for{"$t\0$it"} }, $id;
    }
}

my @types = sort keys %want_type;
if (@type_re) {
    my @re = map { qr/$_/i } @type_re;
    @types = grep { my $t = $_; grep { $t =~ $_ } @re } @types;
}

printf STDERR "- asking mdxfind about %d type(s)\n", scalar @types;

#-----------------------------------------------------------------------
# One pinned mdxfind run per type.

my %found;     # "type\0it" -> label -> [ {ct, pass}, ... ]
my $started = time;
my ($ran, $hits) = (0, 0);

for my $type (@types) {
    last if $limit && $ran >= $limit;
    $ran++;
    next if $dry;

    my $ceiling = $want_type{$type};
    $ceiling = $min_iter if $ceiling < $min_iter;

    my $flag = $is_salted{$type} ? '-F'         : '-f';
    my $file = $is_salted{$type} ? $salted_file : $bare_file;

    my ($code, $out) = run_capture($timeout, $mdxfind,
        '-h', "^\Q$type\E\$", $flag, $file, '-i', $ceiling, $word_file);

    my $n = 0;
    for my $line (split /\n/, $out) {
        next unless $line =~ /^\Q$type\E(?:x(\d+))?\s+(.+)$/;
        my $it = defined $1 ? $1 + 0 : 1;
        my $rest = $2;
        my $vecs = $by_line{$rest} or next;
        for my $v (@$vecs) {
            my $slot = $found{"$type\0$it"}{ $v->{label} } ||= {};
            next if $slot->{"$v->{ct}\0$v->{pass}"};
            $slot->{"$v->{ct}\0$v->{pass}"} = { ct => $v->{ct}, pass => $v->{pass} };
            $n++;
        }
    }
    $hits += $n;
    printf STDERR "-   [%3d/%3d] %-24s -i %d  %3d hit(s)%s\n",
        $ran, scalar @types, $type, $ceiling, $n,
        ($code == -2 ? ' [TIMEOUT]' : '')
        if $verbose && ($n || $verbose > 1 || $code == -2);
}

printf STDERR "- ran %d type(s) in %.1fs, %d vector hit(s)\n",
    $ran, time - $started, $hits;

#-----------------------------------------------------------------------
# Join to the entries, and report what matched nothing we curate.

my %excluded = map { $_ => 1 } @exclude;
my (@candidates, @held);

for my $key (sort keys %found) {
    my ($type, $it) = split /\0/, $key;
    my @ids = @{ $entries_for{$key} || [] };
    my @all_labels = sort keys %{ $found{$key} };
    my @labels = grep { scalar(keys %{ $found{$key}{$_} }) >= $min_vectors }
                 @all_labels;
    my @thin   = grep { scalar(keys %{ $found{$key}{$_} }) <  $min_vectors }
                 @all_labels;

    unless (@ids) {
        printf "# no entry for %s x%d, but john has: %s\n",
            $type, $it, join(' ', map { sprintf('%s(%d)', $_,
                scalar keys %{ $found{$key}{$_} }) } @all_labels);
        next;
    }
    for my $id (@ids) {
        next unless @thin;
        my $have = { map { $_ => 1 } @{ $entry{$id}{tools}{john}{cpu} || [] } };
        my @t = grep { !$have->{$_} } @thin;
        push @held, [$id, \@t, sprintf('reproduced on fewer than %d vector(s)',
                                       $min_vectors)] if @t;
    }
    for my $id (@ids) {
        my $have = { map { $_ => 1 } @{ $entry{$id}{tools}{john}{cpu} || [] } };
        my @new = grep { !$have->{$_} } @labels;
        next unless @new;
        if ($excluded{$id})            { push @held, [$id, \@new, 'named in --exclude'] }
        elsif (@new > $max_per_entry)  { push @held, [$id, \@new,
                                            sprintf('%d formats > --max-per-entry %d',
                                                    scalar @new, $max_per_entry)] }
        else                           { push @candidates, [$id, \@new, $key] }
    }
}

for my $c (@candidates) {
    my ($id, $labels, $key) = @$c;
    my ($type, $it) = split /\0/, $key;
    printf "%-34s %-20s x%d  %s\n", $id, $type, $it,
        join(' ', map { sprintf('%s(%d)', $_, scalar keys %{ $found{$key}{$_} }) }
                  @$labels);
}
for my $h (@held) {
    printf "# %-32s %s  (%s)\n", $h->[0], join(' ', @{ $h->[1] }), $h->[2];
}

printf STDERR "-   candidates for %d entry/entries, %d held back\n",
    scalar @candidates, scalar @held;

#-----------------------------------------------------------------------
# Apply: record the formats and attach john's own vector, so verify-vectors.pl
# can re-derive the claim from the entry file alone.

if ($apply && !$dry) {
    my $changed = 0;
    for my $c (@candidates) {
        my ($id, $labels, $key) = @$c;
        my ($type, $it) = split /\0/, $key;
        my $e = $entry{$id} or next;
        my $blk = $e->{tools}{john} ||= {};

        my %cpu = map { $_ => 1 } @{ $blk->{cpu} || [] }, @$labels;
        $blk->{cpu}           = [ sort keys %cpu ];
        $blk->{verified}      = 'asserted';
        $blk->{verified_at}   = $today;
        $blk->{verified_with} = 'mdxfind';
        $blk->{note}          = "john's own test vector for this format is "
                              . "reproduced by mdxfind pinned to $type at "
                              . "iteration $it";

        my %seen;
        $seen{ $_->{hash} . "\0" . $_->{pass} } = 1 for @{ $e->{vectors} || [] };
        for my $label (@$labels) {
            my ($v) = map { $found{$key}{$label}{$_} }
                      sort keys %{ $found{$key}{$label} };
            next unless $v;
            next if $seen{"$v->{ct}\0$v->{pass}"}++;
            push @{ $e->{vectors} }, { hash => $v->{ct}, pass => $v->{pass},
                                       source => 'john' };
        }
        $changed += emit_entry($path{$id}, $e);
    }
    printf STDERR "-   files rewritten: %d\n", $changed;
    printf STDERR "- now re-run: tools/verify-vectors.pl --tool john\n" if $changed;
}
elsif (@candidates) {
    printf STDERR "-   nothing written; re-run with --apply to record these\n";
}

exit 0;
