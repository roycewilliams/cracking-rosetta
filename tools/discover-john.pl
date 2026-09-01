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
# every canonicalisation, and the special cases go away.
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
use RosettaTools qw(tool_path tool_env_help);

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
   --skip-disabled   do not try the dynamics disabled by dynamic_disabled.conf
   --max-per-entry N hold back entries matched by more than N formats
                     (default 6; they are reported, never written)
   --max-share PCT   hold back a format matching more than PCT% of the corpus
                     (default 20)
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
my ($all, $include_gpu, $skip_disabled, $resume);
my @fmt_re;
my @exclude;
my $timeout       = 60;
my $limit         = 0;
my $verbose       = 0;
my $had_args      = scalar @ARGV;   # house rule: no arguments means show usage
my $max_per_entry = 6;
my $max_share     = 20;

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
    'skip-disabled'   => \$skip_disabled,
    'max-per-entry=i' => \$max_per_entry,
    'max-share=i'     => \$max_share,
    'resume'          => \$resume,
    'apply'           => \$apply,
    'n|dry-run'       => \$dry,
    'v|verbose+'      => \$verbose,
    'h|help'          => \$help,
) or do { usage(); exit 2 };

if ($help) { usage(); exit 0 }
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

my $john_version = $inv->{version} // 'john';

my @candidates;
for my $f (@{ $inv->{formats} || [] }) {
    my $dev = $f->{device} // 'cpu';
    next if $dev ne 'cpu' && !$include_gpu;
    push @candidates, $f->{label};
}
push @candidates, @{ $inv->{disabled_dynamic} || [] } unless $skip_disabled;

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

my @vectors;   # { id, hash, pass }
my %targets;
for my $id (sort keys %entry) {
    my $e = $entry{$id};
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
# Decide what may be written. Two guards, both about not letting one
# degenerate vector or one over-permissive format spray identifiers around.

my $corpus = scalar keys %targets;
my %noisy_fmt = map { $_ => 1 }
                grep { $fmt_hits{$_} * 100 > $max_share * $corpus }
                keys %fmt_hits;

my %excluded = map { $_ => 1 } @exclude;

# See the methodology note: what "crypt" cracks is a fact about this host's
# libc, not about john.
my %host_dependent = map { $_ => 1 } qw(crypt crypt-opencl);

my (@apply_list, @held);
for my $id (sort keys %hits) {
    my @f = sort keys %{ $hits{$id} };
    my @clean = grep { !$noisy_fmt{$_} && !$host_dependent{$_} } @f;

    # Every vector of this entry that cracked at all must have cracked under
    # the same formats; see the methodology note.
    my @sets = map  { join ' ', sort grep { !$noisy_fmt{$_} && !$host_dependent{$_} }
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
    elsif (!@clean) {
        push @held, [$id, \@f, 'every matching format is over-broad'];
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
if (%noisy_fmt) {
    printf STDERR "-   %d over-broad format(s) ignored (> %d%% of the corpus): %s\n",
        scalar keys %noisy_fmt, $max_share,
        join(' ', map { "$_=$fmt_hits{$_}" } sort keys %noisy_fmt);
}
if (%timed_out) {
    printf STDERR "-   %d format(s) hit the %ds timeout: %s\n",
        scalar keys %timed_out, $timeout, join(' ', sort keys %timed_out);
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
        # reach or prove them; dropping them would be a silent demotion.
        my %cpu = map { $_ => 1 } @{ $blk->{cpu} || [] }, @$f;
        $blk->{cpu} = [ sort keys %cpu ];
        delete $blk->{supported};

        # Only a block whose every identifier cracked here may claim tier
        # 'vector'; a block that gained one proven identifier alongside an
        # unproven one keeps the tier and the date it already had, because
        # nothing about that older claim was tested.
        my $proven = !grep { !$hits{$id}{$_} } @{ $blk->{cpu} };
        if ($proven) {
            $blk->{verified}      = 'vector';
            $blk->{verified_at}   = $today;
            $blk->{verified_with} = 'john';
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
