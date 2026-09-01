#!/usr/bin/perl
#
# seed-orphans.pl -- give every tool identifier a findable row
#
# PURPOSE
#
# An identifier a tool publishes and this repository has no entry for is a
# dead end for the person who arrives by it, and arriving by an identifier is
# how most people arrive. When this was written hashcat had 306 such modes of
# 593, mdxfind 274 types of 1001 and john 310 formats of 552. That is the
# FIRST test in STATE.md failing -- good enough to replace the spreadsheet --
# and no amount of expression work fixes it.
#
# Royce decided 2026-08-31 that all of them get first-class entries, including
# the FDE, wallet, archive and document containers, which answered the scope
# question STATE.md had carried since the fourth session.
#
# WHY ONE TOOL AND NOT THREE
#
# This began as seed-hashcat-orphans.pl. The logic that matters -- find the
# orphans, attach to a row that already describes the computation, otherwise
# create one, and NEVER write a claim that was not reproduced -- is identical
# for all three. Only the adapters differ: where the inventory lives, how an
# identifier is spelled, and what command constitutes a round-trip. Three
# copies of the attach-and-slug logic would drift, and the day they do, two
# tools disagree about what a row means. So the shared part is written once
# and %TOOL carries the differences.
#
# NOTHING IS WRITTEN THAT WAS NOT REPRODUCED
#
# Each tool publishes an example for almost every identifier. That is a
# round-trip waiting to happen: run the tool at that identifier against its
# own example and either it recovers the plaintext or it does not. Only an
# identifier that recovers gets a tool block at tier `vector`. One that does
# not is REPORTED and skipped, with no lower tier used as a consolation --
# "the tool says it supports this" is already in data/tools/*.yaml, and
# copying that into a curated entry would launder an inventory line into a
# mapping.
#
# THE THREE TOOLS OFFER DIFFERENT EVIDENCE, AND THE DIFFERENCE MATTERS
#
#   hashcat  publishes example_hash AND example_pass. Cleanest case.
#   mdxfind  publishes example_vector and example_pass, where the vector is
#            "<digest>:<plain>" unsalted and "<digest>:<salt>:<plain>" salted.
#            Stripping the trailing ":<example_pass>" yields the storable
#            hash in both cases; do not try to count colons, several types
#            carry them inside the salt.
#   john     publishes example_ciphertext and NO plaintext. So the plaintext
#            has to be found, not read: john is handed its own example and a
#            candidate list, and whatever it recovers is the plaintext by
#            construction. Candidates are harvested from the second string of
#            every {"hash", "plain"} pair in john's own src/*.c -- which is
#            NOT the source being trusted for anything. STATE.md is right that
#            src/*.c is a bad substitute for the format inventory; here it
#            only proposes strings, and john's own crack is what proves one.
#            A format whose example does not fall gets no entry.
#            Measured 2026-08-31: 7 of 8 sampled formats fell to ~400
#            harvested candidates, where a hand-written list of 17 got 4.
#
# TWO ACTIONS, AND ATTACHING BEATS CREATING
#
# A tool can name an identifier for a computation this repository already
# describes. --attach finds those by normalising the identifier to repo
# expression notation and matching expression:, then requires the tool at
# that identifier to crack THE EXISTING ENTRY'S OWN VECTOR before adding it.
# That vector test is what stops an expression collision from putting an
# identifier on the wrong row: hashcat mode 4510 matched two entries claiming
# sha1(sha1($p).$s) and the vector decided which. Creating a duplicate row
# for a computation already described is the worst outcome available, so
# attaching is tried first and an identifier that attaches is never created.
#
# WHAT AN ENTRY GETS, AND WHAT IT DELIBERATELY DOES NOT
#
# id, name, status, one vector, the tool block at tier vector, a category
# where the tool publishes one, and for a name that is not expression-shaped
# a denotation: of the tool's own label.
#
# It writes no expression: and no OTHER tool's block. derive-expressions.pl
# proves an expression through john's compiler, discover-john.pl finds a john
# format by cracking the entry's vector, and seed-hx.pl / denote-hx.pl settle
# an mdxfind type from the hx specification. Those already do those jobs and
# are already trusted; a second answer to the same question here is the drift
# the two-layer split exists to prevent. Run them after.
#
# mdxfind entries get no denotation: for exactly that reason -- the hx
# appendix states what the type computes far better than its type name does,
# and a denotation written here would foreclose it, because validate.pl
# forbids expression: and denotation: on one entry.
#
# ids ARE FOREVER, so the slug is conservative
#
# `id` is the filename stem, a URL fragment and the dist/rosetta.csv key. The
# slug maps comparison operators to words, because hashcat distinguishes
# "Episerver 6.x < .NET 4" from ">= .NET 4" and stripping punctuation
# collapses two different algorithms into one name. Where a slug still
# collides the identifier is appended rather than the difference being
# papered over.
#
# Usage: seed-orphans.pl --tool hashcat|mdxfind|john [--attach] [--apply] [-v]
#
# Generated by Claude Opus 5 on 2026-08-31

use strict;
use warnings;
use FindBin qw($RealBin);
use lib "$RealBin/lib";
use Getopt::Long qw(GetOptions);
use File::Basename qw(basename);
use File::Path qw(make_path);
use YAML::XS qw(LoadFile);
use RosettaEmit qw(emit_entry);
use RosettaTools qw(tool_path tool_env_help);
use RosettaHx qw(parse_appendix translate_hx);

my $PROG = basename($0);
my $ROOT = "$RealBin/..";

my $algdir  = "$ROOT/data/algorithms";
my $workdir = "$ROOT/tmp/orphans";
my ($tool, $binary, $candfile);
my ($apply, $attach, $verbose, $help, $dry) = (0,0,0,0,0);
my $timeout = 60;
my $limit   = 0;
my @only;
my $had_args = scalar @ARGV;

sub usage {
    print STDERR <<"USAGE";

Usage: $PROG --tool hashcat|mdxfind|john [options]

   --tool NAME      which inventory to seed from (required)
   --binary PATH    that tool's binary (default: \$HASHCAT/\$JOHN/\$MDXFIND,
                    else the path in RosettaTools)
   --algorithms DIR curated entries  (default: data/algorithms)
   --candidates F   john only: candidate plaintexts, one per line. Without
                    it they are harvested from john's own src/*.c.
   --attach         add orphan identifiers to entries that ALREADY describe
                    the computation, instead of creating a new entry.
                    Requires the tool to crack the existing entry's own
                    vector. Run this pass first.
   --only IDENT     just this mode/type/format (repeatable)
   --limit N        stop after N identifiers attempted
   --timeout N      seconds per tool run (default 60)
   --apply          write; without it, report only
   -n, --dry-run    decide ids and report, run nothing
   -v, --verbose    per-identifier detail on stderr (repeatable)
   -h, --help       this help

   Only an identifier whose own published example round-trips gets an entry.
   Exit 0 success, 1 error, 2 usage.

USAGE
    exit 2;
}

GetOptions(
    'tool=s'       => \$tool,
    'binary=s'     => \$binary,
    'algorithms=s' => \$algdir,
    'candidates=s' => \$candfile,
    'attach'       => \$attach,
    'only=s'       => \@only,
    'limit=i'      => \$limit,
    'timeout=i'    => \$timeout,
    'apply'        => \$apply,
    'dry-run|n'    => \$dry,
    'verbose|v+'   => \$verbose,
    'help|h'       => \$help,
) or usage();
usage() if $help || !$had_args || !$tool;
usage() unless $tool =~ /^(hashcat|mdxfind|john)$/;
make_path($workdir) unless -d $workdir;
my %want_ident = map { $_ => 1 } @only;

#-----------------------------------------------------------------------
# Shared helpers.

sub run_capture {
    my ($secs, $cwd, @cmd) = @_;
    my $out = '';
    my $pid = open my $fh, '-|';
    die "$PROG: fork: $!\n" unless defined $pid;
    unless ($pid) {
        chdir $cwd if defined $cwd && length $cwd;
        open STDERR, '>', '/dev/null';
        exec @cmd or exit 127;
    }
    my $code = 0;
    eval {
        local $SIG{ALRM} = sub { kill 'KILL', $pid; die "timeout\n" };
        alarm $secs;
        local $/;
        $out = <$fh> // '';
        alarm 0;
    };
    $code = -2 if $@;
    close $fh;
    waitpid $pid, 0;
    return ($code, $out);
}

sub write_file {
    my ($path, @lines) = @_;
    open my $fh, '>', $path or die "$PROG: $path: $!\n";
    print $fh "$_\n" for @lines;
    close $fh;
    return $path;
}

sub safe { my $s = shift; $s =~ s/[^A-Za-z0-9]/_/g; return $s }

# slug($name) - a tool's label to an id.
sub slug {
    my ($n) = @_;
    my $s = lc $n;
    $s =~ s/>=/ ge /g; $s =~ s/<=/ le /g;
    $s =~ s/>/ gt /g;  $s =~ s/</ lt /g;
    $s =~ s/\$//g;
    $s =~ s/[^a-z0-9]+/-/g;
    $s =~ s/^-+|-+$//g;
    return $s;
}

# The label in this repository's expression notation, or undef.
sub to_expr {
    my ($n) = @_;
    return undef unless defined $n && $n =~ /^[a-z][a-z0-9_]*\(.*\)$/;
    my $s = $n;
    $s =~ s/\s+//g;
    $s =~ s/\$pass\b/\$p/g;
    $s =~ s/\$salt\b/\$s/g;
    $s =~ s/\$user\b/\$u/g;
    return $s;
}

#-----------------------------------------------------------------------
# hashcat category -> this repository's category axis. hashcat groups by
# PRODUCT, this repository by what the row IS, so the mapping is lossy on
# purpose: a product's use of a construction is `application`, which is
# exactly what that value means here.

my %HC_CATEGORY = (
    'Raw Hash'                              => 'primitive',
    'Raw Hash salted and/or iterated'       => 'composite',
    'Raw Hash authenticated'                => 'composite',
    'Raw Checksum'                          => 'primitive',
    'Raw Cipher, Known-plaintext attack'    => 'primitive',
    'Generic KDF'                           => 'kdf',
    'Network Protocol'                      => 'protocol',
    'Operating System'                      => 'application',
    'Database Server'                       => 'application',
    'FTP, HTTP, SMTP, LDAP Server'          => 'application',
    'Enterprise Application Software (EAS)' => 'application',
    'Full-Disk Encryption (FDE)'            => 'application',
    'File-Based Encryption (FBE)'           => 'application',
    'Document'                              => 'application',
    'Password Manager'                      => 'application',
    'Archive'                               => 'application',
    'Forums, CMS, E-Commerce'               => 'application',
    'One-Time Password'                     => 'protocol',
    'Instant Messaging Service'             => 'application',
    'Cryptocurrency Wallet'                 => 'application',
    'Private Key'                           => 'application',
    'Framework'                             => 'application',
    'Application Database'                  => 'application',
    'Plaintext'                             => 'encoding',
);

#-----------------------------------------------------------------------
# john candidate plaintexts. Harvested, then PROVEN by john -- see header.

my @CANDIDATES;
sub load_candidates {
    if ($candfile) {
        open my $fh, '<', $candfile or do {
            print STDERR "$PROG: $candfile: $!\n"; exit 1 };
        chomp(my @l = <$fh>); close $fh;
        return grep { length } @l;
    }
    my $src = $binary; $src =~ s{/run/[^/]+$}{/src};
    unless (-d $src) {
        print STDERR "$PROG: no john source at $src and no --candidates; "
                   . "cannot recover plaintexts for john examples.\n";
        exit 1;
    }
    my %seen;
    for my $f (glob "$src/*.c") {
        open my $fh, '<', $f or next;
        while (my $l = <$fh>) {
            while ($l =~ /\{"[^"]*",\s*"([^"]*)"/g) {
                my $p = $1;
                next unless length $p && length($p) <= 40;
                next if $p =~ /[^\x20-\x7e]/;
                $seen{$p} = 1;
            }
        }
        close $fh;
    }
    # john's house test passwords, in case the harvest is thin
    $seen{$_} = 1 for qw(password openwall john test 12345 123456 abc123
                         hashcat secret magnum password123);
    return sort keys %seen;
}

#-----------------------------------------------------------------------
# Per-tool adapters.

my %MX_SALTED;   # filled for mdxfind
my $HX;          # hx Appendix A, loaded for mdxfind --attach

my %TOOL = (
    hashcat => {
        inv_file => 'hashcat.yaml',
        inv_key  => 'modes',
        tool_key => 'hashcat',
        id_key   => 'modes',
        denote   => 1,
        ident    => sub { $_[0]{mode} },
        label    => sub { $_[0]{name} },
        category => sub { $HC_CATEGORY{ $_[0]{category} // '' } },
        kind     => sub { $_[0]{category} // '' },
        # ($hash, $pass) from the published example
        example  => sub {
            my ($r) = @_;
            my ($h, $p) = ($r->{example_hash} // '', $r->{example_pass} // '');
            return undef unless length $h && length $p && $h !~ /Truncated/;
            return ($h, $p);
        },
        verify   => sub {
            my ($ident, $hash, $pass, $rec) = @_;
            my $hf = write_file("$workdir/hc.$ident.hash", $hash);
            my $wf = write_file("$workdir/hc.$ident.word", $pass);
            my @cmd = ($binary, '-m', $ident, '-a', '0', '--quiet',
                       '--potfile-disable', '--self-test-disable',
                       '--backend-ignore-opencl');
            push @cmd, '--deprecated-check-disable' if $rec->{deprecated};
            my ($code, $out) = run_capture($timeout, undef, @cmd, $hf, $wf);
            return (0, 'timeout') if $code == -2;
            return (1, '') if $out =~ /\Q$hash\E:\Q$pass\E\s*$/m;
            return (0, 'no crack');
        },
    },

    mdxfind => {
        inv_file => 'mdxfind.yaml',
        inv_key  => 'types',
        tool_key => 'mdxfind',
        id_key   => 'types',
        # no denotation: the hx appendix says what the type computes far
        # better than its name does, and denotation: would foreclose it.
        denote   => 0,
        ident    => sub { $_[0]{name} },
        label    => sub { $_[0]{name} },
        category => sub { undef },
        kind     => sub { 'mdxfind type' },
        # An mdxfind TYPE NAME is not expression-shaped, so the default
        # name-based attach can never fire for this tool -- and without an
        # attach path a type describing a computation an entry already has
        # would silently become a duplicate row. The hx appendix is the join
        # that can see it: it states what each type computes. Measured
        # 2026-08-31, exactly 2 of 274 orphan types would have duplicated
        # (MYSQL5MD5, SHA1SHA1PASSSALT). Small, but it is the correct
        # mechanism and the next mdxfind release gets it for free.
        attach_expr => sub {
            my ($r) = @_;
            return undef unless $HX;
            my $h = $HX->{ $r->{name} } or return undef;
            my ($e) = translate_hx($h->{expr});
            return $e;
        },
        example  => sub {
            my ($r) = @_;
            my ($v, $p) = ($r->{example_vector} // '', $r->{example_pass} // '');
            return undef unless length $v && length $p;
            # "<digest>:<plain>" or "<digest>:<salt>:<plain>". Strip the
            # trailing plaintext rather than counting colons -- several
            # types carry a colon inside the salt.
            return undef unless $v =~ s/:\Q$p\E$//;
            return ($v, $p);
        },
        verify   => sub {
            my ($ident, $hash, $pass, $rec) = @_;
            my $s  = safe($ident);
            my $hf = write_file("$workdir/mx.$s.hash", $hash);
            my $wf = write_file("$workdir/mx.$s.word", $pass);
            my $rf = $MX_SALTED{$ident} ? '-F' : '-f';
            my ($code, $out) = run_capture($timeout, undef, $binary,
                '-h', "^\Q$ident\E\$", $rf, $hf, '-i', '1', $wf);
            return (0, 'timeout') if $code == -2;
            # "TYPEx01 <hash>:<plain>" -- require the type, so a broader
            # type cannot claim the crack.
            return (1, '') if $out =~ /^\Q$ident\E\S*\s+\Q$hash\E:\Q$pass\E\s*$/m;
            return (0, 'no crack');
        },
    },

    john => {
        inv_file => 'john.yaml',
        inv_key  => 'formats',
        tool_key => 'john',
        id_key   => 'cpu',
        denote   => 1,
        ident    => sub { $_[0]{label} },
        label    => sub { $_[0]{format_name} // $_[0]{label} },
        category => sub { undef },
        kind     => sub { 'john format' },
        # john publishes no plaintext, so the example is the ciphertext and
        # the plaintext is discovered by verify().
        example  => sub {
            my ($r) = @_;
            return undef if ($r->{device} // 'cpu') ne 'cpu';   # gpu mirrors cpu
            my $c = $r->{example_ciphertext} // '';
            return undef unless length $c;
            return ($c, undef);
        },
        verify   => sub {
            my ($ident, $hash, undef, $rec) = @_;
            my $jdir = $binary; $jdir =~ s{/[^/]+$}{};
            my $jbin = basename($binary);
            my $s    = safe($ident);
            my $hf   = "$workdir/jn.$s.hash";
            write_file($hf, "u:$hash");
            my $pot  = "$workdir/jn.$s.pot";
            unlink $pot;
            my @common = ("./$jbin", "--format=$ident",
                          '--field-separator-char=:', "--pot=$pot");
            my ($code) = run_capture($timeout, $jdir, @common,
                "--wordlist=$workdir/jn.words", "--session=$workdir/jn.$s", $hf);
            return (0, 'timeout') if $code == -2;
            return (0, 'no crack') unless -s $pot;
            # The pot line is "<john's canonical hash>:<plain>". Take the
            # plaintext as everything after the LAST colon of the stored
            # form -- john echoes its own encoding, which may contain colons.
            open my $fh, '<', $pot or return (0, 'no crack');
            my $line = <$fh>; close $fh;
            chomp $line;
            my $plain = $line;
            $plain =~ s/^.*://;
            return (0, 'no crack') unless defined $plain && length $plain;
            return (1, '', $plain);
        },
    },
);

my $T = $TOOL{$tool};
$binary //= tool_path($tool);
# default: the tool's own label, read as an expression
$T->{attach_expr} //= sub { to_expr($TOOL{$tool}{label}->($_[0])) };

#-----------------------------------------------------------------------
# Tool-specific setup.

if ($tool eq 'mdxfind') {
    my $appx = "$ROOT/tmp/hx/appA.txt";
    if (-f $appx) {
        $HX = parse_appendix($appx);
        printf STDERR "- hx appendix: %d type(s), used to attach\n", scalar keys %$HX;
    }
    elsif ($attach) {
        print STDERR "$PROG: no hx appendix at $appx, so --attach has nothing to "
                   . "match on for mdxfind (type names are not expression-shaped). "
                   . "Re-fetch hx.pdf -- see STATE.md -- or skip --attach and "
                   . "accept that a type describing a computation an entry already "
                   . "has will become a duplicate row.\n";
    }
    my $mx = LoadFile("$ROOT/data/tools/mdxfind.yaml");
    for my $t (@{ $mx->{types} }) {
        # 's' is a salt carried in the hash line; 'u' is a userid field
        # carried the same way. Both need -F rather than -f.
        $MX_SALTED{ $t->{name} } = 1
            if grep { $_ eq 's' || $_ eq 'u' } @{ $t->{flags} || [] };
    }
}
if ($tool eq 'john' && !$dry) {
    @CANDIDATES = load_candidates();
    printf STDERR "- %d candidate plaintext(s)\n", scalar @CANDIDATES;
    write_file("$workdir/jn.words", @CANDIDATES);
}

#-----------------------------------------------------------------------
# Load the corpus.

opendir my $dh, $algdir or die "$PROG: $algdir: $!\n";
my @files = sort grep { /\.yaml$/ } readdir $dh;
closedir $dh;

my (%taken, %claimed, %by_expr, %entry_of);
for my $f (@files) {
    my $e = eval { LoadFile("$algdir/$f") } or next;
    next unless $e->{id};
    $taken{ $e->{id} } = 1;
    next if ($e->{status}//'') eq 'merged';
    $entry_of{ $e->{id} } = { path => "$algdir/$f", data => $e };
    push @{ $by_expr{ $e->{expression} } }, $e->{id}
        if defined $e->{expression} && length $e->{expression};
    my $blk = $e->{tools}{ $T->{tool_key} } or next;
    for my $k ($tool eq 'john' ? (qw(cpu gpu)) : ($T->{id_key})) {
        my $v = $blk->{$k};
        $claimed{$_} = 1 for (ref $v eq 'ARRAY' ? @$v : ());
    }
}

my $inv   = LoadFile("$ROOT/data/tools/$T->{inv_file}");
my $VER   = $inv->{version} // $tool;
my @recs  = @{ $inv->{ $T->{inv_key} } };
my @orphans = grep { !$claimed{ $T->{ident}->($_) } } @recs;
@orphans = grep { $want_ident{ $T->{ident}->($_) } } @orphans if @only;
printf STDERR "- %s: %d orphan identifier(s)%s\n", $tool, scalar @orphans,
    (@only ? ' (filtered by --only)' : '');

my ($tried, $ok, $failed, $wrote, $attached, %why) = (0,0,0,0,0);
my %used;

for my $r (@orphans) {
    last if $limit && $tried >= $limit;
    my $ident = $T->{ident}->($r);
    my $label = $T->{label}->($r);

    my @ex = $T->{example}->($r);
    unless (@ex && defined $ex[0]) {
        $why{'no usable example'}++;
        printf STDERR "  skip  %-24s %s\n", $ident, $label if $verbose;
        next;
    }
    my ($hash, $pass) = @ex;

    #-- attach ------------------------------------------------------------
    my $expr = $T->{attach_expr}->($r);
    if ($attach && $expr && $by_expr{$expr}) {
        my @cand = @{ $by_expr{$expr} };
        $tried++;
        if ($dry) {
            printf STDERR "ATTACH? %-24s %-30s -> %s\n", $ident, $expr,
                join(',', @cand);
            next;
        }
        my $landed;
        for my $id (@cand) {
            my $ent = $entry_of{$id} or next;
            my @v = @{ $ent->{data}{vectors} || [] } or next;
            my ($got) = $T->{verify}->($ident, $v[0]{hash}, $v[0]{pass}, $r);
            next unless $got;
            $landed = $id;
            last;
        }
        if ($landed) {
            $attached++;
            printf STDERR "ATTACH  %-24s %-30s -> %s\n", $ident, $expr, $landed;
            next unless $apply;
            my $ent = $entry_of{$landed};
            my $blk = $ent->{data}{tools}{ $T->{tool_key} } ||= {};
            push @{ $blk->{ $T->{id_key} } }, $ident;
            my @s = @{ $blk->{ $T->{id_key} } };
            @s = $tool eq 'hashcat' ? sort { $a <=> $b } @s : sort @s;
            $blk->{ $T->{id_key} } = \@s;
            $blk->{verified}      = 'vector';
            $blk->{verified_at}   = '2026-08-31';
            $blk->{verified_with} = "$tool $VER";
            $blk->{note} = "$ident added 2026-08-31 by seed-orphans.pl: $tool "
                         . "names it \"$label\", which is this entry's own "
                         . "expression, and $tool at that identifier recovers "
                         . "this entry's own vector. It had no entry at all before.";
            emit_entry($ent->{path}, $ent->{data});
            $claimed{$ident} = 1;
            next;
        }
        printf STDERR "  no-attach %-22s %-28s (expression matched %s, vector did not)\n",
            $ident, $expr, join(',', @cand) if $verbose;
    }
    next if $attach;

    #-- create ------------------------------------------------------------
    $tried++;
    # In --dry-run john has no plaintext yet: it is discovered by the real
    # run, so stand one in rather than reporting every format as a failure.
    my ($cracked, $err, $found) = $dry
        ? (1, '', (defined $pass ? $pass : '(discovered at run time)'))
        : $T->{verify}->($ident, $hash, $pass, $r);
    $pass = $found if defined $found;
    unless ($cracked && defined $pass) {
        $failed++;
        $why{"example did not round-trip: " . ($err || 'no plaintext')}++;
        printf STDERR "  FAIL  %-24s %-34s %s\n", $ident, $label,
            ($err || 'no plaintext');
        next;
    }
    $ok++;

    my $id = slug($label);
    $id = slug("$tool-$ident") unless length $id;
    if ($taken{$id} || $used{$id}) {
        $id .= '-' . slug("$tool$ident");
        printf STDERR "  id collision -> %s\n", $id if $verbose;
    }
    $used{$id} = 1;

    my $entry = {
        id     => $id,
        name   => $label,
        status => 'needs-review',
        tools  => {
            $T->{tool_key} => {
                $T->{id_key}  => [ $ident ],
                verified      => 'vector',
                verified_at   => '2026-08-31',
                verified_with => "$tool $VER",
                note          => $tool eq 'john'
                    ? "john's own published example ciphertext for this format, "
                    . "recovered by john under this format. john publishes no "
                    . "plaintext, so the plaintext was found by handing john its "
                    . "own example and a candidate list -- what john recovered IS "
                    . "the plaintext, by construction."
                    : "${tool}'s own published example for this identifier, "
                    . "recovered by $tool at this identifier with ${tool}'s own "
                    . "published plaintext.",
            },
            crack => { supported => 0 },
        },
        vectors => [ { hash => $hash, pass => $pass, source => $tool } ],
    };
    if (my $c = $T->{category}->($r)) { $entry->{category} = $c }

    # A name that is not expression-shaped is a LABEL, which is what
    # denotation: is for. One that IS expression-shaped is left alone so
    # derive-expressions.pl can try to PROVE it -- a denotation here would
    # foreclose that, because validate.pl forbids both on one entry.
    if ($T->{denote} && !to_expr($label)) {
        # Only hashcat publishes a category, so only hashcat can say WHICH
        # kind of thing this is. Asserting "container or application format"
        # for every john format would be false for the raw-hash ones, and a
        # note that is wrong about the algorithm is worse than a vaguer one
        # that is right. `known` gates the stronger sentence.
        my $kind  = $T->{kind}->($r);
        my $known = ($tool eq 'hashcat');
        my $bare  = $known && $kind =~ /^(Raw Hash|Raw Checksum|Raw Cipher|Generic KDF)/;
        $entry->{denotation} = {
            text   => $label,
            source => $tool,
            note   => "${tool}'s own label for $ident"
                    . ($kind && $tool eq 'hashcat' ? ", category \"$kind\"" : '')
                    . ", in $VER."
                    . ($bare || !$known ? ''
                       : " This is a container or application format rather than "
                       . "a bare construction, so there is no single digest "
                       . "expression to record."),
        };
        $entry->{expression_proof} = {
            verified      => 'absent',
            verified_at   => '2026-08-31',
            verified_with => "$tool $VER",
            note          => $bare
                ? "$tool $ident is \"$label\" ($kind). It is a bare construction, "
                . "but john's dynamic EXPRESSION language has no token for it, so "
                . "it cannot be written as an expression here. That says nothing "
                . "about whether a tool can CRACK it."
                : $known
                ? "$tool $ident is a container or application format. john's "
                . "dynamic expression language describes constructions over a "
                . "password and a salt; it cannot express a container's "
                . "KDF-plus-cipher, so this has no expression and will not acquire "
                . "one. That says nothing about whether john can CRACK it -- run "
                . "discover-john.pl, and if john has a format it goes in tools.john."
                : "$tool publishes this as \"$label\" and no category, so what kind "
                . "of construction it is has not been established here. Its name is "
                . "not expression-shaped and john's dynamic EXPRESSION language "
                . "cannot be handed it, so there is no expression on this row. That "
                . "says nothing about whether any tool can CRACK it, and it is not a "
                . "claim that the algorithm HAS no expression -- run seed-hx.pl and "
                . "derive-expressions.pl, which can settle that from evidence.",
        };
    }

    printf STDERR "+ %-24s %-38s %s\n", $ident, $id, $label if $verbose;
    $wrote++;
    next unless $apply;
    emit_entry("$algdir/$id.yaml", $entry);
    $taken{$id} = 1;
}

printf STDERR "\n%s (%s): %d attempted, %d round-tripped, %d failed, %d %s, %d attached\n",
    $PROG, $tool, $tried, $ok, $failed, $wrote,
    ($apply ? 'written' : 'would be written (no --apply)'), $attached;
printf STDERR "  %-52s %d\n", $_, $why{$_} for sort keys %why;
print  STDERR "  now run: derive-expressions.pl, discover-john.pl"
            . ($tool eq 'mdxfind' ? ", seed-hx.pl, denote-hx.pl" : '') . "\n"
    if $apply && $wrote;
exit 0;
