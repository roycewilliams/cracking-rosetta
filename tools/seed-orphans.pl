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
# --unverified: A VISIBLE ROW THAT SAYS IT IS NOT PROVEN
#
# 160 identifiers across the three tools publish an example that does not
# round-trip here -- TrueCrypt and VeraCrypt want the volume header, the
# collider modes recover a cipher key rather than the password, WPA/EAPOL
# wants binary capture input, john's example may not fall to the candidate
# list. Refusing them entirely leaves a dead end for the person who arrives
# by one, which is the gap this tool exists to close.
#
# Royce decided 2026-08-31: give them a row, flagged as failing verification.
# So --unverified writes the row at tier `upstream` and NEVER `vector`. That
# is not a weakening of the rule, it is the rule: `upstream` means "asserted
# by an upstream project that verifies by recomputation", and a tool
# publishing an identifier plus a worked example is exactly that. The tool
# block's note then says, in words, that the local round-trip FAILED and
# which class of failure it was, so a reader is never left inferring it from
# a tier alone.
#
# The tier is also the machine-readable signal, which is why no new field was
# invented for this: an entry whose tool block is `upstream` rather than
# `vector` has, by the existing definition, not been reproduced here.
#
# NOTHING ELSE IS WRITTEN THAT WAS NOT REPRODUCED
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
# describes. --attach finds those by normalizing the identifier to repo
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
use POSIX qw(strftime);
use YAML::XS qw(LoadFile);
use RosettaEmit qw(emit_entry);
use RosettaTools qw(tool_path tool_env_help hashpipe_label);
use RosettaHx qw(parse_appendix translate_hx);

my $PROG = basename($0);
my $ROOT = "$RealBin/..";

my $algdir  = "$ROOT/data/algorithms";
my $workdir = "$ROOT/tmp/orphans";
my ($tool, $binary, $candfile);
my ($hp_binary, $via_hp) = (undef, 0);
my ($apply, $attach, $verbose, $help, $dry, $unverified) = (0,0,0,0,0,0);
my $timeout = 60;
# verified_at is the day the measurement was MADE, so it is read from the
# clock rather than typed. It used to be the literal 2026-08-31 in all three
# writers, which would have back-dated every later run's evidence.
my $DATE = strftime('%Y-%m-%d', localtime);
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
   --unverified     ALSO write a row for an identifier whose example does
                    not round-trip, at tier `upstream` with the failure
                    named in the note. Without this they are only reported.
   --attach         add orphan identifiers to entries that ALREADY describe
                    the computation, instead of creating a new entry.
                    Requires the tool to crack the existing entry's own
                    vector. Run this pass first.
   --only IDENT     just this mode/type/format (repeatable)
   --limit N        stop after N identifiers attempted
   --timeout N      seconds per tool run (default 60)
   --date YYYY-MM-DD  verified_at to record (default: today, UTC)
   --via-hashpipe   mdxfind only: for a type the INSTALLED mdxfind binary
                    does not have, verify the example with hashpipe -c
                    pinned to the same type name and write tier `upstream`.
   --hashpipe PATH  that binary (\$HASHPIPE, else /usr/local/bin/hashpipe)
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
    'unverified'   => \$unverified,
    'only=s'       => \@only,
    'limit=i'      => \$limit,
    'timeout=i'    => \$timeout,
    'date=s'       => \$DATE,
    'via-hashpipe' => \$via_hp,
    'hashpipe=s'   => \$hp_binary,
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

# STATED: john's own (ciphertext, plaintext) pairing, in source order.
#
# WHY THE PAIRING MATTERS AND THE HARVEST ALONE DOES NOT
#
# john publishes an example ciphertext per format and no plaintext, so the
# plaintext is recovered by handing john the example and every candidate the
# harvest below found. That is sound only where john's cmp_exact() is exact.
# For a format john flags FMT_NOT_EXACT -- "Collisions possible (as in
# likely)" in --list=format-all-details, and at runtime "Note: This format may
# emit false positives, so it will keep trying" -- a COLLIDING candidate is
# reported instead, and the candidate list is harvested from the very test
# arrays that hold the collisions.
#
# Measured 2026-09-04 across the 139 entries whose plaintext was derived this
# way: 136 agree with john's stated pairing and 3 do not, all 3 on
# FMT_NOT_EXACT formats. adxcrypt says it in its own comments:
#
#     {"$adxcrypt$54886955", "99999999"},  // default credentials
#     {"$adxcrypt$54886955", "786r"},      // collided password
#
# So the answer is not a better search. john STATES the plaintext beside the
# ciphertext, and reading the pair turns a derivation into a lookup that john
# is then asked to confirm.
my %STATED;

# unescape($lit) - the bytes a C string literal denotes. The harvest used to
# take the literal verbatim, which is how the SIXTEEN-character string
# \xc0\xc1\xc2\xc3 became a candidate and then a published plaintext.
sub unescape {
    my ($s) = @_;
    $s =~ s{\\x([0-9a-fA-F]{2})}{chr hex $1}ge;
    $s =~ s{\\([0-7]{1,3})}{chr oct $1}ge;
    $s =~ s{\\n}{\n}g;
    $s =~ s{\\t}{\t}g;
    $s =~ s{\\r}{\r}g;
    $s =~ s{\\(["\\])}{$1}g;
    return $s;
}

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
    for my $f (glob "$src/*.[ch]") {
        open my $fh, '<', $f or next;
        while (my $l = <$fh>) {
            next if $l =~ m{^\s*//};        # a commented-out test is not a test
            # Both halves are kept: the plaintext as a candidate, and the pair
            # so that this format's own answer can be tried first.
            while ($l =~ /\{\s*"((?:[^"\\]|\\.)*)"\s*,\s*"((?:[^"\\]|\\.)*)"\s*\}/g) {
                my ($ct, $p) = (unescape($1), unescape($2));
                push @{ $STATED{$ct} }, $p
                    if length $ct && !grep { $_ eq $p } @{ $STATED{$ct} || [] };
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

# why_failed($tool, $label, $err) - the class of failure, in words a reader
# can act on. Generic "did not round-trip" tells nobody whether to retry.
sub why_failed {
    my ($tl, $lab, $err) = @_;
    return "the run exceeded the ${timeout}s timeout; it may simply need longer"
        if ($err // '') eq 'timeout';
    return "hashcat's example for this mode is a volume header rather than a "
         . "digest, so a plain -a 0 wordlist attack cannot consume it"
        if $lab =~ /TrueCrypt|VeraCrypt|LUKS|BestCrypt|BitLocker/i;
    return "this is a collider mode: it recovers a cipher key, not the "
         . "password, so the published plaintext is not what comes back"
        if $lab =~ /collider/i;
    return "this mode wants binary capture input rather than a hash line"
        if $lab =~ /WPA|EAPOL|PMKID/i;
    return "this is a pseudo-mode rather than a hash" if $lab =~ /STDOUT/i;
    return "this is a bridged plugin and needs its interpreter configured"
        if $lab =~ /Bridged/i;
    return "john publishes no plaintext for its example, and the example did "
         . "not fall to the ~" . scalar(@CANDIDATES) . " candidate plaintexts "
         . "harvested from john's own source. The plaintext is findable, it "
         . "was simply not in the list"
        if $tl eq 'john';
    return "the tool pinned to this identifier did not reproduce its own "
         . "published example";
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
        binver   => sub { my $v = `\Q$_[0]\E --version 2>&1 </dev/null`;
                          return $v =~ /^\s*(v?[\w.+-]+)\s*$/m ? $1 : undef },
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
        binver   => sub { my $v = `\Q$_[0]\E -V 2>&1 </dev/null`;
                          return $v =~ m{RCS/mdxfind\.c,v\s+(\S+)\s+(\S+)}
                                 ? "RCS $1 ($2)" : undef },
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
        binver   => sub { my $d = $_[0]; $d =~ s{/[^/]+$}{};
                          my $x = $_[0]; $x =~ s{^.*/}{};
                          my $v = `cd \Q$d\E && ./\Q$x\E --list=build-info 2>/dev/null </dev/null`;
                          return $v =~ /^Version:\s*(.+?)\s*$/m ? $1 : undef },
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

            # john's own stated plaintexts for THIS ciphertext go first, so a
            # format whose comparison is not exact reports the documented
            # password rather than the first colliding candidate. Order within
            # the stated list is john's: adxcrypt states the real credential
            # before the collision it labels as one.
            my $wl = "$workdir/jn.words";
            my @stated = @{ $STATED{$hash} || [] };
            if (@stated) {
                my %first = map { $_ => 1 } @stated;
                $wl = "$workdir/jn.$s.words";
                write_file($wl, @stated, grep { !$first{$_} } @CANDIDATES);
            }

            my ($code) = run_capture($timeout, $jdir, @common,
                "--wordlist=$wl", "--session=$workdir/jn.$s", $hf);
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
            # The fourth value says the plaintext is john's own answer for
            # this ciphertext rather than whatever the search turned up, which
            # is the difference the note has to report.
            return (1, '', $plain, (grep { $_ eq $plain } @stated) ? 1 : 0);
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
    my $appx = "$ROOT/data/hx-appendix-a.txt";
    if (-f $appx) {
        $HX = parse_appendix($appx);
        printf STDERR "- hx appendix: %d type(s), used to attach\n", scalar keys %$HX;
    }
    elsif ($attach) {
        print STDERR "$PROG: no hx appendix at $appx, so --attach has nothing to "
                   . "match on for mdxfind (type names are not expression-shaped). "
                   . "Run tools/extract-hx.pl, which renders it from "
                   . "vendor/cynosureprime/hx.8 -- or skip --attach and "
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

# verified_with must name the instrument that RAN, which is not always the one
# the inventory was built from. Measured 2026-09-05: data/tools/mdxfind.yaml
# came from mdxfind 1.576 while the installed binary here is 1.545, so taking
# the version from the inventory stamped every round-trip with a build that
# never ran it. Ask the binary; fall back to the inventory only when it will
# not say, and mark that fallback rather than hiding it.
my $INV_VER = $inv->{version} // $tool;
my $VER     = ($dry ? undef : $T->{binver} && $T->{binver}->($binary)) // $INV_VER;
if ($VER ne $INV_VER) {
    printf STDERR "- NOTE: %s binary reports %s; the inventory was built from %s. "
                . "verified_with records the binary.\n", $tool, $VER, $INV_VER;
}
my @recs  = @{ $inv->{ $T->{inv_key} } };
my @orphans = grep { !$claimed{ $T->{ident}->($_) } } @recs;
@orphans = grep { $want_ident{ $T->{ident}->($_) } } @orphans if @only;
printf STDERR "- %s: %d orphan identifier(s)%s\n", $tool, scalar @orphans,
    (@only ? ' (filtered by --only)' : '');

#-----------------------------------------------------------------------
# THE INVENTORY CAN BE AHEAD OF THE INSTALLED BINARY
#
# data/tools/mdxfind.yaml is regenerated from whatever mdxfind upstream has
# released; /usr/local/bin/mdxfind is whatever is installed. On 2026-09-05
# those were 1.576 and 1.545, and 25 types existed only in the first. Pinning
# the installed binary to a type it does not have prints "No hash types
# selected" and exits 0 -- indistinguishable, to a caller reading only the
# absence of a crack line, from a type that ran and found nothing. So ask the
# binary what it HAS, once, and treat a type it lacks as unmeasurable there
# rather than as a failure.
#
# hashpipe is the second instrument for exactly this. It shares mdxfind's type
# list, it is installed here, and `-c` pins a named type per line -- the
# equivalent of `mdxfind -h '^TYPE$'`. What it establishes is upstream's claim
# reproduced by recomputation, which is tier `upstream` and not tier `vector`:
# `vector` means THIS tool round-tripped it under THIS identifier, and mdxfind
# has not. The row says so and names the command that would promote it.
my %MX_HAVE;
if ($tool eq 'mdxfind' && !$dry) {
    my $h = `\Q$binary\E -h 2>&1 </dev/null`;
    $MX_HAVE{$1} = 1 while $h =~ /^e\d+\s+\S+\s+(\S+)/mg;
    printf STDERR "- installed mdxfind has %d type(s)\n", scalar keys %MX_HAVE
        if $verbose;
}

$hp_binary ||= $ENV{HASHPIPE} || '/usr/local/bin/hashpipe';
my $HP_VER;
sub hp_version {
    return $HP_VER if defined $HP_VER;
    my $v = `\Q$hp_binary\E -V 2>&1 </dev/null`;
    $HP_VER = $v =~ m{RCS/hashpipe\.c,v\s+(\S+)\s+(\S+)} ? "RCS $1 ($2)" : 'unknown';
    return $HP_VER;
}

# hashpipe -c writes a VERIFIED line to stdout, relabelled with the depth that
# actually matched, and echoes a REFUSED line to stderr VERBATIM. The streams
# must stay separate: with them merged, a refusal and a pass look identical.
# Returns (1, '', $emitted_label) on success.
sub hp_verify {
    my ($ident, $vector) = @_;
    my $s  = safe($ident);
    # See RosettaTools::hashpipe_label: a type whose name ends in `x` must
    # carry an explicit depth or hashpipe answers about a different type.
    my $in = write_file("$workdir/hp.$s.in",
                        hashpipe_label($ident) . " $vector");
    # run_capture already sends the child's stderr to /dev/null, so $out is
    # stdout alone -- the separation -c requires.
    my ($code, $out) = run_capture($timeout, undef, $hp_binary, '-c', $in);
    return (0, 'timeout') if $code == -2;
    for my $line (split /\n/, $out) {
        next unless $line =~ /^(\Q$ident\E(?:x\d+)?)\s+\Q$vector\E$/;
        return (1, '', $1);
    }
    return (0, 'hashpipe -c refused the line');
}

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

    # Is this identifier one the installed binary can even be asked about?
    my $absent_here = ($tool eq 'mdxfind' && %MX_HAVE && !$MX_HAVE{$ident}) ? 1 : 0;

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
            $blk->{verified_at}   = $DATE;
            $blk->{verified_with} = "$tool $VER";
            $blk->{note} = "$ident added $DATE by seed-orphans.pl: $tool "
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
    my ($cracked, $err, $found, $stated, $hp_label);
    if ($dry) {
        ($cracked, $err, $found, $stated) =
            (1, '', (defined $pass ? $pass : '(discovered at run time)'), 0);
    }
    elsif ($absent_here) {
        unless ($via_hp) {
            $failed++;
            $why{'type postdates the installed mdxfind binary '
                 . "($VER); re-run with --via-hashpipe"}++;
            printf STDERR "  SKIP  %-24s %-34s not in the installed binary\n",
                $ident, $label;
            next;
        }
        ($cracked, $err, $hp_label) = hp_verify($ident, $r->{example_vector});
        ($found, $stated) = ($pass, 0);
    }
    else {
        ($cracked, $err, $found, $stated) = $T->{verify}->($ident, $hash, $pass, $r);
    }
    $pass = $found if defined $found;
    my $proven = ($cracked && defined $pass) ? 1 : 0;
    unless ($proven) {
        $failed++;
        $why{"example did not round-trip: " . ($err || 'no plaintext')}++;
        printf STDERR "  %-5s %-24s %-34s %s\n",
            ($unverified ? 'UNVER' : 'FAIL'), $ident, $label,
            ($err || 'no plaintext');
        next unless $unverified;
    }
    else { $ok++ }

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
                verified      => (($proven && !$absent_here) ? 'vector' : 'upstream'),
                verified_at   => $DATE,
                verified_with => ($proven && $absent_here)
                    ? "mdxfind $INV_VER, per the inventory; the installed "
                    . "binary is mdxfind $VER and does not have this type; "
                    . "hashpipe " . hp_version() . " reproduced the vector"
                    : "$tool $VER",
                note          => ($proven && $absent_here)
                    ? "NOT ROUND-TRIPPED BY mdxfind HERE, and that is a fact "
                    . "about this host rather than about the type. $ident is "
                    . "a type of $INV_VER, and the installed binary is $VER, so pinning "
                    . "it with -h '^$ident\$' selects no type at all. hashpipe "
                    . "-- which shares mdxfind's type list -- was pinned to this "
                    . "exact name with -c and reproduced mdxfind's own published "
                    . "example, emitting it as \"$hp_label\". That is upstream "
                    . "verified by recomputation, which is what tier `upstream` "
                    . "means. To promote it: install mdxfind $INV_VER and run "
                    . "seed-orphans.pl --tool mdxfind --only $ident, then "
                    . "verify-vectors.pl --tool mdxfind."
                    : !$proven
                    ? "NOT REPRODUCED HERE. $tool publishes this identifier and a "
                    . "worked example, which is what tier `upstream` means, but the "
                    . "local round-trip FAILED: " . why_failed($tool, $label, $err)
                    . ". The row exists so that someone arriving by this identifier "
                    . "is not met with nothing; the claim is upstream's, not this "
                    . "repository's, until a vector is round-tripped here. Re-run "
                    . "seed-orphans.pl --tool $tool --only $ident to retry."
                    : $tool eq 'john'
                    ? ($stated
                       ? "john's own published example ciphertext for this "
                       . "format, recovered by john under this format. "
                       . "--list=format-details publishes no plaintext, but "
                       . "john's SOURCE states one beside this ciphertext and "
                       . "that is the one here: it was offered to john ahead of "
                       . "every other candidate and john recovered it."
                       : "john's own published example ciphertext for this "
                       . "format, recovered by john under this format. john "
                       . "publishes no plaintext and its source states none for "
                       . "this ciphertext, so the plaintext was found by handing "
                       . "john its own example and a candidate list. Where "
                       . "john's comparison is not exact -- it says so per "
                       . "format, and again at run time -- a search can return a "
                       . "colliding string rather than what was hashed, so this "
                       . "plaintext is the weaker half of the vector.")
                    : "${tool}'s own published example for this identifier, "
                    . "recovered by $tool at this identifier with ${tool}'s own "
                    . "published plaintext.",
            },
            crack => { supported => 0 },
        },
        # A vector needs both a hash and a plaintext. john's unproven rows have
        # no plaintext -- that IS the failure -- so they carry no vector, which
        # is honest rather than a placeholder somebody might trust.
        (defined $pass
            ? (vectors => [ { hash => $hash, pass => $pass, source => $tool } ])
            : ()),
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
            verified_at   => $DATE,
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
