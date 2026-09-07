#!/usr/bin/perl
#-----------------------------------------------------------------------
#
# Name: attach-mdxfind-ahead.pl
# Description: put an mdxfind type that the INSTALLED mdxfind binary does not
#              have onto the entry that already describes it, using hashpipe
#              as the oracle
# Category: cracking-rosetta seeder
#
# Project: cracking-rosetta | Phase: 8 - the inventory is ahead of the binary
#
#-----------------------------------------------------------------------
# METHODOLOGY AND WHY THESE CHOICES
#
# THE PROBLEM THIS EXISTS FOR
#
# data/tools/mdxfind.yaml is regenerated from whatever mdxfind upstream has
# released; /usr/local/bin/mdxfind is whatever is installed. Measured
# 2026-09-05 those were RCS 1.576 and RCS 1.545, and 25 types existed only in
# the first. mdxfind cannot be the oracle for a type it does not have, and it
# does not say so in a way a caller notices: pinning it with -h '^TYPE$'
# prints "No hash types selected" and exits 0, which reads exactly like a type
# that ran and found nothing.
#
# hashpipe is the instrument for that gap. It is installed here, it shares
# mdxfind's type list (verified name-identical on every shared index), it
# RECOMPUTES rather than cracking, and `-c` pins a named type per line -- the
# equivalent of `mdxfind -h '^TYPE$'`.
#
# THIS IS A STOPGAP, AND IT IS THE SECOND THING TO REACH FOR
#
# Ask first whether ANOTHER mdxfind build on the host has the type. On
# 2026-09-05 one did -- /home/claude/src/upstream/mdxfind/mdxfind, RCS 1.576,
# built from the upstream clone -- and every one of the 25 mappings this tool
# wrote at tier `upstream` went straight to `vector` under it. Not installed
# is not the same as not usable, and the corpus already cited that build for
# 34 blocks before this tool existed. So:
#
#     tools/verify-vectors.pl --tool mdxfind --mdxfind <build with the type>
#
# is the follow-up, and this tool's output is what you have until there is a
# build to run. Where a vector is stored in another tool's serialization the
# follow-up needs data/mdxfind-transcodes.tsv too, which verify-vectors reads
# as its last fallback.
#
# TWO STAGES, BECAUSE ONE WOULD NOT BE EVIDENCE
#
#   1. PROPOSE. Each of an entry's vectors is fed to hashpipe's DETECTION path
#      on its own line, one invocation per vector. Detection names the FIRST
#      type that reproduces the digest, which is a candidate and nothing more
#      -- MD5CAP is cap(md5($p)), a no-op on a digest with no letters to
#      capitalize, so an unpinned answer routinely names a type that works
#      rather than the type the entry is about.
#      One line per invocation is not fastidiousness: hashpipe re-serializes
#      what it read, refusals go to the other stream, and a batch's output
#      lines therefore do not correspond to its input lines. Feeding the whole
#      corpus at once and matching by position or by plaintext puts the answer
#      on the wrong entry, which is how "MD4SALTPASS" first came back attached
#      to any of the 27 entries whose plaintext is "test1".
#
#   2. PROVE. The proposal is re-run through `hashpipe -c` PINNED to the bare
#      type name, and only a line that comes back on STDOUT under that same
#      name is written. stdout and stderr are never merged: -c echoes a
#      REFUSED line to stderr verbatim, so a merged stream is consistent with
#      a pass and with a refusal alike.
#
# WHY THE TIER IS `upstream` AND NOT `vector`
#
# `vector` means THIS tool round-tripped the vector under THIS identifier.
# mdxfind has not and cannot here. What is established is upstream's claim
# reproduced by recomputation in a second implementation, which is what tier
# `upstream` means. Every row written says which binary is installed, which
# release the inventory came from, and the command that promotes the claim
# once they agree.
#
# WHAT IT REFUSES
#
#   * A type the installed binary DOES have. That is discover-mdxfind.pl's
#     job and mdxfind is the better oracle for it; writing `upstream` here
#     would be weaker than the evidence available.
#   * An entry whose mdxfind block is already at tier `vector`. A block
#     carries ONE tier for every identifier in it, so adding an `upstream`
#     identifier to a `vector` block either overstates the new one or
#     understates the old ones. Reported, never resolved.
#   * A proposal whose pinned re-run does not come back. That is the whole
#     point of stage 2.
#
# THE TRANSCODE FILE
#
# hashpipe's DETECTION path reads several dialects, including john's
# "$dynamic_N$..." wrapper; `-c` does not, and some entries store a vector in
# a serialization no reader here parses at all (john writes RVARY as
# "$rvary$<hex>", mdxfind wants the bare hex). --transcode names a file of
#
#     TYPE <TAB> entry-id <TAB> hash[:salt]:plaintext
#
# lines supplying the type's own serialization of THAT ENTRY'S OWN VECTOR. It
# is a hint about spelling, not a claim: the line still has to survive stage 2
# under the pinned type or nothing is written. Say in the entry that the two
# strings are ONE piece of evidence written twice -- a later reader must not
# count them as two agreeing vectors.
#
# USAGE
#   tools/attach-mdxfind-ahead.pl --report | --apply [--transcode FILE] [-v]
#
# DEPENDENCIES
#   perl, YAML::XS, tools/lib/RosettaEmit.pm, a hashpipe binary, an mdxfind
#   binary (asked only what types it has)
#
#-----------------------------------------------------------------------
# Generated by Claude Opus 5 on 2026-09-05

use strict;
use warnings;

use File::Basename qw(basename);
use File::Path qw(make_path);
use FindBin qw($RealBin);
use Getopt::Long qw(GetOptions);
use POSIX qw(strftime);
use Time::HiRes qw(time);
use YAML::XS qw(LoadFile);

use lib "$RealBin/lib";
use RosettaEmit qw(emit_entry);

my $PROG = basename($0);
my $ROOT = "$RealBin/..";

my $algdir    = "$ROOT/data/algorithms";
my $workdir   = "$ROOT/tmp/attach-ahead";
my $hp_binary = $ENV{HASHPIPE} || '/usr/local/bin/hashpipe';
my $mx_binary = $ENV{MDXFIND}  || '/usr/local/bin/mdxfind';
my $transfile;
my ($report, $apply, $verbose, $help) = (0,0,0,0);
my $DATE = strftime('%Y-%m-%d', localtime);
my @only;
my $had = scalar @ARGV;

sub usage {
    print STDERR <<"END";

Usage: $PROG --report | --apply [options]

   --report          propose, prove, print; write nothing
   --apply           the same, and write what survived
   --transcode FILE  TYPE<TAB>entry-id<TAB>line, for a vector whose stored
                     serialization hashpipe -c cannot read
   --only ID         just this entry (repeatable)
   --hashpipe PATH   hashpipe binary (\$HASHPIPE, else /usr/local/bin/hashpipe)
   --mdxfind PATH    mdxfind binary  (\$MDXFIND,  else /usr/local/bin/mdxfind)
   --algorithms DIR  curated entries (default: data/algorithms)
   --date YYYY-MM-DD verified_at to record (default: today, UTC)
   -v, --verbose     per-entry detail on stderr (repeatable)
   -h, --help        this help

   Only a type the given mdxfind does not have is considered; a type it does
   have belongs to discover-mdxfind.pl, which has the better oracle. Point
   --mdxfind at a build that HAS the type and this tool correctly does
   nothing -- which is the outcome to prefer, since that build can reach tier
   `vector` and this cannot.
   Exit 0 success, 1 error, 2 usage.

END
    exit 2;
}

GetOptions(
    'report'       => \$report,
    'apply'        => \$apply,
    'transcode=s'  => \$transfile,
    'only=s'       => \@only,
    'hashpipe=s'   => \$hp_binary,
    'mdxfind=s'    => \$mx_binary,
    'algorithms=s' => \$algdir,
    'date=s'       => \$DATE,
    'verbose|v+'   => \$verbose,
    'help|h'       => \$help,
) or usage();
usage() if $help || !$had || !($report || $apply);
make_path($workdir) unless -d $workdir;

sub arr { my $r = shift; ref $r eq 'ARRAY' ? @$r : () }

sub run_out {
    # stdout only: the child's stderr goes to /dev/null, which is the
    # separation `-c` requires. A merged stream cannot tell a pass from the
    # verbatim echo of a refusal.
    my (@cmd) = @_;
    my $pid = open my $fh, '-|';
    die "$PROG: fork: $!\n" unless defined $pid;
    unless ($pid) { open STDERR, '>', '/dev/null'; exec @cmd or exit 127 }
    local $/;
    my $out = <$fh> // '';
    close $fh;
    waitpid $pid, 0;
    return $out;
}

# A version banner is the one thing worth reading off the MERGED stream:
# hashpipe writes its RCS header to stderr, and the stream rule that keeps -c
# honest is about verification output, where a refusal echo and a pass are
# indistinguishable once merged. A banner has no such twin.
sub run_banner {
    my (@cmd) = @_;
    my $pid = open my $fh, '-|';
    die "$PROG: fork: $!\n" unless defined $pid;
    unless ($pid) { open STDERR, '>&', \*STDOUT; exec @cmd or exit 127 }
    local $/;
    my $out = <$fh> // '';
    close $fh;
    waitpid $pid, 0;
    return $out;
}

sub write_line { my ($p,$l) = @_; open my $f,'>',$p or die "$PROG: $p: $!\n";
                 print $f "$l\n"; close $f; return $p }
sub safe { my $s = shift; $s =~ s/[^A-Za-z0-9]/_/g; return $s }

#-----------------------------------------------------------------------
# What the installed mdxfind HAS, and what the inventory SAYS it has.

my $mx_h = run_out($mx_binary, '-h');
my %MX_HAVE;
$MX_HAVE{$1} = 1 while $mx_h =~ /^e\d+\s+\S+\s+(\S+)/mg;
die "$PROG: parsed no types from $mx_binary -h\n" unless %MX_HAVE;

my $mx_v = run_banner($mx_binary, '-V');
my $MX_VER = $mx_v =~ m{RCS/mdxfind\.c,v\s+(\S+)\s+(\S+)} ? "RCS $1 ($2)" : 'unknown';
die "$PROG: $mx_binary -V did not state a version; refusing to stamp "
  . "verified_with with a guess\n" if $MX_VER eq 'unknown';
my $hp_v = run_banner($hp_binary, '-V');
my $HP_VER = $hp_v =~ m{RCS/hashpipe\.c,v\s+(\S+)\s+(\S+)} ? "RCS $1 ($2)" : 'unknown';
die "$PROG: $hp_binary -V did not state a version; refusing to stamp "
  . "verified_with with a guess\n" if $HP_VER eq 'unknown';

my $inv = LoadFile("$ROOT/data/tools/mdxfind.yaml");
my $INV_VER = $inv->{version} // 'unknown';
my %INV_TYPE = map { $_->{name} => $_ } @{ $inv->{types} };

printf STDERR "- installed mdxfind %s has %d type(s); the inventory is %s with %d\n",
    $MX_VER, scalar keys %MX_HAVE, $INV_VER, scalar keys %INV_TYPE;
printf STDERR "- hashpipe %s is the oracle\n", $HP_VER;

# The set this tool is allowed to touch at all.
my %AHEAD = map { $_ => 1 } grep { !$MX_HAVE{$_} } keys %INV_TYPE;
printf STDERR "- %d type(s) in the inventory that the installed binary lacks\n",
    scalar keys %AHEAD;

#-----------------------------------------------------------------------
# The corpus.

my (@entries, %claimed);
opendir my $dh, $algdir or die "$PROG: $algdir: $!\n";
for my $f (sort grep { /\.yaml$/ } readdir $dh) {
    my $e = eval { LoadFile("$algdir/$f") } or next;
    next unless $e->{id};
    next if ($e->{status}//'') eq 'merged';
    my $m = ref $e->{tools} eq 'HASH' ? $e->{tools}{mdxfind} : undef;
    $claimed{$_} = 1 for (ref $m eq 'HASH' ? arr($m->{types}) : ());
    push @entries, { path => "$algdir/$f", data => $e };
}
closedir $dh;
my %want = map { $_ => 1 } @only;
@entries = grep { $want{ $_->{data}{id} } } @entries if @only;
printf STDERR "- %d entry(ies)%s\n", scalar @entries, (@only ? ' (filtered)' : '');

#-----------------------------------------------------------------------
# --transcode: TYPE <TAB> entry-id <TAB> line

my %TRANS;    # entry id -> [ [type, line], ... ]
if (defined $transfile) {
    open my $fh, '<', $transfile or die "$PROG: $transfile: $!\n";
    my $n = 0;
    while (<$fh>) {
        chomp; next if /^\s*(#|$)/;
        my ($type, $id, $line) = split /\t/, $_, 3;
        unless (defined $line && length $line) {
            die "$PROG: $transfile line $.: want TYPE<TAB>id<TAB>line\n";
        }
        die "$PROG: $transfile line $.: $type is not a type of $INV_VER\n"
            unless $INV_TYPE{$type};
        push @{ $TRANS{$id} }, [ $type, $line ];
        $n++;
    }
    close $fh;
    printf STDERR "- %d transcode hint(s) from %s\n", $n, $transfile;
}

#-----------------------------------------------------------------------
# Stage 1: propose, one vector per invocation.
# Stage 2: prove, pinned with -c.

sub prove {
    my ($type, $line) = @_;
    my $in = write_line("$workdir/pin." . safe($type) . ".txt", "$type $line");
    my $out = run_out($hp_binary, '-c', $in);
    for my $l (split /\n/, $out) {
        # the emitted label is bare where the input was bare, or carries the
        # depth that actually matched; either is this type, nothing else is
        return $1 if $l =~ /^(\Q$type\E(?:x\d+)?)\s+\Q$line\E$/;
    }
    return undef;
}

my ($proposed, $proved, $written, $refused, $blocked) = (0,0,0,0,0);
my @found;
my $t0 = time;

for my $ent (@entries) {
    my $e  = $ent->{data};
    my @vs = grep { ref $_ eq 'HASH' && defined $_->{hash} && defined $_->{pass} }
             arr($e->{vectors});
    my @cand;

    # transcode hints first: they exist because detection cannot read the
    # stored form, so there is nothing for stage 1 to propose. They are held
    # to the same claimed-elsewhere rule as a proposal -- without it a hint
    # would be re-proposed on every run, and a hint naming a type that has
    # since landed on ANOTHER entry would quietly move it.
    for my $h (@{ $TRANS{ $e->{id} } || [] }) {
        if ($claimed{ $h->[0] }) {
            printf STDERR "  hint-spent %-22s %s already carries this type\n",
                $h->[0], $e->{id} if $verbose;
            next;
        }
        push @cand, $h;
    }

    for my $v (@vs) {
        next if $v->{hash} =~ /\n/ || $v->{pass} =~ /\n/;
        my $in = write_line("$workdir/one.txt", "$v->{hash}:$v->{pass}");
        my $out = run_out($hp_binary, $in);
        for my $l (split /\n/, $out) {
            next unless $l =~ /^(\S+?)(?:x\d+)?\s+(\S.*)$/;
            my ($type, $rest) = ($1, $2);
            next unless $AHEAD{$type};          # only what mdxfind cannot run
            next if $claimed{$type};            # already on some entry
            push @cand, [ $type, $rest ];
        }
    }

    my %seen;
    @cand = grep { !$seen{ $_->[0] }++ } @cand;
    next unless @cand;
    $proposed += @cand;

    my @ok;
    for my $c (@cand) {
        my ($type, $line) = @$c;
        my $label = prove($type, $line);
        unless (defined $label) {
            $refused++;
            printf STDERR "  refused  %-24s %-30s %s\n", $type, $e->{id}, $line
                if $verbose;
            next;
        }
        $proved++;
        push @ok, { type => $type, line => $line, label => $label };
    }
    next unless @ok;

    my $blk = ref $e->{tools} eq 'HASH' ? $e->{tools}{mdxfind} : undef;
    if (ref $blk eq 'HASH' && ($blk->{verified}//'') eq 'vector') {
        $blocked += scalar @ok;
        printf STDERR "  BLOCKED  %-24s %s already at tier vector; a block "
                    . "carries one tier for every identifier in it\n",
            join(',', map { $_->{type} } @ok), $e->{id};
        next;
    }

    for my $o (@ok) {
        printf "%-24s -> %-34s verified as %s\n", $o->{type}, $e->{id}, $o->{label};
        push @found, [ $o->{type}, $e->{id} ];
        $claimed{ $o->{type} } = 1;   # so the residue count below is the same
                                      # figure whether or not --apply ran
    }
    next unless $apply;

    $e->{tools} = {} unless ref $e->{tools} eq 'HASH';
    $blk = $e->{tools}{mdxfind} ||= {};
    my %t = map { $_ => 1 } (arr($blk->{types}), map { $_->{type} } @ok);
    $blk->{types}         = [ sort keys %t ];
    $blk->{verified}      = 'upstream';
    $blk->{verified_at}   = $DATE;
    $blk->{verified_with} = "mdxfind $INV_VER, per the inventory; the installed "
                          . "binary is mdxfind $MX_VER and does not have "
                          . (@ok > 1 ? 'these types' : 'this type') . "; "
                          . "hashpipe $HP_VER reproduced the vector";
    $blk->{note} =
        join(' ', map { "$_->{type} added $DATE by attach-mdxfind-ahead.pl." } @ok)
      . " NOT ROUND-TRIPPED BY mdxfind HERE, and that is a fact about this host "
      . "rather than about the type: the inventory is $INV_VER and the installed "
      . "binary is $MX_VER, so pinning it with -h selects no type at all and "
      . "prints nothing a caller can distinguish from a type that ran and found "
      . "nothing. hashpipe -- which shares mdxfind's type list -- was pinned to "
      . "the bare type name with -c and reproduced THIS ENTRY'S OWN vector, "
      . "emitting "
      . join(' and ', map { "\"$_->{label}\" for $_->{line}" } @ok)
      . ". Where that line is not the vector as stored above, it is the same "
      . "vector written in the type's own serialization -- ONE piece of "
      . "evidence written twice, not two agreeing vectors. That is upstream "
      . "verified by recomputation, which is what tier `upstream` means. To "
      . "promote it: install mdxfind $INV_VER, then verify-vectors.pl --tool "
      . "mdxfind --only $e->{id}.";

    emit_entry($ent->{path}, $e);
    $written += scalar @ok;
}

printf STDERR "\n%s: %d proposed, %d proved, %d refused, %d blocked, %d written%s\n",
    $PROG, $proposed, $proved, $refused, $blocked, $written,
    ($apply ? '' : ' (no --apply)');
printf STDERR "- %.1fs\n", time - $t0;
printf STDERR "- %d type(s) the installed binary lacks are still on no entry\n",
    scalar grep { !$claimed{$_} } keys %AHEAD;
exit 0;
