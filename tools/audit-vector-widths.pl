#!/usr/bin/perl
#-----------------------------------------------------------------------
#
# Name: audit-vector-widths.pl
# Description: find vectors stored narrower than the digest their type emits,
#              and separate a tool's own serialization from a truncation
# Category: cracking-rosetta verifier
#
# Project: cracking-rosetta | Phase: 6 - close the john gap
#
#-----------------------------------------------------------------------
# METHODOLOGY AND WHY THIS EXISTS
#
# HOW THE DEFECT WAS FOUND
#
# Twelve entries of the mdxfind TRUNC family -- SHA1SHA256TRUNC, SHA1WRLTRUNC,
# SHA1MD6TRUNC and the rest -- stored a 32-character hash for a type whose
# output is a 40-character sha1. Each one nevertheless carried tier 'vector'
# for mdxfind, and had carried it for as long as the entries existed.
#
# WHY NOTHING CAUGHT IT
#
# mdxfind converts every loaded hash to binary and compares at the shortest
# length it read. A stored prefix therefore MATCHES: mdxfind reported
#
#     SHA1SHA256TRUNCx01 178f1d54c362162cf48501121c4a5fba:64:password123
#
# and the entry looked proven. The full digest is
# 178f1d54c362162cf48501121c4a5fbab5050670 and the stored string is its first
# 32 characters. verify-vectors.pl asks whether the tool reproduces the stored
# string, which it does, so the round trip closes on a value that is not the
# algorithm's output. Only hashpipe dissented -- it compares the whole digest
# and refused all twelve -- and a refusal reads as "no mapping yet", which is
# indistinguishable from a gap nobody has filled.
#
# WHAT THIS SCRIPT MEASURES
#
# data/tools/mdxfind.yaml publishes example_vector for 1026 of the 1027 types,
# so the width of a type's digest is vendored data and needs no tool run. For
# every vector whose leading field is hex, this compares that field's width
# against the width of the leading field of the type's own published example.
#
# WHY A MISMATCH IS NOT AUTOMATICALLY A DEFECT
#
# Three of the ten mismatches in the corpus at the time of writing are real and
# correct, and each is a tool writing the same credential its own way:
#
#   half-md5      MD5 kept to 16 characters, which is what the format IS
#   mysql4-1-...  32 characters, john's dynamic_1028, whose dynamic.conf line
#                 reads "sha1(sha1_raw($p)) (hash truncated to length 32)"
#   dane-rfc7929  56 characters, hashcat's mode 30420, a sha256 truncated to
#                 224 bits
#
# The schema already has the field that says so: form:. A mismatch on a vector
# that declares form: john or form: hashcat is that tool's spelling and is
# reported as accounted for. A mismatch with no form: at all is unexplained and
# is what this script exists to surface. A mismatch on form: native is a
# contradiction in terms -- native is the producing system's own output, which
# is the width being compared against -- and is reported the loudest.
#
# So the rule this enforces is not "widths must match". It is that a width
# which does not match must SAY which serialization it is, so that the next
# reader can tell a deliberate form from a lost half of a digest without
# re-deriving the digest to find out.
#
#-----------------------------------------------------------------------

use strict;
use warnings;
use File::Basename qw(basename);
use FindBin qw($RealBin);
use Getopt::Long qw(GetOptions);
use YAML::XS ();

my $PROG = basename($0);
my $ROOT = "$RealBin/..";

my $algdir    = "$ROOT/data/algorithms";
my $inventory = "$ROOT/data/tools/mdxfind.yaml";
my ($check, $help);

sub usage {
    print STDERR <<"END_USAGE";

Usage: $PROG [options]

   --algorithms DIR  curated entries    (default: data/algorithms)
   --inventory PATH  mdxfind inventory  (default: data/tools/mdxfind.yaml)
   --check           print nothing unless there is a finding; for CI
   --help            this message

Exit 0 when every width either matches or declares its serialization,
1 when a vector is narrower or wider than its type's digest and does not
say which form it is written in, 2 on a usage error.

END_USAGE
}

GetOptions(
    'algorithms=s' => \$algdir,
    'inventory=s'  => \$inventory,
    'check'        => \$check,
    'help'         => \$help,
) or do { usage(); exit 2 };
if ($help) { usage(); exit 0 }

my $inv = eval { YAML::XS::LoadFile($inventory) }
    or do { print STDERR "$PROG: cannot load $inventory: $@\n"; exit 1 };

# Width of the leading hex field of each type's own published example.
# A type is comparable only when its own example parses as the shape this
# check assumes -- hash:password, or hash:salt:password -- and the leading
# field really is the digest. Two families break that and must be skipped, or
# the "expected" width is nonsense rather than merely wrong:
#
#   IPMI2-SHA1  00:1c9f35d8...:password123   leads with a 2-character prefix
#   IKEPSK-MD5  4141...:4242...:4343...:...  a six-field structured blob
#
# The first is caught by the J flag, which marks a type whose line needs
# structured loading; the second by the field count, since a salt carrying
# colons is not the hash:salt:password this compares against.
my %width;
for my $t (@{ $inv->{types} || [] }) {
    my $ex = $t->{example_vector} or next;
    next if grep { $_ eq 'J' } @{ $t->{flags} || [] };
    my @f = split /:/, $ex;
    next unless @f == 2 || @f == 3;
    next unless $f[0] =~ /^[0-9a-fA-F]+$/;
    $width{ $t->{name} } = length $f[0];
}

opendir(my $dh, $algdir) or do { print STDERR "$PROG: cannot read $algdir: $!\n"; exit 1 };
my @files = sort grep { /\.yaml$/ } readdir $dh;
closedir $dh;

my (@unexplained, @contradiction, @accounted);
my ($entries, $compared) = (0, 0);

for my $f (@files) {
    my $d = eval { YAML::XS::LoadFile("$algdir/$f") } or next;
    next if ($d->{status} // '') eq 'merged';
    next unless ref $d->{vectors} eq 'ARRAY';

    my @types = grep { exists $width{$_} }
                map  { @{ $d->{tools}{$_}{types} || [] } } qw(mdxfind hashpipe);
    next unless @types;
    $entries++;

    for my $v (@{ $d->{vectors} }) {
        my $h = $v->{hash} // next;
        my ($lead) = split /:/, $h, 2;
        next unless defined $lead && $lead =~ /^[0-9a-fA-F]+$/;
        $compared++;

        my $got  = length $lead;
        next if grep { $width{$_} == $got } @types;

        my @want = sort { $a <=> $b } do { my %s; grep { !$s{$_}++ } map { $width{$_} } @types };
        my $form = $v->{form};
        my $rec  = sprintf "%-36s %-22s stored %-4d expected %-11s %s",
                           ($d->{id} // $f), join(',', @types), $got,
                           join('/', @want),
                           (defined $form ? "form: $form" : 'NO form:');

        if    (!defined $form)      { push @unexplained,   $rec }
        elsif ($form eq 'native')   { push @contradiction, $rec }
        else                        { push @accounted,     $rec }
    }
}

my $bad = @unexplained + @contradiction;

unless ($check && !$bad) {
    printf "- %d vector(s) across %d entry/entries compared against the width of "
         . "their type's own published example\n", $compared, $entries;

    if (@contradiction) {
        printf "\n- %d vector(s) declare form: native at a width their type does not "
             . "emit. native IS\n  the producing system's own output, so this says two "
             . "things that cannot both hold:\n\n", scalar @contradiction;
        print "    $_\n" for @contradiction;
    }
    if (@unexplained) {
        printf "\n- %d vector(s) are not the width their type emits and do not say "
             . "which\n  serialization they are. mdxfind compares binary at the "
             . "shortest length it read,\n  so a stored prefix still round-trips and "
             . "the entry looks proven; set form: to\n  the tool whose spelling this "
             . "is, or restore the digest:\n\n", scalar @unexplained;
        print "    $_\n" for @unexplained;
    }
    if (@accounted) {
        printf "\n- %d vector(s) differ in width and say why. These are correct: a "
             . "tool writing the\n  same credential in its own form, which form: "
             . "records:\n\n", scalar @accounted;
        print "    $_\n" for @accounted;
    }
    print "\n- OK: every width either matches or declares its form\n" unless $bad;
}

exit($bad ? 1 : 0);
