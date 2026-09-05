#!/usr/bin/perl
#-----------------------------------------------------------------------
#
# Name: audit-denotations.pl
# Description: check every denotation against the vendored Appendix A, and
#              separate a richer entry from an entry that is simply wrong
# Category: cracking-rosetta verifier
#
# Project: cracking-rosetta | Phase: 6 - close the john gap
#
#-----------------------------------------------------------------------
# METHODOLOGY AND WHY THIS EXISTS
#
# WHY NOTHING RE-READ THE SPECIFICATION
#
# denote-hx.pl writes a denotation only where none exists -- "Never touches an
# entry that already has an expression: or a denotation:". That is the right
# rule for a seeder, because it must not overwrite curated text. Its
# consequence is that no tool ever looked at a denotation again. 483 entries
# still cite Appendix A at the revision they were written from, and the
# specification has moved since.
#
# Vendoring hx.8 made the comparison possible for the first time: the appendix
# is now a file in the tree, so "does this entry still say what the
# specification says?" is a diff and not a memory.
#
# WHAT A DIFFERENCE MEANS, WHICH IS NOT ALWAYS A DEFECT
#
# Three outcomes, and only one is a finding:
#
#   the appendix declines to give an expression
#       49 rows state prose -- "five-variant single-byte salt search, see Note
#       [10]", "(complex: iterates single-char salts)". An entry that says more
#       than that is more useful, not wrong, so a difference is exempt.
#
#   the entry states the EMISSION SET
#       9 rows describe a multi-emit type: "MD5MD5USER is MULTI-EMIT: it
#       matches either md5(md5($p).$u) or md5(md5($p).":".$u)". The appendix
#       gives one of those forms; the entry gives the set. Also richer, also
#       exempt.
#
#   both state an expression and the expressions differ
#       That is a finding. One of the two is wrong about the algorithm.
#
# PROSE IS DECIDED BY SHAPE, NOT BY MARKUP
#
# The obvious test -- the appendix italicises prose -- is wrong. 50 cells are
# wholly italic and one of them is `"{SHA}" . base64(sha1_bin(pass))`, an
# expression that merely happens to be set in italic. So a cell counts as an
# expression when it contains a call, an identifier followed by an open
# parenthesis, and as prose otherwise. That admits the 976 real expressions and
# rejects the 49 descriptions, with no dependence on how the page is typeset.
#
# WHICH SIDE IS AUTHORITATIVE
#
# mdxfind.c. Not this repository, and not the specification either -- though in
# every conflict resolved so far the specification has been the one that was
# right. A finding here is an instruction to go and read the C, not to copy
# hx.8 over the entry.
#
#-----------------------------------------------------------------------

use strict;
use warnings;
use File::Basename qw(basename);
use File::Glob qw(:bsd_glob);
use FindBin qw($RealBin);
use Getopt::Long qw(GetOptions);
use YAML::XS ();

use lib "$RealBin/lib";
use RosettaHx qw(parse_appendix);

my $PROG = basename($0);
my $ROOT = "$RealBin/..";

my $algdir   = "$ROOT/data/algorithms";
my $appendix = "$ROOT/data/hx-appendix-a.txt";
my ($check, $help);

sub usage {
    print STDERR <<"END_USAGE";

Usage: $PROG [options]

   --algorithms DIR  curated entries      (default: data/algorithms)
   --appendix FILE   parsed Appendix A    (default: data/hx-appendix-a.txt)
   --check           print nothing unless there is a finding; for CI
   --help            this message

Exit 0 when every denotation either matches the appendix or is exempt,
1 when an entry and the specification both state an expression and the two
disagree, 2 on a usage error.

END_USAGE
}

GetOptions(
    'algorithms=s' => \$algdir,
    'appendix=s'   => \$appendix,
    'check'        => \$check,
    'help'         => \$help,
) or do { usage(); exit 2 };
if ($help) { usage(); exit 0 }

my $hx = eval { parse_appendix($appendix) }
    or do { print STDERR "$PROG: cannot read $appendix: $@\n"; exit 1 };

# A cell states an expression when it contains a call; anything else is prose.
sub is_expression { return $_[0] =~ /\w\s*\(/ ? 1 : 0 }

# The entry is describing the emission set rather than one construction.
sub states_emission_set {
    return $_[0] =~ /MULTI-EMIT|matches either|emits (?:EIGHT|several)/ ? 1 : 0;
}

my @files = bsd_glob("$algdir/*.yaml");
my (@conflict, $compared, $same, $declines, $emission);
$compared = $same = $declines = $emission = 0;

for my $f (sort @files) {
    my $d = eval { YAML::XS::LoadFile($f) } or next;
    next if ($d->{status} // '') eq 'merged';
    my $den = $d->{denotation}                  or next;
    next unless ($den->{source} // '') eq 'mdxfind';
    my $ty  = $d->{tools}{mdxfind}{types}[0]    or next;
    my $e   = $hx->{$ty}                        or next;

    $compared++;
    my $entry = $den->{text} // '';
    if ($e->{expr} eq $entry)             { $same++;     next }
    if (!is_expression($e->{expr}))       { $declines++; next }
    if (states_emission_set($entry))      { $emission++; next }

    push @conflict, { id => $d->{id} // basename($f), ty => $ty,
                      ix => $e->{index}, hx => $e->{expr}, en => $entry };
}

unless ($check && !@conflict) {
    printf "- %d denotation(s) compared against Appendix A; %d identical\n",
           $compared, $same;
    printf "- exempt: %d where the appendix states prose, %d where the entry "
         . "states the emission set\n", $declines, $emission;

    if (@conflict) {
        printf "\n- %d entry/entries and the specification BOTH state an "
             . "expression, and the two\n  disagree. One of them is wrong about "
             . "the algorithm; mdxfind.c decides which:\n\n", scalar @conflict;
        for my $c (@conflict) {
            printf "    %-30s %-24s %s\n      hx.8 : %s\n      entry: %s\n\n",
                   $c->{id}, $c->{ty}, $c->{ix}, $c->{hx}, $c->{en};
        }
    } else {
        print "\n- OK: no entry contradicts the specification\n";
    }
}

exit(@conflict ? 1 : 0);
