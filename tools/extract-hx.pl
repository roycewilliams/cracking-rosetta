#!/usr/bin/perl
#-----------------------------------------------------------------------
#
# Name: extract-hx.pl
# Description: render Appendix A of the vendored hx specification into the
#              flat text the seeding tools read
# Category: cracking-rosetta extractor
#
# Project: cracking-rosetta | Phase: upstream seed data
#
#-----------------------------------------------------------------------
# METHODOLOGY AND WHY THESE CHOICES
#
# APPENDIX A IS A SOURCE, AND IT IS VENDORED LIKE ONE
#
# Appendix A states what each mdxfind type computes. It is the authority
# behind every denotation: this repository sources to mdxfind, and behind the
# expressions seed-hx.pl proposes. It arrives as `vendor/cynosureprime/hx.8`,
# the troff source of the published specification, fetched by
# tools/fetch-upstream.sh and recorded in vendor/cynosureprime/PROVENANCE.md
# with the commit it came from.
#
# This script turns that troff into the three-column text RosettaHx's
# parse_appendix() reads: index, name, expression, tab separated. Output is
# committed, so the seeding tools have a source in the repository and a
# reader can diff a specification change the same way they diff a catalog
# change.
#
# WHAT THE TROFF NEEDS DOING TO IT
#
# Two constructs stand between the table and a usable expression, and both
# are silent: they yield a row that parses and means the wrong thing.
#
#   Font and character escapes.  \fI...\fP wraps the prose gloss on 271 rows,
#   \(em and \(en are dashes, \s-2/\s+2 shrink a long type name.  Left in,
#   they become part of the expression string and every comparison against
#   one fails.
#
#   Multi-line table cells.  tbl writes a cell too wide for its column as
#   `T{` at the end of the row, the content on following lines, and `T}` to
#   close.  The row then reads `e947 TELEGRAM-SHA256 T{`, which parses
#   cleanly and records the expression of TELEGRAM-SHA256 as the literal
#   string "T{".
#
# The gloss in parentheses is KEPT.  RosettaHx::strip_gloss separates it from
# the expression, and denote-hx.pl needs it: for a row that states prose
# rather than a construction, the prose is the denotation.
#
# WHAT IT DOES NOT DO
#
# It does not interpret the expressions, resolve a Note reference, or repair
# a row it finds doubtful. Appendix A has been measured wrong about its own
# types -- e308 omits the password operand -- and those are recorded in
# data/upstream-findings.yaml against the entries they affect. A row is
# transcribed as it stands; judgment lives where the evidence is.
#
# Usage: extract-hx.pl [--source FILE] [--out FILE] [-v] [-n]
# Exit 0 success, 1 error, 2 usage.
#-----------------------------------------------------------------------
use strict;
use warnings;
use File::Basename qw(basename);
use Getopt::Long qw(GetOptions);

my $PROG = basename($0);
my $ROOT = do { my $d = $0; $d =~ s{/[^/]+$}{}; "$d/.." };

my ($source, $out, $verbose, $dry, $help);
GetOptions(
    'source=s' => \$source, 'out=s' => \$out,
    'verbose+' => \$verbose, 'n|dry-run' => \$dry, 'h|help' => \$help,
) or usage(2);
usage(0) if $help;
usage(2) if !@ARGV && !defined $source && !defined $out && !$verbose && !$dry && !$help && 0;

$source //= "$ROOT/vendor/cynosureprime/hx.8";
$out    //= "$ROOT/data/hx-appendix-a.txt";

sub usage {
    my ($rc) = @_;
    print <<"USAGE";

Usage: $PROG [options]

   --source FILE  vendored Appendix A troff (default: vendor/cynosureprime/hx.8)
   --out FILE     where to write the flat table (default: data/hx-appendix-a.txt)
   -n, --dry-run  report what would be written; write nothing
   -v, --verbose  per-row detail
   -h, --help     this help

   Renders Appendix A into "index<TAB>name<TAB>expression" for
   RosettaHx::parse_appendix. Font escapes and multi-line tbl cells are
   resolved; the parenthesised gloss is kept, because a row that states prose
   rather than a construction is where a denotation comes from.

   Exit 0 success, 1 error, 2 usage.

USAGE
    exit $rc;
}

open my $fh, '<', $source or die "$PROG: $source: $!\n";
my @lines = <$fh>;
close $fh;

# Join tbl's multi-line cells first, so a row is one line before anything
# else looks at it.
my @joined;
for (my $i = 0; $i <= $#lines; $i++) {
    my $l = $lines[$i];
    chomp $l;
    if ($l =~ /T\{\s*$/) {
        $l =~ s/T\{\s*$//;
        my @cell;
        while (++$i <= $#lines) {
            my $c = $lines[$i];
            chomp $c;
            last if $c =~ /^\s*T\}/;
            push @cell, $c;
        }
        $l .= join ' ', @cell;
    }
    push @joined, $l;
}

sub detroff {
    my ($s) = @_;
    $s =~ s/\\f\(..//g;         # \f(CW and friends
    $s =~ s/\\f[IPBR]//g;       # italic, previous, bold, roman
    $s =~ s/\\s[-+]?\d//g;      # size changes
    $s =~ s/\\\(em/--/g;        # em dash
    $s =~ s/\\\(en/-/g;         # en dash
    $s =~ s/\\\(aq/'/g;
    $s =~ s/\\&//g;             # zero-width
    $s =~ s/\\ / /g;            # unpaddable space
    $s =~ s/\\e/\\/g;           # literal backslash
    $s =~ s/\s+/ /g;
    $s =~ s/^\s+|\s+$//g;
    return $s;
}

my (@rows, %seen, @dup);
for my $l (@joined) {
    next unless $l =~ /^(e\d+)\t(\S+)\t(.+)$/;
    my ($idx, $name, $expr) = ($1, $2, $3);
    $name = detroff($name);
    $expr = detroff($expr);
    next unless length $name;
    push @dup, $name if $seen{$name}++;
    push @rows, [$idx, $name, $expr];
    printf STDERR "-   %-8s %-26s %s\n", $idx, $name, $expr if ($verbose // 0) > 1;
}

die "$PROG: $source yielded no rows; is it Appendix A?\n" unless @rows;

my $header = "# GENERATED by tools/$PROG from vendor/cynosureprime/hx.8 -- do not edit; regenerate.\n"
           . "# Appendix A of the hx specification: index, name, expression, tab separated.\n"
           . "# The parenthesised gloss is part of the third field on purpose; RosettaHx\n"
           . "# separates it, and a row that states prose rather than a construction is\n"
           . "# where a denotation comes from.\n";

my $body = join '', map { join("\t", @$_) . "\n" } @rows;

printf STDERR "- %s: %d row(s)%s\n", $PROG, scalar @rows,
    (@dup ? sprintf(', %d duplicate name(s): %s', scalar @dup, join(', ', @dup[0..($#dup>4?4:$#dup)])) : '');

if ($dry) { print STDERR "- dry run; $out not written\n"; exit 0 }

open my $o, '>', $out or die "$PROG: $out: $!\n";
print {$o} $header, $body;
close $o;
printf STDERR "- wrote %s\n", $out;
exit 0;
