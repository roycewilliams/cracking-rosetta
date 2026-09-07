#!/usr/bin/perl
#-----------------------------------------------------------------------
#
# Name: availability.pl
# Description: derive, from the upstream git history, the earliest released
#              version of each tool that carries each identifier
# Category: cracking-rosetta generated deliverable
#
# Project: cracking-rosetta | Phase: 7 - pre-publication readiness
#
#-----------------------------------------------------------------------
# METHODOLOGY AND WHY THIS EXISTS
#
# THE DEFECT IT ANSWERS
#
# This repository tracks upstream TIP, not releases (CLAUDE.md, "Canonical
# sources", decided 2026-09-06). That is the right call -- a release lags by
# months and the mappings people arrive asking about are the new ones -- but
# it has a cost that was invisible until it was measured. On 2026-09-06,
# comparing `git ls-tree v7.1.2 src/modules` against HEAD in the hashcat
# clone: 582 modes in the latest release, 595 at tip. THIRTEEN modes exist in
# no release at all -- 17050, 34301, 35300, 35400, 35500, 35600, 35700,
# 35800, 36100, 36200, 36300, 36400, 36410 -- and this repository publishes
# all thirteen at tier `vector`. Eleven of them predate that date.
#
# So a reader on hashcat 7.1.2 finds a row, runs the mode, and hashcat tells
# them it does not exist. The row is not wrong; it is answering a question
# about a build the reader does not have. mdxfind has the same shape: types
# e1003-e1027 are absent from the installed 1.545, which is why CLAUDE.md
# carries "THE INVENTORY CAN BE AHEAD OF THE INSTALLED BINARY, and mdxfind's
# way of saying so is indistinguishable from finding nothing."
#
# WHY A GENERATED FILE AND NOT A FIELD
#
# A `since:` field in every tool block would put the answer in ~1569 entry
# files, carrying something git can derive, and would have to be re-checked
# by hand on every upstream release. The defect is in the PUBLICATION, not in
# the curation, so it is fixed where the publication is made. That is also
# STATE.md's third test: a field must earn itself against a defect in the
# data, and this one is not in the data.
#
# WHAT A VERSION MEANS, WHICH DIFFERS PER TOOL
#
#   hashcat   tags are RELEASES (v7.1.2). A mode is a file,
#             src/modules/module_NNNNN.c, so the commit that ADDED the file is
#             exact and `git tag --contains` gives the first release carrying
#             it. An empty first_version means: in no release yet.
#   mdxfind   tags are REVISIONS -- upstream tags most RCS revisions, so
#             v1.579 is RCS 1.579. The type list is the Types[] array in
#             mdxfind.c, parsed at each tag.
#   hashpipe  as mdxfind, in hashpipe.c.
#
# john is NOT covered. There is no claude-owned clone (john lives under
# /usr/local/src/sec/crack, royce-owned, and the corpus rule is not to run git
# in another user's repository), and a john format label lives in an fmt_main
# struct rather than in a file name, so the cheap file-based derivation does
# not apply. Its absence is stated in README rather than being published as
# empty rows, because an empty first_version already means something else.
#
# THE OBSERVATION FLOOR, AND WHY A COLUMN CARRIES IT
#
# This derivation can only see as far back as the shape it reads. hashcat did
# not always keep a mode in its own file: the plugin layout arrives with
# src/modules at v6.0.0 (measured 2026-09-06), so MD5 -- in hashcat since long
# before -- resolves to v6.0.0 and not to its real origin. mdxfind's and
# hashpipe's clones likewise begin at their oldest tag, v1.213 and v1.17,
# and upstream's earlier RCS revisions are not in git at all.
#
# Publishing v6.0.0 for MD5 with nothing beside it would read as "introduced
# in 6.0.0", which is false. So first_version_exact says which it is: `yes`
# means the identifier really did appear in that version, `no` means it was
# already present in the oldest version this derivation can see and may be
# older. The floor is per tool and is computed, never typed -- for hashcat
# the earliest tag carrying a src/modules tree, for the other two the
# earliest tag.
#
# first_seen_date IS THE OBSERVATION, NOT THE ORIGIN
#
# It is the earliest date this derivation can see the identifier upstream:
# for hashcat the commit that ADDED its module file, for mdxfind and hashpipe
# the first tag carrying the type. It earns its place on hashcat, where it is
# the only thing that says a mode in no release landed on 2026-09-04; on the
# other two it necessarily equals first_version_date, since a tag is the
# finest granularity available there. Read it with first_version_exact: where
# that says `no`, this is the floor of the window and not an origin.
#
# WHAT first_version DOES NOT SAY
#
# That the identifier EXISTED, not that it worked. hashcat commit 524399968
# ("repair 6 VeraCrypt modes") shipped six modes that could not finish their
# own self test in earlier releases where the module file was nonetheless
# present. So this file answers "will my build recognise this identifier",
# which is the question a reader actually hits first, and not "will my build
# compute it correctly".
#
# THE POSITIVE CONTROL
#
# A parser that silently read the wrong array, or an empty one, would produce
# a plausible-looking file in which everything looks new. So for mdxfind and
# hashpipe the parse at the tag matching the committed inventory's OWN
# version must contain every type that inventory lists, and the run dies if
# it does not. Measured 2026-09-06, the parse gives 1002 real types at
# v1.545 and 1027 at v1.579, which are exactly the counts the two binaries
# report -- two independent runtime readings agreeing with the parse.
#
# NOT IN CI. It needs the upstream clones, which a hosted runner does not
# have, so render.yml cannot regenerate this file. It is generated locally
# and committed, exactly like data/tools/*.yaml, which are likewise produced
# from local binaries. Re-run it after any upstream fetch.
#
#-----------------------------------------------------------------------
# Generated by Claude Opus 5 on 2026-09-06

use strict;
use warnings;
use Getopt::Long qw(GetOptions);
use File::Basename qw(basename);
use YAML::XS ();

my $PROG = basename($0);
my $ROOT = $0 =~ m{^(.*)/tools/[^/]+$} ? $1 : '.';

my %CLONE = (
    hashcat  => '/home/claude/src/upstream/hashcat',
    mdxfind  => '/home/claude/src/upstream/mdxfind',
    hashpipe => '/home/claude/src/upstream/hashpipe',
);
# The file each tool keeps its type table in. hashcat has none: a mode is a
# file, which is why its derivation is exact and the other two are a parse.
my %SRC = (mdxfind => 'mdxfind.c', hashpipe => 'hashpipe.c');

sub usage {
    print STDERR <<"END_USAGE";

Usage: $PROG [options]

   --tool NAME       hashcat, mdxfind, hashpipe or all (default: all;
                     repeatable)
   --clone-hashcat PATH   upstream clone (default: $CLONE{hashcat})
   --clone-mdxfind PATH   upstream clone (default: $CLONE{mdxfind})
   --clone-hashpipe PATH  upstream clone (default: $CLONE{hashpipe})
   --tools DIR       generated inventories (default: data/tools)
   -o, --out FILE    write here instead of stdout
   -v, --verbose     per-tool counts on stderr (repeatable)
   -h, --help        this help

   Writes dist/availability.csv content: one row per (tool, identifier) with
   the earliest upstream version that carries it.

   Regenerate the committed file with:
     $PROG -o dist/availability.csv

   Needs the upstream clones and git, so it is NOT run in CI; it is generated
   locally and committed, like data/tools/*.yaml. Re-run after an upstream
   fetch.

   Exit 0 success, 1 error, 2 usage.
END_USAGE
    return;
}

my (@tool, $tools_dir, $outfile, $verbose, $help);
GetOptions(
    'tool=s@'          => \@tool,
    'clone-hashcat=s'  => \$CLONE{hashcat},
    'clone-mdxfind=s'  => \$CLONE{mdxfind},
    'clone-hashpipe=s' => \$CLONE{hashpipe},
    'tools=s'          => \$tools_dir,
    'out|o=s'          => \$outfile,
    'verbose|v+'       => \$verbose,
    'help|h'           => \$help,
) or do { usage(); exit 2 };

if ($help) { usage(); exit 0 }
$tools_dir //= "$ROOT/data/tools";

@tool = ('all') unless @tool;
my %want = map { $_ => 1 } @tool;
if ($want{all}) { %want = map { $_ => 1 } qw(hashcat mdxfind hashpipe) }
for my $t (sort keys %want) {
    next if $t =~ /^(hashcat|mdxfind|hashpipe)$/;
    print STDERR "$PROG: --tool must be hashcat, mdxfind, hashpipe or all, "
               . "not '$t'.\n";
    exit 2;
}

#-----------------------------------------------------------------------
# git helpers. Every one runs with -C so nothing depends on the cwd, and
# every one is read-only: this tool never writes into a clone.

sub git {
    my ($dir, @args) = @_;
    my @cmd = ('git', '-C', $dir, @args);
    open my $fh, '-|', @cmd or die "$PROG: cannot run git in $dir: $!\n";
    my @out = <$fh>;
    close $fh;
    chomp @out;
    return @out;
}

# tags($dir) - every tag, oldest version first. --sort=v:refname is what makes
# v1.99 sort before v1.100; the default lexical order does not.
sub tags { return grep { length } git($_[0], 'tag', '--sort=v:refname') }

sub tag_date {
    my ($dir, $tag) = @_;
    my ($d) = git($dir, 'log', '-1', '--format=%ad', '--date=short', $tag);
    return $d // '';
}

#-----------------------------------------------------------------------
# The Types[] parse, for mdxfind and hashpipe.
#
# The array is `char *Types[] = { ... };` with the internal index as the
# position -- index 0 is "none", so the type at position N is that tool's eN.
# Anchored on the closing "\n};" so a later array in the same file cannot
# extend the match.

sub parse_types {
    my ($text) = @_;
    return unless defined $text;
    return unless $text =~ /char \*Types\[\] *= *\{(.*?)\n\};/s;
    my $body = $1;
    my @names = $body =~ /"((?:[^"\\]|\\.)*)"/g;
    return unless @names;
    return \@names;
}

#-----------------------------------------------------------------------
# hashcat: a mode is a file, so the introducing commit is exact.

sub availability_hashcat {
    my ($dir, $inv) = @_;
    my @tg = tags($dir) or die "$PROG: no tags in $dir\n";
    my $latest = $tg[-1];

    # The observation floor: the earliest tag that keeps modes in their own
    # files at all. Anything resolving to it is "at or before", not "new in".
    my $floor = '';
    for my $t (@tg) {
        my @ls = git($dir, 'ls-tree', '--name-only', $t, 'src/modules');
        if (grep { length } @ls) { $floor = $t; last }
    }

    my @rows;
    my $unknown = 0;
    for my $m (@{ $inv->{modes} }) {
        my $mode = $m->{mode};
        # hashcat ZERO-PADS the module file name to five digits: mode 0 is
        # module_00000.c, not module_0.c. Getting this wrong is silent -- the
        # path simply never existed, so every mode below 10000 comes back
        # with no introducing commit and reads as "in no release", which is
        # exactly backwards for the oldest modes in the tool.
        my $path = sprintf 'src/modules/module_%05d.c', $mode;

        # The commit that ADDED the file, on the current branch.
        my ($add) = git($dir, 'log', '--diff-filter=A', '--format=%H%x09%ad',
                        '--date=short', '-1', '--', $path);
        my ($sha, $date) = defined $add ? split /\t/, $add, 2 : ();

        my ($first, $fdate) = ('', '');
        if (defined $sha && length $sha) {
            # --contains lists every tag whose history holds the commit; in
            # version order the first is the earliest release that has it.
            my @in = grep { length }
                     git($dir, 'tag', '--sort=v:refname', '--contains', $sha);
            $first = $in[0] // '';
            $fdate = length $first ? tag_date($dir, $first) : ($date // '');
        }
        else { $unknown++ }

        # Present in the newest release? Ask for the blob rather than infer
        # it from the tag list, so a mode REMOVED since is reported honestly.
        my @ls = git($dir, 'ls-tree', '--name-only', $latest, $path);
        my $in_latest = (grep { $_ eq $path } @ls) ? 'yes' : 'no';

        push @rows, {
            tool        => 'hashcat',
            identifier  => $mode,
            index       => '',
            name        => $m->{name} // '',
            first       => $first,
            first_date  => length $first ? $fdate : '',
            exact       => length $first
                            ? ($first eq $floor ? 'no' : 'yes') : '',
            introduced  => $date // '',
            in_latest   => $in_latest,
            latest      => $latest,
            sort        => $mode,
        };
    }
    printf STDERR "- hashcat: %d mode(s), %d tag(s), latest %s, floor %s"
                . ($unknown ? ", $unknown with no introducing commit" : "")
                . "\n", scalar @rows, scalar @tg, $latest, $floor if $verbose;
    return @rows;
}

#-----------------------------------------------------------------------
# mdxfind and hashpipe: parse Types[] at every tag.

sub availability_types {
    my ($tool, $dir, $inv) = @_;
    my $src = $SRC{$tool};
    my @tg  = tags($dir) or die "$PROG: no tags in $dir\n";
    my $latest = $tg[-1];

    my (%first, %fdate, %parsed_at);
    for my $t (@tg) {
        my $text = join "\n", git($dir, 'show', "$t:$src");
        my $names = parse_types($text);
        unless ($names) {
            die "$PROG: could not parse Types[] from $src at $t.\n"
              . "  A silent skip here would date every type to a later tag "
              . "than the truth, so this is fatal.\n";
        }
        $parsed_at{$t} = { map { $_ => 1 } @$names };
        for my $n (@$names) {
            next if $n eq 'none';
            next if exists $first{$n};
            $first{$n} = $t;
            $fdate{$n} = tag_date($dir, $t);
        }
    }

    # THE POSITIVE CONTROL. The committed inventory names a version; the parse
    # at that tag must contain every type the inventory lists. Without this a
    # parser reading the wrong array produces a plausible file in which
    # everything looks new.
    my $ver = $inv->{version} // '';
    my ($rev) = $ver =~ /([0-9]+\.[0-9]+)/;
    my $ctl = defined $rev ? "v$rev" : undef;
    if (defined $ctl && $parsed_at{$ctl}) {
        my @missing = grep { !$parsed_at{$ctl}{ $_->{name} } } @{ $inv->{types} };
        if (@missing) {
            die "$PROG: control FAILED for $tool at $ctl: "
              . scalar(@missing) . " inventoried type(s) are absent from the "
              . "parse, first '" . $missing[0]{name} . "'.\n"
              . "  The inventory came from a binary at that version, so the "
              . "parse is wrong, not the inventory.\n";
        }
        printf STDERR "- %s: control OK at %s -- all %d inventoried type(s) "
                    . "present in the parse\n",
            $tool, $ctl, scalar @{ $inv->{types} } if $verbose;
    }
    else {
        printf STDERR "- %s: NO CONTROL -- the inventory names version '%s' "
                    . "and no matching tag is in the clone. The dates below "
                    . "rest on an unchecked parse.\n", $tool, $ver;
    }

    my @rows;
    for my $t (@{ $inv->{types} }) {
        my $n = $t->{name};
        my $f = $first{$n} // '';
        push @rows, {
            tool       => $tool,
            identifier => $n,
            index      => $t->{index} // '',
            name       => $n,
            first      => $f,
            first_date => $fdate{$n} // '',
            # The floor here is simply the oldest tag in the clone: a type
            # present in it was already there and may be far older, since
            # upstream's earlier RCS revisions never reached git.
            exact      => length $f ? ($f eq $tg[0] ? 'no' : 'yes') : '',
            introduced => $fdate{$n} // '',
            in_latest  => $parsed_at{$latest}{$n} ? 'yes' : 'no',
            latest     => $latest,
            sort       => $t->{index_num} // 0,
        };
    }
    printf STDERR "- %s: %d type(s), %d tag(s), latest %s\n",
        $tool, scalar @rows, scalar @tg, $latest if $verbose;
    return @rows;
}

#-----------------------------------------------------------------------

sub csv_field {
    my ($v) = @_;
    $v = '' unless defined $v;
    return $v =~ /[",\r\n]/ ? '"' . ($v =~ s/"/""/gr) . '"' : $v;
}

my @all;
for my $t (qw(hashcat mdxfind hashpipe)) {
    next unless $want{$t};
    my $dir = $CLONE{$t};
    unless (-d "$dir/.git") {
        # Loudly, never silently: a missing clone must not look like a tool
        # with no identifiers.
        print STDERR "$PROG: SKIPPING $t -- no git clone at $dir. "
                   . "Its rows will be absent from the output.\n";
        next;
    }
    my $path = "$tools_dir/$t.yaml";
    my $inv = eval { YAML::XS::LoadFile($path) }
        or die "$PROG: cannot load $path: $@\n";
    push @all, $t eq 'hashcat' ? availability_hashcat($dir, $inv)
                               : availability_types($t, $dir, $inv);
}
die "$PROG: nothing to write.\n" unless @all;

my $out = \*STDOUT;
if (defined $outfile) {
    open my $fh, '>', $outfile or die "$PROG: cannot write $outfile: $!\n";
    $out = $fh;
}

my @COLS = qw(tool identifier index name first_version first_version_date
              first_version_exact first_seen_date in_latest_release
              latest_release);
print {$out} join(',', @COLS), "\n";
for my $r (sort { $a->{tool} cmp $b->{tool}
               || ($a->{sort} <=> $b->{sort})
               || $a->{identifier} cmp $b->{identifier} } @all) {
    print {$out} join(',', map { csv_field($_) }
        $r->{tool}, $r->{identifier}, $r->{index}, $r->{name},
        $r->{first}, $r->{first_date}, $r->{exact}, $r->{introduced},
        $r->{in_latest}, $r->{latest}), "\n";
}
close $out if defined $outfile;

my $none = grep { $_->{first} eq '' } @all;
printf STDERR "- %d row(s); %d identifier(s) are in NO tagged release\n",
    scalar @all, $none;
exit 0;
