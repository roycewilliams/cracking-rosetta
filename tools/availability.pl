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
#   john      tags are RELEASES, but only nine are jumbo releases and the
#             newest is 1.9.0-Jumbo-1, dated 2019-05-14. A label is not a
#             file, so the instrument is git's pickaxe: the commit that first
#             ADDED the quoted literal "<label>" under src/. Covered as of
#             2026-09-06, with a claude-owned clone at
#             /home/claude/src/upstream/john.
#
# JOHN IS THE STARKEST CASE THIS FILE HAS, AND THAT IS THE POINT. This host
# runs 1.9.0-jumbo-1+bleeding-9a336d800a; HEAD is contained in NO tag, so
# every format added since May 2019 is in no release at all. A reader who
# installed john from a distribution package has 1.9.0-Jumbo-1 and does not
# have them. hashcat's thirteen unreleased modes are a footnote beside it.
#
# THE INSTRUMENT, AND WHAT WAS MEASURED BEFORE CHOOSING IT. Three candidates
# were tried against the 402 named labels the committed inventory lists,
# at HEAD, on 2026-09-06:
#
#   a struct-field literal (^\s*"label",$)            12 of 402
#   #define FORMAT_LABEL + struct field + suffix     376 of 402
#   any quoted literal anywhere in src/              401 of 402
#
# The first two lose formats because several share one file and spell the
# label differently, which is the same defect CLAUDE.md records for
# seed-john-vectors.pl. The third has the recall but a tree grep cannot say
# WHEN, and a common word in an unrelated context would answer early -- the
# reassuring direction, which is the wrong one to be wrong in.
#
# So the pickaxe, which asks when the literal ENTERED src/ rather than
# whether it is there, and a guard on top of it: the introducing commit must
# have touched a file whose name looks like a format implementation
# (_fmt_plug.c, _plug.c, _fmt.c, fmt_*.c). A label whose literal first
# appears somewhere else is WITHHELD -- empty first_version, empty
# first_seen_date -- and counted, rather than published as a date this
# derivation cannot defend.
#
# DYNAMICS ARE NOT COVERED and are not published as rows. The 150 dynamic_N
# labels are defined in configuration (run/dynamic.conf) and in
# dynamic_preloads.c, not by a C string literal that the pickaxe can follow,
# so the instrument above does not apply to them. Their absence is stated
# here and in README rather than published as empty rows, because an empty
# first_version already means "in no release".
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
    john     => '/home/claude/src/upstream/john',
);
# The file each tool keeps its type table in. hashcat has none: a mode is a
# file, which is why its derivation is exact and the other two are a parse.
my %SRC = (mdxfind => 'mdxfind.c', hashpipe => 'hashpipe.c');

sub usage {
    print STDERR <<"END_USAGE";

Usage: $PROG [options]

   --tool NAME       hashcat, mdxfind, hashpipe, john or all (default: all;
                     repeatable)
   --clone-hashcat PATH   upstream clone (default: $CLONE{hashcat})
   --clone-mdxfind PATH   upstream clone (default: $CLONE{mdxfind})
   --clone-hashpipe PATH  upstream clone (default: $CLONE{hashpipe})
   --clone-john PATH      upstream clone (default: $CLONE{john})
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
    'clone-john=s'     => \$CLONE{john},
    'tools=s'          => \$tools_dir,
    'out|o=s'          => \$outfile,
    'verbose|v+'       => \$verbose,
    'help|h'           => \$help,
) or do { usage(); exit 2 };

if ($help) { usage(); exit 0 }
$tools_dir //= "$ROOT/data/tools";

@tool = ('all') unless @tool;
my %want = map { $_ => 1 } @tool;
if ($want{all}) { %want = map { $_ => 1 } qw(hashcat mdxfind hashpipe john) }
for my $t (sort keys %want) {
    next if $t =~ /^(hashcat|mdxfind|hashpipe|john)$/;
    print STDERR "$PROG: --tool must be hashcat, mdxfind, hashpipe, john or "
               . "all, not '$t'.\n";
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
# john: a label is not a file, so the pickaxe answers when the literal
# entered src/. See the header for the three instruments that were measured
# before this one was chosen, and for the guard below.

# Only these tags are jumbo RELEASES. john also carries 1.7.9, 1.8.0, 1.9.0
# (core, not jumbo) and CUDA / JOHN_1_7 / Owl-*-release, which are not
# releases of this tool at all -- and `--sort=v:refname` puts those LAST, so
# taking the final tag would name Owl-3_1-release as john's latest release.
sub john_releases {
    my ($dir) = @_;
    return grep { /^\d+\.\d+(?:\.\d+)?-[Jj]umbo-\d+$/ }
           git($dir, 'tag', '--sort=v:refname');
}

# The guard: a format's label enters src/ in a format implementation. If the
# introducing commit touched none, the pickaxe found the string somewhere
# else and the row is withheld rather than dated.
sub looks_like_format_file {
    return scalar grep { m{(?:_fmt_plug|_plug|_fmt)\.[ch]$|/fmt_[^/]*\.[ch]$} } @_;
}

sub availability_john {
    my ($dir, $inv) = @_;
    my @rel = john_releases($dir) or die "$PROG: no jumbo release tag in $dir\n";
    my $latest = $rel[-1];
    my $floor  = $rel[0];

    my (@rows, $withheld, $bulked, $skipped_dynamic);
    for my $f (@{ $inv->{formats} }) {
        my $label = $f->{label} // next;
        # dynamics are configuration, not a literal the pickaxe can follow
        if ($label =~ /^dynamic_/) { $skipped_dynamic++; next }

        # NO --diff-filter=A here, and that is the whole difference from the
        # hashcat derivation above. There the identifier IS a file, so "the
        # commit that added the file" is exact. Here it is a string, and
        # asking for a commit that both added a FILE and changed the count of
        # the string answers with the first NEW FILE that happens to mention
        # it: measured 2026-09-06, that dated "NT" to 2022-03-31 and called
        # it unreleased, when NT is one of the oldest formats john has.
        my ($add) = git($dir, 'log', '-S', "\"$label\"",
                        '--reverse', '--format=%H%x09%ad', '--date=short',
                        '--', 'src/');
        my ($sha, $date) = defined $add ? split(/\t/, $add, 2) : ();

        my ($first, $fdate, $intro, $bulk) = ('', '', '', 0);
        if (defined $sha && length $sha) {
            my @touched = git($dir, 'show', '--name-only', '--format=', $sha);
            my $nfmt = looks_like_format_file(@touched);
            # A commit touching a handful of format files introduced this
            # format. One touching dozens is a tree-wide refactor that merely
            # moved the string, so the count first CHANGED there while the
            # label may be much older -- "NT" lands on a 114-file commit of
            # 2013-06-09 that way. Such a row keeps its release as an UPPER
            # BOUND and says so through first_version_exact: no.
            $bulk = 1 if $nfmt > 4;
            $bulked++ if $bulk;
            if ($nfmt) {
                $intro = $bulk ? '' : ($date // '');
                my @in = grep { /^\d+\.\d+(?:\.\d+)?-[Jj]umbo-\d+$/ }
                         git($dir, 'tag', '--sort=v:refname', '--contains', $sha);
                $first = $in[0] // '';
                $fdate = length $first ? tag_date($dir, $first) : '';
            }
            else { $withheld++ }
        }
        else { $withheld++ }

        # In the newest release? The pickaxe says when it ARRIVED; presence
        # today is a separate question, and a label introduced before the
        # latest release could still have been removed since. Ask the tree.
        my $in_latest = 'no';
        if (length $first) {
            my @hit = grep { length }
                      git($dir, 'grep', '-l', '-F', "\"$label\"", $latest, '--', 'src/');
            $in_latest = @hit ? 'yes' : 'no';
        }

        push @rows, {
            tool       => 'john',
            identifier => $label,
            index      => '',
            name       => $f->{algorithm_name} // '',
            first      => $first,
            first_date => $fdate,
            exact      => length $first
                            ? (($first eq $floor || $bulk) ? 'no' : 'yes') : '',
            introduced => $intro,
            in_latest  => $in_latest,
            latest     => $latest,
            sort       => 0,   # not numeric: the comparator falls
                               # through to identifier cmp for john
        };
    }
    # Two reasons a row carries no first_seen_date, reported apart because
    # they are different facts: the pickaxe could not attribute the literal
    # at all, or it attributed it to a tree-wide refactor whose date says
    # nothing about this format. Both leave the column empty, and their SUM
    # is what a reader counting empty dates in the file will find.
    printf STDERR "- john: %d format(s), %d jumbo release tag(s), latest %s, "
                . "floor %s; %d undated (%d with no introducing commit under "
                . "src/ or touching no format file, %d attributed to a "
                . "refactor of more than four format files), %d dynamic(s) "
                . "not covered\n",
        scalar @rows, scalar @rel, $latest, $floor,
        ($withheld // 0) + ($bulked // 0), $withheld // 0, $bulked // 0,
        $skipped_dynamic // 0 if $verbose;
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
for my $t (qw(hashcat john mdxfind hashpipe)) {
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
             : $t eq 'john'  ? availability_john($dir, $inv)
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
