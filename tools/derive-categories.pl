#!/usr/bin/perl
#-----------------------------------------------------------------------
#
# Name: derive-categories.pl
# Description: write category: where a rule can defend it, and leave the rest
#              in the curation queue
# Category: cracking-rosetta deriver
#
# Project: cracking-rosetta | Phase: 7 - fill the largest empty column
#
#-----------------------------------------------------------------------
# METHODOLOGY AND WHY THESE CHOICES
#
# THE PROBLEM IS THE SIZE OF THE ASK, NOT THE DIFFICULTY OF EACH ANSWER
#
# category: is the sheet's old 'class' column: which axis an entry sits on.
# 1251 of 1560 entries have none, and curate.pl duly offers all 1251 as
# questions. Nobody is going to answer 1251 questions, so the column stays
# empty and the CSV ships with its largest field blank.
#
# But most of those answers are already IN the entry. An entry whose proven
# expression is md5($p) is a primitive; one whose mdxfind block declares two
# iterations is iterated. Asking a person for those is asking them to restate
# what the file says. So this derives what a rule can defend, and leaves
# everything else in the queue -- which is the point: a human answering the
# residue is answering the questions that actually need a human.
#
# EVERY RULE WAS CHECKED AGAINST THE ANSWERS A HUMAN ALREADY GAVE
#
# 309 entries were categorised by hand before this existed, and that is a test
# set nobody had to build. Rules 1-5 contradicted none of them when they were
# written, and rule 6 contradicts none of them today. A rule that contradicted
# a curator would be wrong by definition: the curator is the authority this
# tool is trying not to waste.
#
# THE TEST SET IS NOT STATIC, AND RULE 5 HAS SINCE DRIFTED ONTO TWO OF IT
#
# Re-measured 2026-09-01, after rule 6 was added: rule 5 now contradicts the
# curator on huawei-sha1-md5-pass-salt and solarwinds-serv-u, both of which a
# human called 'application' and rule 5 calls 'composite'. Nothing was edited
# and no rule changed. At the control-set commit both entries carried
# expression_proof: absent, so rule 5 did not fire on them and the original
# claim was true when it was made; a later session proved both expressions and
# rule 5 started firing. The lesson is that this test set moves underneath the
# ruleset, so --check is the thing to believe and this comment is not.
#
# It is also the only evidence anyone has about rule ordering, and it points at
# rule 6: on both entries hashcat's category agrees with the curator and the
# expression does not. Two samples is not enough to reorder on -- 17 entries
# now reading 'composite' would become 'application' -- so rule 6 stays last
# and --check reports the 19 entries where the two differ. Deciding that
# boundary is curation and belongs to a person.
#
# THE RULES, IN ORDER, AND WHY EACH IS DEFENSIBLE
#
#   1. application: is set            -> application
#      The schema's own definition of the field: it names the product a row is
#      about, which is what category 'application' means.
#
#   2. an encodes/input-encoding edge -> HELD, no category written
#      This is the guard, and it is here because of a real defect. md5uc's
#      expression is md5($p) -- the uppercase hex is not expressible -- so the
#      primitive rule fires on it, and md5uc is an encoding. The relation is
#      what distinguishes them, and it is SYMMETRIC, so it cannot say which
#      side is the encoding: md5 carries the same edge. Both are therefore
#      held. Three entries, and holding them is correct: 'which of these two is
#      the encoded one' is exactly a curator's question.
#
#   3. mdxfind iterations > 1         -> iterated
#      CLAUDE.md: the iteration suffix is identity, MD5x02 is john's dynamic_2.
#      A block declaring N > 1 IS the statement that this is another algorithm
#      applied N times, which is the schema's definition of 'iterated'. It is
#      checked before the expression rules because it says more: an entry with
#      both is iterated, not merely composite.
#
#   4. proven expression, exactly F($p)  -> primitive
#   5. proven expression, anything else  -> composite
#      'primitive: one hash function over the plaintext' is literally the shape
#      F($p). Everything else with an expression is a construction. Where the
#      line falls between them was NOT decided here: md5-pass-salt (md5($p.$s))
#      and md5-salt-pass (md5($s.$p)) were already categorised 'composite' by a
#      curator, so a single hash over a salted concatenation is composite in
#      this repository, and rule 5 follows that rather than inventing a rule.
#
#      Only tier 'vector' or 'upstream' counts. An 'asserted' expression is a
#      human's claim, and deriving a category from it would launder that claim
#      into a second field at a strength it never had.
#
#   6. hashcat's own category for the mode  -> the human answer it maps to
#      LAST, so it only ever reaches what rules 3-5 could not answer. hashcat
#      publishes a category per mode -- 'Full-Disk Encryption (FDE)', 'Generic
#      KDF', 'Network Protocol', 23 of them, already in data/tools/hashcat.yaml
#      at tier upstream. Crosstabbed against the 309 human answers (recover the
#      control set with `git archive 63801b5^ data/algorithms`), 21 of the 23
#      map to exactly ONE human answer and contradict none. The table below
#      carries each mapping's support count, because n=96 for FDE and n=1 for
#      'Plaintext' are not the same quality of evidence and a reader should not
#      have to re-measure to see which is which.
#
#      Two are held because the humans SPLIT on them, and two more because no
#      human ever answered one: hashcat's 'Database Server' covers both
#      mssql2000 (a construction) and oracle7 (a product), and 'Undefined' is
#      hashcat declining to classify. Those are curator questions, which is
#      exactly what the residue is for.
#
#      An entry naming several modes must have them AGREE on hashcat's
#      category, or the entry says nothing usable -- the same shape as the
#      encodes guard in rule 2.
#
#      Placed ABOVE rules 4 and 5, below rule 3. Royce, 2026-09-01: of the
#      three tools only hashcat publishes human judgement about what KIND of
#      thing a mode is, which is the question this field asks -- mdxfind and
#      john publish no classification at all, so there is nothing to weigh it
#      against. It stays below rule 3 because an iteration count is a statement
#      about identity, not about kind, and hashcat merges the two axes under
#      'Raw Hash salted and/or iterated'.
#
#      The evidence agreed. Rules 4/5 and rule 6 differed on 19 live entries,
#      and on none of the control set -- but two control-set entries had drifted
#      since: huawei-sha1-md5-pass-salt and solarwinds-serv-u, where a curator
#      said 'application', rule 5 says 'composite' and rule 6 says
#      'application'. The reorder resolves both without editing either file.
#
#      A HOLD in rule 6 is not a stop. It means hashcat cannot classify the
#      mode, so the expression rules still get their turn; only rule 2's
#      encoding guard halts derivation outright.
#
# WHAT IS DELIBERATELY NOT DERIVED
#
# kdf and protocol. The tempting rule is to read denotation: and call anything
# containing pbkdf2(), scrypt() or argon2() a kdf. Measured 2026-09-01 against
# the human answers, it fires on keepass-argon2-kdbx-v4,
# scryptcrypt-scrypt-unix and terra-station-wallet-...-pbkdf2-pass, all three
# of which a curator called 'application' -- correctly, because they are
# products that USE a KDF. Distinguishing "is a KDF" from "is a product built
# on one" is judgement, not a lookup, so it stays a question. Rule 6 reaches
# 188 of what is left; run the tool for the figure rather than trusting this
# comment.
#
# NOTHING IS EVER OVERWRITTEN
#
# An entry that already has a category: is never touched, in either direction.
# --check reports where a rule disagrees with an existing value, because that
# is either a bad rule or a bad entry and both are worth knowing, but it is a
# report and never an edit.
#
#-----------------------------------------------------------------------
# Generated by Claude Opus 5 on 2026-09-01

use strict;
use warnings;

use File::Basename qw(basename);
use File::Temp ();
use FindBin qw($RealBin);
use Getopt::Long qw(GetOptions);
use YAML::XS ();

use lib "$RealBin/lib";
use RosettaEmit qw(emit_entry);

my $PROG = basename($0);
my $ROOT = "$RealBin/..";

sub usage {
    print STDERR <<"END_USAGE";

Usage: $PROG [options]

   --algorithms DIR  curated entries (default: data/algorithms)
   --hashcat FILE    hashcat inventory for rule 6
                     (default: data/tools/hashcat.yaml)
   --only ID         consider just this entry (repeatable)
   --check           also report where a rule disagrees with a category the
                     entry already carries; never edits either way
   --baseline REF    git ref whose data/algorithms holds the curator-written
                     categories. Any category present there is PROTECTED and
                     is never rewritten. Required by --rederive.
   --rederive        rewrite categories THIS TOOL wrote that the current
                     ruleset no longer agrees with -- for a rule change, not
                     for routine use. Needs --baseline and, to write, --apply.
   --apply           write the derived categories into data/algorithms
   -v, --verbose     one line per derivation (repeatable: also the held ones)
   -h, --help        this help

   Without --apply nothing is written: the run reports what it would derive.
   Exit 0 success, 1 error, 2 usage.

END_USAGE
    return;
}

my ($algdir, $hcfile, $baseline, $rederive, $apply, $check, $help);
my (%protected, @rewrite);
my @only;
my $verbose  = 0;
my $had_args = scalar @ARGV;      # house rule: no arguments means show usage

GetOptions(
    'algorithms=s' => \$algdir,
    'hashcat=s'    => \$hcfile,
    'baseline=s'   => \$baseline,
    'rederive'     => \$rederive,
    'only=s'       => \@only,
    'check'        => \$check,
    'apply'        => \$apply,
    'v|verbose+'   => \$verbose,
    'h|help'       => \$help,
) or do { usage(); exit 2 };

if ($help)     { usage(); exit 0 }
if (!$had_args) { usage(); exit 2 }

$algdir //= "$ROOT/data/algorithms";
$hcfile //= "$ROOT/data/tools/hashcat.yaml";

# --rederive overwrites, which is the one thing this tool otherwise never does.
# It is only defensible because a baseline says which values are a curator's,
# so refuse without one rather than guessing.
if ($rederive && !defined $baseline) {
    print STDERR "$PROG: --rederive needs --baseline REF: without it the tool\n"
               . "$PROG: cannot tell its own earlier output from a curator's\n"
               . "$PROG: answer, and it must never overwrite the latter.\n";
    usage();
    exit 2;
}

#-----------------------------------------------------------------------
# The baseline. category: carries no provenance of its own -- no tier, no
# source -- so the only record of who wrote a given value is git history. A ref
# from before this tool first ran is therefore the curator set: every category
# in it is a human's, and every category that appeared afterwards is this
# tool's. Externalising it as a --baseline ref keeps that judgement auditable
# instead of hidden in the code.

sub baseline_categories {
    my ($ref) = @_;

    # Project tmp/, per the house rule, and cleaned up on exit.
    my $tmp = File::Temp->newdir(
        TEMPLATE => 'derive-categories-baseline-XXXXXX',
        DIR      => "$ROOT/tmp",
        CLEANUP  => 1,
    );
    my $dir = "$tmp";

    # List form, so no shell parses the ref. Two steps rather than a pipe for
    # the same reason.
    my $tar = "$dir/baseline.tar";
    system('git', '-C', $ROOT, 'archive', '-o', $tar, $ref, 'data/algorithms') == 0
        or do { print STDERR "$PROG: git archive $ref failed\n"; exit 1 };
    system('tar', '-x', '-f', $tar, '-C', $dir) == 0
        or do { print STDERR "$PROG: cannot unpack the baseline archive\n"; exit 1 };

    my $bdir = "$dir/data/algorithms";
    opendir(my $bh, $bdir)
        or do { print STDERR "$PROG: $ref has no data/algorithms\n"; exit 1 };
    my @bf = grep { /\.yaml$/ } readdir $bh;
    closedir $bh;

    my %cat;
    for my $f (@bf) {
        my $e = eval { YAML::XS::LoadFile("$bdir/$f") } or next;
        next unless $e->{id} && defined $e->{category};
        $cat{ $e->{id} } = $e->{category};
    }
    printf STDERR "- baseline %s: %d file(s), %d curator-written category/"
                . "categories protected\n", $ref, scalar @bf, scalar keys %cat;
    return %cat;
}

%protected = baseline_categories($baseline) if defined $baseline;

#-----------------------------------------------------------------------
# Rule 6's table. hashcat category -> the one human answer it mapped to in the
# control set, with that mapping's support count. See the methodology note;
# regenerate with the crosstab described there rather than editing by hand.

my %HASHCAT_CATEGORY = (
    # hashcat category                       category        n
    'Application Database'                => ['application',  1],
    'Archive'                             => ['application', 22],
    'Cryptocurrency Wallet'               => ['application', 34],
    'Document'                            => ['application', 21],
    'Enterprise Application Software (EAS)' => ['application', 9],
    'FTP, HTTP, SMTP, LDAP Server'        => ['application',  6],
    'File-Based Encryption (FBE)'         => ['application',  4],
    'Framework'                           => ['application',  4],
    'Full-Disk Encryption (FDE)'          => ['application', 96],
    'Generic KDF'                         => ['kdf',         11],
    'Instant Messaging Service'           => ['application',  5],
    'Network Protocol'                    => ['protocol',    24],
    'One-Time Password'                   => ['protocol',     1],
    'Operating System'                    => ['application', 12],
    'Password Manager'                    => ['application', 10],
    'Plaintext'                           => ['encoding',     1],
    'Private Key'                         => ['application', 13],
    'Raw Checksum'                        => ['primitive',    6],
    'Raw Cipher, Known-plaintext attack'  => ['primitive',    6],
    'Raw Hash authenticated'              => ['composite',    4],
    'Raw Hash salted and/or iterated'     => ['composite',    6],
);

# The two the humans SPLIT on, with the split, so the held reason can say so
# rather than lumping them in with the ones nobody ever answered.
my %HASHCAT_SPLIT = (
    'Raw Hash'               => 'encoding 1, primitive 1',
    'Forums, CMS, E-Commerce' => 'application 10, composite 1',
);

# mode -> hashcat's own category, from the generated inventory.
my %MODE_CATEGORY;
{
    my $hc = eval { YAML::XS::LoadFile($hcfile) };
    unless ($hc && $hc->{modes}) {
        print STDERR "$PROG: cannot read hashcat inventory $hcfile\n";
        exit 1;
    }
    $MODE_CATEGORY{ $_->{mode} } = $_->{category} for @{ $hc->{modes} };
}

# Rule 6 proper. Returns (category, why) or (undef, why), same contract as
# derive(); split out so --check can ask it about an entry an earlier rule
# already answered.
sub hashcat_category {
    my ($e) = @_;

    my @modes = @{ $e->{tools}{hashcat}{modes} || [] };
    return (undef, 'no rule: no application:, no iteration count, no proven '
                 . 'expression and no hashcat mode')
        unless @modes;

    my %seen = map { ($MODE_CATEGORY{$_} // '(not in the inventory)') => 1 } @modes;
    if (keys %seen > 1) {
        return (undef, 'held: the modes this entry names sit in different '
                     . 'hashcat categories (' . join('; ', sort keys %seen) . ')');
    }
    my ($hcat) = keys %seen;

    if (my $split = $HASHCAT_SPLIT{$hcat}) {
        return (undef, "held: hashcat category '$hcat' is one a curator has "
                     . "already answered two ways ($split)");
    }
    my $m = $HASHCAT_CATEGORY{$hcat};
    return (undef, "held: no curator has ever categorised an entry in hashcat "
                 . "category '$hcat', so there is nothing to map it to")
        unless $m;

    return ($m->[0], "hashcat category '$hcat' (agreed by "
                   . join(',', @modes) . "); $m->[1] human answer(s) in the "
                   . 'control set, all of them ' . $m->[0]);
}
my %only = map { $_ => 1 } @only;

#-----------------------------------------------------------------------
# The ruleset. Returns (category, why) or (undef, why); the 'why' is printed
# under --verbose and is the whole audit trail, so it names the evidence
# rather than the rule number.

sub derive {
    my ($e) = @_;

    # 1. The field exists precisely to say this.
    return ('application', 'application: names a product')
        if defined $e->{application};

    # 2. The guard. See the methodology note on md5uc.
    for my $r (@{ $e->{relations} || [] }) {
        next unless $r->{kind} eq 'encodes' || $r->{kind} eq 'input-encoding';
        return (undef, "held: a $r->{kind} edge to $r->{entry} means the "
                     . 'expression cannot tell this row from the one it encodes');
    }

    # 3. An iteration count IS the claim that this is another entry applied N
    #    times, and it outranks the expression rules because it says more.
    my $it = $e->{tools}{mdxfind}{iterations} // 1;
    return ('iterated', "tools.mdxfind.iterations = $it")
        if $it > 1;

    # 6. hashcat's own classification of the mode, ABOVE the expression rules.
    #    Royce, 2026-09-01: of the three tools only hashcat publishes human
    #    judgement about what KIND of thing a mode is, and that is the question
    #    this field asks. mdxfind and john publish no classification at all.
    #    It stays below rule 3, because an iteration count is a statement about
    #    identity rather than about kind.
    my ($hcat, $hwhy) = hashcat_category($e);
    return ($hcat, $hwhy) if defined $hcat;

    # 4/5. Only a proven expression counts; see the methodology note. Reached
    #      when hashcat named no usable category -- a HOLD there means hashcat
    #      cannot tell us, not that nobody can, so the expression still gets
    #      its turn.
    my $tier = $e->{expression_proof}{verified} // '';
    my $x    = $e->{expression};
    if (defined $x && length $x && ($tier eq 'vector' || $tier eq 'upstream')) {
        # ^ one function name, then $p alone, then close: md5($p), haval128_3($p).
        return ('primitive', "expression $x is one function of \$p alone (tier $tier)")
            if $x =~ /^\w[\w.-]*\(\s*\$p\s*\)$/;
        return ('composite', "expression $x is a construction, not one function "
                           . "of \$p alone (tier $tier)");
    }

    # Nothing answered. hashcat's reason is the more specific one.
    return (undef, $hwhy);
}

#-----------------------------------------------------------------------
# Walk.

opendir(my $dh, $algdir) or do { print STDERR "$PROG: cannot read $algdir: $!\n"; exit 1 };
my @files = sort grep { /\.yaml$/ } readdir $dh;
closedir $dh;

my (%yield, %held_why, %held_bucket, @disagree, @overruled, @write);
my ($seen, $tombstone, $already, $held, $norule) = (0, 0, 0, 0, 0);

for my $f (@files) {
    my $p = "$algdir/$f";
    my $e = eval { YAML::XS::LoadFile($p) };
    unless ($e && $e->{id}) { print STDERR "$PROG: cannot load $p\n"; next }
    next if @only && !$only{ $e->{id} };
    # A tombstone is not an algorithm and validate.pl forbids a category on it.
    if (($e->{status} // '') eq 'merged') { $tombstone++; next }
    $seen++;

    my ($cat, $why) = derive($e);

    # Where an earlier rule answered, we never see what hashcat would have
    # said. Ask it anyway under --check: a disagreement is evidence about the
    # ruleset and is lost otherwise.
    if ($check && defined $cat && $why !~ /^hashcat category/) {
        my ($hcat) = hashcat_category($e);
        push @overruled, [$e->{id}, $cat, $hcat, $why]
            if defined $hcat && $hcat ne $cat;
    }

    if (defined $e->{category}) {
        $already++;
        if (defined $cat && $cat ne $e->{category}) {
            # --rederive corrects values this tool wrote under a ruleset that
            # has since changed. A curator's answer is never a candidate.
            if ($rederive && !$protected{ $e->{id} }) {
                push @rewrite, [$p, $e, $cat, $e->{category}, $why];
            }
            elsif ($check) {
                push @disagree, [$e->{id}, $e->{category}, $cat,
                                 ($baseline ? ($protected{$e->{id}} ? 'curator' : 'this tool')
                                            : 'unknown'), $why];
            }
        }
        next;
    }

    unless (defined $cat) {
        if ($why =~ /^held/) {
            $held++;
            $held_why{ $e->{id} } = $why;
            # Bucket by reason. Rule 2 and rule 6 both hold, for unrelated
            # reasons, and a single lumped count hid which was which.
            my $bucket =
                  $why =~ /encodes|input-encoding/       ? 'an encoding edge'
                : $why =~ /answered two ways/            ? 'a hashcat category curators split on'
                : $why =~ /nothing to map it to/         ? 'a hashcat category no curator has answered'
                : $why =~ /different hashcat categories/ ? 'modes in disagreeing hashcat categories'
                :                                          'another reason';
            $held_bucket{$bucket}++;
        }
        else { $norule++ }
        printf STDERR "-   %-46s %s\n", $e->{id}, $why if $verbose > 1;
        next;
    }

    $yield{$cat}++;
    push @write, [$p, $e, $cat];
    printf STDERR "-   %-46s %-11s %s\n", $e->{id}, $cat, $why if $verbose;
}

#-----------------------------------------------------------------------
# Report on stdout so it can be redirected; counts on stderr per the house
# convention.

printf "%-46s %s\n", $_->[1]{id}, $_->[2] for @write;

if ($check && @overruled) {
    print "\n# an earlier rule answered these and rule 6 would have said\n"
        . "# otherwise. Since 2026-09-01 rule 6 outranks the expression rules,\n"
        . "# so what remains here is rule 3: mdxfind declares an iteration\n"
        . "# count, which is a statement about identity, while hashcat files\n"
        . "# the same mode under 'Raw Hash salted and/or iterated' and merges\n"
        . "# the two axes this repository keeps apart. Rule 3 wins on purpose.\n";
    printf "# %-44s kept=%-11s hashcat=%-11s %s\n", @$_ for @overruled;
}

if ($check) {
    if (@disagree) {
        print "\n# a rule disagrees with a category already on the entry -- one\n"
            . "# of the two is wrong, and neither is edited here. 'by' says who\n"
            . "# wrote the existing value, which needs --baseline to know.\n";
        printf "# %-44s have=%-11s rule=%-11s by=%-8s %s\n", @$_ for @disagree;
    }
    else {
        print STDERR "- --check: no rule contradicts any of the $already "
                   . "category/categories already written\n";
    }
}

if ($rederive) {
    if (@rewrite) {
        print "\n# --rederive: categories this tool wrote that the current\n"
            . "# ruleset no longer agrees with. None of these is a curator's:\n"
            . "# every value present in the baseline is protected.\n";
        printf "# %-44s %-11s -> %-11s %s\n", $_->[1]{id}, $_->[3], $_->[2], $_->[4]
            for @rewrite;
    }
    else {
        print STDERR "- --rederive: nothing to correct; the ruleset agrees "
                   . "with every category this tool wrote\n";
    }
}

printf STDERR "- %d entry/entries (%d tombstone(s) skipped); %d already had a "
            . "category\n", $seen, $tombstone, $already;
printf STDERR "-   to rewrite: %d\n", scalar @rewrite if $rederive;
printf STDERR "-   derived %d: %s\n", scalar @write,
    join('  ', map { "$_ $yield{$_}" } sort keys %yield) || '(none)';
printf STDERR "-   left for a curator: %d with no rule, %d held\n", $norule, $held;
printf STDERR "-     held by %-46s %d\n", $_, $held_bucket{$_}
    for sort { $held_bucket{$b} <=> $held_bucket{$a} || $a cmp $b } keys %held_bucket;
printf STDERR "-     held: %s\n", join(' ', sort keys %held_why) if $verbose;

#-----------------------------------------------------------------------
# Apply.

if ($apply) {
    my ($added, $corrected) = (0, 0);
    for my $w (@write) {
        my ($p, $e, $cat) = @$w;
        $e->{category} = $cat;
        $added += emit_entry($p, $e);
    }
    for my $w (@rewrite) {
        my ($p, $e, $cat) = @$w;
        $e->{category} = $cat;
        $corrected += emit_entry($p, $e);
    }
    printf STDERR "-   files written: %d new category/categories, %d corrected\n",
        $added, $corrected;
}
elsif (@write || @rewrite) {
    print STDERR "-   nothing written; re-run with --apply to record these\n";
}

exit 0;
