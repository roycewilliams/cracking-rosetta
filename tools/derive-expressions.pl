#!/usr/bin/perl
#-----------------------------------------------------------------------
#
# Name: derive-expressions.pl
# Description: propose an expression for an entry that has none, and PROVE it
#              by handing it to john's dynamic compiler against that entry's
#              own vectors
# Category: cracking-rosetta curator
#
# Project: cracking-rosetta | Phase: 6 - make the semantic join key real
#
#-----------------------------------------------------------------------
# METHODOLOGY AND WHY THESE CHOICES
#
# THE PROBLEM expressions.pl COULD NOT SOLVE
#
# expressions.pl transcribes "john --list=subformats": if an entry names a
# dynamic and that dynamic prints what it computes, the expression is copied
# across. That reached 144 entries and stops dead at the rest, because the
# remaining entries name no john format at all. The expression is the semantic
# join key -- the thing that lets a validator assert two tools' identifiers
# denote the same construction -- so leaving 640 entries without one leaves
# the key mostly decorative.
#
# WHY A GUESS CAN BE SAFE HERE
#
# CLAUDE.md's prime directive is that no mapping is asserted unless it was
# reproduced. That normally rules out deriving an expression from a name. It
# does not rule it out here, because john's dynamic compiler takes an
# expression on the command line:
#
#     john --format=dynamic='sha1(md5($p).$s)'
#
# So a candidate never has to be believed. Hand it to john against the entry's
# OWN hash and its OWN plaintext and either john recovers the plaintext or it
# does not. The name is only a way of generating something to test; the test
# is the same round-trip that every other tier-'vector' fact in this repo
# rests on. A rejected candidate costs one john invocation and writes nothing.
#
# mdxfind's hx compiler would be a second oracle, but this build exposes no
# CLI flag that compiles an expression (see STATE gotcha 19), so john is the
# only one available.
#
# THREE CANDIDATE GENERATORS, DELIBERATELY REDUNDANT
#
#   1. name:   the sheet already wrote most of these as expressions --
#              "haval128_3(md5($plain))". Substituting $plain -> $p and
#              $salt -> $s is transcription, the same class of operation
#              expressions.pl performs, and it is the highest-fidelity source.
#   2. id:     this repo's own slugs encode the construction --
#              "haval128-3-md5-plain-plain".
#   3. mdxfind type: the type names are themselves a compact postfix
#              concatenation language -- MD5SALTMD5PASS, SHA1MD5SALT,
#              HAV160-5 -- plus an iteration count carried in the block.
#
# They are run together on purpose. Agreement is a strong candidate; a
# DISAGREEMENT is itself a finding, because it means the entry's id, its name
# or its mdxfind type is wrong, and the report names those entries.
#
# NEVER DROP A TOKEN
#
# Every generator tokenises against a closed vocabulary and BAILS on the first
# token it does not know. This is the rule that keeps the tool honest.
# MD5CAP's "CAP" is not in the vocabulary, so no candidate is emitted for it --
# whereas silently ignoring the token would emit md5($p), which john would
# happily "prove" because cap() is a no-op on a lowercase digest. That is
# precisely the masking trap CLAUDE.md documents, and dropping tokens is how
# a tool walks into it. HEXSALT, DSALT, lsb32, SPECAM, HUM, CX, DRU and
# friends are unguessable and stay unguessed.
#
# The function vocabulary is not hand-written either: it is harvested from
# john's own subformat listing, so the tool can only propose functions this
# john build has demonstrated it has. A candidate naming bcrypt(), descrypt()
# or streebog256() is discarded before john is ever started.
#
# THE GUARD: EVERY VECTOR MUST FALL, NOT THE FIRST
#
# An entry with three vectors and a candidate that cracks two has found a
# coincidence, not an algorithm. That is exactly how dynamic_1011 looked like
# MD5PASSMD5: two of its four test vectors use the password as the salt, so
# md5($p.md5($s)) and md5($p.md5($p)) agree on them. So a candidate is proven
# only when every vector the entry carries is recovered under it.
#
# AMBIGUITY IS REPORTED, NOT RESOLVED
#
# Every candidate is tried, not just the first that works, and if two
# DIFFERENT expressions each reproduce every vector then nothing is written.
# Two expressions that agree on one short vector need not agree in general --
# an empty or degenerate salt is enough -- and choosing between them is
# curation. Those entries are listed for a human.
#
# WHERE THE RESULT GOES, AND WHERE IT MUST NOT
#
# expression: gets the bare expression, john_dynamic_expr: gets
# "dynamic=<expr>". Never tools.john.cpu. An ad-hoc expression is not a john
# format identifier -- no --list=formats will ever show it -- and putting it
# in the identifier column would inflate john's coverage number with something
# nobody can look up. The john gap must not move because of this tool.
#
# EXPECT validate.pl TO FAIL AFTER THE FIRST --apply
#
# That is the collision gate doing its job: two entries claiming the same
# expression must be joined by relations. Adding expressions in bulk makes
# every md5($p.$s) variant in the corpus visible to its siblings at once.
# The answer is a relations pass with tools/relate.pl --from, not a weaker
# rule. Stage it with --limit.
#
# DEPENDENCIES
#
#   perl, YAML::XS, tools/lib/RosettaEmit.pm
#   john with the dynamic compiler (1.9.0-jumbo bleeding)
#
#-----------------------------------------------------------------------
# Generated by Claude Opus 5 on 2026-08-29

use strict;
use warnings;

use File::Basename qw(basename);
use File::Path qw(make_path);
use FindBin qw($RealBin);
use Getopt::Long qw(GetOptions);
use YAML::XS ();

use lib "$RealBin/lib";
use RosettaEmit qw(emit_entry);
use RosettaTools qw(tool_path tool_env_help);

my $PROG = basename($0);
my $ROOT = "$RealBin/..";
my $TODAY = do { my @t = localtime; sprintf '%04d-%02d-%02d',
                 $t[5] + 1900, $t[4] + 1, $t[3] };

# The john build string, taken from the extracted inventory rather than probed
# again, so every tier this run writes names exactly the build data/tools was
# generated from.
sub john_version {
    my $y = eval { YAML::XS::LoadFile("$ROOT/data/tools/john.yaml") };
    my $v = $y && $y->{version};
    return (defined $v && length $v) ? "john $v" : 'john';
}

sub usage {
    print STDERR <<"END_USAGE";

Usage: $PROG [options]

   --john PATH         john binary       (default: @{[tool_env_help('john')]})
   --algorithms DIR    curated entries   (default: data/algorithms)
   --subformats PATH   read john's listing from a file instead of running it
   --only ID           just this entry   (repeatable)
   --limit N           stop after N entries that had a candidate to try
   --max-candidates N  cap candidates tried per entry (default 12)
   --timeout N         seconds per john run (default 60)
   --overwrite         re-derive from scratch even where an expression is
                       already recorded, instead of only re-proving it
   --denote            record the NEGATIVE result: for an entry whose name is
                       expression-shaped but names a function john's dynamic
                       vocabulary does not have, write expression_proof
                       verified: absent plus a denotation: of the name
   --apply             write expression: and john_dynamic_expr:
   -n, --dry-run       generate and report candidates, run no john
   -v, --verbose       per-entry detail (repeatable)
   -h, --help          this help

   Without --apply nothing is written. Exit 0 success, 1 error, 2 usage.

END_USAGE
    return;
}

my ($john, $algdir, $subfile, $help, $apply, $overwrite, $dry, $denote);
my @only;
my $maxcand = 12;
my $timeout = 60;
my $limit   = 0;
my $verbose = 0;
my $had_args = scalar @ARGV;

GetOptions(
    'john=s'           => \$john,
    'algorithms=s'     => \$algdir,
    'subformats=s'     => \$subfile,
    'only=s'           => \@only,
    'limit=i'          => \$limit,
    'max-candidates=i' => \$maxcand,
    'timeout=i'        => \$timeout,
    'overwrite'        => \$overwrite,
    'denote'           => \$denote,
    'apply'            => \$apply,
    'n|dry-run'        => \$dry,
    'v|verbose+'       => \$verbose,
    'h|help'           => \$help,
) or do { usage(); exit 2 };

if ($help)      { usage(); exit 0 }
if (!$had_args) { usage(); exit 2 }

$john = tool_path('john', $john);
$algdir //= "$ROOT/data/algorithms";
my %only = map { $_ => 1 } @only;

my $workdir = "$ROOT/tmp/derive-expressions";
make_path($workdir) unless -d $workdir;

#-----------------------------------------------------------------------
# The function vocabulary, harvested from john rather than hand-listed.
#
# "john --list=subformats" is 474 worked examples of the dynamic syntax. Every
# function name that appears in one is a function this build has. Nothing else
# may appear in a candidate, which is what stops the tool proposing bcrypt(),
# descrypt() or streebog256() and spending a john start finding out.

my $listing;
if (defined $subfile) {
    open my $fh, '<', $subfile
        or do { print STDERR "$PROG: cannot read $subfile: $!\n"; exit 1 };
    local $/;
    $listing = <$fh>;
    close $fh;
}
else {
    my $jd = $john; $jd =~ s{/[^/]+$}{};
    my $jb = basename($john);
    $listing = qx{cd @{[quotemeta $jd]} && ./@{[quotemeta $jb]} --list=subformats 2>/dev/null};
}

my %FN;
$FN{$1} = 1 while ($listing // '') =~ /([a-z][a-z0-9_]*)\(/g;

# john spells the "digest as raw bytes" variant <name>_raw, and the listing
# only demonstrates it for the functions some dynamic happens to use. The
# variant exists for all of them, so admit it for every base name seen.
$FN{"${_}_raw"} = 1 for grep { !/_raw$/ } keys %FN;

unless (keys %FN > 20) {
    print STDERR "$PROG: john's subformat listing yielded no vocabulary.\n";
    exit 1;
}
printf STDERR "- john vocabulary: %d function name(s)\n", scalar keys %FN;

#-----------------------------------------------------------------------
# Token tables.
#
# Two spellings of the same table: mdxfind SHOUTS its type names and this repo
# slugifies its ids. Both map onto john's function names. A name john does not
# have is dropped from the table below at load time rather than listed here as
# an exception, so the tables can name a family this john lacks without the
# generators being able to emit it.

my %MDX_FN = (
    MD2 => 'md2', MD4 => 'md4', MD5 => 'md5',
    SHA0 => undef,                       # john has no sha0; kept as a reminder
    SHA1 => 'sha1', SHA224 => 'sha224', SHA256 => 'sha256',
    SHA384 => 'sha384', SHA512 => 'sha512',
    'SHA3-224' => 'sha3_224', 'SHA3-256' => 'sha3_256',
    'SHA3-384' => 'sha3_384', 'SHA3-512' => 'sha3_512',
    RMD128 => 'ripemd128', RMD160 => 'ripemd160',
    RMD256 => 'ripemd256', RMD320 => 'ripemd320',
    WRL => 'whirlpool', GOST => 'gost', TIGER => 'tiger',
    SM3 => 'sm3', PANAMA => 'panama',
    KECCAK224 => 'keccak_224', KECCAK256 => 'keccak_256',
    KECCAK384 => 'keccak_384', KECCAK512 => 'keccak_512',
    SKEIN224 => 'skein224', SKEIN256 => 'skein256',
    SKEIN384 => 'skein384', SKEIN512 => 'skein512',
);
# haval: mdxfind writes the bare width for the 3-pass variant (HAV128 is
# haval128_3) and spells the others HAV<width>-<passes>.
for my $w (qw(128 160 192 224 256)) {
    $MDX_FN{"HAV$w"} = "haval${w}_3";
    $MDX_FN{"HAV$w-$_"} = "haval${w}_$_" for qw(3 4 5);
}

my %SLUG_FN;
for my $k (keys %MDX_FN) {
    next unless defined $MDX_FN{$k};
    (my $s = lc $k) =~ s/_/-/g;
    $SLUG_FN{$s} = $MDX_FN{$k};
}
# The slugs people actually typed: john's own spellings, and the shorthands
# the sheet used.
$SLUG_FN{$_} = $_ for grep { !/_raw$/ } keys %FN;      # md5, haval128_3, ...
for my $f (grep { /_/ && !/_raw$/ } keys %FN) {        # haval128_3 -> haval128-3
    (my $s = $f) =~ s/_/-/g;
    $SLUG_FN{$s} = $f;
}
$SLUG_FN{'whirlpool'} = 'whirlpool';
$SLUG_FN{'wrl'}       = 'whirlpool';
$SLUG_FN{"rmd$_"} = "ripemd$_" for qw(128 160 256 320);

# Operands and the modifier functions, in both spellings.
my %MDX_OP = (PASS => '$p', SALT => '$s', USER => '$u');
my %MDX_MOD = (UC => 'uc', LC => 'lc',
               UTF16 => 'utf16', UTF16LE => 'utf16le', UTF16BE => 'utf16be');
my %SLUG_OP = (plain => '$p', pass => '$p', password => '$p',
               salt => '$s', user => '$u', userid => '$u', username => '$u');
my %SLUG_MOD = (uc => 'uc', lc => 'lc', uppercase => 'uc', lowercase => 'lc',
                utf16 => 'utf16', 'utf16le' => 'utf16le', 'utf16be' => 'utf16be');

# The sheet wrote PHP's names for two functions john spells differently. This
# is a rename, not a guess: strtoupper IS uc. Nothing else PHP-ish is aliased,
# because base64_encode, strrev, substr and str_rot13 have no john equivalent
# and inventing one is how a wrong expression gets written.
my %NAME_ALIAS = (strtoupper => 'uc', upper => 'uc',
                  strtolower => 'lc', lower => 'lc',
                  wrl => 'whirlpool');

# Drop anything john cannot actually compile, so a generator physically cannot
# emit it.
for my $t (\%MDX_FN, \%SLUG_FN) {
    for my $k (keys %$t) {
        delete $t->{$k} unless defined $t->{$k} && $FN{ $t->{$k} };
    }
}
for my $t (\%MDX_MOD, \%SLUG_MOD) {
    for my $k (keys %$t) { delete $t->{$k} unless $FN{ $t->{$k} } }
}

#-----------------------------------------------------------------------
# Expression assembly.
#
# A token list is read as a concatenation. The only real ambiguity is how much
# of what follows a nested function swallows -- SHA1MD5SALT is
# sha1(md5($p).$s) but MD5SALTMD5PASS is md5($s.md5($p)) -- so rather than
# pick a rule and be wrong half the time, all three readings are enumerated
# and john decides. Enumeration is capped: these token lists are short, but
# nothing good happens if one is not.

my $ENUM_CAP = 32;

sub _dot { my ($a, $b) = @_; return length $b ? "$a.$b" : $a }

# seq(@tokens) - every reading of this token list as a concatenation.
sub seq {
    my @t = @_;
    return ('') unless @t;

    my $h = shift @t;
    my @out;

    if ($h->{t} eq 'op') {
        push @out, _dot($h->{v}, $_) for seq(@t);
    }
    else {                                  # a function or a modifier
        my $f = $h->{v};

        # (a) it swallows everything that follows
        for my $a (seq(@t)) {
            push @out, sprintf('%s(%s)', $f, length $a ? $a : '$p');
        }
        # (b) it swallows nothing: implicit $p, the rest is concatenated after
        if (@t) {
            push @out, _dot("$f(\$p)", $_) for seq(@t);
        }
        # (c) it swallows exactly the next token
        if (@t >= 2) {
            my ($one) = seq($t[0]);
            my @rest = @t[1 .. $#t];
            $one = '$p' unless defined $one && length $one;
            push @out, _dot("$f($one)", $_) for seq(@rest);
        }
    }

    my (%seen, @uniq);
    for (@out) { push @uniq, $_ unless $seen{$_}++; last if @uniq >= $ENUM_CAP }
    return @uniq;
}

# build(@tokens) - the candidates for a whole type/id, i.e. the readings in
# which the FIRST token is a function wrapping everything else. An expression
# is a digest, so a top level that is a bare concatenation is not a candidate.
sub build {
    my @t = @_;
    return () unless @t && $t[0]{t} ne 'op';
    my $f = shift(@t)->{v};
    my @out;
    for my $a (seq(@t)) {
        push @out, sprintf('%s(%s)', $f, length $a ? $a : '$p');
    }
    return @out;
}

# iterate($expr, $n) - the mdxfind iteration count is part of the identity:
# MD5 at -i 2 is md5(md5($p)). Only meaningful for an expression over the
# password alone and mentioning it once; where a salt is involved, mdxfind's
# re-feeding rule is not documented here, so nothing is emitted.
sub iterate {
    my ($expr, $n) = @_;
    return $expr if !$n || $n <= 1;
    return () if $expr =~ /\$[su]/;
    return () unless 1 == (() = $expr =~ /\$p/g);
    my $cur = $expr;
    for (2 .. $n) {
        (my $next = $expr) =~ s/\$p/$cur/;
        $cur = $next;
    }
    return $cur;
}

#-----------------------------------------------------------------------
# Generator 1: the name: field.
#
# Most sheet rows already spell the construction -- "haval128_3(md5($plain))".
# This is transcription, so it is tried first. It is also the strictest
# reader: the whole string must consume against the grammar, which is what
# throws out 'hash("gost-crypto", $plain)' and 'gost(md5($p).":".$s)'
# (john's compiler has no literal constants; verified by trying one).

sub from_name {
    my ($name) = @_;
    return () unless defined $name;

    my $s = $name;
    $s =~ s/\s+//g;
    $s =~ s/\$(?:plain|pass|password)\b/\$p/g;
    $s =~ s/\$salt\b/\$s/g;
    $s =~ s/\$(?:user|username|userid)\b/\$u/g;

    return () unless $s =~ /^[a-z][a-z0-9_]*\(.*\)$/;

    # Consume the whole string against the grammar; anything left over -- a
    # literal, a second salt, a comment -- disqualifies it.
    my $depth = 0;
    my $pos   = 0;
    while ($pos < length $s) {
        if ($s =~ /\G([a-z][a-z0-9_]*)\(/gc) {
            my $fn = $NAME_ALIAS{$1} // $1;
            return () unless $FN{$fn};
            if ($fn ne $1) {                 # rewrite in place, keeping pos
                my $at = pos($s) - length($1) - 1;
                substr($s, $at, length $1) = $fn;
                pos($s) = $at + length($fn) + 1;
            }
            $depth++;
        }
        elsif ($s =~ /\G\)/gc)      { $depth--; return () if $depth < 0 }
        elsif ($s =~ /\G\./gc)      { }
        elsif ($s =~ /\G\$[psu]/gc) { }
        else                        { return () }
        $pos = pos($s);
    }
    return () if $depth != 0;
    return ($s);
}

#-----------------------------------------------------------------------
# Generator 2: the entry id.
#
# "haval128-3-md5-plain-plain" -> haval128_3(md5($p).$p). Split on '-', then
# re-join the pairs that spell one function ("haval128" + "3", "sha3" + "256").
# A trailing "x2" is an iteration count, the same fact the mdxfind block
# carries as iterations:.

sub from_id {
    my ($id) = @_;
    my @parts = split /-/, lc $id;
    return () unless @parts;

    my $iter = 1;
    if ($parts[-1] =~ /^x0*(\d+)$/) { $iter = $1; pop @parts }
    return () unless @parts;
    return () if @parts > 10;

    my @tok;
    while (@parts) {
        my $two = @parts >= 2 ? "$parts[0]-$parts[1]" : undef;
        if (defined $two && $SLUG_FN{$two}) {
            push @tok, { t => 'fn', v => $SLUG_FN{$two} };
            splice @parts, 0, 2;
        }
        elsif ($SLUG_FN{ $parts[0] }) {
            push @tok, { t => 'fn', v => $SLUG_FN{ shift @parts } };
        }
        elsif ($SLUG_MOD{ $parts[0] }) {
            push @tok, { t => 'fn', v => $SLUG_MOD{ shift @parts } };
        }
        elsif ($SLUG_OP{ $parts[0] }) {
            push @tok, { t => 'op', v => $SLUG_OP{ shift @parts } };
        }
        elsif ($parts[0] eq 'raw' && @tok && $tok[-1]{t} eq 'fn') {
            # "raw" names the previous function's raw-bytes variant.
            my $r = $tok[-1]{v} . '_raw';
            return () unless $FN{$r};
            $tok[-1]{v} = $r;
            shift @parts;
        }
        else { return () }              # unknown token: emit nothing
    }
    return map { iterate($_, $iter) } build(@tok);
}

#-----------------------------------------------------------------------
# Generator 3: the mdxfind type name.
#
# A postfix concatenation language with no separators, so the tokeniser is a
# longest-match scan over the table. It bails at the first position nothing
# matches, which is what keeps MD5CAP, MD5DSALT, SHA1lsb32 and MD5SPECAM out.

my @MDX_KEYS = sort { length($b) <=> length($a) || $a cmp $b }
               (keys %MDX_FN, keys %MDX_OP, keys %MDX_MOD, 'RAW');

sub from_type {
    my ($type, $iter) = @_;
    return () unless defined $type && length $type;
    my $s = uc $type;
    $s =~ s/\s+//g;

    my @tok;
    POS: while (length $s) {
        for my $k (@MDX_KEYS) {
            next unless index($s, $k) == 0;
            substr($s, 0, length $k) = '';
            if    ($MDX_FN{$k})  { push @tok, { t => 'fn', v => $MDX_FN{$k} } }
            elsif ($MDX_MOD{$k}) { push @tok, { t => 'fn', v => $MDX_MOD{$k} } }
            elsif ($MDX_OP{$k})  { push @tok, { t => 'op', v => $MDX_OP{$k} } }
            else {                                     # RAW
                return () unless @tok && $tok[-1]{t} eq 'fn';
                my $r = $tok[-1]{v} . '_raw';
                return () unless $FN{$r};
                $tok[-1]{v} = $r;
            }
            next POS;
        }
        return ();                       # unknown token: emit nothing
    }
    return () if @tok > 10;
    return map { iterate($_, $iter) } build(@tok);
}

#-----------------------------------------------------------------------
# The oracle.
#
# One john run per candidate, over every vector the entry has at once. The
# machinery is verify-vectors.pl's and discover-john.pl's, for their reasons:
# john echoes its own encoding rather than the input, so attribution is by a
# synthetic login read back from --show, and --field-separator-char=tab keeps
# a vector containing ':' from being read as "login:hash".

sub run_capture {
    my ($secs, $cwd, @argv) = @_;
    my $out = '';
    my $pid = open(my $fh, '-|');
    defined $pid or return (-1, '');
    if (!$pid) {
        chdir $cwd or exit 127;
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

my $jdir = $john; $jdir =~ s{/[^/]+$}{};
my $jbin = './' . basename($john);

my $runs = 0;

# prove($expr, $vectors) - true when EVERY vector falls to this expression.
sub prove {
    my ($expr, $vecs, $tag) = @_;

    my $hashf = "$workdir/$tag.hash";
    my $wordf = "$workdir/$tag.word";
    my $potf  = "$workdir/$tag.pot";

    my (@lines, %want, %login_of);
    my $i = 0;
    for my $v (@$vecs) {
        my $login = 'v' . $i++;
        $login_of{$login} = $v;
        $want{"$v->{hash}\0$v->{pass}"} = 1;
        push @lines, "$login\t$v->{hash}";
        # A salted vector is stored "<hash>:<salt>"; john's dynamics want
        # "<hash>$<salt>". Both lines carry the same login, so either crack
        # credits the vector.
        my ($h, $salt) = split /:/, $v->{hash}, 2;
        push @lines, "$login\t$h\$$salt"
            if defined $salt && length $salt && $salt !~ /:/;
    }

    my %uw;
    my @words = grep { !$uw{$_}++ } map { $_->{pass} } @$vecs;

    for my $pair ([$hashf, \@lines], [$wordf, \@words]) {
        open my $fh, '>', $pair->[0] or die "$PROG: cannot write $pair->[0]: $!\n";
        print {$fh} "$_\n" for @{ $pair->[1] };
        close $fh;
    }
    unlink $potf;

    my @common = ($jbin, "--format=dynamic=$expr", '--field-separator-char=tab',
                  "--pot=$potf");
    $runs++;
    my ($code) = run_capture($timeout, $jdir, @common,
                             "--wordlist=$wordf", "--session=$workdir/$tag",
                             $hashf);
    return 0 unless -s $potf;

    my (undef, $shown) = run_capture($timeout, $jdir, @common, '--show', $hashf);

    my %got;
    for my $line (split /\n/, $shown // '') {
        my ($login, $pw) = split /\t/, $line, 2;
        next unless defined $login && defined $pw;
        my $v = $login_of{$login} or next;
        next unless $pw eq $v->{pass};
        $got{"$v->{hash}\0$v->{pass}"} = 1;
    }
    # john deduplicates identical hashes on load and --show prints such a hash
    # once, so the comparison is over distinct (hash, plaintext) pairs.
    for my $k (keys %want) { return 0 unless $got{$k} }
    return scalar(keys %want) ? 1 : 0;
}

#-----------------------------------------------------------------------
# The negative result, and why it is worth writing down.
#
# 378 entries generate no candidate at all, and they will generate none on
# every future run too. Leaving them blank makes "nobody has reached this yet"
# indistinguishable from "this algorithm has no expression", so the question
# gets re-asked forever and 859 john runs get re-spent finding out.
#
# But 'absent' must be a FACT, not a shrug. The one this tool can state
# honestly is narrow and checkable: the entry's name is already
# expression-shaped -- the sheet wrote md5(base64_encode($plain)) or
# hmac("sha1", $plain, $salt) -- and at least one function in it is not in the
# vocabulary john's dynamic compiler accepts. That is not an opinion about the
# algorithm; it is a lookup against the 106 names harvested from john's own
# subformat listing.
#
# It is emphatically NOT a claim that john cannot crack the thing. john has
# formats for HMAC-SHA1 and for bcrypt; it has no hmac() or bcrypt() token in
# the dynamic EXPRESSION language, which is a different sentence, and the note
# written on each entry says so.
#
# The wording itself then survives as denotation: -- the user-facing answer to
# "what is this algorithm" for a row whose expression column must stay empty.
# It is stored exactly as the sheet spelled it, $plain and all, with
# source: sheet, so it is attributed rather than asserted.

# unknown_functions($name) - the john-vocabulary misses in an expression-shaped
# name, or () if the name is not expression-shaped or names nothing unknown.
sub unknown_functions {
    my ($name) = @_;
    return () unless defined $name;
    my $s = $name;
    $s =~ s/\s+//g;
    return () unless $s =~ /^[a-z][a-z0-9_]*\(.*\)$/;

    my (%miss, @order);
    while ($s =~ /([a-z][a-z0-9_]*)\(/g) {
        my $f = $NAME_ALIAS{$1} // $1;
        next if $FN{$f};
        push @order, $f unless $miss{$f}++;
    }
    return @order;
}

#-----------------------------------------------------------------------
# Entries.

opendir(my $dh, $algdir)
    or do { print STDERR "$PROG: cannot read $algdir: $!\n"; exit 1 };
my @files = sort grep { /\.yaml$/ } readdir $dh;
closedir $dh;

my ($seen, $had_expr, $no_vector, $no_candidate, $tried) = (0, 0, 0, 0, 0);
my (@proven, @failed, @ambiguous, @disagree, @unproven);
my $promoted = 0;
my $denoted  = 0;
my %by_expr;
my $started = time;
my $tag_n   = 0;

# Expressions already on record, so the collision forecast below is against
# the whole corpus rather than only this run's output. validate.pl fails on a
# shared expression regardless of which run wrote it.
my %prior_expr;
for my $f (@files) {
    my $e = eval { YAML::XS::LoadFile("$algdir/$f") } or next;
    next unless $e->{id} && defined $e->{expression} && length $e->{expression};
    push @{ $prior_expr{ $e->{expression} } }, $e->{id};
}

ENTRY: for my $f (@files) {
    my $path = "$algdir/$f";
    my $e = eval { YAML::XS::LoadFile($path) } or next;
    next unless $e->{id};
    next if %only && !$only{ $e->{id} };
    $seen++;

    # Three cases, not two.
    #
    #   already at tier 'vector'  -- proven by this tool on a previous run;
    #                                nothing to do.
    #   an expression, lower tier -- a PROMOTION target. The question is not
    #                                "what might this be" but "does the string
    #                                we already record actually hold up", so
    #                                the only candidate offered is that string.
    #                                A failure here is a finding: it means a
    #                                transcribed expression does not reproduce
    #                                the entry's own vector.
    #   no expression             -- derive from the generators, as before.
    my $has_expr = defined $e->{expression} && length $e->{expression};
    my $cur_tier = ref $e->{expression_proof} eq 'HASH'
                 ? ($e->{expression_proof}{verified} // '') : '';
    my $promote  = 0;

    if ($has_expr && !$overwrite) {
        if ($cur_tier eq 'vector') { $had_expr++; next }
        $promote = 1;
    }

    # --denote does not need a vector: it records that no expression exists,
    # which is a statement about john's vocabulary, not about this hash.
    if ($denote && !$has_expr && !defined $e->{expression_proof}) {
        my @miss = unknown_functions($e->{name});
        if (@miss) {
            $denoted++;
            printf "%-34s absent: no %s in john's dynamic vocabulary\n",
                $e->{id}, join(', ', map { "$_()" } @miss)
                if $verbose || !$apply;
            if ($apply) {
                $e->{expression_proof} = {
                    verified      => 'absent',
                    verified_at   => $TODAY,
                    verified_with => john_version(),
                    note          => sprintf(
                        "john's dynamic expression vocabulary has no %s, so "
                      . "this construction cannot be written as an expression; "
                      . "that is separate from whether john has a FORMAT for it",
                        join(', ', map { "$_()" } @miss)),
                };
                (my $text = $e->{name}) =~ s/\s+$//;
                $e->{denotation} = { text => $text, source => 'sheet' };
                emit_entry($path, $e);
            }
            next;
        }
    }

    # A vector is the whole point: without one there is nothing to prove
    # against, and an unproven expression is exactly what this repo forbids.
    my @vecs = grep { defined $_->{hash} && defined $_->{pass}
                      && $_->{hash} !~ /\t/ && $_->{pass} !~ /\t/ }
               @{ $e->{vectors} || [] };
    unless (@vecs) { $no_vector++; next }

    my $mdx  = $e->{tools}{mdxfind} || {};
    my $iter = $mdx->{iterations} || 1;

    my @g_name = $promote ? ($e->{expression}) : from_name($e->{name});
    my @g_id   = $promote ? ()                    : from_id($e->{id});
    my @g_type = $promote ? ()
               : map { from_type($_, $iter) } @{ $mdx->{types} || [] };

    # Order is preference order: transcription, then our slug, then mdxfind's.
    my (%src, %seen_c, @cands);
    for my $pair (['name', \@g_name], ['id', \@g_id], ['type', \@g_type]) {
        for my $c (@{ $pair->[1] }) {
            next unless defined $c && length $c;
            # An expression that never mentions the password is not a
            # candidate for anything: mdxfind's bare "MD5SALT" tokenises to
            # md5($s), which is the tokeniser losing an implicit operand
            # rather than a construction anyone computes.
            next unless $c =~ /\$p/;
            push @{ $src{$c} }, $pair->[0];
            next if $seen_c{$c}++;
            push @cands, $c;
        }
    }

    # A generator disagreement is a finding in itself: it means the id, the
    # name or the mdxfind type is describing a different algorithm.
    if (!$promote && @g_name && @g_id) {
        my %id_set = map { $_ => 1 } @g_id;
        # The id generator ENUMERATES readings, so it routinely returns
        # dozens. Printing them all buries the finding; three is enough to
        # see which way it went.
        push @disagree, sprintf('%-34s name=%s  id=%s%s', $e->{id},
                                $g_name[0], join(', ', @g_id[0 .. ($#g_id > 2 ? 2 : $#g_id)]),
                                @g_id > 3 ? sprintf(' (+%d more)', @g_id - 3) : '')
            unless grep { $id_set{$_} } @g_name;
    }

    unless (@cands) { $no_candidate++; next }
    @cands = @cands[0 .. $maxcand - 1] if @cands > $maxcand;

    $tried++;
    last ENTRY if $limit && $tried > $limit;

    if ($dry) {
        printf "%-34s %s\n", $e->{id},
            join('  |  ', map { "$_ [" . join('+', @{ $src{$_} }) . "]" } @cands);
        next;
    }

    my @won;
    for my $c (@cands) {
        $tag_n++;
        push @won, $c if prove($c, \@vecs, sprintf('c%05d', $tag_n));
    }

    if (!@won) {
        push @{ $promote ? \@unproven : \@failed },
            sprintf('%-34s %s', $e->{id}, join(' | ', @cands));
        printf STDERR "-   %-34s no candidate proved (%d tried)\n",
            $e->{id}, scalar @cands if $verbose > 1;
        next;
    }
    if (@won > 1) {
        # Two different expressions each reproduced every vector. On this
        # entry's inputs they agree; in general they need not. Curation.
        push @ambiguous, sprintf('%-34s %s', $e->{id}, join(' | ', @won));
        next;
    }

    my $expr = $won[0];
    push @{ $by_expr{$expr} }, $e->{id};
    my $how = $promote ? sprintf('promoted from %s', $cur_tier || 'untiered')
                       : join('+', @{ $src{$expr} });
    $promoted++ if $promote;
    push @proven, sprintf('%-34s %-46s [%s]', $e->{id}, $expr, $how);
    printf "%-34s %-46s [%s]\n", $e->{id}, $expr, $how
        if $verbose || !$apply;

    next unless $apply;
    $e->{expression}        = $expr;
    $e->{john_dynamic_expr} = "dynamic=$expr";

    # Tier 'vector', and it means what it means everywhere else in this repo:
    # this exact string was compiled by john and recovered this entry's own
    # plaintext from its own hash. Not "john says dynamic_N computes this" --
    # that is expressions.pl's 'upstream'.
    $e->{expression_proof} = {
        verified      => 'vector',
        verified_at   => $TODAY,
        verified_with => john_version(),
        note          => 'round-tripped as --format=dynamic=<expr> against '
                       . 'every vector this entry carries',
    };
    delete $e->{denotation};   # an expression supersedes the fallback wording
    emit_entry($path, $e);
}

my $elapsed = time - $started;

#-----------------------------------------------------------------------
# Report.

printf STDERR "- %d entry/entries considered in %ds (%d john run(s))\n",
    $seen, $elapsed, $runs;
printf STDERR "-   already had an expression %d, no vector %d, "
            . "no candidate generated %d\n",
    $had_expr, $no_vector, $no_candidate;
printf STDERR "-   recorded as having NO expression (--denote) %d\n", $denoted
    if $denote;
printf STDERR "-   candidates tried on %d, PROVEN %d (of which %d promoted "
            . "from a lower tier), ambiguous %d, none proved %d\n",
    $tried, scalar @proven, $promoted, scalar @ambiguous, scalar @failed;

if (@unproven) {
    printf "\n# %d entry/entries whose ALREADY RECORDED expression did not\n"
         . "# reproduce their own vectors. Their tier was left alone, not\n"
         . "# demoted -- but each of these is either a wrong expression, a\n"
         . "# vector of a different algorithm, or a construction john's\n"
         . "# dynamic compiler cannot express. Worth a look.\n",
        scalar @unproven;
    print "# $_\n" for @unproven;
}

if (@ambiguous) {
    printf "\n# %d entry/entries where more than one expression reproduced "
         . "EVERY vector.\n# Nothing was written: choosing between them is "
         . "curation, not a round-trip.\n", scalar @ambiguous;
    print "# $_\n" for @ambiguous;
}

if (@disagree && $verbose) {
    printf "\n# %d entry/entries whose name: and id: propose different "
         . "expressions.\n# One of the two is wrong; the proof says which.\n",
        scalar @disagree;
    print "# $_\n" for @disagree;
}

if (@failed && $verbose > 1) {
    printf "\n# %d entry/entries where no candidate cracked every vector\n",
        scalar @failed;
    print "# $_\n" for @failed;
}

my %group;
for my $x (keys %by_expr) {
    my %seen_id;
    $group{$x} = [ grep { !$seen_id{$_}++ }
                   @{ $by_expr{$x} }, @{ $prior_expr{$x} || [] } ];
}
my @collide = grep { @{ $group{$_} } > 1 } sort keys %group;
if (@collide) {
    printf "\n# %d expression(s) claimed by more than one entry, counting the\n"
         . "# %d already on record. validate.pl fails on these until relate.pl\n"
         . "# joins them; that relations pass is the expected next step.\n",
        scalar @collide, scalar keys %prior_expr;
    printf "# %-46s %s\n", $_, join(' ', @{ $group{$_} }) for @collide;
}

printf STDERR "-   nothing written; re-run with --apply\n" unless $apply || $dry;

exit 0;
