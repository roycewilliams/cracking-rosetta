package RosettaExpr;
#-----------------------------------------------------------------------
#
# Name: RosettaExpr
# Description: compile an entry's expression: into a Perl sub, for the
#              constructions this host can compute directly
#
#-----------------------------------------------------------------------
# METHODOLOGY AND WHY THIS EXISTS
#
# Two tools need to compute an entry's construction without asking a cracker.
# vanity.pl searches for a salt that makes a digest start 'dec0ded', which is
# hundreds of millions of evaluations and cannot shell out. triage-expressions
# needs a control vector it computed itself, so that "john's compiler will not
# reproduce this" can be separated from "nobody knows what this computes".
#
# It was vanity.pl's private parser first. It moved here the moment there was
# a second caller, because two implementations of "what does this expression
# mean" is exactly the drift this repository exists to prevent: the day they
# disagree, one of them is silently wrong about an entry.
#
# THE VOCABULARY IS STILL SMALL, AND STILL BAILS
#
# It began as md5/sha1/sha256/sha512 over hex strings, and that was the whole
# language. On 2026-09-02 the measurement that widened it: of the 181 entries
# whose expression sits at tier `upstream`, 143 carried triage's verdict
# [no-john-format] -- "no john format, and RosettaExpr cannot compile this
# either, so nothing here can check it". Every one of those 143 was the SAME
# branch. They were not unanswerable questions about the data; they were this
# module's four-function vocabulary, reported as if it were a fact about the
# entries. curate.pl suppresses a human question on that verdict, so the
# boundary of this file was silently deciding what nobody would ever be asked.
#
# What was added is exactly what those 143 needed and nothing else: raw
# (binary) digest output, and the representation and slicing operators --
# cut, pad, trunc, upper, lower, cap, rev, hex, base64, fromhex, frombase64.
#
# It widened again on 2026-09-04, by sha224, sha384 and the utf16 family,
# on the same kind of measurement and with the same restraint: those are
# the tokens this host can compute from CORE PERL alone. Digest::SHA
# already supplied sha224 and sha384, and the utf16 conversion is written
# out below rather than imported. Projected before the code was written
# (tmp/expr-gain.pl): 39 entries whose expression this module refuses
# today and would then compile.
#
# WHAT IS DELIBERATELY STILL OUTSIDE, and why it is not an oversight:
# md4 (42 more entries), whirlpool (18), gost, ripemd, haval, tiger,
# snefru, sha3/keccak, panama, skein, sm3, sha0. Every one needs a module
# this host does not have -- measured 2026-09-04, only Digest::MD5,
# Digest::SHA and Encode are installed -- so adding them is a packaging
# decision, not a code change. md4 is the single biggest lever left.
#
# IT WIDENED AGAIN ON 2026-09-04, BY $c1..$c8 -- AND THOSE ARE JOHN'S
#
# 31 of the corpus's 615 expressions failed here with no unknown function
# token at all, and 30 of them were the same shape: john's dynamic constant
# suffix, `md5($s.$c1.md5($p)),c1=-`. Not a vocabulary gap, a grammar one.
# (The thirty-first is `md5(md5($s.$p):$s)`, a bare colon literal, which is
# the other thing this grammar does not model. Left alone deliberately.)
#
# hx has NO constants in this form -- its own answer is a STRING LITERAL,
# `md5(salt . "-" . md5(pass))` -- so the notation here is john's and john
# is the oracle for it. What john does was read out of its source rather
# than its documentation, on the rule CLAUDE.md already carries for the
# dynamic language:
#
#   src/dynamic_compiler.c  find_the_extra_params()  where the list starts
#                           get_param()              a comma ends a value,
#                                                    unless backslashed
#                           handle_extra_params()    c1..c8, and an EMPTY
#                                                    value stops the scan
#                           comp_get_symbol()        a $cN with no value is
#                                                    an error, not a blank
#   src/dynamic_utils.c     dynamic_Demangle()       \\ and \xHH, and a
#                                                    backslash before
#                                                    anything else is kept
#
# Three consequences worth naming, because each is a place a reasonable
# guess is wrong:
#
#   - The list starts at the first comma at PAREN DEPTH ZERO, not at the
#     first comma. john can afford `strchr(expr, ',')` because its own
#     grammar has no comma inside an expression; this repository's does --
#     `md5(cut($c1.upper(sha1(sha1_raw($p))),0,40)),c1=*` is a real entry.
#   - An EMPTY value is not the empty string, it is a missing constant, and
#     john refuses the expression. So do we. (No corpus entry has one; the
#     one that looks like it, md5padmd5, is `c1= ` with a space.)
#   - The values must be PACKED from c1. john's loop breaks at the first
#     one it does not find, so a c2 without a c1 is not merely odd, it is
#     unusable -- and it would silently compile here as a dropped token,
#     which is the one thing this module exists not to do.
#
# The bytes never reach the eval. They live in a lexical array the compiled
# sub closes over, and only the INDEX is written into the source, so the
# rule that nothing from an entry file is interpolated still holds exactly.
#
# The bail rule is UNCHANGED and is what keeps the widening safe: an unknown
# function, a wrong arity, a token outside the grammar, all return undef
# rather than being skipped. Skipping a token silently changes the meaning of
# the expression -- cap(md5($p)) with cap() dropped is md5($p), a different
# algorithm that happens to agree on every digest whose first letter is
# already upper case, which is the exact trap md5cap records.
#
# THE SEMANTICS ARE UPSTREAM'S, MEASURED, NOT INFERRED
#
# Every operator below matches mdxfind's own hx engine, checked by building
# its standalone evaluator from the source tree CLAUDE.md names as the highest
# authority and running both over the same inputs. tools/test-rosetta-expr.pl
# carries the fixture and re-measures it with --oracle. Two that a careful
# reading would still have got wrong, and which the oracle settled:
#
#   cap()  capitalizes the first lower-case LETTER, not the first character.
#          cap('975790dfb...') moves the 'd' at index 6.
#   pad()  TRUNCATES when the input is already longer than the width; it is
#          "make it exactly this many bytes", not "at least".
#
# THE VALUE MODEL IS BYTES
#
# It had to become bytes to add _raw at all: base64(sha1_raw($p)) is base64 of
# 20 bytes, and base64 of the 40-character hex string is a different value
# that also looks plausible. Hashes emit lower-case hex by default and raw
# bytes under _raw (hx spells that suffix _bin; this repository spells it
# _raw, and RosettaHx translates -- both are accepted here). Nothing decodes
# or re-encodes text, so non-ASCII bytes pass through untouched.
#
# WHY IT EMITS PERL SOURCE RATHER THAN NESTED CLOSURES
#
# Speed, measured: a closure chain ran 1.8x slower than the flat expression
# (0.88 vs 1.55 MH/s on this host), and vanity.pl evaluates 2.7e8 candidates
# for one seven-character marker. Nothing from an entry file reaches the eval
# except the SHAPE: function names are looked up in %HASH/%RAW/%OP and never
# interpolated, integer arguments are emitted only after matching /^-?\d+$/,
# and a token outside the grammar bails before any source is built.
#
#-----------------------------------------------------------------------
# Generated by Claude Opus 5 on 2026-08-30

use strict;
use warnings;

use Digest::MD5 qw(md5 md5_hex);
use Digest::SHA qw(sha1 sha1_hex sha224 sha224_hex sha256 sha256_hex
                   sha384 sha384_hex sha512 sha512_hex);
use MIME::Base64 qw(encode_base64);

use Exporter 'import';
our @EXPORT_OK = qw(compile_expression expr_functions split_constants);

# split_constants($expression) -> ($body, \%const) or ()
#
# Exported because a second reader of the notation is a second GRAMMAR, and
# the two drift. denote-hx.pl's ill_formed() had its own idea of what an
# expression may contain and did not know about the `,cN=VALUE` list at all,
# so on 2026-09-05 it called all 33 expressions carrying a constant
# ill-formed -- including four john had PROVEN that morning -- and --repair
# would have withdrawn every one of them. It now asks here instead.
sub split_constants { return _split_params(@_) }

# Hex-emitting form: the default role for every hash in hx.
our %HASH = (
    md5    => \&md5_hex,
    sha1   => \&sha1_hex,
    sha224 => \&sha224_hex,
    sha256 => \&sha256_hex,
    sha384 => \&sha384_hex,
    sha512 => \&sha512_hex,
);

# Raw-emitting form, reached by the _raw (or hx's _bin) suffix.
our %RAW = (
    md5    => \&md5,
    sha1   => \&sha1,
    sha224 => \&sha224,
    sha256 => \&sha256,
    sha384 => \&sha384,
    sha512 => \&sha512,
);

#-----------------------------------------------------------------------
# The representation and slicing operators, each a transcription of the
# matching fn_* in mdxfind's hx_func.c. Kept as named subs rather than
# inlined source so the emitted expression stays a flat chain of calls.
#-----------------------------------------------------------------------

# fn_upper / fn_lower use toupper/tolower under the C locale, so ASCII only.
# tr/// rather than uc()/lc() because those can touch bytes above 0x7f.
sub _upper { my $x = $_[0]; $x =~ tr/a-z/A-Z/; return $x }
sub _lower { my $x = $_[0]; $x =~ tr/A-Z/a-z/; return $x }

sub _rev { return scalar reverse $_[0] }

# fn_hex: bytes to lower-case hex.
sub _hex { return unpack('H*', $_[0]) }

# fn_cap: with no position, upper-case the FIRST byte in a-z and stop. With a
# position, only that byte, and only if it is in a-z; a negative position
# counts back from the end. Anything else is left exactly as it was.
sub _cap {
    my ($x, $pos) = @_;
    if (defined $pos) {
        $pos += length($x) if $pos < 0;
        return $x if $pos < 0 || $pos >= length $x;
        my $c = substr($x, $pos, 1);
        substr($x, $pos, 1) = uc $c if $c ge 'a' && $c le 'z';
        return $x;
    }
    # \G[^a-z]* anchors the scan at the string start, so this replaces the
    # first a-z byte and nothing later.
    $x =~ s/\G([^a-z]*)([a-z])/$1 . uc($2)/e;
    return $x;
}

# fn_cut: start defaults to 0, a negative start counts back from the end and
# clamps at 0, a start past the end yields the empty string, and a length
# past the end is clamped rather than being an error.
sub _cut {
    my ($x, $start, $len) = @_;
    my $inlen = length $x;
    $start = 0 unless defined $start;
    if ($start < 0) { $start += $inlen; $start = 0 if $start < 0 }
    $start = $inlen if $start > $inlen;
    if (defined $len) { $len = 0 if $len < 0 }
    else              { $len = $inlen - $start }
    $len = $inlen - $start if $start + $len > $inlen;
    return substr($x, $start, $len);
}

# fn_trunc: cut from zero.
sub _trunc { return _cut($_[0], 0, $_[1]) }

# fn_pad: NUL-pad to exactly this width, or truncate to it. hx clamps the
# width to [0, 65536].
sub _pad {
    my ($x, $n) = @_;
    $n = 0     if $n < 0;
    $n = 65536 if $n > 65536;
    return substr($x, 0, $n) if length($x) >= $n;
    return $x . ("\0" x ($n - length $x));
}

# fn_base64: standard alphabet, padded, no line breaks.
sub _base64 { return encode_base64($_[0], '') }

#-----------------------------------------------------------------------
# fn_utf16le / fn_utf16be. hx does NOT zero-extend each byte; it converts
# UTF-8 to UTF-16 through iconv with //IGNORE (hx_func.c, fn_utf16le and
# hx_iconv_convert). Three consequences, none of them guessable from the
# name, all three MEASURED against the hx binary on 2026-09-04:
#
#   'e' U+00E9 as UTF-8 c3 a9  ->  one unit e900, not two units c300 a900
#   an invalid sequence        ->  DROPPED, not replaced by U+FFFD
#   U+1F600                    ->  the surrogate pair 3dd8 00de
#
# So a blind widening -- the obvious reading, and what mdxfind's own -b flag
# does internally for NTLM (hx_func.c line 1429 calls that one "blind zero
# extension") -- is a DIFFERENT function, agreeing only on ASCII. Every
# vector in this corpus is ASCII today, which is exactly why this had to be
# measured rather than assumed: the two cannot be told apart by the data.
#
# The drop granularity was measured too, since //IGNORE's resync is not
# specified anywhere a reader would find it. It is the maximal subpart:
# c3 41 drops one byte and decodes the 41, f0 9f 41 drops TWO and decodes
# the 41. _utf8_next reproduces every case in the fixture.
#-----------------------------------------------------------------------

# _utf8_next($bytes, $i, $len) -> (code point, bytes consumed), or
# (undef, bytes to drop) for a sequence iconv would ignore. Overlongs
# (c0/c1, e0 80, f0 80), UTF-8-encoded surrogates (ed a0) and anything
# above U+10FFFF (f4 90, f5-ff) are all invalid and so all dropped.
sub _utf8_next {
    my ($x, $i, $n) = @_;
    my $c = ord substr($x, $i, 1);
    return ($c, 1) if $c < 0x80;

    # $need continuation bytes, and the range the FIRST of them may take --
    # which is narrower than 80-bf exactly where a wider range would admit
    # an overlong, a surrogate or an out-of-range code point.
    my ($need, $lo, $hi);
    if    ($c >= 0xc2 && $c <= 0xdf) { $need = 1; ($lo, $hi) = (0x80, 0xbf) }
    elsif ($c == 0xe0)               { $need = 2; ($lo, $hi) = (0xa0, 0xbf) }
    elsif ($c == 0xed)               { $need = 2; ($lo, $hi) = (0x80, 0x9f) }
    elsif ($c >= 0xe1 && $c <= 0xef) { $need = 2; ($lo, $hi) = (0x80, 0xbf) }
    elsif ($c == 0xf0)               { $need = 3; ($lo, $hi) = (0x90, 0xbf) }
    elsif ($c == 0xf4)               { $need = 3; ($lo, $hi) = (0x80, 0x8f) }
    elsif ($c >= 0xf1 && $c <= 0xf3) { $need = 3; ($lo, $hi) = (0x80, 0xbf) }
    else                             { return (undef, 1) }   # never a lead

    my $cp  = $c & ($need == 1 ? 0x1f : $need == 2 ? 0x0f : 0x07);
    my $got = 0;
    for my $k (1 .. $need) {
        # Out of input, or a byte outside the range: drop the lead plus the
        # continuation bytes already accepted, and resync on the next byte.
        return (undef, 1 + $got) if $i + $k >= $n;
        my $b = ord substr($x, $i + $k, 1);
        my ($l, $h) = $k == 1 ? ($lo, $hi) : (0x80, 0xbf);
        return (undef, 1 + $got) if $b < $l || $b > $h;
        $cp = ($cp << 6) | ($b & 0x3f);
        $got++;
    }
    return ($cp, 1 + $need);
}

sub _utf16 {
    my ($x, $be) = @_;
    my $out = '';
    my $n   = length $x;
    my $i   = 0;
    while ($i < $n) {
        my ($cp, $used) = _utf8_next($x, $i, $n);
        $i += $used;
        next unless defined $cp;                       # //IGNORE
        # Above the BMP UTF-16 needs a surrogate pair; _utf8_next has
        # already refused every code point that cannot be encoded.
        my @u = $cp <= 0xffff ? ($cp)
              : ( 0xd800 + (($cp - 0x10000) >> 10),
                  0xdc00 + (($cp - 0x10000) & 0x3ff) );
        $out .= pack($be ? 'n*' : 'v*', @u);
    }
    return $out;
}
sub _utf16le { return _utf16($_[0], 0) }
sub _utf16be { return _utf16($_[0], 1) }

# fn_frombase64: transcribed rather than handed to MIME::Base64, which
# discards characters outside the alphabet where hx STOPS at the first one.
# They agree on well-formed input and the corpus is well-formed, but the
# difference is exactly the kind that would surface as one entry disagreeing
# for a reason nobody could see.
my %B64 = do {
    my $a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    map { substr($a, $_, 1) => $_ } 0 .. 63;
};
sub _frombase64 {
    my @in = split //, $_[0];
    my $out = '';
    my $i = 0;
    while ($i + 1 < @in) {
        my $a = $B64{ $in[$i++] };
        my $b = $i < @in ? $B64{ $in[$i++] } : 0;
        my $c = ($i < @in && $in[$i] ne '=') ? $B64{ $in[$i++] } : undef;
        my $d = ($i < @in && $in[$i] ne '=') ? $B64{ $in[$i++] } : undef;
        last if !defined $a || !defined $b;
        $out .= chr((($a << 2) | ($b >> 4)) & 0xff);
        $out .= chr(((($b & 0xf) << 4) | ($c >> 2)) & 0xff) if defined $c;
        $out .= chr(((($c & 0x3) << 6) | $d) & 0xff)        if defined $d;
    }
    return $out;
}

# fn_fromhex: whole pairs only, and a non-hex nibble reads as 0 rather than
# aborting -- which is what hx does, however odd it looks.
sub _fromhex {
    my ($x) = @_;
    my $out = '';
    for my $i (0 .. int(length($x) / 2) - 1) {
        my $pair = substr($x, $i * 2, 2);
        my $hi = index('0123456789abcdef', lc substr($pair, 0, 1));
        my $lo = index('0123456789abcdef', lc substr($pair, 1, 1));
        $hi = 0 if $hi < 0;
        $lo = 0 if $lo < 0;
        $out .= chr(($hi << 4) | $lo);
    }
    return $out;
}

# name => [ sub, min args, max args, { position => 1 } for integer arguments ]
# Argument positions are counted from 1; position 0 is the value operand.
our %OP = (
    upper      => [ \&_upper,      1, 1, {} ],
    lower      => [ \&_lower,      1, 1, {} ],
    rev        => [ \&_rev,        1, 1, {} ],
    hex        => [ \&_hex,        1, 1, {} ],
    base64     => [ \&_base64,     1, 1, {} ],
    frombase64 => [ \&_frombase64, 1, 1, {} ],
    fromhex    => [ \&_fromhex,    1, 1, {} ],
    utf16      => [ \&_utf16le,    1, 1, {} ],
    utf16le    => [ \&_utf16le,    1, 1, {} ],
    utf16be    => [ \&_utf16be,    1, 1, {} ],
    cap        => [ \&_cap,        1, 2, { 1 => 1 } ],
    cut        => [ \&_cut,        2, 3, { 1 => 1, 2 => 1 } ],
    trunc      => [ \&_trunc,      2, 2, { 1 => 1 } ],
    pad        => [ \&_pad,        2, 2, { 1 => 1 } ],
);

sub expr_functions {
    return sort keys %HASH, (map { ("${_}_raw", "${_}_bin") } keys %HASH),
                 keys %OP;
}

sub _tokenize {
    my ($e) = @_;
    my @t;
    while (length $e) {
        $e =~ s/^\s+// and next;
        # An integer literal, optionally negative: cut()'s start can be < 0.
        if ($e =~ s/^(-?[0-9]+)//)              { push @t, [ int  => $1 ]; next }
        if ($e =~ s/^([A-Za-z][A-Za-z0-9_]*)//) { push @t, [ name => $1 ]; next }
        if ($e =~ s/^\$([ps])(?![A-Za-z0-9_])//){ push @t, [ var  => $1 ]; next }
        # A constant reference. Only 1-8 exist; $c9 is not a token john
        # accepts either, so it falls through and bails.
        if ($e =~ s/^\$c([1-8])(?![A-Za-z0-9_])//){ push @t, [ const => $1 ]; next }
        # ':' is punctuation AND an operand. john prints a literal colon
        # inside an expression and elides the concatenation dots around it,
        # so md5(A:B) and md5(A.:.B) are the same string written two ways.
        # See _parse_term and _parse_concat, which is where that is resolved.
        if ($e =~ s/^([().,:])//)               { push @t, [ punc => $1 ]; next }
        return;                                  # a token we do not know: bail
    }
    return \@t;
}

sub _at {
    my ($t, $pos, $kind, $val) = @_;
    return 0 unless $pos->[0] < @$t;
    return 0 unless $t->[ $pos->[0] ][0] eq $kind;
    return 1 unless defined $val;
    return $t->[ $pos->[0] ][1] eq $val;
}

# _parse_concat / _parse_term - return a fragment of PERL SOURCE, or undef.
# $pos is an index into the token list, advanced in place. $const is the
# constant map, threaded through so an unbound $cN can bail where it is
# seen rather than being resolved later, or worse, silently.
# A colon may stand where a '.' would, on either side of itself, because john
# writes md5(A:B) for md5(A . ":" . B). Juxtaposition is permitted ONLY next
# to a colon: $prev_colon gates it, so md5($s$p) is still the syntax error it
# always was and two operands cannot silently run together.
sub _begins_term {
    my ($t, $pos) = @_;
    return 0 unless $pos->[0] < @$t;
    my ($kind) = @{ $t->[ $pos->[0] ] };
    return $kind eq 'var' || $kind eq 'const' || $kind eq 'name' || $kind eq 'int';
}

sub _parse_concat {
    my ($t, $pos, $const) = @_;
    my $left = _parse_term($t, $pos, $const);
    return unless defined $left;
    my $prev_colon = 0;
    while (1) {
        if (_at($t, $pos, punc => '.')) {
            $pos->[0]++;
            my $right = _parse_term($t, $pos, $const);
            return unless defined $right;
            $left = "$left . $right";
            $prev_colon = 0;
        }
        elsif (_at($t, $pos, punc => ':')) {
            my $right = _parse_term($t, $pos, $const);   # consumes the ':'
            return unless defined $right;
            $left = "$left . $right";
            $prev_colon = 1;
        }
        elsif ($prev_colon && _begins_term($t, $pos)) {
            my $right = _parse_term($t, $pos, $const);
            return unless defined $right;
            $left = "$left . $right";
            $prev_colon = 0;
        }
        else { last }
    }
    return $left;
}

# The argument list of a call: each argument is either a bare integer literal
# (only where the function declares that position an integer) or a full
# concatenation. Returns the list of source fragments, or undef.
sub _parse_args {
    my ($t, $pos, $ints, $const) = @_;
    my @arg;
    while (1) {
        my $n = scalar @arg;                 # 0 is the value operand
        if ($ints->{$n} && _at($t, $pos, 'int')) {
            push @arg, $t->[ $pos->[0] ][1] + 0;
            $pos->[0]++;
        }
        else {
            my $a = _parse_concat($t, $pos, $const);
            return unless defined $a;
            push @arg, $a;
        }
        last unless _at($t, $pos, punc => ',');
        $pos->[0]++;
    }
    return \@arg;
}

sub _parse_term {
    my ($t, $pos, $const) = @_;
    return unless $pos->[0] < @$t;
    my ($kind, $val) = @{ $t->[ $pos->[0] ] };

    # A literal colon. It is the only literal in the notation, and it is here
    # because john's --list=subformats prints one: dynamic_1350 is
    # md5(md5($s.$p):$s) and dynamic_35/36 are sha1(uc($u).:.$p) and
    # sha1($u.:.$p). Measured 2026-09-06 against this build's 404 subformat
    # expressions: three carry a colon and nothing else carries any other
    # literal, so this widens the grammar by exactly what john uses and no
    # more. A general string literal is NOT added -- an unquoted literal
    # would make every unknown token look like data instead of bailing, and
    # bailing on the first unknown token is what keeps a wrong expression
    # from proving itself.
    if ($kind eq 'punc' && $val eq ':') {
        $pos->[0]++;
        return "':'";
    }

    if ($kind eq 'var') {
        $pos->[0]++;
        return $val eq 'p' ? '$_[0]' : '$_[1]';
    }
    # A constant. Only the INDEX is written into the source; the bytes stay
    # in the lexical the compiled sub closes over. An index with no value
    # bails, exactly as john's compiler refuses it.
    if ($kind eq 'const') {
        return unless defined $const->{$val};
        $pos->[0]++;
        return "\$C[$val]";
    }
    return unless $kind eq 'name';

    my $name = lc $val;
    # A hash, in either output role. hx spells the raw suffix _bin; this
    # repository spells it _raw. Both resolve to the same primitive.
    my ($table, $key);
    if    ($HASH{$name})                            { $table = \%HASH; $key = $name }
    elsif ($name =~ /^(.+)_(?:raw|bin)$/ && $RAW{$1}) { $table = \%RAW;  $key = $1 }

    if ($table) {
        $pos->[0]++;
        return unless _at($t, $pos, punc => '(');
        $pos->[0]++;
        my $inner = _parse_concat($t, $pos, $const);
        return unless defined $inner;
        return unless _at($t, $pos, punc => ')');   # arity is exactly one
        $pos->[0]++;
        my $which = $table == \%HASH ? 'HASH' : 'RAW';
        return "\$RosettaExpr::${which}{'$key'}->($inner)";
    }

    my $op = $OP{$name} or return;                  # unknown function: bail
    my (undef, $min, $max, $ints) = @$op;
    $pos->[0]++;
    return unless _at($t, $pos, punc => '(');
    $pos->[0]++;
    my $arg = _parse_args($t, $pos, $ints, $const);
    return unless defined $arg;
    return unless _at($t, $pos, punc => ')');
    $pos->[0]++;
    return if @$arg < $min || @$arg > $max;
    # Integer arguments are emitted as literals, so re-check the shape: only
    # a value that came from an 'int' token can reach here, and it has to
    # look like one before it is written into source.
    for my $n (keys %$ints) {
        next unless $n < @$arg;
        return unless $arg->[$n] =~ /^-?[0-9]+$/;
    }
    return "\$RosettaExpr::OP{'$name'}[0]->(" . join(', ', @$arg) . ')';
}

#-----------------------------------------------------------------------
# The constant suffix. See the header for where each rule was read out of
# john's source; the short version is that none of it is guessable.
#-----------------------------------------------------------------------

# _demangle($value) - john's dynamic_Demangle. \\ is a backslash, \xHH is a
# byte (\x00 included -- john measures the length rather than trusting the
# NUL), and a backslash before anything else is KEPT, escape and all.
sub _demangle {
    my ($v) = @_;
    my $out = '';
    my $i   = 0;
    my $n   = length $v;
    while ($i < $n) {
        my $c = substr($v, $i, 1);
        if ($c ne '\\') { $out .= $c; $i++; next }
        $i++;
        if ($i >= $n)                        { $out .= '\\'; last }
        my $d = substr($v, $i, 1);
        if ($d eq '\\')                      { $out .= '\\'; $i++; next }
        if ($d ne 'x')                       { $out .= '\\';       next }
        # \x, and john keeps the whole thing literally unless BOTH digits
        # are there and both are hex.
        my $hh = substr($v, $i + 1, 2);
        if (length($hh) == 2 && $hh =~ /^[0-9A-Fa-f]{2}$/) {
            $out .= chr hex $hh;
            $i += 3;
        }
        else { $out .= '\\'; $i++ }
    }
    return $out;
}

# _split_params($expr) - ($body, \%const), or undef where the suffix is
# present but is not something this module models. An expression with no
# suffix returns an empty map, never undef.
sub _split_params {
    my ($e) = @_;

    # The list starts at the first comma at paren depth ZERO. An unbalanced
    # expression bails here rather than being parsed as a body.
    my ($depth, $cut) = (0, undef);
    for my $i (0 .. length($e) - 1) {
        my $c = substr($e, $i, 1);
        if    ($c eq '(') { $depth++ }
        elsif ($c eq ')') { $depth--; return if $depth < 0 }
        elsif ($c eq ',' && $depth == 0) { $cut = $i; last }
    }
    return ($e, {}) unless defined $cut;
    my $body   = substr($e, 0, $cut);
    my $params = substr($e, $cut + 1);

    # A comma ends a value unless it is backslashed, which is john's rule
    # in get_param() and is the only way a value can contain one.
    my @piece = ('');
    for my $i (0 .. length($params) - 1) {
        my $c = substr($params, $i, 1);
        if ($c eq ',' && ($i == 0 || substr($params, $i - 1, 1) ne '\\')) {
            push @piece, ''; next;
        }
        $piece[-1] .= $c;
    }

    my %const;
    for my $p (@piece) {
        my ($k, $v) = $p =~ /^\s*c([1-8])=(.*)$/s or return;  # only cN=
        return if exists $const{$k};                          # said twice
        return unless length $v;      # john: an empty value is a MISSING one
        $const{$k} = _demangle($v);
    }
    # Packed from c1, because john's scan breaks at the first gap and every
    # constant after it is then unset.
    for my $k (1 .. scalar keys %const) { return unless defined $const{$k} }
    return ($body, \%const);
}

# compile_expression($expression) - a sub($pass, $salt) returning the value
# the expression denotes (lower-case hex for a plain hash, but base64 or raw
# bytes where the expression says so), or undef if any part of the expression
# is outside the vocabulary.
sub compile_expression {
    my ($expr) = @_;
    return unless defined $expr && length $expr;
    my ($src, $const) = _split_params($expr);
    return unless defined $src;
    my $t = _tokenize($src) or return;
    return unless @$t;
    my $pos = [0];
    my $body = _parse_concat($t, $pos, $const);
    return unless defined $body;
    return unless $pos->[0] == @$t;              # trailing junk: bail
    # 1-based, so $C[3] is $c3. The eval closes over this lexical; nothing
    # from the entry file is interpolated into the source.
    my @C;
    $C[$_] = $const->{$_} for keys %$const;
    return scalar eval "sub { $body }";
}

1;
