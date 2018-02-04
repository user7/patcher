package Patcher;

use strict;
use warnings;

use Data::Dumper;
use File::Temp;
use File::Slurp;
use IPC::Run;
use Carp qw/ verbose croak /;

# perl export magic
require Exporter;
our @ISA       = qw/ Exporter /;
our @EXPORT_OK = qw/
    modify_context
    reset_context
    load_config
    add_symbol
    patch
    apply_and_save
    print_patches
    topic
    patch_divert
    patch_divert_all
    tt
    ss
    pp
    /;


sub import {
    warnings->import;
    strict->import;
    utf8->import;
    Patcher->export_to_level(1, @_);
}

#
# ------------------
#  patcher context

our $ctx;


sub reset_context {
    $ctx = {
        settings       => {},
        symbol_offset  => {},
        symbol_section => {},
        section_base   => {},
        section_offset => {},
        patches        => [],
    };

    modify_context(@_);
    return $ctx;
}


sub modify_context {
    _die_args("modify_context", undef, @_);

    while (@_) {
        my ($k, $v) = (shift, shift);
        my $t = $ctx;
        $k = [ split /\s+/, $k ]
            if $k =~ /\s/;
        if (ref($k) eq "ARRAY") {
            $t = $t->{ shift @$k } //= {} while @$k > 1;
            $k = shift @$k;
        }
        $t->{$k} = $v;
    }

    unless (exists $ctx->{input_bytes}) {
        $ctx->{input_bytes} = read_file(
            $ctx->{input_file},
            binmode  => ":raw",
            err_mode => "carp",
        ) if exists $ctx->{input_file};
    }

    return $ctx;
}

reset_context();

#
# ----------------
#  config loader


sub load_config {
    for my $c (@_) {
        croak "file $c not found"
            unless -f $c;

        do $c;
        die if $@;
        die "unable to read $c: $@" if $!;
    }
}

#
# --------------
#  patcher API


sub add_symbol {
    _die_args("add_symbol", undef, @_);
    my %args = @_;
    my ($name, $off, $sec) = ($args{name}, _wrap($args{off}), $args{section});

    if (not defined $sec and $ctx->{settings}{deduce_section}) {
        my $so = $ctx->{section_offset};
        croak "unable to deduce section, section offsets are not given"
            unless $so;
        for my $s (sort keys %{$ctx->{section_offset}}) {
            next if $so->{$s} > $off;
            next if defined $sec and $so->{$s} < $so->{$sec};
            $sec = $s;
        }
    }

    croak "name, section and off are required"
        unless defined $name
        and defined $off
        and defined $sec;
    if (exists $ctx->{symbol_offset}{$name}) {
        return
            if defined $ctx->{symbol_offset}{$name}
            and $ctx->{symbol_offset}{$name} eq $off;
        croak(
            "symbol '$name' is already defined as ",
            ss($ctx->{symbol_offset}{$name})
        );
    }
    $ctx->{symbol_offset}{$name}  = $off;
    $ctx->{symbol_section}{$name} = $sec;
}


sub patch {
    _die_args("patch", undef, @_);
    my $p = {@_};

    $p->{desc} //= $ctx->{settings}{default_desc};

    croak "every patch needs description"
        unless defined $p->{desc} and ref($p->{desc}) eq "";

    _eval_rethrow(sub { _patch($p) }, "when parsing '$p->{desc}'", $p);
}


sub apply_and_save {
    _apply();

    print_patches()
        unless $ctx->{settings}{quiet};

    _save();
}


sub print_patches {
    my $file = shift;
    my $fh;
    if ($file) {
        open $fh, ">", $file
            or croak "unable to open $file: $!";
    } else {
        $fh = *STDOUT{IO};
    }

    for my $p (@{ $ctx->{patches} }) {
        next
            unless defined $p->{pchunk} and length $p->{pchunk}{bytes} > 0;

        my $topic    = defined $p->{topic} ? "$p->{topic} | " : "";
        my $pbin     = $p->{pchunk}{bytes};
        my $lmax     = $ctx->{settings}{truncate_long_dumps} // length $pbin;
        my $b        = substr($pbin, 0, $lmax);
        my $add      = "";
        my $sym_name = find_symbol($p->{poff});
        $sym_name = " ($sym_name)"
            unless $sym_name eq "";
        $add .= "... (" . length($pbin) . " bytes)"
            if length $b < length $pbin;
        printf $fh "applied '%s%s' at %08x%s: %s\n", $topic, $p->{desc},
            $p->{poff},
            $sym_name, _hexdump($b) . $add;
    }

    close $fh
        if $file;
}


sub find_symbol {
    my ($off) = @_;

    my $at_func = "";
    my $nearest_sym;
    my $nearest_sym_off;
    my $ctx_so = $ctx->{symbol_offset};
    for my $sym (sort keys %$ctx_so) {
        my $sym_off = $ctx_so->{$sym};
        next
            if $ctx_so->{$sym} > $off;

        next
            if $sym_off == $off
            and $ctx->{settings}{off_name_enclosing_scope}
            and $sym !~ /^proc_/;

        next
            if defined $nearest_sym and $nearest_sym_off > $sym_off;

        if ($sym_off == $off) {
            return ""
                if $ctx->{settings}{off_name_skip_zero_offsets};

            return "$sym+0";
        }

        $nearest_sym     = $sym;
        $nearest_sym_off = $sym_off;
    }

    return ""
        unless defined $nearest_sym;

    my $d    = $off - $nearest_sym_off;
    my $maxd = $ctx->{settings}{off_name_max_dist};
    return ""
        if defined $maxd and $d > $maxd;

    return "$nearest_sym+$d";
}


sub topic {
    die "topic must be a string or undef"
        unless ref($_[0]) eq "";

    $ctx->{topic} = $_[0];
}


sub patch_divert {
    my ($where, $from, $to) = @_;

    patch(
        off    => $where,
        desc   => "divert $from -> $to",
        cchunk => "#gas# call $from",
        pchunk => "#gas# call $to",
    );
}

# Changes all occurances of 'call old_target' (within the given section) to
# 'call new_target'. Algorithm is simplistic and may produce false positives,
# although unlikely. It also does not track calculated or offset calls. Finally
# it will not affect calls from other patches as all patches are applied at the
# last moment, however diverts produced may overlap-clash with other patches.
sub patch_divert_all {
    my ($old_target, $new_target) = @_;

    return
        unless defined $ctx->{input_bytes};

    my $ot = $ctx->{symbol_offset}{$old_target};
    die "no symbol $old_target exists"
        unless defined $ot;

    die "only .text symbols are supported"
        unless $ctx->{symbol_section}{$old_target} eq ".text";

    my $maxi = 2**32;
    my $off  = $ctx->{section_offset}{".text"};
    my $end  = $ctx->{section_offset}{".data"};
    while ($off + 5 < $end) {
        my ($op, $addr) =
            unpack("CV", substr($ctx->{input_bytes}, $off, 5));

        ++$off, next
            unless $op == 0xe8 and ($addr + $off + 5) % $maxi == $ot;

        patch_divert($off, $old_target, $new_target);
        $off += 5;
    }
}

#
# ------
#  aux


sub _patch {
    my $p = shift;

    my $coff = $p->{coff} // $p->{off};
    if (defined $p->{cchunk}) {
        croak "coff is not defined, cchunk makes no sense"
            unless defined $coff;

        $p->{cchunk} = build_chunk($p->{cchunk});
        croak "empty cchunk makes no sense"
            if length $p->{cchunk}{bytes} == 0;
    } else {
        croak "no cchunk present, specifying coff makes no sense"
            if defined $p->{coff};
    }

    my $poff = $p->{poff} // $p->{off};
    if (defined $p->{pchunk}) {
        croak "no poff when both cchunk and pchunk are present"
            if not defined $poff and defined $p->{cchunk};

        $p->{pchunk} = build_chunk($p->{pchunk});
    } else {
        croak "no cchunk or pchunk, nothing to do"
            unless defined $p->{cchunk};

        croak "no pchunk present, specifying poff makes no sense"
            if defined $p->{poff};

        if ($p->{fill_nop}) {
            $p->{pchunk} = build_chunk("");
            $poff = $coff;
        }
    }

    if (defined $p->{pchunk} and defined $p->{cchunk}) {
        croak "cchunk starts after pchunk (pchunk is not covered)"
            if $poff < $coff;

        croak "cchunk ends before pchunk (pchunk is not covered)"
            if $coff + length $p->{cchunk}{bytes} <
            $poff + length $p->{pchunk}{bytes};
    }

    if ($p->{fill_nop}) {
        croak "no cchunk present, fill_nop makes no sense"
            unless defined $p->{cchunk};

        my $d =
            ($coff + length $p->{cchunk}{bytes}) -
            ($poff + length $p->{pchunk}{bytes});

        $p->{pchunk}{bytes} .= pack("H*", "90") x $d
            if $d > 0;
    }

    $p->{coff} = $coff if defined $p->{cchunk};
    $p->{poff} = $poff if defined $p->{pchunk};

    if (defined $p->{topic}) {
        $ctx->{topic} = $p->{topic};
    } else {
        $p->{topic} = $ctx->{topic}
            if defined $ctx->{topic};
    }

    push(@{$ctx->{patches}}, $p);
}


sub _place_patch {
    my $p = shift;
    return
        if defined $p->{poff};    # already placed

    return
        unless defined $p->{pchunk};    # pure check patch

    croak "unable to place, pspace_off is not defined"
        unless defined $ctx->{pspace_off};

    croak "unable to place, pspace_len is not defined"
        unless defined $ctx->{pspace_len};

    my $off = $ctx->{pspace_off};
    $off += -$off % ($p->{pchunk}{align} // 1);

    my $len = $off - $ctx->{pspace_off} + length $p->{pchunk}{bytes};

    croak "no free patch space left for patch"
        if $ctx->{pspace_len} < $len;

    $ctx->{pspace_off} += $len;
    $ctx->{pspace_len} -= $len;
    $p->{poff} = $off;
}


sub _add_symbols {

    # add symbols and check clashes
    my %src_patch_id;
    for (my $i = 0 ; $i < @{ $ctx->{patches} } ; ++$i) {
        my $p = $ctx->{patches}[$i];
        next
            unless exists $p->{pchunk} and exists $p->{pchunk}{globals};
        my $gg = $p->{pchunk}{globals};
        for my $g (sort keys %$gg) {
            my $old_id = $src_patch_id{$g};
            croak(    "multiple definitions of $g: "
                    . "in patch '$p->{desc}' and "
                    . "in patch '$ctx->{patches}[$old_id]{desc}'")
                if defined $old_id;

            $src_patch_id{$g} = $i;
            add_symbol(
                off     => $p->{poff} + $gg->{$g},
                name    => $g,
                section => ".text"
            );
        }
    }

    # check all symbols available
    for my $p (@{ $ctx->{patches} }) {
        next unless defined $p->{pchunk};
        for my $link ($p->{pchunk}{link_abs}, $p->{pchunk}{link_rel}) {
            next unless defined $link;
            for my $s (sort { $a <=> $b } keys %$link) {
                my ($sym, $delta) = _split_sym($link->{$s});
                croak "patch '$p->{desc}' references undefined symbol $sym"
                    unless exists $ctx->{symbol_offset}{$sym};
            }
        }
    }
}


sub _add_relocator_dummy {
    return
        unless defined $ctx->{settings}{relocator};

    # will be placed according to alignment
    my $re_patch = {
        desc   => "add dummy $ctx->{settings}{relocator}",
        pchunk => {
            bytes   => "",
            globals => { $ctx->{settings}{relocator} => 0 },
        }
    };
    push(@{$ctx->{patches}}, $re_patch);
    return $re_patch;
}


sub _add_relocator {
    my $rname = $ctx->{settings}{relocator};
    return
        unless defined $rname;

    croak "unable to produce relocator without data_bootstrap_ptr"
        unless defined $ctx->{data_bootstrap_ptr};

    croak "unable to produce relocator without data_bootstrap_var"
        unless defined $ctx->{data_bootstrap_var};

    my %sec_offset;
    $sec_offset{$_} = $ctx->{section_offset}{$_} // 0 for (qw/ .text .data /);

    my %relocs = (
        ".text" => "",
        ".data" => "",
    );
    my $text_relocs = "";
    my $data_relocs = "";
    for my $o (sort { $a <=> $b } keys %{$ctx->{relocs}}) {
        my $n = $ctx->{relocs}{$o};
        my ($sym, $delta) = _split_sym($n);
        my $sec      = $ctx->{symbol_section}{$sym};
        my $var_dsec = $ctx->{symbol_offset}{$sym} - $sec_offset{$sec} + $delta;
        my $rel_dsec = $o - $sec_offset{".text"};
        my $item     = sprintf("       .int 0x%x, 0x%x\n",
            _wrap($rel_dsec), _wrap($var_dsec));

        # print "# reloc $sec $n: $item" if $sec eq ".data";
        $relocs{$sec} .= $item;
    }

    croak "no symbol $rname defined"
        unless defined $ctx->{symbol_offset}{$rname};

    my $relocator_dsec = $ctx->{symbol_offset}{$rname} - $sec_offset{".text"};
    my $bootstrap_ptr_dsec = $ctx->{data_bootstrap_ptr} - $sec_offset{".text"};
    my $bootstrap_var_dsec = $ctx->{data_bootstrap_var} - $sec_offset{".data"};

    my $chunk = gas("
        start:
            push    eax
            push    ebx
            push    ecx
            push    edx
            push    esi
            push    edi
            push    ebp
            call    get_retaddr

        retaddr:
            lea     esi, [ eax - (retaddr - start) ]

            lea     eax, [ esi + (relocs_text - start) ]
            lea     ebx, [ esi + (relocs_data - start) ]
            lea     ecx, [ esi - $relocator_dsec ]
            mov     edx, ecx
            call    apply_table

            mov     eax, ebx
            lea     ebx, [ esi + (relocs_data_end - start) ]
            mov     edx, [ esi - $relocator_dsec + $bootstrap_ptr_dsec ]
            sub     edx, $bootstrap_var_dsec
            call    apply_table

            pop     ebp
            pop     edi
            pop     esi
            pop     edx
            pop     ecx
            pop     ebx
            pop     eax
            ret

        apply_table_loop:
            mov     edi, [ eax ]
            mov     ebp, [ eax + 4 ]
            add     ebp, edx
            mov     [ edi + ecx ], ebp
            add     eax, 8
        apply_table:
            cmp     eax, ebx
            jl      apply_table_loop
            ret

        get_retaddr:
            mov     eax, [ esp ]
            ret

        relocs_text:
" . $relocs{".text"} . "
        relocs_data:
" . $relocs{".data"} . "
        relocs_data_end:
    ");

    patch(desc => "add $rname", pchunk => $chunk, symbol => $rname);
    _place_patch($ctx->{patches}[-1]);
}


sub _apply_patch {
    my $p = shift;

    my $cbytes;
    my $coff = $p->{coff};
    if (defined $p->{cchunk}) {
        $cbytes = $p->{cchunk}{bytes};
        if (defined $ctx->{input_bytes}) {
            croak "attempt to check range [$coff, "
                . ($coff - 1 + length $cbytes)
                . "] not inside source file ("
                . length($ctx->{input_bytes})
                . " bytes)"
                unless $coff + length $cbytes <= length $ctx->{input_bytes};

            my $got = substr($ctx->{input_bytes}, $coff, length $cbytes);
            croak "check failed: check chunk is missing,\n"
                . " expected: "
                . _hexdump($cbytes) . "\n"
                . "      got: "
                . _hexdump($got) . "\n"
                unless $got eq $cbytes;
        }
    }

    if (defined $p->{pchunk}) {
        my $poff   = $p->{poff};
        my $pbytes = $p->{pchunk}{bytes};

        if (defined $ctx->{input_bytes}) {
            croak "attempt to patch range [$poff, "
                . ($poff - 1 + length $pbytes)
                . "] outside source file ("
                . length($ctx->{input_bytes})
                . " bytes)"
                if $poff + length $pbytes > length $ctx->{input_bytes};
        }

        $p->{pchunk}{bytes} = $pbytes;
        substr($ctx->{input_bytes}, $poff, length $pbytes) = $pbytes
            if defined $ctx->{input_bytes};
    }
}


sub _apply {
    _add_relocator_dummy();

    for my $p (@{ $ctx->{patches} }) {
        _eval_rethrow(
            sub {
                _place_patch($p);
                add_symbol(
                    off     => $p->{poff},
                    name    => $p->{name},
                    section => ".text"
                ) if defined $p->{name} and defined $p->{poff};
            },
            "_place_patch",
            $p
        );
    }

    _add_symbols();

    add_symbol(
        off     => 0,
        name    => ".text",
        section => ".text",
    );
    $ctx->{relocs} //= {};
    for my $p (@{ $ctx->{patches} }) {
        _eval_rethrow(sub { _link_chunk($p->{cchunk}, $p->{coff}) },
            "link cchunk", $p);

        _eval_rethrow(sub { _link_chunk($p->{pchunk}, $p->{poff}) },
            "link pchunk", $p);
    }

    _add_relocator();

    my @pp = grep { defined $_->{poff} and length $_->{pchunk}{bytes} > 0 }
        @{ $ctx->{patches} };
    @pp = sort { $a->{poff} <=> $b->{poff} } @pp;
    for (my $i = 1 ; $i < @pp ; ++$i) {
        my $prev = $pp[ $i - 1 ];
        my $cur  = $pp[$i];
        croak "patches $prev->{desc} and $cur->{desc} intersect"
            if $prev->{poff} + length $prev->{pchunk}{bytes} > $cur->{poff};
    }

    for my $p (@{ $ctx->{patches} }) {
        _eval_rethrow(sub { _apply_patch($p) }, "_apply_patch", $p);
    }
}


sub _split_sym {
    my $n = shift;
    my ($sym, $delta) = ($n, 0);
    $sym = $1, $delta = $2
        if $n =~ /^([^-+]*)([-+][0-9]+)$/;
    return ($sym, $delta);
}

# this is optional, returns 0 unless both section_base and section_offset are present
sub _adjust_seg {
    my $sym   = shift;
    my $sec   = defined $sym ? $ctx->{symbol_section}{$sym} : ".text";
    my $sbase = $ctx->{section_base}{$sec};
    my $soff  = $ctx->{section_offset}{$sec};
    return 0
        unless defined $sbase and defined $soff;

    return -$soff + $sbase;    # addition to convert executable offset to memory
}


sub _link_chunk {
    my ($c, $off) = @_;

    if ($c->{globals} && %{ $c->{globals} }) {
        croak "offset is required for exporting globals"
            unless defined $off;

        for my $g (sort keys %{$c->{globals}}) {
            add_symbol(
                off     => $c->{globals}{$g} + $off,
                name    => $g,
                section => ".text",
            );
        }
    }

    if ($c->{link_rel} && %{ $c->{link_rel} }) {
        croak "offset is required for location linking"
            unless defined $off;

        for my $o (sort { $a <=> $b } keys %{$c->{link_rel}}) {
            my $n = $c->{link_rel}{$o};
            my ($sym, $delta) = _split_sym($n);

            croak "location $n is not defined when linking"
                unless exists $ctx->{symbol_offset}{$sym};

            croak "unimplemented: linking code with .data section"
                if $ctx->{symbol_section}{$sym} ne ".text";

            substr($c->{bytes}, $o, 4) =
                pack("V", $ctx->{symbol_offset}{$sym} + $delta - ($off + $o));
        }
    }

    if ($c->{link_abs} && %{ $c->{link_abs} }) {
        croak "offset is required for variable linking"
            unless defined $off;

        for my $o (sort { $a <=> $b } keys %{$c->{link_abs}}) {
            my $n = $c->{link_abs}{$o};
            my ($sym, $delta) = _split_sym($n);

            croak "symbol '$sym' is not defined"
                unless exists $ctx->{symbol_offset}{$sym};

            $ctx->{relocs}{ $o + $off } = $n;

            substr($c->{bytes}, $o, 4) = pack("V",
                $ctx->{symbol_offset}{$sym} + _adjust_seg($sym) + $delta);
        }
    }

    if ($c->{link_self} && %{ $c->{link_self} }) {
        croak "offset is required for self linking"
            unless defined $off;

        while (my ($o, $delta) = each %{$c->{link_self}}) {
            my $var = $off + $delta;
            $var = "+$var"
                if $var >= 0;
            my $symb = ".text" . $var;

            $ctx->{relocs}{ $o + $off } = $symb;

            substr($c->{bytes}, $o, 4) =
                pack("V", $off + _adjust_seg() + $delta);
        }
    }
}


sub _save {
    if ($ctx->{output_file}) {
        croak "error saving $ctx->{output_file}: nothing got patched\n"
            unless $ctx->{input_bytes};
        write_file(
            $ctx->{output_file},
            {
                binmode  => ":raw",
                err_mode => "carp",
            },
            $ctx->{input_bytes}
        );
        print "updated $ctx->{output_file}\n";
    }
}


sub _wrap {
    my $n = shift;

    croak "integer expected, got " . tt($n)
        unless defined $n
        and ref($n) eq ""
        and $n =~ /^[-+]?\d+/;

    my $bits = $ctx->{settings}{arch_bits} // 32;
    return $n % (2**$bits);
}


sub tt {
    return Data::Dumper->new(\@_)->Indent(0)->Terse(1)->Sortkeys(1)->Dump;
}


sub ss {
    return Data::Dumper->new(\@_)->Indent(1)->Terse(1)->Sortkeys(1)->Dump;
}


sub pp {
    print ss(\@_);
}


sub _die_args {
    my ($func, $arg_template, @args) = @_;
    croak "$func requires even number of arguments"
        if @args % 2 == 1;

    # TODO arg template
}


sub _hexdump {
    my $s = unpack("H*", shift);
    $s =~ s/../$& /g;
    return $s;
}


sub _pack_hex {
    my ($xbytes) = @_;

    croak "error: bad symbols in hex dump: $1"
        if $xbytes =~ /([^0-9a-fA-F\s].*)$/;

    $xbytes =~ s/\s//g;
    croak "error: odd number of symbols in hex dump: $xbytes"
        if length($xbytes) % 2;

    return pack("H*", $xbytes);
}


sub _unpack_delta {
    my ($bytes, $roff) = @_;
    my $d = unpack("V", substr($bytes, $roff, 4));
    $d -= 2**32
        if $d >= 2**31;
    return $d == 0 ? "" : $d > 0 ? "+$d" : $d;
}


sub _parse_objdump {
    my $out = shift;

    my %salign;
    my %sbytes;
    my %ssize;
    my @sseq;

    # section list
    my ($sections) = $out =~ /^Sections:\nIdx.*\n((?: .*\n)*)/m;
    for my $sline (split /\n/, $sections) {
        my @items = split /\s+/, $sline;
        my ($sname, $ssize, $salign) = @items[ 2, 3, 7 ];

        next unless $sname =~ /text|data|bss|slt/;

        $salign{$sname} =
            $ctx->{settings}{honor_alignment}
            ? 2**($salign =~ s/^2\*\*//r)
            : 1;
        $ssize{$sname}  = hex $ssize;
        $sbytes{$sname} = "";

        push(@sseq, $sname);
    }

    # sections contents
    my @contents = $out =~ /(^Contents of section.*:\n(?: [0-9a-f].*\n)*)/mg;
    for my $c (@contents) {
        my ($cheader, @clines) = split /\n/, $c;
        croak "bad contents section header: $cheader"
            unless $cheader =~ /^Contents of section (.*):$/;
        my $sname = $1;

        next
            unless exists $sbytes{$sname};

        for my $cline (@clines) {
            croak "bad line: $cline"
                unless $cline =~
                /^ ([0-9a-f]+) ((?:(?:[0-9a-f]{2}){1,4} ){1,4}) .*/;
            my ($off, $xbytes) = ($1, $2);
            croak "parse error, offset does not match bytes count at $off: $c"
                unless hex $off == length $sbytes{$sname};
            $sbytes{$sname} .= _pack_hex($xbytes);
        }
    }

    # building chunk body
    my $bytes     = "";
    my $max_align = 1;
    my %soff;
    for my $sname (@sseq) {
        $max_align = $salign{$sname}
            if $salign{$sname} > $max_align;

        my $off = length($bytes);

        $sbytes{$sname} = "\0" x $ssize{$sname}
            if $sname eq ".bss";

        croak "section size $ssize{$sname} does not match binary chunk size "
            . length($sbytes{$sname})
            unless $ssize{$sname} eq length($sbytes{$sname});

        # empty section does not need to be aligned
        $soff{$sname} = $off, next
            if $sbytes{$sname} eq "";

        my $npad = -$off % $salign{$sname};
        $bytes .= "\0" x $npad . $sbytes{$sname};
        $soff{$sname} = $off + $npad;
    }

    # extracting globals
    my ($symbols) = $out =~ /^SYMBOL TABLE:\n((?:[0-9a-f].*\n)*)/m;
    my %globals;
    for my $sl (split /\n/, $symbols) {
        my ($off, $sname, $sym) = $sl =~ /^([0-9a-f]+) g.{7}(\S+)\s+\S+\s+(.*)/;
        next unless defined $sym;
        croak "unknown section $sname referenced: $symbols "
            unless exists $soff{$sname};
        $globals{$sym} = $soff{$sname} + hex($off);
    }

    # extracting relocations
    my @relocs =
        $out =~ /(^RELOCATION RECORDS FOR .*:\nOFFSET.*\n(?:[0-9a-f].*\n)*)/mg;
    my %link_rel;
    my %link_abs;
    my %link_self;
    for my $r (@relocs) {
        croak "bad relocation listing: $r"
            unless $r =~ /^RELOCATION RECORDS FOR \[(.*)\]:\n.*\n((?:.*\n)*)$/;
        my ($sname, $rlist) = ($1, $2);
        next unless exists $sbytes{$sname};

        for my $rline (split /\n/, $rlist) {
            croak "bad relocation line: $rline"
                unless $rline =~ /^([0-9a-f]+) (\S+) +(.*)$/;
            my ($roff, $rtype, $symb) = (hex($1) + $soff{$sname}, $2, $3);

            croak "relocation mentions unknown section $symb: $rline"
                if $symb =~ /^\./ and not exists $soff{$symb};

            if ($rtype eq "R_386_32") {
                if ($symb =~ /^\./) {

                    # offset from section boundary is embedded into instruction
                    $link_self{$roff} =
                        unpack("V", substr($bytes, $roff, 4)) + $soff{$symb};
                    next;
                }

                $link_abs{$roff} = $symb . _unpack_delta($bytes, $roff);
                next;
            }

            if ($rtype eq "R_386_PC32") {
                if ($symb =~ /^\./) {

                    # offset from section boundary is embedded into instruction
                    my $eo = unpack("V", substr($bytes, $roff, 4));
                    substr($bytes, $roff, 4) =
                        pack("V", $eo + $soff{$symb} - $roff);
                    next;
                }

                $link_rel{$roff} = $symb . _unpack_delta($bytes, $roff);
                next;
            }
            croak "unknown reloc type $rtype";
        }
    }

    my $res = {
        bytes     => $bytes,
        align     => $max_align,
        globals   => \%globals,
        link_rel  => \%link_rel,
        link_abs  => \%link_abs,
        link_self => \%link_self,
    };

    $res->{sections} = \%soff
        if $ctx->{settings}{need_sections};

    return $res;
}


sub _objdump {
    my ($objf) = @_;

    my ($out, $err);
    IPC::Run::run [ qw/ objdump -sxw /, $objf ], ">", \$out, "2>", \$err
        or croak "objdump error: $err";

    my $res =
        _eval_rethrow(sub { _parse_objdump($out); }, "_parse_objdump", $out);

    $res->{objdump} = $out
        if $ctx->{settings}{need_objdump};

    if ($ctx->{settings}{need_listing}) {
        IPC::Run::run [ qw/ objdump -dr -Mintel /, $objf ], ">", \$out,
            "2>", \$err
            or croak "objdump error: $err";
        $res->{listing} = $out;
    }

    return $res;
}


sub _croak_source {
    my ($where, $code, $out) = @_;
    my $i = 1;
    $code =~ s/^/$i++." "/meg;
    croak "$where\n$code\nerror was:$out\n";
}


sub gcc {
    my ($code, @opts) = @_;

    croak "scalar with C code expected, got ", tt($code)
        unless defined $code and ref($code) eq "";

    my $out;
    my $tmpf = File::Temp->new(TEMPLATE => "bp-gcc-XXXXX");

    IPC::Run::run [
        qw/ gcc -xc -m32 -fno-asynchronous-unwind-tables -march=i386 -ffreestanding /,
        @opts,
        qw/ -c - -o /,
        $tmpf,
        ],
        "<", \$code, "&>", \$out
        or _croak_source("when compiling:", $code, $out);

    return _objdump($tmpf);
}


sub gas {
    my ($code, @opts) = @_;

    croak "scalar with assembly listing expected, got ", tt($code)
        unless defined $code and ref($code) eq "";

    # use intel syntax by default
    $code = ".intel_syntax noprefix\n$code"
        unless $code =~ /att_syntax/s;

    my $tmpf = File::Temp->new(TEMPLATE => "bp-as-XXXXX");
    my $out;
    IPC::Run::run [ qw/ as --32 -march=i386 /, @opts, "-o", $tmpf ], "<",
        \$code, "&>", \$out
        or _croak_source("when assembling:", $code, $out);

    return _objdump($tmpf);
}


sub build_chunk {
    my ($c) = @_;

    croak "undef chunk to build"
        unless defined $c;

    my $node = $c;
    if (ref($c) eq "") {
        if ($c =~ /^#([^#]*)#(.*)$/s) {
            my ($header, $source) = ($1, $2);
            my ($format, @opts) = split(/\s+/, $header);

            $node = {
                format => $format // "",
                opts   => \@opts,
                source => $source
            };
        } else {
            $node = { format => "hex", source => $c };
        }
    }

    return $node
        if defined $node->{bytes};

    croak "no bytes and bad source: ", tt($node->{source})
        unless defined $node->{source} and ref($node->{source}) eq "";

    croak "bad format field: ", tt($node->{format})
        unless defined $node->{format} and ref($node->{format}) eq "";

    $node->{bytes} = _pack_hex($node->{source}), return $node
        if $node->{format} eq "hex";

    $node->{bytes} = $node->{source}, return $node
        if $node->{format} eq "";

    return { %$node, %{ gas($node->{source}, @{ $node->{opts} }) } }
        if $node->{format} eq "gas";

    return { %$node, %{ gcc($node->{source}, @{ $node->{opts} }) } }
        if $node->{format} eq "gcc";

    croak "unknown format $node->{format}";
}


sub _eval_rethrow {
    my ($func, $where, @info) = @_;
    my $res = eval { $func->(); };

    return $res
        unless $@;

    my $inf = ss(@info);
    $inf =~ s/^/    /m;

    die "$where, args were:\n$inf\n  error: $@";
}

1;
