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
        settings              => {},
        symbol_offset         => {},
        symbol_section        => {},
        section_offset        => {},
        section_length        => {},
        section_base          => {},
        section_source        => {},
        section_pspace_offset => {},
        section_pspace_length => {},
        source_bytes          => {},
        source_input_file     => {},
        source_output_file    => {},
        patches               => [],
        reloc_rel             => {},
        reloc_abs             => {},
    };

    modify_context(@_);
    return $ctx;
}

sub _die_args;


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

    for my $src (sort keys %{$ctx->{source_input_file}}) {
        my $f = $ctx->{source_input_file}{$src};
        next if defined $ctx->{source_bytes}{$src};
        $ctx->{source_bytes}{$src} = read_file(
            $f,
            binmode  => ":raw",
            err_mode => "carp",
        );
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
    my $s = {@_};

    _eval_rethrow(sub { _add_symbol($s) }, "when adding '$s->{name}'", $s);
}


sub patch {
    _die_args("patch", undef, @_);
    my $p = {@_};

    $p->{desc} //= $ctx->{settings}{default_desc};

    croak "desc is required"
        unless defined $p->{desc} and ref($p->{desc}) eq "";

    _eval_rethrow(sub { _patch($p) }, "when parsing '$p->{desc}'", $p);
}


sub apply_and_save {
    _prepare_patches();
    _apply_patches();

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
        my $sym_name = find_symbol($p->{off_section}, $p->{section});
        $sym_name = " ($sym_name)"
            unless $sym_name eq "";
        my $at;
        $at //= sprintf("%s %08x", $p->{source}, $p->{off_source})
            if defined $p->{source} and defined $p->{off_source};
        $at //= sprintf("%s %08x", $p->{section}, $p->{off_section})
            if defined $p->{off_section} and defined $p->{off_section};
        $at //= sprintf("??? %08x", $p->{off})
            if defined $p->{off};
        $at //= "";

        my $add = "";
        $add .= "... (" . length($pbin) . " bytes)"
            if length $b < length $pbin;
        printf $fh "patch %s '%s%s'%s: %s\n", $at, $topic, $p->{desc},
            $sym_name, _hexdump($b) . $add;
    }

    close $fh
        if $file;
}


sub find_symbol {
    my ($off, $sec) = @_;
    unless (defined $sec) {
        my $o = { off => $off };
        _update_offsets($o);
        ($off, $sec) = ($o->{off_section}, $o->{section});
    }
    return "" unless defined $off and defined $sec;

    my $nearest_sym;
    my $nearest_sym_off;
    for my $sym (sort keys %{$ctx->{symbol_offset}}) {
        next
            unless defined $ctx->{symbol_section}{$sym}
            and $ctx->{symbol_section}{$sym} eq $sec;

        my $sym_off = $ctx->{symbol_offset}{$sym};
        next if $ctx->{symbol_offset}{$sym} > $off;

        next
            if $sym_off == $off
            and $ctx->{settings}{off_name_enclosing_scope}
            and $sym !~ /^proc_/;

        next
            if defined $nearest_sym and $nearest_sym_off > $sym_off;

        if ($sym_off == $off) {
            next
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
    my ($sec, $old_target, $new_target) = @_;
    return unless _check_filter({ topic => $ctx->{topic} // "" });

    croak "unknown section or not bound to source"
        unless defined $sec and defined $ctx->{section_source}{$sec};
    my $src = $ctx->{section_source}{$sec};
    croak "no source for section $sec"
        unless defined $ctx->{source_bytes}{$src};
    my $bytes = \$ctx->{source_bytes}{$src};

    my $soff = $ctx->{section_offset}{$sec};
    my $slen = $ctx->{section_length}{$sec};
    croak "no offset or length for section"
        unless defined $soff and defined $slen;

    my $ot = $ctx->{symbol_offset}{$old_target};
    croak "no symbol $old_target exists"
        unless defined $ot;

    croak "symbol section does not match $sec"
        unless $ctx->{symbol_section}{$old_target} eq $sec;

    my $maxi = 2**32;
    my $off  = $soff;
    my $end  = $soff + $slen;
    while ($off + 5 <= $end) {
        my ($op, $addr) =
            unpack("CV", substr($$bytes, $off, 5));

        ++$off, next
            unless $op == 0xe8 and ($addr + $off + 5 - $soff) % $maxi == $ot;

        patch_divert($off, $old_target, $new_target);
        $off += 5;
    }
}

#
# ------
#  aux

# convert file offset to section-based if possible
sub _update_offsets {
    my $o   = shift;
    my $sec = $o->{section};
    my $off = $o->{off};
    return if not defined $sec and not defined $off;

    unless (defined $sec) {
        if ($ctx->{settings}{deduce_section}) {

            # deduce section if possible
            for my $s (sort keys %{$ctx->{section_offset}}) {
                my $soff = $ctx->{section_offset}{$s};
                my $slen = $ctx->{section_length}{$s};
                my $ssrc = $ctx->{section_source}{$s};

                # sections not bound to source
                next unless defined $ssrc;

                # bound to another source
                next if defined $o->{source} and $ssrc ne $o->{source};
                next if $soff > $off;
                next if defined $slen        and $off - $soff > $slen;
                croak "sections $s and $sec both match offset $off"
                    if defined $sec;
                $sec = $s;
            }
            if (defined $sec) {
                $o->{section} = $sec;
                croak "section $sec has no offset"
                    unless defined $ctx->{section_offset}{$sec};
                my $so = $off - $ctx->{section_offset}{$sec};
                croak "off_section is being redefined"
                    if defined $o->{off_section} and $o->{off_section} != $so;
                $o->{off_section} = $so;
            }
        }
    }

    if (defined($sec) and defined($off) and not defined($o->{off_section})) {
        my $slen = $ctx->{section_length}{$sec};
        croak "offset $off is too large for section $sec"
            if defined $slen and $off > $slen;
        $o->{off_section} = $off;
    }

    unless (defined $o->{source}) {
        if (defined $sec) {
            my $src = $ctx->{section_source}{$sec};
            if (defined $src) {

                # croak "no source for section $sec"
                #    unless defined $src;

                $o->{source} = $src;
                if (defined $o->{off_section}) {
                    croak "section $sec has no offset"
                        unless defined $ctx->{section_offset}{$sec};
                    $o->{off_source} =
                        $o->{off_section} + $ctx->{section_offset}{$sec};
                }
            }
        } else {
            if (defined $ctx->{default_source}) {
                $o->{source}     = $ctx->{default_source};
                $o->{off_source} = $off
                    if defined $off;
            }
        }
    }
}


sub _add_symbol {
    my $s = shift;
    my $n = $s->{name};
    croak "name is required"
        unless defined $n;
    _update_offsets($s);
    croak "section was not specified or deduced"
        unless defined $s->{section};
    croak "off was not specified"
        unless defined $s->{off};
    if (exists $ctx->{symbol_offset}{$n}) {
        return
            if defined $ctx->{symbol_offset}{$n}
            and $ctx->{symbol_offset}{$n} eq $s->{off};
        croak
            "symbol $n is already defined at $ctx->{symbol_offset}{$n} != $s->{off}";
    }
    $ctx->{symbol_offset}{$n}  = $s->{off_section};
    $ctx->{symbol_section}{$n} = $s->{section};
}


sub _check_filter {
    my $p      = shift;
    my $filter = $ctx->{settings}{patch_filter};
    return 1 unless defined $filter;
    if (ref($filter) eq "Regexp") {
        return 1 if ($p->{topic} // "") =~ $filter;
    } else {
        croak "unsupported filter type '" . ref($filter) . "'";
    }
}


sub _patch {
    my $p = shift;
    _update_offsets($p);
    if (defined $p->{cchunk}) {
        croak "off is not defined, cchunk makes no sense"
            unless defined $p->{off};

        $p->{cchunk} = build_chunk($p->{cchunk});
        croak "empty cchunk makes no sense"
            if length $p->{cchunk}{bytes} == 0;
    } else {
        croak "no cchunk or pchunk, nothing to do"
            unless defined $p->{pchunk};
    }

    if (defined $p->{pchunk}) {
        $p->{pchunk} = build_chunk($p->{pchunk});
    } else {
        $p->{pchunk} = build_chunk("")
            if $p->{fill_nop};
    }

    if (defined $p->{pchunk} and defined $p->{cchunk}) {
        croak "cchunk ends before pchunk (pchunk is not covered)"
            if length($p->{cchunk}{bytes}) < length($p->{pchunk}{bytes});
    }

    if ($p->{fill_nop}) {
        croak "no cchunk present, fill_nop makes no sense"
            unless defined $p->{cchunk};

        my $d = length($p->{cchunk}{bytes}) - length($p->{pchunk}{bytes});
        $p->{pchunk}{bytes} .= pack("H*", "90") x $d
            if $d > 0;
    }

    # TODO whole 'topic' thing is messy and needs refactoring,
    # make them independent, make them store docs
    if (defined $p->{topic}) {
        $ctx->{topic} = $p->{topic};
    } else {
        $p->{topic} = $ctx->{topic}
            if defined $ctx->{topic};
    }
    return unless _check_filter($p);

    push(@{$ctx->{patches}}, $p);
}


sub _place_patch {
    my $p = shift;
    return
        if defined $p->{off_source};    # already placed

    return
        unless defined $p->{pchunk};    # pure check patch

    croak "unable to place patch without section"
        unless defined $p->{section};

    my $pspace_off = $ctx->{section_pspace_offset}{ $p->{section} };
    croak "unable to place '$p->{desc}', no pspace for $p->{section}"
        unless defined $pspace_off;
    my $pspace_len = $ctx->{section_pspace_length}{ $p->{section} };

    my $align = -$pspace_off % ($p->{pchunk}{align} // 1);
    my $len = $align + length $p->{pchunk}{bytes};

    croak "no free patch space left for patch"
        if defined $pspace_len and $pspace_len < $len;

    my $sec_off = $ctx->{section_offset}{ $p->{section} };
    my $sec_src = $ctx->{section_source}{ $p->{section} };
    croak "section $p->{section} has no offset or source"
        unless defined $sec_off and defined $sec_src;

    $p->{off_section} = $pspace_off + $align;
    $p->{off_source}  = $p->{off_section} + $sec_off;
    $p->{off}         = $p->{off_source};
    $p->{source}      = $sec_src;

    $ctx->{section_pspace_offset}{ $p->{section} } += $len;
    $ctx->{section_pspace_length}{ $p->{section} } -= $len
        if defined $pspace_len;
}


sub _add_symbols {

    # add symbols and check clashes
    my %src_patch_id;
    for (my $i = 0 ; $i < @{ $ctx->{patches} } ; ++$i) {
        my $p = $ctx->{patches}[$i];
        next unless exists $p->{pchunk} and exists $p->{pchunk}{globals};
        my $gg = $p->{pchunk}{globals};
        for my $g (sort keys %$gg) {
            my $old_id = $src_patch_id{$g};
            croak(    "multiple definitions of $g: "
                    . "in patch '$p->{desc}' and "
                    . "in patch '$ctx->{patches}[$old_id]{desc}'")
                if defined $old_id;

            $src_patch_id{$g} = $i;
            add_symbol(
                off     => $p->{off_section} + $gg->{$g},
                name    => $g,
                section => $p->{section}
            );
        }
    }

    for my $s (sort keys %{$ctx->{section_offset}}) {
        add_symbol(
            off     => 0,
            name    => $s,
            section => $s,
        );
    }
}


sub _produce_reloc_chunk {
    my %ss;
    my $i = 0;
    $ss{$_} = $i++ for sort keys %{$ctx->{section_offset}};
    my $chunk = "";
    for my $type (qw/ reloc_abs reloc_rel /) {
        my $is_rel = $type eq "reloc_rel";
        for my $src_seg (sort keys %{$ctx->{$type}}) {
            my $offs        = $ctx->{$type}{$src_seg};
            my $src_seg_num = $ss{$src_seg};
            croak "unknown section $src_seg"
                unless defined $src_seg_num;

            for my $src_off (sort { $a <=> $b } keys %$offs) {
                my $dst_ref = $offs->{$src_off};
                my ($dst_sym, $dst_delta) = _split_ref($dst_ref);
                croak "unable to extract symbol from ref $dst_ref"
                    unless defined $dst_sym;

                my $dst_seg = $ctx->{symbol_section}{$dst_sym};
                croak "no section for $dst_ref"
                    unless defined $dst_seg;

                my $dst_seg_num = $ss{$dst_seg};
                croak "unknown section $dst_seg"
                    unless defined $dst_seg_num;

                my $dst_off = $ctx->{symbol_offset}{$dst_sym};
                croak "no offset for $dst_ref"
                    unless defined $dst_off;
                $dst_off += $dst_delta;

                $chunk .= pack("CCCVV",
                    $is_rel, $src_seg_num, $dst_seg_num, $src_off, $dst_off);
            }
        }
    }
    $ctx->{reloc_chunk_bytes} = $chunk;
}


sub _create_virtual_sections {
    for my $sec (sort keys %{$ctx->{section_pspace_offset}}) {
        my $src = $ctx->{section_source}{$sec};
        $src //= $sec;
        next if exists $ctx->{source_bytes}{$src};
        my $off = $ctx->{section_pspace_offset}{$sec};
        croak "no section_pspace_offset for $sec"
            unless defined $off;
        $ctx->{source_bytes}{$src} = "\0" x $off;
    }
}


sub _add_relocator_dummy {
    my $rname = $ctx->{settings}{relocator};
    return unless defined $rname;
    patch(
        desc   => "add dummy $rname",
        pchunk => {
            bytes   => "",
            globals => { $rname => 0 },
        },
        section => ".text",
    );
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

    croak "cross-section relative relocations are not supported"
        if keys %{$ctx->{reloc_rel}};

    my @rk = keys %{$ctx->{reloc_abs}};
    croak "relocations outside of .text are not supported"
        unless @rk < 2 and (@rk == 1 ? $rk[0] eq ".text" : 1);

    my $rr = $ctx->{reloc_abs}{".text"};
    for my $off (sort { $a <=> $b } keys %$rr) {
        my $ref = $rr->{$off};
        my ($sym, $delta) = _split_ref($ref);
        my $sec = $ctx->{symbol_section}{$sym};
        croak "symbol $sym+$delta has no section defined"
            unless defined $sec;
        my $var_dsec = $ctx->{symbol_offset}{$sym} + $delta;
        my $rel_dsec = $off;
        my $item     = sprintf("       .int 0x%x, 0x%x\n",
            _wrap($rel_dsec), _wrap($var_dsec));

        # print "# reloc $sec $ref: $item";    # if $sec eq ".data";
        $relocs{$sec} .= $item;
    }

    croak "no symbol $rname defined"
        unless defined $ctx->{symbol_offset}{$rname};

    my $relocator_dsec =
        $ctx->{symbol_offset}{$rname} - $sec_offset{".text"};
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

    patch(
        desc    => "add $rname",
        pchunk  => $chunk,
        symbol  => $rname,
        section => ".text",
    );

    _place_patch($ctx->{patches}[-1]);
}


sub _check_patch {
    my $p = shift;

    return unless exists $ctx->{source_bytes}{ $p->{source} };
    my $bytes = \$ctx->{source_bytes}{ $p->{source} };

    my $cbytes = $p->{cchunk}{bytes};
    return unless defined $cbytes;

    croak "attempt to check range [$p->{off_source}, "
        . ($p->{off_source} - 1 + length $cbytes)
        . "] outside of the source file ("
        . length($$bytes)
        . " bytes)"
        unless $p->{off_source} + length $cbytes <= length $$bytes;

    my $got = substr($$bytes, $p->{off_source}, length $cbytes);
    croak "check failed: check chunk is missing,\n"
        . " expected: "
        . _hexdump($cbytes) . "\n"
        . "      got: "
        . _hexdump($got) . "\n"
        unless $got eq $cbytes;
}


sub _apply_patch {
    my $p = shift;

    return unless exists $ctx->{source_bytes}{ $p->{source} };
    my $bytes = \$ctx->{source_bytes}{ $p->{source} };

    return unless defined $p->{pchunk};
    my $pbytes = $p->{pchunk}{bytes};

    croak "chunk is not built"
        unless defined $pbytes;

    substr($$bytes, $p->{off_source}, length $pbytes) = $pbytes;
}


sub _prepare_patches {
    _add_relocator_dummy();

    for my $p (@{ $ctx->{patches} }) {
        _eval_rethrow(
            sub {
                _place_patch($p);
                add_symbol(
                    off     => $p->{off_section},
                    name    => $p->{name},
                    section => $p->{section},
                    )
                    if defined $p->{name}
                    and defined $p->{section}
                    and defined $p->{off_section};
            },
            "_place_patch",
            $p
        );
    }

    _add_symbols();

    $ctx->{relocs} //= {};
    for my $p (@{ $ctx->{patches} }) {
        for my $c (qw/ pchunk cchunk /) {
            _eval_rethrow(
                sub { _link_chunk($p->{$c}, $p->{section}, $p->{off_section}) },
                "link $c",
                $p
            );
        }
    }

    _add_relocator();
    _check_placement();
    _create_virtual_sections();
    _produce_reloc_chunk();

    for my $p (@{ $ctx->{patches} }) {
        _eval_rethrow(sub { _check_patch($p) }, "_check_patch", $p);
    }
}


sub _apply_patches {
    for my $p (@{ $ctx->{patches} }) {
        _eval_rethrow(sub { _apply_patch($p) }, "_apply_patch", $p);
    }
}


sub _check_placement {
    my %patches;
    for my $p (@{ $ctx->{patches} }) {
        _eval_rethrow(
            sub {
                _update_offsets($p);
                croak "no source or off_source in patch '$p->{desc}'"
                    unless defined $p->{off_source} and defined $p->{source};

                if (defined $ctx->{source_bytes}{ $p->{source} }) {
                    my $l = length $ctx->{source_bytes}{ $p->{source} };
                    if (defined $p->{cchunk}) {
                        croak "attempt to check range not within source"
                            unless $l >=
                            $p->{off_source} + length $p->{cchunk}{bytes};
                    }
                    if (defined $p->{pchunk}) {
                        croak "attempt to patch range not within source"
                            unless $l >=
                            $p->{off_source} + length $p->{pchunk}{bytes};
                    }
                }

                return
                    unless defined $p->{pchunk}
                    and length $p->{pchunk}{bytes} > 0;

                push(@{$patches{ $p->{source} } //= []}, $p);
            },
            "_check_placement loop",
            $p
        );
    }
    for my $src (sort keys %patches) {
        my @p =
            sort { $a->{off_source} <=> $b->{off_source} } @{ $patches{$src} };
        for (my $i = 1 ; $i < @p ; ++$i) {
            my $prev = $p[ $i - 1 ];
            my $cur  = $p[$i];
            croak "patches $prev->{desc} and $cur->{desc} intersect"
                if $prev->{off_source} + length $prev->{pchunk}{bytes} >
                $cur->{off_source};
        }
    }
}


sub _split_ref {
    my $ref = shift;
    return (undef, int($ref)) if $ref =~ /^[-+]?\d+$/;
    my ($sym, $delta) = ($ref, 0);
    $sym = $1, $delta = $2 if $ref =~ /^([^-+]+)([-+][0-9]+)$/;
    return ($sym, int($delta));
}

# this is optional, returns 0 unless both section_base and section_offset are present
sub _sym_base {
    my $sym = shift;
    croak "_sym_base undefined symbol"
        unless defined $sym;    #TODO common integrity check

    my $sec = $ctx->{symbol_section}{$sym};
    croak "no section for symbol $sym"
        unless defined $sec;

    return $ctx->{section_base}{$sec} // 0;
}


sub _link_chunk_croak {
    my ($sec, $off) = @_;
    croak "offset is required for linking"
        unless defined $off;
    croak "section is required for linking"
        unless defined $sec;
}


sub _link_chunk {
    my ($c, $sec, $off) = @_;

    if ($c->{link_rel} && %{ $c->{link_rel} }) {
        _link_chunk_croak($sec, $off);
        for my $o (sort { $a <=> $b } keys %{$c->{link_rel}}) {
            my $ref = $c->{link_rel}{$o};
            my ($sym, $delta) = _split_ref($ref);
            croak "undefined reference $ref"
                unless defined $ctx->{symbol_offset}{$sym};
            if ($ctx->{symbol_section}{$sym} eq $sec) {    # inter-section
                substr($c->{bytes}, $o, 4) = pack("V",
                    $ctx->{symbol_offset}{$sym} + $delta - ($off + $o));
            } else {
                $ctx->{reloc_rel}{$sec}{ $o + $off } = $ref;
            }
        }
    }

    if ($c->{link_abs} && %{ $c->{link_abs} }) {
        _link_chunk_croak($sec, $off);
        for my $o (sort { $a <=> $b } keys %{$c->{link_abs}}) {
            my $ref = $c->{link_abs}{$o};
            my ($sym, $delta) = _split_ref($ref);
            croak "undefined reference $ref"
                unless exists $ctx->{symbol_offset}{$sym};
            $ctx->{reloc_abs}{$sec}{ $o + $off } = $ref;
            substr($c->{bytes}, $o, 4) = pack("V",
                $ctx->{symbol_offset}{$sym} + _sym_base($sym) + $delta);
        }
    }

    if ($c->{link_self} && %{ $c->{link_self} }) {
        _link_chunk_croak($sec, $off);
        for my $o (sort { $a <=> $b } keys %{$c->{link_self}}) {
            my $ref = $c->{link_self}{$o};
            my $var = $off + $ref;
            $var = "+$var" if $var >= 0;
            $ctx->{reloc_abs}{$sec}{ $o + $off } = $sec . $var;

            substr($c->{bytes}, $o, 4) =
                pack("V", $off + _sym_base($sec) + $ref);
        }
    }
}


sub _save {
    for my $src (sort keys %{$ctx->{source_output_file}}) {
        my $f = $ctx->{source_output_file}{$src};
        next unless defined $f;
        croak "error saving $f: nothing got patched\n"
            unless defined $ctx->{source_bytes}{$src};
        write_file(
            $f,
            {
                binmode  => ":raw",
                err_mode => "carp",
            },
            $ctx->{source_bytes}{$src}
        );
        print "written $f\n";
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
    my ($out, $opts) = @_;

    my %salign;
    my %sbytes;
    my %ssize;
    my @sseq;

    # section list
    my ($sections) = $out =~ /^Sections:\nIdx.*\n((?: .*\n)*)/m;
    for my $sline (split /\n/, $sections) {
        my @items = split /\s+/, $sline;
        my ($sname, $ssize, $salign) = @items[ 2, 3, 7 ];

        next unless $sname =~ /text|data|bss|slt|comment/;
        next if $sname eq ".comment" and not $opts->{keep_comment};

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
            my ($roff, $rtype, $symb) =
                (hex($1) + $soff{$sname}, $2, $3);

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
    my ($objf, $opts) = @_;
    $opts //= {};

    my ($out, $err);
    IPC::Run::run [ qw/ objdump -sxw /, $objf ], ">", \$out, "2>", \$err
        or croak "objdump error: $err";

    my $res = _eval_rethrow(sub { _parse_objdump($out, $opts); },
        "_parse_objdump", $out);

    $res->{objdump} = $out
        if $ctx->{settings}{need_objdump};

    if ($ctx->{settings}{need_listing}) {
        IPC::Run::run [ qw/ objdump -dr --insn-width=8 -Mintel /, $objf ],
            ">", \$out, "2>", \$err
            or croak "objdump error: $err";
        $res->{listing} = $out;
    }

    return $res;
}


sub _croak_source {
    my ($where, $code, $out) = @_;
    my $i = 1;
    $code =~ s/^/$i++." "/meg;
    croak "$where\n$code\nerror was: $out\n";
}


sub gcc {
    my ($code, $opts) = @_;

    croak "scalar with C code expected as first argument, got ", tt($code)
        if defined $code and ref($code) ne "";

    $opts //= {};
    croak "opts hash ref expected as second argument, got ", tt($opts)
        unless ref($opts) eq "HASH";

    my $out;
    my $tmpf = File::Temp->new(TEMPLATE => "bp-gcc-XXXXX");
    my @build_opts;
    @build_opts = @{ $opts->{build_opts} }
        if ref($opts->{build_opts});
    IPC::Run::run [
        qw/ gcc -xc -m32 -fno-asynchronous-unwind-tables -march=i386 -ffreestanding /,
        @build_opts,
        "-c",
        (defined $code ? ("-") : ()),
        "-o",
        $tmpf,
        ],
        (defined $code ? ("<", \$code) : ()), "&>", \$out
        or _croak_source("when compiling:", $code // "", $out);

    return _objdump($tmpf, $opts);
}


sub gas {
    my ($code, $opts) = @_;

    croak "scalar with assembly listing expected, got ", tt($code)
        unless defined $code and ref($code) eq "";

    $opts //= {};
    croak "opts hash ref expected as second argument, got ", tt($opts)
        unless ref($opts) eq "HASH";

    # use intel syntax by default
    $code = ".intel_syntax noprefix\n$code"
        unless $code =~ /att_syntax/s;

    my $out;
    my $tmpf = File::Temp->new(TEMPLATE => "bp-as-XXXXX");
    my @build_opts;
    @build_opts = @{ $opts->{build_opts} }
        if ref($opts->{build_opts});
    IPC::Run::run [ qw/ as --32 -march=i386 /, @build_opts, "-o", $tmpf ],
        "<", \$code, "&>", \$out
        or _croak_source("when assembling:", $code, $out);

    return _objdump($tmpf, $opts);
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
                opts   => { build_opts => \@opts },
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

    return { %$node, %{ gas($node->{source}, $node->{opts}) } }
        if $node->{format} eq "gas";

    return { %$node, %{ gcc($node->{source}, $node->{opts}) } }
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
