package Patcher;

use strict;
use warnings;

use Data::Dumper;
use File::Temp;
use File::Slurp;
use IPC::Run;
use Storable qw(freeze thaw);

# perl export magic
require Exporter;
our @ISA       = qw/ Exporter /;
our @EXPORT_OK = qw/
    modify_context
    context_get
    reset_context
    load_config
    add_symbol
    topic
    patch
    print_patches
    patch_divert
    patch_divert_all
    link_apply_save
    link_patches
    apply_patches
    save
    tt
    ss
    pp
    _die
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
        build_cache           => {},
        build_cache_usage     => {},
    };

    modify_context(@_);
    return $ctx;
}

sub _die_args;
sub _die;


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
        $ctx->{source_bytes}{$src} = read_file($f, binmode => ":raw");
    }

    return $ctx;
}

reset_context();


sub context_get {
    my @path;
    my $r = $ctx;
    for my $p (@_) {
        push(@path, $p);
        _die "no value " . join(".", @path) . " in patcher context"
            unless ref($r) eq "HASH";
        $r = $r->{$p};
    }
    return $r;
}

#
# ----------------
#  config loader

our $DYING = 0;


sub load_config {
    for my $f (@_) {
        modify_context("load_config_current_file", $f);
        eval {
            my $e = eval qq(#line 1 "$f"\n) . read_file $f;
            die $@ if $@;
        };
        if ($@) {
            die $@ if $DYING;
            _die "error in $f: $@";
        }
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

    _die "desc is required"
        unless defined $p->{desc} and ref($p->{desc}) eq "";

    _eval_rethrow(sub { _patch($p) }, "when parsing '$p->{desc}'", $p);
}


sub generate_digest {
    my $out = "";
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
            if defined $p->{section} and defined $p->{off_section};
        $at //= sprintf("??? %08x", $p->{off})
            if defined $p->{off};
        $at //= "";

        my $add = "";
        $add .= "... (" . length($pbin) . " bytes)"
            if length $b < length $pbin;
        $out .= sprintf "patch %s '%s%s'%s: %s\n", $at, $topic, $p->{desc},
            $sym_name, _hexdump($b) . $add;
    }
    $out =~ s/\n/\r\n/g;
    return $out;
}


sub find_symbol {
    my ($off, $sec) = @_;
    unless (defined $sec) {
        my $o = { off => $off };
        _update_offsets($o);
        ($off, $sec) = ($o->{off_section}, $o->{section});
    }
    return "" unless defined $off and defined $sec;

    my $index = $ctx->{symbol_index};
    unless ($index) {
        $index = {};
        my $ignore = $ctx->{settings}{find_offset}{ignore};
        _die "settings.find_offset.ignore is not a Regex"
            if defined $ignore and ref($ignore) ne "Regexp";

        for my $sym (
            sort {
                my $soa = $ctx->{symbol_offset}{$a};
                my $sob = $ctx->{symbol_offset}{$b};
                $soa != $sob ? $soa <=> $sob : $a cmp $b;
            }
            keys %{$ctx->{symbol_offset}}
            )
        {
            next if $ignore and $sym =~ $ignore;

            my $ssec = $ctx->{symbol_section}{$sym};
            next unless $ssec;

            $index->{$ssec} //= [];
            push(@{$index->{$ssec}}, [ $ctx->{symbol_offset}{$sym}, $sym ]);
        }
        $ctx->{symbol_index} = $index;
    }

    my $si = $index->{$sec};
    return "" unless $si;

    my ($min, $max, $minv, $maxv) = (0, @$si - 1, $si->[0][0], $si->[-1][0]);
    return "" if $minv > $off;
    if ($maxv < $off) {
        $minv = $maxv;
        $min  = $max;
    } else {
        while (1) {
            my $mid  = int(($max + $min) / 2);
            my $midv = $si->[$mid][0];
            my $change;

            $min = $mid, $minv = $midv, $change = 1
                if $min != $mid and $midv < $off;

            $max = $mid, $maxv = $midv, $change = 1
                if $max != $mid and $midv >= $off;

            last unless $change;
        }
    }

    if ($maxv == $off and not $ctx->{settings}{off_name_skip_zero_offsets}) {
        $minv = $maxv;
        $min  = $max;
    }
    my $d        = $off - $minv;
    my $max_dist = $ctx->{settings}{off_name_max_dist};
    return "" if defined $max_dist and $d > $max_dist;
    return "$si->[$min][1]+$d";
}


sub topic {
    die "topic must be a string or undef"
        unless ref($_[0]) eq "";

    $ctx->{topic} = $_[0];
}


sub patch_divert {
    my ($where, $from, $to, $op) = @_;
    $op //= "call";
    patch(
        off    => $where,
        desc   => "divert $from -> $to",
        cchunk => "#gas# call $from",
        pchunk => "#gas# $op $to",
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

    _die "unknown section or not bound to source"
        unless defined $sec and defined $ctx->{section_source}{$sec};
    my $src = $ctx->{section_source}{$sec};
    _die "no source for section $sec"
        unless defined $ctx->{source_bytes}{$src};
    my $bytes = \$ctx->{source_bytes}{$src};

    my $soff = $ctx->{section_offset}{$sec};
    my $slen = $ctx->{section_length}{$sec};
    _die "no offset or length for section"
        unless defined $soff and defined $slen;

    my $ot = $ctx->{symbol_offset}{$old_target};
    _die "no symbol '$old_target' exists"
        unless defined $ot;

    _die "symbol section does not match $sec"
        unless $ctx->{symbol_section}{$old_target} eq $sec;

    my $index = $ctx->{call_index} // {};
    unless ($index->{$sec}) {
        my $si = $index->{$sec} = {};
        my $off = $soff;
        my $end = $soff + $slen;
        while ($off + 5 <= $end) {
            my ($op, $delta) = unpack("CV", substr($$bytes, $off, 5));
            ++$off, next
                unless $op == 0xe8;

            my $t = $off + 5 + $delta;
            $t -= 2**32 if $delta >= 2**31;
            ++$off, next
                if $t < $soff or $t > $end;
            $t -= $soff;
            $si->{$t} //= [];
            push(@{$si->{$t}}, $off);
            ++$off;
        }
        $ctx->{call_index} = $index;
    }

    my $si = $index->{$sec};
    _die "internal error, failed to build index for $sec" unless $si;

    my $offs = $si->{$ot};
    _die "no calls to $old_target found in section $sec"
        unless $offs;

    patch_divert($_, $old_target, $new_target) for @$offs;
}


sub link_apply_save {
    link_patches();
    apply_patches();
    save();
}


sub build_cache_load {
    my $f = $ctx->{settings}{build_cache_file};
    return unless $f;
    unless (-f $f) {
        print "cache file '$f' does not exist\n";
        return;
    }
    eval {
        my $data = read_file($f, { binmode => ":raw" });
        $ctx->{build_cache} = thaw $data;
    };
    if ($@) {
        print "cache not loaded: $@\n";
    } else {
        print "cache loaded from '$f'\n";
    }
}


sub build_cache_save {
    my $f = $ctx->{settings}{build_cache_file};
    return unless $f;
    return unless $ctx->{build_cache};
    for my $i (keys %{$ctx->{build_cache}}) {
        delete $ctx->{build_cache}{$i}
            unless $ctx->{build_cache_usage}{$i};
    }
    my $data = freeze($ctx->{build_cache});
    write_file $f, { binmode => ":raw" }, $data;
}

#
# ------
#  aux


sub _stack {
    my ($skip)    = @_;
    my $max_depth = 30;
    my $e         = -1;
    my @stack     = "stack trace:";
    my $i;
    for ($i = $skip ; $i < $max_depth ; ++$i) {
        my ($package, $filename, $line, $sub) = caller($i);
        last unless $package;

        splice(@stack, -2, 2)
            if @stack >= 2
            and $sub =~ /^(Patcher::load_config|Patcher::_eval_rethrow)$/;

        push(@stack, "   $sub called at $filename line $line");
    }
    my $out .= join("\n", @stack, "");
    $out .= "...\n"
        if $i == $max_depth;
    return $out;
}


sub _die {
    my ($err) = @_;
    die $err if $DYING;
    $err = ss(@_) if @_ > 1 or @_ == 1 and ref($_[0]) ne '';
    $err = "error: $err\n"
        if defined $err and $err !~ /^error/;
    $DYING = 1;
    die(($err // "") . _stack(1));
}

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
                _die "sections $s and $sec both match offset $off"
                    if defined $sec;
                $sec = $s;
            }
            if (defined $sec) {
                $o->{section} = $sec;
                _die "section $sec has no offset"
                    unless defined $ctx->{section_offset}{$sec};
                my $so = $off - $ctx->{section_offset}{$sec};
                _die "off_section is being redefined"
                    if defined $o->{off_section} and $o->{off_section} != $so;
                $o->{off_section} = $so;
            }
        }
    }

    if (defined($sec) and defined($off) and not defined($o->{off_section})) {
        my $slen = $ctx->{section_length}{$sec};
        _die "offset $off is too large for section $sec"
            if defined $slen and $off > $slen;
        $o->{off_section} = $off;
    }

    unless (defined $o->{source}) {
        if (defined $sec) {
            my $src = $ctx->{section_source}{$sec};
            if (defined $src) {
                $o->{source} = $src;
                if (defined $o->{off_section}) {
                    _die "section $sec has no offset"
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
    _die "name is required"
        unless defined $n;
    _update_offsets($s);
    _die "section was not specified or deduced"
        unless defined $s->{section};
    _die "off was not specified"
        unless defined $s->{off};
    if (exists $ctx->{symbol_offset}{$n}) {
        return
            if defined $ctx->{symbol_offset}{$n}
            and $ctx->{symbol_offset}{$n} eq $s->{off};
        _die
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
        _die "unsupported filter type '" . ref($filter) . "'";
    }
}


sub _patch {
    my $p = shift;
    _update_offsets($p);

    # TODO whole 'topic' thing is messy and needs refactoring,
    # make them independent, make them store docs
    if (defined $p->{topic}) {
        $ctx->{topic} = $p->{topic};
    } else {
        $p->{topic} = $ctx->{topic}
            if defined $ctx->{topic};
    }

    my $bctx = {};
    $bctx->{label} = "'" . ($p->{topic} // "") . ' | ' . $p->{desc} . "'"
        unless $ctx->{settings}{quiet};
    $bctx->{nocache} = 1 if $p->{nocache};

    if (defined $p->{cchunk}) {
        _die "off is not defined, cchunk makes no sense"
            unless defined $p->{off};

        $p->{cchunk} = build_chunk($p->{cchunk}, $bctx);
        _die "empty cchunk makes no sense"
            if length $p->{cchunk}{bytes} == 0;
    } else {
        _die "no cchunk or pchunk, nothing to do"
            unless defined $p->{pchunk};
    }

    if (defined $p->{pchunk}) {
        $p->{pchunk} = build_chunk($p->{pchunk}, $bctx);
    } else {
        $p->{pchunk} = build_chunk("", { nocache => 1 }) if $p->{fill_nop};
    }

    if (defined $p->{pchunk} and defined $p->{cchunk}) {
        _die "cchunk ends before pchunk (pchunk is not covered, "
            . length($p->{pchunk}{bytes}) . " > "
            . length($p->{cchunk}{bytes}) . ")"
            if length($p->{cchunk}{bytes}) < length($p->{pchunk}{bytes});
    }

    if ($p->{fill_nop}) {
        _die "no cchunk present, fill_nop makes no sense"
            unless defined $p->{cchunk};

        my $d = length($p->{cchunk}{bytes}) - length($p->{pchunk}{bytes});
        $p->{pchunk}{bytes} .= pack("H*", "90") x $d
            if $d > 0;
    }

    if (    defined $p->{pchunk}
        and defined $p->{cchunk}
        and $ctx->{settings}{require_check_match_patch})
    {
        _die "pchunk is smaller than cchunk (forgot fill_nop?)"
            if length($p->{pchunk}{bytes}) < length($p->{cchunk}{bytes});
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

    _die "unable to place patch without section"
        unless defined $p->{section};

    my $pspace_off = $ctx->{section_pspace_offset}{ $p->{section} };
    _die "unable to place '$p->{desc}', no pspace for $p->{section}"
        unless defined $pspace_off;
    my $pspace_len = $ctx->{section_pspace_length}{ $p->{section} };

    my $align = -$pspace_off % ($p->{pchunk}{align} // 1);
    my $len = $align + length $p->{pchunk}{bytes};

    _die "no free patch space left for patch"
        if defined $pspace_len and $pspace_len < $len;

    my $sec_off = $ctx->{section_offset}{ $p->{section} };
    my $sec_src = $ctx->{section_source}{ $p->{section} };
    _die "section $p->{section} has no offset or source"
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
            _die(     "multiple definitions of $g: "
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
            _die "unknown section $src_seg"
                unless defined $src_seg_num;

            for my $src_off (sort { $a <=> $b } keys %$offs) {
                my $dst_ref = $offs->{$src_off};
                my ($dst_sym, $dst_delta) = _split_ref($dst_ref);
                _die "unable to extract symbol from ref $dst_ref"
                    unless defined $dst_sym;

                my $dst_seg = $ctx->{symbol_section}{$dst_sym};
                _die "no section for $dst_ref"
                    unless defined $dst_seg;

                my $dst_seg_num = $ss{$dst_seg};
                _die "unknown section $dst_seg"
                    unless defined $dst_seg_num;

                my $dst_off = $ctx->{symbol_offset}{$dst_sym};
                _die "no offset for $dst_ref"
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
        _die "no section_pspace_offset for $sec"
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

    _die "unable to produce relocator without data_bootstrap_ptr"
        unless defined $ctx->{data_bootstrap_ptr};

    _die "unable to produce relocator without data_bootstrap_var"
        unless defined $ctx->{data_bootstrap_var};

    my %sec_offset;
    $sec_offset{$_} = $ctx->{section_offset}{$_} // 0 for (qw/ .text .data /);

    my %relocs = (
        ".text" => "",
        ".data" => "",
    );
    my $text_relocs = "";
    my $data_relocs = "";

    _die "cross-section relative relocations are not supported"
        if keys %{$ctx->{reloc_rel}};

    my @rk = keys %{$ctx->{reloc_abs}};
    _die "relocations outside of .text are not supported"
        unless @rk < 2 and (@rk == 1 ? $rk[0] eq ".text" : 1);

    my $rr = $ctx->{reloc_abs}{".text"};
    for my $off (sort { $a <=> $b } keys %$rr) {
        my $ref = $rr->{$off};
        my ($sym, $delta) = _split_ref($ref);
        my $sec = $ctx->{symbol_section}{$sym};
        _die "symbol $sym+$delta has no section defined"
            unless defined $sec;
        my $var_dsec = $ctx->{symbol_offset}{$sym} + $delta;
        my $rel_dsec = $off;
        my $item     = sprintf("       .int 0x%x, 0x%x\n",
            _wrap($rel_dsec), _wrap($var_dsec));

        # print "# reloc $sec $ref: $item";    # if $sec eq ".data";
        $relocs{$sec} .= $item;
    }

    _die "no symbol $rname defined"
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

    _die "attempt to check range [$p->{off_source}, "
        . ($p->{off_source} - 1 + length $cbytes)
        . "] outside of the source file ("
        . length($$bytes)
        . " bytes)"
        unless $p->{off_source} + length $cbytes <= length $$bytes;

    my $got = substr($$bytes, $p->{off_source}, length $cbytes);
    _die "check failed: check chunk is missing,\n"
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

    _die "chunk is not built"
        unless defined $pbytes;

    substr($$bytes, $p->{off_source}, length $pbytes) = $pbytes;
}


sub link_patches {
    print "linking patches\n"
        unless $ctx->{settings}{quiet};

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
    $ctx->{source_bytes}{digest} = generate_digest();
}


sub apply_patches {
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
                _die "no source or off_source in patch '$p->{desc}'"
                    unless defined $p->{off_source} and defined $p->{source};

                if (defined $ctx->{source_bytes}{ $p->{source} }) {
                    my $l = length $ctx->{source_bytes}{ $p->{source} };
                    if (defined $p->{cchunk}) {
                        _die "attempt to check range not within source"
                            unless $l >=
                            $p->{off_source} + length $p->{cchunk}{bytes};
                    }
                    if (defined $p->{pchunk}) {
                        _die "attempt to patch range not within source"
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
            _die "patches '$prev->{desc}' and '$cur->{desc}' intersect"
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
    _die "_sym_base undefined symbol"
        unless defined $sym;    #TODO common integrity check

    my $sec = $ctx->{symbol_section}{$sym};
    _die "no section for symbol $sym"
        unless defined $sec;

    return $ctx->{section_base}{$sec} // 0;
}


sub _link_chunk_croak {
    my ($sec, $off) = @_;
    _die "offset is required for linking"
        unless defined $off;
    _die "section is required for linking"
        unless defined $sec;
}


sub _link_chunk {
    my ($c, $sec, $off) = @_;

    if ($c->{link_rel} && %{ $c->{link_rel} }) {
        _link_chunk_croak($sec, $off);
        for my $o (sort { $a <=> $b } keys %{$c->{link_rel}}) {
            my $ref = $c->{link_rel}{$o};
            my ($sym, $delta) = _split_ref($ref);
            _die "undefined reference $ref"
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
            _die "undefined reference $ref"
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


sub save {
    for my $src (sort keys %{$ctx->{source_output_file}}) {
        my $f = $ctx->{source_output_file}{$src};
        next unless defined $f;
        _die "error saving $f: nothing got patched\n"
            unless defined $ctx->{source_bytes}{$src};
        write_file($f, { binmode => ":raw" }, $ctx->{source_bytes}{$src});
        print "written $f\n";
    }
}


sub _wrap {
    my $n = shift;

    _die "integer expected, got " . tt($n)
        unless defined $n
        and ref($n) eq ""
        and $n =~ /^[-+]?\d+/;

    my $bits = $ctx->{settings}{arch_bits} // 32;
    return $n % (2**$bits);
}


sub _asciify_string {
    my $max_string = $ctx->{settings}{format_max_string};
    my $s          = shift;
    my $ell;
    substr($s, $max_string) = '', $ell = 1
        if defined $max_string and length($s) > $max_string;
    unless ($ctx->{settings}{format_dont_asciify}) {
        $s = '!' . _hexdump($s) if $s =~ m/[^[:print:]\r\n\t\0 ]/;
    }
    substr($s, $max_string) = '', $ell = 1
        if defined $max_string && length($s) > $max_string;
    substr($s, -3) = "..."
        if $ell;
    return $s;
}


sub _rebuild {
    my ($v) = @_;
    return $v
        unless defined $v;
    return _asciify_string($v)
        if ref($v) eq '';

    if (ref($v) eq 'ARRAY') {
        my @res;
        for my $el (@$v) {
            push(@res, _rebuild($el));
        }
        return \@res;
    }

    if (ref($v) eq 'HASH') {
        my %res;
        while (my ($key, $val) = each %$v) {
            $res{$key} = _rebuild($val);
        }
        return \%res;
    }

    if (ref($v) eq 'SCALAR') {
        my $s = _rebuild($$v);
        return \$s;
    }

    _die "internal error rebuild for " . ref($v) . " is not supported";
}


sub tt {
    return Data::Dumper->new([ _rebuild @_ ])->Indent(0)->Terse(1)->Sortkeys(1)
        ->Dump;
}


sub ss {
    return Data::Dumper->new([ _rebuild @_ ])->Indent(1)->Terse(1)->Sortkeys(1)
        ->Dump;
}


sub pp {
    print ss(\@_);
}


sub _die_args {
    my ($func, $arg_template, @args) = @_;
    _die "$func requires even number of arguments"
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

    _die "error: bad symbols in hex dump: $1"
        if $xbytes =~ /([^0-9a-fA-F\s].*)$/;

    $xbytes =~ s/\s//g;
    _die "error: odd number of symbols in hex dump: $xbytes"
        if length($xbytes) % 2;

    return pack("H*", $xbytes);
}


sub _unpack_delta {
    my ($bytes, $roff, $add) = @_;
    my $d = unpack("V", substr($bytes, $roff, 4)) + $add;
    $d -= 2**32
        if $d >= 2**31;
    return $d == 0 ? "" : $d > 0 ? "+$d" : $d;
}


sub _parse_objdump {
    my ($out, $opts) = @_;

    my $pe = $out =~ /file format pe-i386/s;
    my %salign;
    my %sbytes;
    my %ssize;
    my %id_to_sname;
    my @sseq;

    # section list
    my ($sections) = $out =~ /^Sections:\nIdx.*\n((?: .*\n)*)/m;
    for my $sline (split /\n/, $sections) {
        my @items = split /\s+/, $sline;
        my ($sid, $sname, $ssize, $salign) = @items[ 1, 2, 3, 7 ];

        next unless $sname =~ /^\.(text|rdata|rodata.*|data|bss|slt|comment)$/;
        next if $sname eq ".comment" and not $opts->{keep_comment};

        $salign{$sname} =
            $ctx->{settings}{honor_alignment}
            ? 2**($salign =~ s/^2\*\*//r)
            : 1;
        $ssize{$sname}     = hex $ssize;
        $sbytes{$sname}    = "";
        $id_to_sname{$sid} = $sname;

        push(@sseq, $sname);
    }

    # sections contents
    my @contents = $out =~ /(^Contents of section.*:\n(?: [0-9a-f].*\n)*)/mg;
    for my $c (@contents) {
        my ($cheader, @clines) = split /\n/, $c;
        _die "bad contents section header: $cheader"
            unless $cheader =~ /^Contents of section (.*):$/;
        my $sname = $1;

        next
            unless exists $sbytes{$sname};

        for my $cline (@clines) {
            _die "bad line: $cline"
                unless $cline =~
                /^ ([0-9a-f]+) ((?:(?:[0-9a-f]{2}){1,4} ){1,4}) .*/;
            my ($off, $xbytes) = ($1, $2);
            _die "parse error, offset does not match bytes count at $off: $c"
                unless hex $off == length $sbytes{$sname};
            $sbytes{$sname} .= _pack_hex($xbytes);
        }
        if ($pe and $sname eq '.text') {
            if ($sbytes{$sname} =~ /\x90+$/s) {
                my $len = length($&);
                substr($sbytes{$sname}, -$len) = '';
                $ssize{$sname} -= $len;
            }
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

        _die "section size $ssize{$sname} does not match binary chunk size "
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
    my ($symbols) = $out =~ /^SYMBOL TABLE:\n((?:\S.*\n)*)/m;
    my %globals;
    for my $sl (split /\n/, $symbols) {
        my ($off, $sname, $sym);
        if ($pe) {
            my ($sid, $scl, $nx);
            ($sid, $scl, $nx, $off, $sym) =
                $sl =~
                /^\[\s*[0-9]+\]\(sec\s+([0-9]+)\)\(fl.*\)\(ty.*\)\(scl\s+(.*)\) \(nx\s+([0-9]+)\)\s+0x([0-9a-f]+)\s+(.*)/;
            unless (defined $sym) {

                # print "no match $sl\n";
                next;
            } else {

                # print "match $sl\n";
                # print "sid=$sid nx=$nx off=$off sym=$sym soff=$soff{$id_to_sname{$sid}}\n";
            }

            # next unless $nx == 1;
            next if defined $soff{$sym};
            next unless $scl == 2;
            next unless $sid;
            $sym =~ s/^_+//g;
            $sname = $id_to_sname{ $sid - 1 };
            _die "no section with id $sid"
                unless $sname;
        } else {
            ($off, $sname, $sym) =
                $sl =~ /^([0-9a-f]+) g.{7}(\S+)\s+\S+\s+(.*)/;
            next unless defined $sym;
            _die "unknown section $sname referenced: $symbols "
                unless exists $soff{$sname};
        }
        $globals{$sym} = $soff{$sname} + hex($off);
    }

    # extracting relocations
    my @relocs =
        $out =~ /(^RELOCATION RECORDS FOR .*:\nOFFSET.*\n(?:[0-9a-f].*\n)*)/mg;
    my %link_rel;
    my %link_abs;
    my %link_self;
    for my $r (@relocs) {
        _die "bad relocation listing: $r"
            unless $r =~ /^RELOCATION RECORDS FOR \[(.*)\]:\n.*\n((?:.*\n)*)$/;
        my ($sname, $rlist) = ($1, $2);
        next unless exists $sbytes{$sname};

        for my $rline (split /\n/, $rlist) {
            _die "bad relocation line: $rline"
                unless $rline =~ /^([0-9a-f]+) (\S+) +(.*)$/;
            my ($roff, $rtype, $sym) =
                (hex($1) + $soff{$sname}, $2, $3);

            $sym =~ s/^_+//g;

            _die "relocation mentions unknown section $sym: $rline"
                if $sym =~ /^\./ and not exists $soff{$sym};

            if ($rtype =~ /R_386_32|dir32/) {
                if ($sym =~ /^\./) {

                    # offset from section boundary is embedded into instruction
                    $link_self{$roff} =
                        unpack("V", substr($bytes, $roff, 4)) + $soff{$sym};
                    next;
                }

                $link_abs{$roff} = $sym . _unpack_delta($bytes, $roff, 0);
                next;
            }

            if ($rtype =~ /R_386_PC32|DISP32/) {
                my $dfunc = $rtype eq "DISP32" ? -4 : 0;
                if ($sym =~ /^\./) {

                    # offset from section boundary is embedded into instruction
                    my $eo = unpack("V", substr($bytes, $roff, 4)) + $dfunc;
                    substr($bytes, $roff, 4) =
                        pack("V", $eo + $soff{$sym} - $roff);
                    next;
                }

                $link_rel{$roff} = $sym . _unpack_delta($bytes, $roff, $dfunc);
                next;
            }
            _die "unknown reloc type $rtype";
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


sub _chunk_requires_linking {
    my $ch = shift;
    for (qw/ link_rel link_abs link_self /) {
        return 1
            if defined $ch->{$_}
            and ref($ch->{$_}) eq "HASH"
            and %{ $ch->{$_} };
    }
    return 0;
}


sub _objdump {
    my ($objf, $opts) = @_;
    $opts //= {};

    my ($out, $err);
    IPC::Run::run [ qw/ objdump -sxw /, $objf ], ">", \$out, "2>", \$err
        or _die "objdump error: $err";

    my $res = _eval_rethrow(sub { _parse_objdump($out, $opts); },
        "_parse_objdump", $out);

    $res->{objdump} = $out
        if $ctx->{settings}{need_objdump};

    if ($ctx->{settings}{need_listing}) {
        IPC::Run::run [ qw/ objdump -dr --insn-width=8 -Mintel /, $objf ],
            ">", \$out, "2>", \$err
            or _die "objdump error: $err";
        $res->{listing} = $out;
    }

    return $res;
}


sub _croak_source {
    my ($where, $code, $out) = @_;
    my $i = 1;
    $code =~ s/^/$i++." "/meg;
    _die "$where\n$code\nerror was: $out\n";
}


sub gcc {
    my ($code, $opts) = @_;

    _die "scalar with C code expected as first argument, got ", tt($code)
        if defined $code and ref($code) ne "";

    $opts //= {};
    _die "opts hash ref expected as second argument, got ", tt($opts)
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

    _die "scalar with assembly listing expected, got ", tt($code)
        unless defined $code and ref($code) eq "";

    $opts //= {};
    _die "opts hash ref expected as second argument, got ", tt($opts)
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
    my ($c, $bctx) = @_;
    _die "undef chunk to build"
        unless defined $c;

    my $key;
    goto rebuild unless $ctx->{build_cache};
    goto rebuild if $bctx and $ctx->{nocache};
    goto rebuild if ref($c) eq '' and $c =~ /^(##|[^#])/;    # raw chunk

    $Storable::canonical = 1;
    $key                 = freeze(\$c);
    $Storable::canonical = 0;

    $ctx->{build_cache_usage}{$key}++, return thaw($ctx->{build_cache}{$key})
        if exists $ctx->{build_cache}{$key};

    print("building $bctx->{label}\n"), delete $bctx->{label}
        if $bctx and exists $bctx->{label};

rebuild:
    my $res = _build_chunk($c);
    $ctx->{build_cache}{$key} = freeze($res), $ctx->{build_cache_usage}{$key}++
        if defined $key;
    return $res;
}


sub _build_chunk {
    my ($c) = @_;

    _die "undef chunk to build"
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

    _die "no bytes and bad source: ", tt($node->{source})
        unless defined $node->{source} and ref($node->{source}) eq "";

    _die "bad format field: ", tt($node->{format})
        unless defined $node->{format} and ref($node->{format}) eq "";

    $node->{bytes} = _pack_hex($node->{source}), return $node
        if $node->{format} eq "hex";

    $node->{bytes} = $node->{source}, return $node
        if $node->{format} eq "";

    return { %$node, %{ gas($node->{source}, $node->{opts}) } }
        if $node->{format} eq "gas";

    return { %$node, %{ gcc($node->{source}, $node->{opts}) } }
        if $node->{format} eq "gcc";

    _die "unknown format $node->{format}";
}


sub _eval_rethrow {
    my ($func, $where, @info) = @_;
    my $res = eval { $func->(); };

    return $res
        unless $@;

    my $inf = ss(@info);
    $inf =~ s/^/    /mg;

    my $err = $@;
    $err = "error: $@" unless $@ =~ /^error:/;

    _die "$where, args were:\n$inf\n$err";
}

1;
