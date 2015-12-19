use warnings;
use strict;

use Test::Most tests => 55;
use Test::Most;
use Test::Deep;
use FindBin;
use lib "$FindBin::Bin/../lib";

$SIG{PIPE} = 'ignore';    # for watch

use_ok("Patcher");


sub common_settings {
    return (
        settings => {
            need_listing    => 1,
            honor_alignment => 0,
            quiet           => 1,
        },
        section_base   => {},
        section_offset => {},
        symbol_offset  => {},
        symbol_section => {},
        patches        => [],
    );
}

{
    my $c = eval { Patcher::reset_context(common_settings); };
    if ($@) {
        diag("exception: $@");
        fail("reset_context");
    } else {
        cmp_deeply($c, { common_settings, }, "reset_context");
    }
}


sub dd {
    my $msg = "";
    for my $arg (@_) {
        if (ref($arg) eq "" and defined $arg) {
            $msg .= $arg;
        } else {
            $msg .= Data::Dumper->new([$arg])->Indent(1)->Terse(1)->Sortkeys(1)
                ->Dump;
        }
    }
    diag($msg);
}


sub eval_test {
    my ($tname, $sub, $action, $check) = @_;
    Patcher::reset_context(common_settings);
    my $res = eval { $sub->() };
    if ($action eq "catch") {
        if ($@) {
            return like($@, $check, $tname);
        } else {
            fail($tname);
            dd("expected exception, got value: ", $res);
            return 0;
        }
    }

    if ($@) {
        fail($tname);
        dd("expected value, got exception: ", $@);
        return 0;
    }

    if ($action eq "compare") {
        cmp_deeply($res, $check, $tname)
            or dd("full result was:\n", $res);
        return;
    }

    die "unknown action $action";
}

# context manipulation tests

eval_test(
    "reset_context discards old context",
    sub {
        Patcher::reset_context("settings honor_alignment" => 1);
        Patcher::reset_context(settings => { honor_alignment => 0 })
            ->{settings};
    },
    compare => { honor_alignment => 0 }
);

eval_test(
    "reset_context throws on odd number of arguments",
    sub {
        Patcher::reset_context(1);
    },
    catch => qr/modify_context requires even number of arguments/,
);

eval_test(
    "modify_context throws on odd number of arguments",
    sub {
        Patcher::modify_context(1);
    },
    catch => qr/modify_context requires even number of arguments/,
);

eval_test(
    "modify_context chain mode",
    sub {
        Patcher::modify_context([qw/ settings long story /] => 1)
            ->{settings}{long};
    },
    compare => { story => 1 },
);

eval_test(
    "modify_context inline chain mode",
    sub {
        Patcher::modify_context("settings long story" => 1)->{settings}{long};
    },
    compare => { story => 1 },
);

# XXX should throw in strict mode
eval_test(
    "modify_context assgin",
    sub {
        Patcher::modify_context(settings => 1)->{settings};
    },
    compare => 1,
);

my $bits = "$FindBin::Bin/bits";

# loader tests
eval_test(
    "load_config",
    sub {
        Patcher::load_config("$bits/good-load");
        return Patcher::modify_context()->{settings}{good_load};
    },
    compare => 1,
);

eval_test(
    "load_config non-exsitent file",
    sub {
        Patcher::load_config("non-existent");
        return Patcher::modify_context()->{settings}{good_load};
    },
    catch => qr/file non-existent not found/,
);

eval_test(
    "load_config malformed file",
    sub {
        Patcher::load_config("$bits/bad-load");
        return Patcher::modify_context()->{settings}{good_load};
    },
    catch => qr/Patcher::nonsense called/,
);

# build_chunk tests
eval_test(
    "build_chunk hex",
    sub { Patcher::build_chunk("41 4243")->{bytes} },
    compare => "ABC",
);

eval_test(
    "build_chunk malformed hex",
    sub { Patcher::build_chunk("41+4243") },
    catch => qr/bad symbols in hex/,
);

eval_test(
    "build_chunk format hex",
    sub {
        Patcher::build_chunk({ source => "41 42 43", format => "hex" })
            ->{bytes};
    },
    compare => "ABC",
);

# further tests produce binary chunks, need this to make check failures readable
sub _unpack_deep {
    my $c = shift;

    if (ref($c) eq "ARRAY") {
        return [ map { _unpack_deep($_) } @$c ];
    }

    if (ref($c) eq "HASH") {
        for my $k (keys %$c) {
            if (    $k =~ /bytes|input_bytes/
                and defined $c->{$k}
                and ref($c->{$k}) eq "")
            {
                $c->{$k} = Patcher::_hexdump($c->{$k});
            } else {
                $c->{$k} = _unpack_deep($c->{$k});
            }
        }
    }

    return $c;
}

# gas tests
my $obj_common = {
    align     => 1,
    globals   => {},
    link_abs  => {},
    link_rel  => {},
    link_self => {},
    listing   => ignore,
};

eval_test(
    "gas",
    sub {
        _unpack_deep Patcher::gas("");
    },
    compare => {
        %$obj_common, bytes => "",
    },
);

eval_test(
    "gas option",
    sub {
        _unpack_deep Patcher::gas("", "-gstabs");
    },
    compare => {
        %$obj_common, bytes => "",
    },
);

eval_test(
    "gas inline",
    sub {
        _unpack_deep Patcher::build_chunk("#gas -defsym foo=0 #");
    },
    compare => {
        %$obj_common,
        format => "gas",
        bytes  => "",
        opts   => [ "-defsym", "foo=0" ],
        source => "",
    },
);

eval_test(
    "gas malformed syntax",
    sub { Patcher::gas("nonsense") },
    catch => qr/no such instruction.*nonsense/,
);

eval_test(
    "gas call",
    sub {
        _unpack_deep Patcher::gas("call print");
    },
    compare => {
        %$obj_common,
        bytes    => "e8 fc ff ff ff ",
        link_rel => { 1 => "print-4", },
    },
);

eval_test(
    "gas global",
    sub {
        Patcher::gas(".global foo\n foo:")->{globals};
    },
    compare => { "foo" => 0 },
);

eval_test(
    "gas data",
    sub {
        Patcher::gas("
            .data
                .asciz \"ABC\"
        ")->{bytes};
    },
    compare => "ABC\0",
);

eval_test(
    "gas data ref",
    sub {
        _unpack_deep Patcher::gas("
                push offset msg
            .data
            msg:
                .asciz \"ABC\"
        ");
    },
    compare => {
        %$obj_common,
        bytes     => "68 00 00 00 00 41 42 43 00 ",
        link_self => { 1 => 5 },
    },
);

eval_test(
    "gas call data",
    sub {
        _unpack_deep Patcher::gas("
                call foo
            .data
                .byte 0x99
                foo:
        ");
    },
    compare => { %$obj_common, bytes => "e8 01 00 00 00 99 " },
);

# gcc tests
eval_test(
    "gcc",
    sub {
        _unpack_deep Patcher::gcc("");
    },
    compare => {
        %$obj_common, bytes => "",
    },
);

eval_test(
    "gcc option",
    sub {
        _unpack_deep Patcher::gcc("", "-O3");
    },
    compare => {
        %$obj_common, bytes => "",
    },
);

eval_test(
    "gcc inline",
    sub {
        _unpack_deep Patcher::build_chunk("#gcc -O3#");
    },
    compare => {
        %$obj_common,
        bytes  => "",
        source => "",
        format => "gcc",
        opts   => ["-O3"],
    },
);

eval_test(
    "gcc call, global",
    sub {
        _unpack_deep Patcher::gcc("
            void foo();
            void bar() {
                foo();
            }
        ",
            "-O2",
        );
    },
    compare => {
        %$obj_common,
        bytes    => "e9 fc ff ff ff ",    # optimizer turns call to jump, no ret
        link_rel => { 1 => "foo-4" },
        globals  => { bar => 0 },
    },
);

eval_test(
    "gcc data, data ref, global",
    sub {
        _unpack_deep Patcher::gcc("
            extern char const * var;
            void bar() {
                var = \"9\";
            }
        ",
            "-O2",
        );
    },
    compare => {
        %$obj_common,
        bytes     => "c7 05 00 00 00 00 00 00 00 00 c3 39 00 ",
        link_self => { 6 => 11 },
        link_abs  => { 2 => 'var' },
        globals   => { bar => 0 },
    },
);

# add_symbol from 32
eval_test(
    "add_symbol",
    sub {
        Patcher::add_symbol(
            section => ".text",
            name    => 'X',
            off     => 3,
        );
        $Patcher::ctx;
    },
    compare => {
        common_settings,
        settings       => ignore,
        symbol_offset  => { X => 3 },
        symbol_section => { X => '.text' },
    },
);

eval_test(
    "add_symbol conflict",
    sub {
        Patcher::modify_context(symbol_offset => { X => 4 });
        Patcher::add_symbol(
            section => ".text",
            name    => 'X',
            off     => 3,
        );
    },
    catch => qr/'X' is already defined/,
);

eval_test(
    "patch no desc",
    sub {
        Patcher::patch();
    },
    catch => qr/every patch needs description/,
);

eval_test(
    "patch no chunks",
    sub {
        Patcher::patch(desc => "p1");
    },
    catch => qr/no cchunk or pchunk/,
);

eval_test(
    "patch cchunk -coff",
    sub {
        Patcher::patch(
            desc   => "p1",
            cchunk => "",
        );
    },
    catch => qr/coff is not defined/,
);

eval_test(
    "patch coff -cchunk",
    sub {
        Patcher::patch(
            desc => "p1",
            coff => 0,
        );
    },
    catch => qr/no cchunk present, specifying coff makes no sense/,
);

eval_test(
    "patch build failure",
    sub {
        Patcher::patch(
            desc   => "p1",
            coff   => 0,
            cchunk => "#ghc#",
        );
    },
    catch => qr/unknown format ghc/,
);

eval_test(
    "patch empty cchunk",
    sub {
        Patcher::patch(
            desc   => "p1",
            cchunk => " ",
            coff   => 0,
        );
    },
    catch => qr/empty cchunk makes no sense/,
);

eval_test(
    "patch pchunk build failure",
    sub {
        Patcher::patch(
            desc   => "p1",
            pchunk => "#go#",
            poff   => 0,
        );
    },
    catch => qr/unknown format go/,
);

eval_test(
    "patch poff -pchunk",
    sub {
        Patcher::patch(
            desc   => "p1",
            cchunk => "90",
            off    => 1,
            poff   => 0,
        );
    },
    catch => qr/no pchunk present, specifying poff makes no sense/,
);

eval_test(
    "patch cchunk",
    sub {
        Patcher::patch(
            desc   => "p1",
            cchunk => "61",
            coff   => 3,
        );
        _unpack_deep $Patcher::ctx->{patches};
    },
    compare => [
        {
            cchunk => { bytes => "61 ", format => "hex", source => "61" },
            coff   => 3,
            desc   => "p1",
        },
    ],
);

eval_test(
    "patch cchunk check",
    sub {
        Patcher::modify_context(input_bytes => "ABC");
        Patcher::patch(
            desc   => "p",
            cchunk => "42",
            coff   => 1,
        );
        Patcher::apply_and_save();
    },
    compare => ignore
);

eval_test(
    "patch intersection",
    sub {
        Patcher::modify_context(input_bytes => "ABC");
        Patcher::patch(
            desc   => "1",
            cchunk => "4142",
            pchunk => "0000",
            off    => 0,
        );
        Patcher::patch(
            desc   => "2",
            cchunk => "4243",
            pchunk => "0000",
            off    => 1,
        );
        Patcher::apply_and_save();
    },
    catch => qr/patches 1 and 2 intersect/,
);

eval_test(
    "patch fill_nop no cchunk throws",
    sub {
        Patcher::modify_context(input_bytes => "ABC");
        Patcher::patch(
            desc     => "p",
            pchunk   => "",
            fill_nop => 1,
        );
        Patcher::apply_and_save();
        unpack("H*", $Patcher::ctx->{input_bytes});
    },
    catch => qr/no cchunk present/,
);

eval_test(
    "patch fill_nop",
    sub {
        Patcher::modify_context(input_bytes => "ABC");
        Patcher::patch(
            desc     => "p",
            cchunk   => "42",
            coff     => 1,
            fill_nop => 1,
        );
        Patcher::apply_and_save();
        unpack("H*", $Patcher::ctx->{input_bytes});
    },
    compare => "419043",
);

eval_test(
    "patch empty pchunk + coff throws",
    sub {
        Patcher::modify_context(input_bytes => "ABC");
        Patcher::patch(
            desc   => "p",
            cchunk => "42",
            pchunk => "",
            coff   => 1,
        );
        Patcher::apply_and_save();
        unpack("H*", $Patcher::ctx->{input_bytes});
    },
    catch => qr/no poff when both cchunk and pchunk are present/,
);

eval_test(
    "patch empty pchunk + coff + fill_nop throws",
    sub {
        Patcher::modify_context(input_bytes => "ABC");
        Patcher::patch(
            desc     => "p",
            cchunk   => "42",
            fill_nop => 1,
            pchunk   => "",
            coff     => 1,
        );
        Patcher::apply_and_save();
        unpack("H*", $Patcher::ctx->{input_bytes});
    },
    catch => qr/no poff when both cchunk and pchunk are present/,
);

eval_test(
    "patch pchunk + coff + fill_nop",
    sub {
        Patcher::modify_context(input_bytes => "ABC");
        Patcher::patch(
            desc     => "p",
            cchunk   => "42 43",
            off      => 1,
            fill_nop => 1,
            pchunk   => "00",
        );
        Patcher::apply_and_save();
        unpack("H*", $Patcher::ctx->{input_bytes});
    },
    compare => "410090",
);

eval_test(
    "patch pchunk + poff + coff + fill_nop",
    sub {
        Patcher::modify_context(input_bytes => "ABC ");
        Patcher::patch(
            desc     => "p",
            cchunk   => "41 42 43",
            coff     => 0,
            poff     => 1,
            fill_nop => 1,
            pchunk   => "aa",
        );
        Patcher::apply_and_save();
        Patcher::_hexdump($Patcher::ctx->{input_bytes});
    },
    compare => "41 aa 90 20 ",
);

eval_test(
    "patch cchunk out of range",
    sub {
        Patcher::modify_context(input_bytes => "zxc");
        Patcher::patch(
            desc   => "p",
            cchunk => "aa bb",
            coff   => 2,
        );
        Patcher::apply_and_save();
    },
    catch => qr/attempt to check range.*not inside source file/,
);

eval_test(
    "patch pchunk before cchunk",
    sub {
        Patcher::modify_context(input_bytes => "zxc");
        Patcher::patch(
            desc   => "p",
            cchunk => "aa bb",
            coff   => 1,
            pchunk => "cc dd",
            poff   => 0,
        );
        Patcher::apply_and_save();
    },
    catch => qr/cchunk starts after pchunk/,
);

eval_test(
    "patch pchunk after cchunk",
    sub {
        Patcher::modify_context(input_bytes => "zxc");
        Patcher::patch(
            desc   => "p",
            cchunk => "aa bb",
            coff   => 0,
            pchunk => "cc dd",
            poff   => 1,
        );
        Patcher::apply_and_save();
    },
    catch => qr/cchunk ends before pchunk/,
);

eval_test(
    "patch free pchunk no pspace throws",
    sub {
        Patcher::modify_context(input_bytes => "ABC ");
        Patcher::patch(
            desc   => "p",
            pchunk => "aa",
        );
        Patcher::apply_and_save();
        Patcher::_hexdump($Patcher::ctx->{input_bytes});
    },
    catch => qr/unable to place, pspace_off is not defined/,
);

eval_test(
    "patch free pchunk out of pspace",
    sub {
        Patcher::modify_context(
            input_bytes => "ABC ",
            pspace_off  => 1,
            pspace_len  => 2,
        );
        Patcher::patch(
            desc   => "p",
            pchunk => "aa bb cc",
        );
        Patcher::apply_and_save();
        Patcher::_hexdump($Patcher::ctx->{input_bytes});
    },
    catch => qr/no free patch space left for patch/,
);

eval_test(
    "link call loop",
    sub {
        Patcher::modify_context(
            input_bytes => "\0" x 10,
            pspace_off  => 0,
            pspace_len  => 10,
        );
        Patcher::patch(
            desc   => "add foo",
            pchunk => "#gas# call bar",
            name   => "foo",
        );
        Patcher::patch(
            desc   => "add bar",
            pchunk => "#gas# call foo",
            name   => "bar",
        );
        Patcher::apply_and_save();
        _unpack_deep $Patcher::ctx;
    },
    compare => superhashof({ input_bytes => "e8 00 00 00 00 e8 f6 ff ff ff " }),
);

eval_test(
    "link var loop",
    sub {
        Patcher::modify_context(
            input_bytes => "\0" x 10,
            pspace_off  => 0,
            pspace_len  => 10,
        );
        Patcher::patch(
            desc   => "add foo",
            pchunk => "#gas# push offset bar",
            name   => "foo",
        );
        Patcher::patch(
            desc   => "add bar",
            pchunk => "#gas# push offset foo",
            name   => "bar",
        );
        Patcher::apply_and_save();
        _unpack_deep $Patcher::ctx;
    },
    compare => superhashof({ input_bytes => "68 05 00 00 00 68 00 00 00 00 " }),
);

# the final boss of a test
{
    my $file_header = Patcher::_pack_hex("112233");

    my $text_off   = length $file_header;
    my $text_len   = 0x1000;
    my $text_vbase = 0;

    my $data_off   = $text_off + $text_len;
    my $data_len   = 0x500;
    my $data_vbase = 0x1000;

    my $default_off = 0x20000;
    my $actual_off  = 0x30000;

    my $var_ref_dseg = 4;                           # in .text
    my $var_ref_off  = $text_off + $var_ref_dseg;

    my $var_loc_dseg   = 8;                                           # in .data
    my $var_loc_actual = $data_vbase + $actual_off + $var_loc_dseg;

    my $pspace_off = 16 + $text_off;
    my $pspace_len = $data_off - $pspace_off - 32;

    my $var2_dseg = 0x44;                                             # in .data

    eval_test(
        "relocator",
        sub {
            Patcher::modify_context(
                input_bytes => $file_header . "\0" x ($text_len + $data_len),
                pspace_off  => $pspace_off,
                pspace_len  => $pspace_len,
                section_base => {
                    ".text" => $text_vbase + $default_off,
                    ".data" => $data_vbase + $default_off,
                },
                section_offset => {
                    ".text" => $text_off,
                    ".data" => $data_off,
                },

                "settings relocator" => "proc_reloc",
                data_bootstrap_ptr   => $text_off + $var_ref_dseg,
                data_bootstrap_var   => $data_off + $var_loc_dseg,
            );
            Patcher::patch(
                desc   => "add fake bootstrap",
                pchunk => "#gas# .int $var_loc_actual",
                poff   => $var_ref_off,
            );
            Patcher::patch(
                desc   => "add push self",
                pchunk => "#gas#
                    msg:
                        push offset msg + 4
                ",
            );
            Patcher::add_symbol(
                section => ".data",
                name    => "var2",
                off     => $data_off + $var2_dseg
            );
            Patcher::patch(
                desc   => "add push var2",
                pchunk => "#gas#
                        push offset var2
                ",
            );
            Patcher::apply_and_save();

            my $li = $Patcher::ctx->{patches}[-1]{pchunk}{listing};

            # diag($li);

            my $ch = _unpack_deep($Patcher::ctx)->{input_bytes};
            $ch =~ s/(00 )+$//;
            return $ch;
        },
        compare => re(
            "11 22 33 "                # header
                . "00 " x 4            # skip till var_ref_dseg
                . "08 10 03 00 "       # pointer to var_loc_actual
                . "00 " x 8            # skip before pspace
                . "68 14 00 02 00 "    # push pointer to itself + 4
                . "68 44 10 02 00 "    # push pointer to var2 in .data
                . ".* c3 "             # relocator
                . "11 00 00 00 "       # relocation at .text+0x11
                . "14 00 00 00 "       #  referring to .text+0x14
                . "16 00 00 00 "       # relocation at .text+0x15
                . "44 "                #  referring to .data+0x44
        ),
    );
}

# TODO multiple sections
# TODO multiple definitions
# TODO linking conflicts
# TODO undefined symbol
