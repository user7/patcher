use warnings;
use strict;
no warnings "experimental";

use Test::Most;
use Test::Deep;
use FindBin;
use lib "$FindBin::Bin/../lib";

$SIG{PIPE} = 'ignore';    # for watch
my @tests = (sub { use_ok("Patcher") });
sub eval_test;

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

eval_test(
    "modify_context assgin",
    sub {
        Patcher::modify_context(settings => 1)->{settings};
    },
    compare => 1,
);

# loader tests
my $bits = "$FindBin::Bin/bits";

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
    catch => qr/non-existent' - sysopen: No such file or directory/,
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
        _unpack_deep Patcher::gas("", { build_opts => ["-gstabs"] });
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
        opts   => { build_opts => [ "-defsym", "foo=0" ] },
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
    compare => superhashof(
        {
            %$obj_common, link_rel => { 1 => "print-4", },
        }
    ),
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
    compare => { %$obj_common, bytes => re("^e8 01 00 00 00 99 (00 )*") },
);

# gcc tests
eval_test(
    "gcc",
    sub {
        Patcher::gcc("")->{bytes};
    },
    compare => "",
);

eval_test(
    "gcc option",
    sub {
        _unpack_deep Patcher::gcc("", { build_opts => ["-O3"] });
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
        opts   => { build_opts => ["-O3"] },
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
            { build_opts => ["-O2"] },
        );
    },
    compare => {
        %$obj_common,
        bytes => re("e9 .. .. .. .. "),   # optimizer turns call to jump, no ret
        link_rel => { 1 => "foo-4" },
        globals => { bar => 0 },
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
            { build_opts => ["-O2"] },
        );
    },
    compare => {
        %$obj_common,
        bytes     => re("c7 05 00 00 00 00 00 00 00 00 c3 39 (00 )*"),
        link_self => { 6 => 11 },
        link_abs  => { 2 => 'var' },
        globals   => { bar => 0 },
    },
);

eval_test(
    "add_symbol rel",
    sub {
        Patcher::modify_context("section_offset .text" => 10);
        Patcher::add_symbol(
            name    => "X",
            off     => 2,
            section => ".text",
        );
        $Patcher::ctx;
    },
    compare => superhashof(
        {
            symbol_offset  => { X => 2 },
            symbol_section => { X => '.text' },
        }
    ),
);

# TODO no good seg
eval_test(
    "add_symbol abs",
    sub {
        Patcher::modify_context("settings deduce_section" => 1);
        Patcher::modify_context("section_offset .text"    => 10);
        Patcher::modify_context("section_source .text"    => "s");
        Patcher::add_symbol(
            name => "X",
            off  => 13,
        );
        $Patcher::ctx;
    },
    compare => superhashof(
        {
            symbol_offset  => { X => 3 },
            symbol_section => { X => ".text" },
        }
    ),
);

eval_test(
    "add_symbol abs mismatch",
    sub {
        Patcher::modify_context("section_offset .text" => 10);
        Patcher::add_symbol(
            name => "X",
            off  => "5",
        );
        $Patcher::ctx;
    },
    catch => qr/section was not specified or deduced/,
);

eval_test(
    "add_symbol rel mismatch",
    sub {
        Patcher::modify_context("section_offset .text" => 10);
        Patcher::modify_context("section_length .text" => 3);
        Patcher::add_symbol(
            name    => "X",
            off     => "20",
            section => ".text",
        );
        $Patcher::ctx;
    },
    catch => qr/offset 20 is too large for section .text/
);

eval_test(
    "add_symbol conflict",
    sub {
        Patcher::modify_context("section_offset .text" => 1);
        Patcher::modify_context("symbol_offset X"      => 4);
        Patcher::add_symbol(
            name    => "X",
            off     => "3",
            section => ".text",
        );
    },
    catch => qr/X is already defined/,
);

eval_test(
    "patch no desc",
    sub {
        Patcher::patch();
    },
    catch => qr/desc is required/,
);

eval_test(
    "patch no chunks",
    sub {
        Patcher::patch(desc => "p1");
    },
    catch => qr/no cchunk or pchunk/,
);

eval_test(
    "patch cchunk -off",
    sub {
        Patcher::patch(
            desc   => "p1",
            cchunk => "",
        );
    },
    catch => qr/off is not defined/,
);

eval_test(
    "patch off -cchunk",
    sub {
        Patcher::patch(
            desc => "p1",
            off  => 0,
        );
    },
    catch => qr/no cchunk or pchunk/,
);

eval_test(
    "patch cchunk build failure",
    sub {
        Patcher::patch(
            desc   => "p1",
            cchunk => "#ghc#",
            off    => 0,
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
            off    => 0,
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
            off    => 0,
        );
    },
    catch => qr/unknown format go/,
);

eval_test(
    "patch cchunk",
    sub {
        Patcher::modify_context("section_offset .text" => 1);
        Patcher::patch(
            desc    => "p1",
            cchunk  => "61",
            off     => 3,
            section => ".text",
        );
        _unpack_deep $Patcher::ctx->{patches};
    },
    compare => [
        {
            cchunk      => { bytes => "61 ", format => "hex", source => "61" },
            off         => 3,
            off_section => 3,
            desc        => "p1",
            section     => ".text",
        },
    ],
);

eval_test(
    "patch cchunk check",
    sub {
        Patcher::modify_context("source_bytes s"       => "ABC");
        Patcher::modify_context("section_source .text" => "s");
        Patcher::modify_context("section_offset .text" => 0);
        Patcher::patch(
            desc    => "p",
            cchunk  => "42",
            off     => 1,
            section => ".text",

        );
        Patcher::link_apply_save();
    },
    compare => ignore
);

eval_test(
    "patch intersection",
    sub {
        Patcher::modify_context("source_bytes s"       => "ABC");
        Patcher::modify_context("section_source .text" => "s");
        Patcher::modify_context("section_offset .text" => 0);
        Patcher::patch(
            desc    => "1",
            cchunk  => "4142",
            pchunk  => "0000",
            off     => 0,
            section => ".text",
        );
        Patcher::patch(
            desc    => "2",
            cchunk  => "4243",
            pchunk  => "0000",
            off     => 1,
            section => ".text",
        );
        Patcher::link_apply_save();
    },
    catch => qr/patches '1' and '2' intersect/,
);

eval_test(
    "patch fill_nop no cchunk throws",
    sub {
        Patcher::modify_context("source_bytes s" => "ABC");
        Patcher::patch(
            desc     => "p",
            pchunk   => "",
            fill_nop => 1,
        );
        Patcher::link_apply_save();
        unpack("H*", $Patcher::ctx->{input_bytes});
    },
    catch => qr/no cchunk present/,
);

eval_test(
    "patch fill_nop",
    sub {
        Patcher::modify_context("section_offset .text" => 0);
        Patcher::modify_context("section_source .text" => "s");
        Patcher::modify_context("source_bytes s"       => "ABC");
        Patcher::patch(
            desc     => "p",
            cchunk   => "42",
            off      => 1,
            fill_nop => 1,
            section  => ".text",
        );
        Patcher::link_apply_save();
        unpack("H*", $Patcher::ctx->{source_bytes}{s});
    },
    compare => "419043",
);

eval_test(
    "patch pchunk + off + fill_nop",
    sub {
        Patcher::modify_context(default_source   => "s");
        Patcher::modify_context("source_bytes s" => "ABC");
        Patcher::patch(
            desc     => "p",
            cchunk   => "42 43",
            off      => 1,
            fill_nop => 1,
            pchunk   => "00",
        );
        Patcher::link_apply_save();
        unpack("H*", $Patcher::ctx->{source_bytes}{s});
    },
    compare => "410090",
);

eval_test(
    "patch cchunk out of range",
    sub {
        Patcher::modify_context(default_source   => "s");
        Patcher::modify_context("source_bytes s" => "zxc");
        Patcher::patch(
            desc   => "p",
            cchunk => "aa bb",
            off    => 2,
        );
        Patcher::link_apply_save();
    },
    catch => qr/attempt to check range not within source/,
);

eval_test(
    "patch pchunk after cchunk",
    sub {
        Patcher::modify_context("source_bytes s" => "zxc");
        Patcher::patch(
            desc   => "p",
            cchunk => "aa",
            pchunk => "cc dd",
            off    => 0,
        );
        Patcher::link_apply_save();
    },
    catch => qr/cchunk ends before pchunk/,
);

eval_test(
    "patch free pchunk no pspace throws",
    sub {
        Patcher::modify_context("source_bytes s"       => "zxc");
        Patcher::modify_context("section_source .text" => "s");
        Patcher::modify_context("section_offset .text" => 0);
        Patcher::patch(
            desc    => "p",
            pchunk  => "aa",
            section => ".text",
        );
        Patcher::link_apply_save();
        Patcher::_hexdump($Patcher::ctx->{source_bytes}{s});
    },
    catch => qr/unable to place '.*', no pspace/,
);

eval_test(
    "patch free pchunk out of pspace",
    sub {
        Patcher::modify_context("source_bytes s" => "ABC");
        Patcher::modify_context(
            "section_pspace_offset .text" => 1,
            "section_pspace_length .text" => 2,
        );
        Patcher::patch(
            desc    => "p",
            pchunk  => "aa bb cc",
            section => ".text",
        );
        Patcher::link_apply_save();
        Patcher::_hexdump($Patcher::ctx->{source_bytes}{s});
    },
    catch => qr/no free patch space left for patch/,
);

eval_test(
    "link call loop",
    sub {
        Patcher::modify_context(
            source_bytes          => { s       => "\0" x 10 },
            section_source        => { ".text" => "s" },
            section_offset        => { ".text" => 0 },
            section_pspace_offset => { ".text" => 0 },
            section_pspace_length => { ".text" => 10 },
        );
        Patcher::patch(
            desc    => "add foo",
            pchunk  => "#gas# call bar",
            name    => "foo",
            section => ".text",
        );
        Patcher::patch(
            desc    => "add bar",
            pchunk  => "#gas# call foo",
            name    => "bar",
            section => ".text",
        );
        Patcher::link_apply_save();
        Patcher::_hexdump($Patcher::ctx->{source_bytes}{s});
    },
    compare => "e8 00 00 00 00 e8 f6 ff ff ff ",
);

# TODO check deduce section
eval_test(
    "link var loop",
    sub {
        Patcher::modify_context(
            source_bytes          => { s       => "\0" x 10 },
            section_source        => { ".text" => "s" },
            section_offset        => { ".text" => 0 },
            section_pspace_offset => { ".text" => 0 },
            section_pspace_length => { ".text" => 10 },
        );
        Patcher::patch(
            desc    => "add foo",
            pchunk  => "#gas# push offset bar",
            name    => "foo",
            section => ".text",
        );
        Patcher::patch(
            desc    => "add bar",
            pchunk  => "#gas# push offset foo",
            name    => "bar",
            section => ".text",
        );
        Patcher::link_apply_save();
        Patcher::_hexdump($Patcher::ctx->{source_bytes}{s});
    },
    compare => "68 05 00 00 00 68 00 00 00 00 ",
);

plan tests => scalar(@tests);
$_->() for @tests;
exit 0;

# TODO big section check before apply
# TODO multiple sections
# TODO multiple definitions
# TODO linking conflicts
# TODO undefined symbol

sub dump_diag_ {
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

sub eval_test_ {
    my ($tname, $sub, $action, $check) = @_;
    my $res = eval {
        Patcher::reset_context(
            settings => {
                need_listing    => 1,
                honor_alignment => 0,
                quiet           => 1,
            },
            section_offset        => {},
            section_length        => {},
            section_base          => {},
            section_source        => {},
            section_pspace_offset => {},
            section_pspace_length => {},
            source_bytes          => {},
            source_input_file     => {},
            source_output_file    => {},
            symbol_section        => {},
            symbol_offset         => {},
            alias_symbol          => {},
            patches               => [],
            reloc_rel             => {},
            reloc_abs             => {},
            build_cache           => {},
            build_cache_usage     => {},
        );
        $sub->()
    };
    if ($action eq "catch") {
        if ($@) {
            return like($@, $check, $tname);
        } else {
            fail($tname);
            dump_diag_("expected exception, got value: ", $res);
            return 0;
        }
    }

    if ($@) {
        fail($tname);
        dump_diag_("expected value, got exception: ", $@);
        return 0;
    }

    if ($action eq "compare") {
        cmp_deeply($res, $check, $tname)
            or dump_diag_("full result was:\n", $res);
        return;
    }

    die "unknown action $action";
}

sub eval_test {
    my @args = @_;
    die "argument 3 of eval_test must be either 'catch' or 'compare', got '$args[2]'"
        if $args[2] !~ /^(catch|compare)$/;
    push (@tests, sub { eval_test_(@args) });
}
