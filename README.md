Patcher
=======

Patcher.pm is a perl module that simplifies creation of binary patches for
executables. Individual patches are specified in config-like .pl files as
binary, assembly or C code, the patcher takes care of compiling, linking and
storing them inside the target executable.  It should work on any recent Linux
system and bin/patcher.exe is a Windows version made with perl packer. It is
primarily targeted at older DOS executables where you may not have an option of
using dynamic library and have to fit the patch into original file.

License
-------

This program is free software, you can redistribute and/or modify it under the
terms of [GPLv3 license](LICENSE). It directly includes parts of
[GCC](https://gcc.gnu.org/), as binaries shipped with
[MinGW](http://www.mingw.org) and [Strawberry Perl](http://strawberryperl.com/)
projects. The source code for those projects can be found on their respective
websites.

Authors
-------

Written by Alexey Svirchevsky.
