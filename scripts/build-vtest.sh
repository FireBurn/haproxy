#!/bin/sh

set -eux

curl -fsSL "https://code.vinyl-cache.org/vtest/VTest2/archive/main.tar.gz" -o VTest.tar.gz
mkdir ../vtest
tar xvf VTest.tar.gz -C ../vtest --strip-components=1
# Special flags due to: https://github.com/vtest/VTest/issues/12

# Note: do not use "make -C ../vtest", otherwise MAKEFLAGS contains "w"
# and fails (see Options/Recursion in GNU Make doc, it contains the list
# of options without the leading '-').
# MFLAGS works on BSD but misses variable definitions on GNU Make.
# Better just avoid the -C and do the cd ourselves then.

cd ../vtest

make FLAGS="-O2 -s -Wall"
