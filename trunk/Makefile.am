## Process this file with automake to produce Makefile.in

# Make sure that when we re-make ./configure, we get the macros we need
# ACLOCAL_AMFLAGS = -I m4

# This is so we can #include <google/foo>
AM_CPPFLAGS = -I$(top_srcdir)/src

# For a non-optimized (debug) build, change "-DNDEBUG" to "-DDEBUG".
AM_CXXFLAGS = -DNDEBUG -DNO_THREADS

# Enable verbose gcc warnings.  We use the older option name "-W" to be
# compatible with gcc v3.3 and earlier.  That option should be changed to
# "-Wextra" when we can be sure that early gcc versions will not be used.
if GCC
AM_CXXFLAGS += -Wall -Wwrite-strings -Woverloaded-virtual -W
endif

AM_LDFLAGS = -no-undefined $(LIBSTDCXX_LA_LINKER_FLAG)

googleincludedir = $(includedir)/google
## The .h files you want to install (that is, .h files that people
## who install this package can include in their own applications.)
googleinclude_HEADERS = src/google/vcdecoder.h src/google/vcencoder.h \
			src/google/output_string.h

docdir = $(prefix)/share/doc/$(PACKAGE)-$(VERSION)
dist_doc_DATA = AUTHORS COPYING ChangeLog INSTALL NEWS README THANKS \
		src/gtest/README

# The manual pages that should be installed
dist_man1_MANS = man/vcdiff.1

## The libraries (.so's) you want to build and install
lib_LTLIBRARIES =

## Binaries to be built and installed; these are added in the RULES section
bin_PROGRAMS =

## Binary and script unit tests you want to run when people type 'make check'.
## Tests are added one by one to these lists in the RULES sections.
check_PROGRAMS =
check_SCRIPTS =

## Other binaries, scripts, and libraries that are built but not automatically
## installed.
noinst_PROGRAMS =
noinst_SCRIPTS =
noinst_LTLIBRARIES =

## vvvv RULES TO MAKE THE LIBRARIES, BINARIES, AND UNITTESTS

# google-gflags: Used for command-line client
#     Please refer to http://code.google.com/p/google-gflags/ for details
noinst_LTLIBRARIES += libgflags.la
libgflags_la_SOURCES = src/gflags/gflags.h \
		       src/mutex.h \
		       src/gflags.cc \
		       src/gflags_reporting.cc

# gtest (Google Test): Used for unit tests only
#     Please refer to http://code.google.com/p/googletest/ for details
noinst_LTLIBRARIES += libgtest.la
libgtest_la_SOURCES = src/gtest/gtest.h \
		      src/gtest/gtest-death-test.h \
		      src/gtest/gtest-message.h \
		      src/gtest/gtest_pred_impl.h \
		      src/gtest/gtest-spi.h \
		      src/gtest/gtest_prod.h \
		      src/gtest/internal/gtest-death-test-internal.h \
		      src/gtest/internal/gtest-filepath.h \
		      src/gtest/internal/gtest-internal.h \
		      src/gtest/internal/gtest-port.h \
		      src/gtest/internal/gtest-string.h \
		      src/gtest/src/gtest-internal-inl.h \
		      src/gtest/gtest.cc \
		      src/gtest/gtest-death-test.cc \
		      src/gtest/gtest-filepath.cc \
		      src/gtest/gtest-port.cc \
		      src/testing.h

noinst_LTLIBRARIES += libgtest_main.la
libgtest_main_la_SOURCES = src/gtest/gtest_main.cc
libgtest_main_la_LIBADD = libgtest.la

noinst_LTLIBRARIES += libvcdecoder_test_common.la
libvcdecoder_test_common_la_SOURCES = src/vcdecoder_test.h \
				      src/vcdecoder_test.cc
libvcdecoder_test_common_la_LIBADD = libvcddec.la libgtest_main.la

# libvcdcom: The open-vcdiff *common* library
lib_LTLIBRARIES += libvcdcom.la
libvcdcom_la_SOURCES = src/google/output_string.h \
		       src/addrcache.h \
		       src/checksum.h \
		       src/codetable.h \
		       src/logging.h \
		       src/varint_bigendian.h \
		       src/vcdiff_defs.h \
		       src/zlib.h \
		       src/zconf.h \
		       src/adler32.c \
		       src/addrcache.cc \
		       src/codetable.cc \
		       src/logging.cc \
		       src/varint_bigendian.cc

# libvcddec: The open-vcdiff *decoder* library
lib_LTLIBRARIES += libvcddec.la
libvcddec_la_SOURCES = src/google/vcdecoder.h \
		       src/decodetable.h \
		       src/headerparser.h \
		       src/decodetable.cc \
		       src/headerparser.cc \
		       src/vcdecoder.cc
libvcddec_la_LIBADD = libvcdcom.la

# libvcdenc: The open-vcdiff *encoder* library
lib_LTLIBRARIES += libvcdenc.la
libvcdenc_la_SOURCES = src/google/vcencoder.h \
		       src/blockhash.h \
		       src/codetablewriter_interface.h \
		       src/compile_assert.h \
		       src/encodetable.h \
		       src/instruction_map.h \
		       src/rolling_hash.h \
		       src/vcdiffengine.h \
		       src/blockhash.cc \
		       src/encodetable.cc \
		       src/instruction_map.cc \
		       src/vcdiffengine.cc \
                       src/vcencoder.cc
libvcdenc_la_LIBADD = libvcdcom.la

bin_PROGRAMS += vcdiff
vcdiff_SOURCES = src/vcdiff_main.cc
vcdiff_LDADD = libvcddec.la libvcdenc.la libgflags.la

check_PROGRAMS += addrcache_test
addrcache_test_SOURCES = src/addrcache_test.cc
addrcache_test_LDADD = libvcdcom.la libgtest_main.la

check_PROGRAMS += blockhash_test
blockhash_test_SOURCES = src/blockhash_test.cc
blockhash_test_LDADD = libvcdenc.la libgtest_main.la

check_PROGRAMS += codetable_test
codetable_test_SOURCES = src/codetable_test.cc
codetable_test_LDADD = libvcdcom.la libgtest_main.la

check_PROGRAMS += decodetable_test
decodetable_test_SOURCES = src/decodetable_test.cc
decodetable_test_LDADD = libvcddec.la libgtest_main.la

check_PROGRAMS += encodetable_test
encodetable_test_SOURCES = src/encodetable_test.cc
encodetable_test_LDADD = libvcdenc.la libgtest_main.la

check_PROGRAMS += headerparser_test
headerparser_test_SOURCES = src/headerparser_test.cc
headerparser_test_LDADD = libvcddec.la libgtest_main.la

check_PROGRAMS += instruction_map_test
instruction_map_test_SOURCES = src/instruction_map_test.cc
instruction_map_test_LDADD = libvcdenc.la libgtest_main.la

check_PROGRAMS += output_string_test
output_string_test_SOURCES = src/output_string_crope.h \
			     src/output_string_test.cc
output_string_test_LDADD = libgtest_main.la

check_PROGRAMS += rolling_hash_test
rolling_hash_test_SOURCES = src/rolling_hash_test.cc
rolling_hash_test_LDADD = libvcdcom.la libgtest_main.la

check_PROGRAMS += varint_bigendian_test
varint_bigendian_test_SOURCES = src/varint_bigendian_test.cc
varint_bigendian_test_LDADD = libvcdcom.la libgtest_main.la

check_PROGRAMS += vcdecoder1_test
vcdecoder1_test_SOURCES = src/vcdecoder1_test.cc
vcdecoder1_test_LDADD = libvcdecoder_test_common.la

check_PROGRAMS += vcdecoder2_test
vcdecoder2_test_SOURCES = src/vcdecoder2_test.cc
vcdecoder2_test_LDADD = libvcdecoder_test_common.la

check_PROGRAMS += vcdecoder3_test
vcdecoder3_test_SOURCES = src/vcdecoder3_test.cc
vcdecoder3_test_LDADD = libvcdecoder_test_common.la

check_PROGRAMS += vcdecoder4_test
vcdecoder4_test_SOURCES = src/vcdecoder4_test.cc
vcdecoder4_test_LDADD = libvcdecoder_test_common.la

check_PROGRAMS += vcdecoder5_test
vcdecoder5_test_SOURCES = src/vcdecoder5_test.cc
vcdecoder5_test_LDADD = libvcdecoder_test_common.la

check_PROGRAMS += vcdiffengine_test
vcdiffengine_test_SOURCES = src/vcdiffengine_test.cc
vcdiffengine_test_LDADD = libvcdenc.la libgtest_main.la

check_PROGRAMS += vcencoder_test
vcencoder_test_SOURCES = src/vcencoder_test.cc
vcencoder_test_LDADD = libvcddec.la libvcdenc.la libgtest_main.la

check_SCRIPTS += src/vcdiff_test.sh
dist_noinst_DATA = testdata/configure.ac.v0.1 \
                   testdata/configure.ac.v0.2 \
                   testdata/allocates_4gb.vcdiff

## ^^^^ END OF RULES TO MAKE THE LIBRARIES, BINARIES, AND UNITTESTS

TESTS = $(check_PROGRAMS) $(check_SCRIPTS)
## TESTS_ENVIRONMENT sets environment variables for when you run unit tests,
## but it only seems to take effect for *binary* unit tests (argh!)
TESTS_ENVIRONMENT = SRCDIR="$(top_srcdir)"

rpm: dist-gzip packages/rpm.sh packages/rpm/rpm.spec
	@cd packages && ./rpm.sh ${PACKAGE} ${VERSION}

deb: dist-gzip packages/deb.sh packages/deb/*
	@cd packages && ./deb.sh ${PACKAGE} ${VERSION}

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

EXTRA_DIST = $(check_SCRIPTS) \
	     autogen.sh \
	     packages/rpm.sh \
	     packages/rpm/rpm.spec \
	     packages/deb.sh \
	     packages/deb \
	     src/solaris/libstdc++.la \
	     testdata/empty_file.txt \
	     vsprojects/config.h \
	     vsprojects/stdint.h \
	     vsprojects/vcdiff_test.bat \
	     vsprojects/open-vcdiff.sln \
	     vsprojects/addrcache_test/addrcache_test.vcproj \
	     vsprojects/blockhash_test/blockhash_test.vcproj \
	     vsprojects/codetable_test/codetable_test.vcproj \
	     vsprojects/decodetable_test/decodetable_test.vcproj \
	     vsprojects/encodetable_test/encodetable_test.vcproj \
	     vsprojects/gtest/gtest.vcproj \
	     vsprojects/headerparser_test/headerparser_test.vcproj \
	     vsprojects/instruction_map_test/instruction_map_test.vcproj \
	     vsprojects/output_string_test/output_string_test.vcproj \
	     vsprojects/rolling_hash_test/rolling_hash_test.vcproj \
	     vsprojects/varint_bigendian_test/varint_bigendian_test.vcproj \
	     vsprojects/vcdcom/vcdcom.vcproj \
	     vsprojects/vcddec/vcddec.vcproj \
	     vsprojects/vcdecoder1_test/vcdecoder1_test.vcproj \
	     vsprojects/vcdecoder2_test/vcdecoder2_test.vcproj \
	     vsprojects/vcdecoder3_test/vcdecoder3_test.vcproj \
	     vsprojects/vcdecoder4_test/vcdecoder4_test.vcproj \
	     vsprojects/vcdecoder5_test/vcdecoder5_test.vcproj \
	     vsprojects/vcdenc/vcdenc.vcproj \
	     vsprojects/vcdiff/vcdiff.vcproj \
	     vsprojects/vcdiffengine_test/vcdiffengine_test.vcproj \
	     vsprojects/vcdiff_test/vcdiff_test.vcproj \
	     vsprojects/vcencoder_test/vcencoder_test.vcproj
