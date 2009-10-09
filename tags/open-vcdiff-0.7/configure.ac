## Process this file with autoconf to produce configure.
## In general, the safest way to proceed is to run ./autogen.sh

# make sure we're interpreted by some minimal autoconf
AC_PREREQ(2.57)

AC_INIT(open-vcdiff, 0.7, opensource@google.com)
AC_CONFIG_SRCDIR(README)
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(src/config.h)

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_CXX
AM_CONDITIONAL(GCC, test "$GCC" = yes)   # let the Makefile know if we're gcc
AC_CANONICAL_HOST

# Issue #21:  Fail to test on MinGW 5.1.4
# Disabling fast install keeps libtool from creating wrapper scripts around
# the executables it builds.  Such scripts have caused failures on MinGW.
# Using this option means an extra link step is executed during "make install".
AC_DISABLE_FAST_INSTALL

AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

# Check whether some low-level functions/files are available
AC_HEADER_STDC

# Built-in memcmp can be inefficient when gcc compiles for x86 processors.
# In those cases, use an alternative function instead of memcmp.
case $host_cpu in
  *86*)
    if test "$GCC" = "yes"; then
      AC_DEFINE(VCDIFF_USE_BLOCK_COMPARE_WORDS, 1,
                Use custom compare function instead of memcmp)
    fi
    ;;
esac

AC_CHECK_HEADERS([ext/rope])
AC_CHECK_HEADERS([getopt.h])
AC_CHECK_HEADERS([malloc.h])
AC_CHECK_HEADERS([sys/mman.h])
AC_CHECK_HEADERS([sys/time.h])
AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([windows.h])
AC_CHECK_FUNCS([gettimeofday QueryPerformanceCounter])
AC_CHECK_FUNCS([memalign posix_memalign])
AC_CHECK_FUNCS([mprotect])

# Start of definitions needed by gflags package

AC_CHECK_HEADERS([stdint.h sys/types.h inttypes.h])
AC_CHECK_HEADERS([fnmatch.h])
AC_CHECK_FUNCS([strtoll strtoq])
AC_CHECK_TYPES([uint16_t, u_int16_t, __int16])

AX_C___ATTRIBUTE__

# End of definitions needed by gflags package

# Solaris 10 6/06 has a bug where /usr/sfw/lib/libstdc++.la is empty.
# If so, we replace it with our own version.
LIBSTDCXX_LA_LINKER_FLAG=
if test -f /usr/sfw/lib/libstdc++.la && ! test -s /usr/sfw/lib/libstdc++.la
then
  LIBSTDCXX_LA_LINKER_FLAG='-L$(top_srcdir)/src/solaris'
fi
AC_SUBST(LIBSTDCXX_LA_LINKER_FLAG)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
