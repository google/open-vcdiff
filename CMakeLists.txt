CMAKE_MINIMUM_REQUIRED(VERSION 2.8.13)

# Configuration options
option(vcdiff_build_tests "Build all of vcdiff tests." ON)
option(vcdiff_build_exec "Build vcdiff exectuable" ON)

# Add subprojects first so we won't interfere with config.h.in

IF (vcdiff_build_exec)
  SET(GFLAGS_BUILD_gflags_LIB OFF)
  SET(GFLAGS_BUILD_gflags_nothreads_LIB ON)
  SET(GFLAGS_INSTALL_HEADERS OFF)
  SET(GFLAGS_INSTALL_SHARED_LIBS OFF)
  SET(GFLAGS_INSTALL_STATIC_LIBS OFF)
  ADD_SUBDIRECTORY(gflags)
ENDIF()

IF (vcdiff_build_tests)
  SET(gtest_install OFF CACHE BOOL "Don't install gtest" FORCE)
  ADD_SUBDIRECTORY(googletest/googletest)
ENDIF()

PROJECT(open-vcdiff)
SET(PROJECT_VERSION 1.0)
SET(PROJECT_SOVERSION 1)

INCLUDE(CheckIncludeFiles)
CHECK_INCLUDE_FILES(ext/rope HAVE_EXT_ROPE)
CHECK_INCLUDE_FILES(getopt.h HAVE_GETOPT_H)
CHECK_INCLUDE_FILES(malloc.h HAVE_MALLOC_H)
CHECK_INCLUDE_FILES(sys/mman.h HAVE_SYS_MMAN_H)
CHECK_INCLUDE_FILES(sys/time.h HAVE_SYS_TIME_H)
CHECK_INCLUDE_FILES(unistd.h HAVE_UNISTD_H)
CHECK_INCLUDE_FILES(windows.h HAVE_WINDOWS_H)

INCLUDE(CheckFunctionExists)
CHECK_FUNCTION_EXISTS(gettimeofday HAVE_GETTIMEOFDAY)
CHECK_FUNCTION_EXISTS(QueryPerformanceCounter HAVE_QUERYPERFORMANCECOUNTER)
CHECK_FUNCTION_EXISTS(memalign HAVE_MEMALIGN)
CHECK_FUNCTION_EXISTS(posix_memalign HAVE_POSIX_MEMALIGN)
CHECK_FUNCTION_EXISTS(mprotect HAVE_MPROTECT)

CONFIGURE_FILE(${PROJECT_SOURCE_DIR}/src/config.h.in ${PROJECT_BINARY_DIR}/config.h)
INCLUDE_DIRECTORIES("${PROJECT_BINARY_DIR}")

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src)
INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/zlib)

SET(VCDCOM_SRC
  "src/google/format_extension_flags.h"
  "src/google/output_string.h"
  "src/addrcache.h"
  "src/checksum.h"
  "src/codetable.h"
  "src/logging.h"
  "src/unique_ptr.h"
  "src/varint_bigendian.h"
  "src/vcdiff_defs.h"
  "src/zlib/zlib.h"
  "src/zlib/zconf.h"
  "src/zlib/adler32.c"
  "src/addrcache.cc"
  "src/codetable.cc"
  "src/logging.cc"
  "src/varint_bigendian.cc"
)
ADD_LIBRARY(vcdcom "" ${VCDCOM_SRC})
ADD_LIBRARY(vcdcom_shared "SHARED" ${VCDCOM_SRC})
SET_TARGET_PROPERTIES(vcdcom_shared PROPERTIES
  OUTPUT_NAME vcdcom
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_SOVERSION})

SET(VCDDEC_SRC
  "src/decodetable.cc"
  "src/headerparser.cc"
  "src/vcdecoder.cc"
)
ADD_LIBRARY(vcddec "" ${VCDDEC_SRC})
TARGET_LINK_LIBRARIES(vcddec vcdcom)
ADD_LIBRARY(vcddec_shared "SHARED" ${VCDDEC_SRC})
SET_TARGET_PROPERTIES(vcddec_shared PROPERTIES
  OUTPUT_NAME vcddec
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_SOVERSION})
TARGET_LINK_LIBRARIES(vcddec_shared vcdcom_shared)

SET(VCDENC_SRC
  "src/blockhash.cc"
  "src/encodetable.cc"
  "src/instruction_map.cc"
  "src/jsonwriter.cc"
  "src/vcdiffengine.cc"
  "src/vcencoder.cc"
)
ADD_LIBRARY(vcdenc "" ${VCDENC_SRC})
TARGET_LINK_LIBRARIES(vcdenc vcdcom)
ADD_LIBRARY(vcdenc_shared "SHARED" ${VCDENC_SRC})
SET_TARGET_PROPERTIES(vcdenc_shared PROPERTIES
  OUTPUT_NAME vcdenc
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_SOVERSION})
TARGET_LINK_LIBRARIES(vcdenc_shared vcdcom_shared)


INSTALL(DIRECTORY src/google DESTINATION include)
INSTALL(TARGETS vcdcom vcdenc vcddec DESTINATION lib)
INSTALL(TARGETS vcdcom_shared vcdenc_shared vcddec_shared DESTINATION lib)

IF (vcdiff_build_exec)
  ADD_EXECUTABLE(vcdiff "src/vcdiff_main.cc")
  TARGET_LINK_LIBRARIES(vcdiff vcddec vcdenc gflags)
  INSTALL(TARGETS vcdiff DESTINATION bin)
ENDIF()

if (vcdiff_build_tests)
  ENABLE_TESTING()

  ADD_LIBRARY(vcdecoder_test_common
    "src/vcdecoder_test.cc"
  )
  TARGET_LINK_LIBRARIES(vcdecoder_test_common vcddec gtest_main)


  ADD_EXECUTABLE(addrcache_test src/addrcache_test.cc)
  TARGET_LINK_LIBRARIES(addrcache_test vcdcom gtest_main)
  ADD_TEST(addrcache_test addrcache_test)

  ADD_EXECUTABLE(blockhash_test src/blockhash_test.cc)
  TARGET_LINK_LIBRARIES(blockhash_test vcdenc gtest_main)
  ADD_TEST(blockhash_test blockhash_test)

  ADD_EXECUTABLE(codetable_test src/codetable_test.cc)
  TARGET_LINK_LIBRARIES(codetable_test vcdcom gtest_main)
  ADD_TEST(codetable_test codetable_test)

  ADD_EXECUTABLE(decodetable_test src/decodetable_test.cc)
  TARGET_LINK_LIBRARIES(decodetable_test vcddec vcdcom gtest_main)
  ADD_TEST(decodetable_test decodetable_test)

  ADD_EXECUTABLE(encodetable_test src/encodetable_test.cc)
  TARGET_LINK_LIBRARIES(encodetable_test vcdenc vcdcom gtest_main)
  ADD_TEST(encodetable_test encodetable_test)

  ADD_EXECUTABLE(headerparser_test src/headerparser_test.cc)
  TARGET_LINK_LIBRARIES(headerparser_test vcddec vcdcom gtest_main)
  ADD_TEST(headerparser_test headerparser_test)

  ADD_EXECUTABLE(instruction_map_test src/instruction_map_test.cc)
  TARGET_LINK_LIBRARIES(instruction_map_test vcdenc vcdcom gtest_main)
  ADD_TEST(instruction_map_test instruction_map_test)

  ADD_EXECUTABLE(output_string_test src/output_string_test.cc)
  TARGET_LINK_LIBRARIES(output_string_test gtest_main)
  ADD_TEST(output_string_test output_string_test)

  ADD_EXECUTABLE(rolling_hash_test src/rolling_hash_test.cc)
  TARGET_LINK_LIBRARIES(rolling_hash_test vcdcom gtest_main)
  ADD_TEST(rolling_hash_test rolling_hash_test)

  ADD_EXECUTABLE(varint_bigendian_test src/varint_bigendian_test.cc)
  TARGET_LINK_LIBRARIES(varint_bigendian_test vcdcom gtest_main)
  ADD_TEST(varint_bigendian_test varint_bigendian_test)

  ADD_EXECUTABLE(vcdecoder1_test src/vcdecoder1_test.cc)
  TARGET_LINK_LIBRARIES(vcdecoder1_test vcdecoder_test_common)
  ADD_TEST(vcdecoder1_test vcdecoder1_test)

  ADD_EXECUTABLE(vcdecoder2_test src/vcdecoder2_test.cc)
  TARGET_LINK_LIBRARIES(vcdecoder2_test vcdecoder_test_common)
  ADD_TEST(vcdecoder2_test vcdecoder2_test)

  ADD_EXECUTABLE(vcdecoder3_test src/vcdecoder3_test.cc)
  TARGET_LINK_LIBRARIES(vcdecoder3_test vcdecoder_test_common)
  ADD_TEST(vcdecoder3_test vcdecoder3_test)

  ADD_EXECUTABLE(vcdecoder4_test src/vcdecoder4_test.cc)
  TARGET_LINK_LIBRARIES(vcdecoder4_test vcdecoder_test_common)
  ADD_TEST(vcdecoder4_test vcdecoder4_test)

  ADD_EXECUTABLE(vcdecoder5_test src/vcdecoder5_test.cc)
  TARGET_LINK_LIBRARIES(vcdecoder5_test vcdecoder_test_common)
  ADD_TEST(vcdecoder5_test vcdecoder5_test)

  ADD_EXECUTABLE(vcdiffengine_test src/vcdiffengine_test.cc)
  TARGET_LINK_LIBRARIES(vcdiffengine_test vcdenc vcdcom gtest_main)
  ADD_TEST(vcdiffengine_test vcdiffengine_test)

  ADD_EXECUTABLE(vcencoder_test src/vcencoder_test.cc)
  TARGET_LINK_LIBRARIES(vcencoder_test vcddec vcdenc vcdcom gtest_main)
  ADD_TEST(vcencoder_test vcencoder_test)

  ADD_EXECUTABLE(jsonwriter_test src/jsonwriter_test.cc)
  TARGET_LINK_LIBRARIES(jsonwriter_test vcdenc vcdcom gtest_main)
  ADD_TEST(jsonwriter_test jsonwriter_test)
ENDIF()  # vcdiff_build_tests
