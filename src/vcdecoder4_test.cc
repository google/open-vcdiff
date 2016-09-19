// Copyright 2008 The open-vcdiff Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <config.h>
#include "google/vcdecoder.h"
#include <string>
#include "codetable.h"
#include "testing.h"
#include "varint_bigendian.h"  // NOLINT
#include "vcdecoder_test.h"
#include "vcdiff_defs.h"  // VCD_SOURCE

namespace open_vcdiff {
namespace {

// Use the interleaved file header with the standard encoding.  Should work.
class VCDiffDecoderInterleavedAllowedButNotUsed
    : public VCDiffStandardDecoderTest {
 public:
  VCDiffDecoderInterleavedAllowedButNotUsed() {
    UseInterleavedFileHeader();
  }
  virtual ~VCDiffDecoderInterleavedAllowedButNotUsed() { }
};

TEST_F(VCDiffDecoderInterleavedAllowedButNotUsed, Decode) {
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  EXPECT_TRUE(decoder_.DecodeChunk(delta_file_.data(),
                                   delta_file_.size(),
                                   &output_));
  EXPECT_TRUE(decoder_.FinishDecoding());
  EXPECT_EQ(expected_target_.c_str(), output_);
}

TEST_F(VCDiffDecoderInterleavedAllowedButNotUsed, DecodeWithChecksum) {
  ComputeAndAddChecksum();
  InitializeDeltaFile();
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  EXPECT_TRUE(decoder_.DecodeChunk(delta_file_.data(),
                                   delta_file_.size(),
                                   &output_));
  EXPECT_TRUE(decoder_.FinishDecoding());
  EXPECT_EQ(expected_target_.c_str(), output_);
}

typedef VCDiffDecoderInterleavedAllowedButNotUsed
    VCDiffDecoderInterleavedAllowedButNotUsedByteByByte;

TEST_F(VCDiffDecoderInterleavedAllowedButNotUsedByteByByte, Decode) {
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  for (size_t i = 0; i < delta_file_.size(); ++i) {
    EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[i], 1, &output_));
  }
  EXPECT_TRUE(decoder_.FinishDecoding());
  EXPECT_EQ(expected_target_.c_str(), output_);
}

TEST_F(VCDiffDecoderInterleavedAllowedButNotUsedByteByByte,
       DecodeWithChecksum) {
  ComputeAndAddChecksum();
  InitializeDeltaFile();
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  for (size_t i = 0; i < delta_file_.size(); ++i) {
    EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[i], 1, &output_));
  }
  EXPECT_TRUE(decoder_.FinishDecoding());
  EXPECT_EQ(expected_target_.c_str(), output_);
}

// Use the standard file header with the interleaved encoding.  Should fail.
class VCDiffDecoderInterleavedUsedButNotSupported
    : public VCDiffInterleavedDecoderTest {
 public:
  VCDiffDecoderInterleavedUsedButNotSupported() {
    UseStandardFileHeader();
  }
  virtual ~VCDiffDecoderInterleavedUsedButNotSupported() { }
};

TEST_F(VCDiffDecoderInterleavedUsedButNotSupported, DecodeShouldFail) {
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  EXPECT_FALSE(decoder_.DecodeChunk(delta_file_.data(),
                                    delta_file_.size(),
                                    &output_));
  EXPECT_EQ("", output_);
}

TEST_F(VCDiffDecoderInterleavedUsedButNotSupported,
       DecodeByteByByteShouldFail) {
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  bool failed = false;
  for (size_t i = 0; i < delta_file_.size(); ++i) {
    if (!decoder_.DecodeChunk(&delta_file_[i], 1, &output_)) {
      failed = true;
      break;
    }
  }
  EXPECT_TRUE(failed);
  // The decoder should not create more target bytes than were expected.
  EXPECT_GE(expected_target_.size(), output_.size());
}

// Divides up the standard encoding into eight separate delta file windows.
// Each delta instruction appears in its own window.
class VCDiffStandardWindowDecoderTest : public VCDiffDecoderTest {
 protected:
  static const size_t kWindow2Size = 61;

  VCDiffStandardWindowDecoderTest();
  virtual ~VCDiffStandardWindowDecoderTest() {}

 private:
  static const char kWindowBody[];
};

const size_t VCDiffStandardWindowDecoderTest::kWindow2Size;

const char VCDiffStandardWindowDecoderTest::kWindowBody[] = {
// Window 1:
    VCD_SOURCE,  // Win_Indicator: take source from dictionary
    FirstByteOfStringLength(kDictionary),  // Source segment size
    SecondByteOfStringLength(kDictionary),
    '\x00',  // Source segment position: start of dictionary
    '\x08',  // Length of the delta encoding
    '\x1C',  // Size of the target window (28)
    '\x00',  // Delta_indicator (no compression)
    '\x00',  // length of data for ADDs and RUNs
    '\x02',  // length of instructions section
    '\x01',  // length of addresses for COPYs
    // No data for ADDs and RUNs
    // Instructions and sizes (length 2)
    '\x13',  // VCD_COPY mode VCD_SELF, size 0
    '\x1C',  // Size of COPY (28)
    // Addresses for COPYs (length 1)
    '\x00',  // Start of dictionary
// Window 2:
    '\x00',  // Win_Indicator: No source segment (ADD only)
    '\x44',  // Length of the delta encoding
    static_cast<char>(kWindow2Size),  // Size of the target window (61)
    '\x00',  // Delta_indicator (no compression)
    '\x3D',  // length of data for ADDs and RUNs
    '\x02',  // length of instructions section
    '\x00',  // length of addresses for COPYs
    // Data for ADD (length 61)
    ' ', 'I', ' ', 'h', 'a', 'v', 'e', ' ', 's', 'a', 'i', 'd', ' ',
    'i', 't', ' ', 't', 'w', 'i', 'c', 'e', ':', '\n',
    'T', 'h', 'a', 't', ' ',
    'a', 'l', 'o', 'n', 'e', ' ', 's', 'h', 'o', 'u', 'l', 'd', ' ',
    'e', 'n', 'c', 'o', 'u', 'r', 'a', 'g', 'e', ' ',
    't', 'h', 'e', ' ', 'c', 'r', 'e', 'w', '.', '\n',
    // Instructions and sizes (length 2)
    '\x01',  // VCD_ADD size 0
    '\x3D',  // Size of ADD (61)
    // No addresses for COPYs
// Window 3:
    VCD_TARGET,  // Win_Indicator: take source from decoded data
    '\x59',  // Source segment size: length of data decoded so far
    '\x00',  // Source segment position: start of decoded data
    '\x08',  // Length of the delta encoding
    '\x2C',  // Size of the target window
    '\x00',  // Delta_indicator (no compression)
    '\x00',  // length of data for ADDs and RUNs
    '\x02',  // length of instructions section
    '\x01',  // length of addresses for COPYs
    // No data for ADDs and RUNs
    // Instructions and sizes (length 2)
    '\x23',  // VCD_COPY mode VCD_HERE, size 0
    '\x2C',  // Size of COPY (44)
    // Addresses for COPYs (length 1)
    '\x58',  // HERE mode address (27+61 back from here_address)
// Window 4:
    VCD_TARGET,  // Win_Indicator: take source from decoded data
    '\x05',  // Source segment size: only 5 bytes needed for this COPY
    '\x2E',  // Source segment position: offset for COPY
    '\x09',  // Length of the delta encoding
    '\x07',  // Size of the target window
    '\x00',  // Delta_indicator (no compression)
    '\x02',  // length of data for ADDs and RUNs
    '\x01',  // length of instructions section
    '\x01',  // length of addresses for COPYs
    // Data for ADD (length 2)
    'h', 'r',
    // Instructions and sizes (length 1)
    '\xA7',  // VCD_ADD size 2 + VCD_COPY mode SELF size 5
    // Addresses for COPYs (length 1)
    '\x00',  // SELF mode address (start of source segment)
// Window 5:
    '\x00',  // Win_Indicator: No source segment (ADD only)
    '\x0F',  // Length of the delta encoding
    '\x09',  // Size of the target window
    '\x00',  // Delta_indicator (no compression)
    '\x09',  // length of data for ADDs and RUNs
    '\x01',  // length of instructions section
    '\x00',  // length of addresses for COPYs
    // Data for ADD (length 9)
    'W', 'h', 'a', 't', ' ', 'I', ' ', 't', 'e',
    // Instructions and sizes (length 1)
    '\x0A',       // VCD_ADD size 9
    // No addresses for COPYs
// Window 6:
    '\x00',  // Win_Indicator: No source segment (RUN only)
    '\x08',  // Length of the delta encoding
    '\x02',  // Size of the target window
    '\x00',  // Delta_indicator (no compression)
    '\x01',  // length of data for ADDs and RUNs
    '\x02',  // length of instructions section
    '\x00',  // length of addresses for COPYs
    // Data for RUN (length 1)
    'l',
    // Instructions and sizes (length 2)
    '\x00',  // VCD_RUN size 0
    '\x02',  // Size of RUN (2)
    // No addresses for COPYs
// Window 7:
    '\x00',  // Win_Indicator: No source segment (ADD only)
    '\x22',  // Length of the delta encoding
    '\x1B',  // Size of the target window
    '\x00',  // Delta_indicator (no compression)
    '\x1B',  // length of data for ADDs and RUNs
    '\x02',  // length of instructions section
    '\x00',  // length of addresses for COPYs
    // Data for ADD: 4th section (length 27)
    ' ', 'y', 'o', 'u', ' ',
    't', 'h', 'r', 'e', 'e', ' ', 't', 'i', 'm', 'e', 's', ' ', 'i', 's', ' ',
    't', 'r', 'u', 'e', '.', '\"', '\n',
    // Instructions and sizes (length 2)
    '\x01',  // VCD_ADD size 0
    '\x1B',  // Size of ADD (27)
    // No addresses for COPYs
  };

VCDiffStandardWindowDecoderTest::VCDiffStandardWindowDecoderTest() {
  UseStandardFileHeader();
  delta_window_body_.assign(kWindowBody, sizeof(kWindowBody));
}

TEST_F(VCDiffStandardWindowDecoderTest, Decode) {
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  EXPECT_TRUE(decoder_.DecodeChunk(delta_file_.data(),
                                   delta_file_.size(),
                                   &output_));
  EXPECT_TRUE(decoder_.FinishDecoding());
  EXPECT_EQ(expected_target_.c_str(), output_);
}

// Bug 1287926: If DecodeChunk() stops in the middle of the window header,
// and the expected size of the current target window is smaller than the
// cumulative target bytes decoded so far, an underflow occurs and the decoder
// tries to allocate ~MAX_INT bytes.
TEST_F(VCDiffStandardWindowDecoderTest, DecodeBreakInFourthWindowHeader) {
  // Parse file header + first two windows.
  const size_t chunk_1_size = delta_file_header_.size() + 83;
  // Parse third window, plus everything up to "Size of the target window" field
  // of fourth window, but do not parse complete header of fourth window.
  const size_t chunk_2_size = 12 + 5;
  CHECK_EQ(VCD_TARGET, static_cast<unsigned char>(delta_file_[chunk_1_size]));
  CHECK_EQ(0x00, static_cast<int>(delta_file_[chunk_1_size + chunk_2_size]));
  string output_chunk1, output_chunk2, output_chunk3;
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[0],
                                   chunk_1_size,
                                   &output_chunk1));
  EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[chunk_1_size],
                                   chunk_2_size,
                                   &output_chunk2));
  EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[chunk_1_size + chunk_2_size],
                                   delta_file_.size()
                                       - (chunk_1_size + chunk_2_size),
                                   &output_chunk3));
  EXPECT_TRUE(decoder_.FinishDecoding());
  EXPECT_EQ(expected_target_.c_str(),
            output_chunk1 + output_chunk2 + output_chunk3);
}

TEST_F(VCDiffStandardWindowDecoderTest, DecodeChunkNoVcdTargetAllowed) {
  decoder_.SetAllowVcdTarget(false);
  // Parse file header + first two windows.
  const size_t chunk_1_size = delta_file_header_.size() + 83;
  // The third window begins with Win_Indicator = VCD_TARGET which is not
  // allowed.
  CHECK_EQ(VCD_TARGET, static_cast<unsigned char>(delta_file_[chunk_1_size]));
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[0], chunk_1_size, &output_));
  // Just parsing one more byte (the VCD_TARGET) should result in an error.
  EXPECT_FALSE(decoder_.DecodeChunk(&delta_file_[chunk_1_size], 1, &output_));
  // The target data for the first two windows should have been output.
  EXPECT_EQ(expected_target_.substr(0, 89).c_str(), output_);
}

TEST_F(VCDiffStandardWindowDecoderTest, DecodeInTwoParts) {
  const size_t delta_file_size = delta_file_.size();
  for (size_t i = 1; i < delta_file_size; i++) {
    string output_chunk1, output_chunk2;
    decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
    EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[0],
                                     i,
                                     &output_chunk1));
    EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[i],
                                     delta_file_size - i,
                                     &output_chunk2));
    EXPECT_TRUE(decoder_.FinishDecoding());
    EXPECT_EQ(expected_target_.c_str(), output_chunk1 + output_chunk2);
  }
}

TEST_F(VCDiffStandardWindowDecoderTest, DecodeInThreeParts) {
  const size_t delta_file_size = delta_file_.size();
  for (size_t i = 1; i < delta_file_size - 1; i++) {
    for (size_t j = i + 1; j < delta_file_size; j++) {
      string output_chunk1, output_chunk2, output_chunk3;
      decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
      EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[0],
                                       i,
                                       &output_chunk1));
      EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[i],
                                       j - i,
                                       &output_chunk2));
      EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[j],
                                       delta_file_size - j,
                                       &output_chunk3));
      EXPECT_TRUE(decoder_.FinishDecoding());
      EXPECT_EQ(expected_target_.c_str(),
                output_chunk1 + output_chunk2 + output_chunk3);
    }
  }
}

// For the window test, the maximum target window size is much smaller than the
// target file size.  (The largest window is Window 2, with 61 target bytes.)
// Use the minimum values possible.
TEST_F(VCDiffStandardWindowDecoderTest, TargetMatchesWindowSizeLimit) {
  decoder_.SetMaximumTargetWindowSize(kWindow2Size);
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  EXPECT_TRUE(decoder_.DecodeChunk(delta_file_.data(),
                                   delta_file_.size(),
                                   &output_));
  EXPECT_TRUE(decoder_.FinishDecoding());
  EXPECT_EQ(expected_target_.c_str(), output_);
}

TEST_F(VCDiffStandardWindowDecoderTest, TargetMatchesFileSizeLimit) {
  decoder_.SetMaximumTargetFileSize(expected_target_.size());
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  EXPECT_TRUE(decoder_.DecodeChunk(delta_file_.data(),
                                   delta_file_.size(),
                                   &output_));
  EXPECT_TRUE(decoder_.FinishDecoding());
  EXPECT_EQ(expected_target_.c_str(), output_);
}

TEST_F(VCDiffStandardWindowDecoderTest, TargetExceedsWindowSizeLimit) {
  decoder_.SetMaximumTargetWindowSize(kWindow2Size - 1);
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  EXPECT_FALSE(decoder_.DecodeChunk(delta_file_.data(),
                                    delta_file_.size(),
                                    &output_));
  EXPECT_EQ("", output_);
}

TEST_F(VCDiffStandardWindowDecoderTest, TargetExceedsFileSizeLimit) {
  decoder_.SetMaximumTargetFileSize(expected_target_.size() - 1);
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  EXPECT_FALSE(decoder_.DecodeChunk(delta_file_.data(),
                                    delta_file_.size(),
                                    &output_));
  EXPECT_EQ("", output_);
}

typedef VCDiffStandardWindowDecoderTest
    VCDiffStandardWindowDecoderTestByteByByte;

TEST_F(VCDiffStandardWindowDecoderTestByteByByte, Decode) {
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  for (size_t i = 0; i < delta_file_.size(); ++i) {
    EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[i], 1, &output_));
  }
  EXPECT_TRUE(decoder_.FinishDecoding());
  EXPECT_EQ(expected_target_.c_str(), output_);
}

TEST_F(VCDiffStandardWindowDecoderTestByteByByte, DecodeExplicitVcdTarget) {
  decoder_.SetAllowVcdTarget(true);
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  for (size_t i = 0; i < delta_file_.size(); ++i) {
    EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[i], 1, &output_));
  }
  EXPECT_TRUE(decoder_.FinishDecoding());
  EXPECT_EQ(expected_target_.c_str(), output_);
}

// Windows 3 and 4 use the VCD_TARGET flag, so decoder should signal an error.
TEST_F(VCDiffStandardWindowDecoderTestByteByByte, DecodeNoVcdTarget) {
  decoder_.SetAllowVcdTarget(false);
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  size_t i = 0;
  for (; i < delta_file_.size(); ++i) {
    if (!decoder_.DecodeChunk(&delta_file_[i], 1, &output_)) {
      break;
    }
  }
  // The failure should occur just at the position of the first VCD_TARGET.
  EXPECT_EQ(delta_file_header_.size() + 83, i);
  // The target data for the first two windows should have been output.
  EXPECT_EQ(expected_target_.substr(0, 89).c_str(), output_);
}

// Divides up the interleaved encoding into eight separate delta file windows.
class VCDiffInterleavedWindowDecoderTest
    : public VCDiffStandardWindowDecoderTest {
 protected:
  VCDiffInterleavedWindowDecoderTest();
  virtual ~VCDiffInterleavedWindowDecoderTest() {}
 private:
  static const char kWindowBody[];
};

const char VCDiffInterleavedWindowDecoderTest::kWindowBody[] = {
// Window 1:
    VCD_SOURCE,  // Win_Indicator: take source from dictionary
    FirstByteOfStringLength(kDictionary),  // Source segment size
    SecondByteOfStringLength(kDictionary),
    '\x00',  // Source segment position: start of dictionary
    '\x08',  // Length of the delta encoding
    '\x1C',  // Size of the target window (28)
    '\x00',  // Delta_indicator (no compression)
    '\x00',  // length of data for ADDs and RUNs
    '\x03',  // length of instructions section
    '\x00',  // length of addresses for COPYs
    '\x13',  // VCD_COPY mode VCD_SELF, size 0
    '\x1C',  // Size of COPY (28)
    '\x00',  // Start of dictionary
// Window 2:
    '\x00',  // Win_Indicator: No source segment (ADD only)
    '\x44',  // Length of the delta encoding
    '\x3D',  // Size of the target window (61)
    '\x00',  // Delta_indicator (no compression)
    '\x00',  // length of data for ADDs and RUNs
    '\x3F',  // length of instructions section
    '\x00',  // length of addresses for COPYs
    '\x01',  // VCD_ADD size 0
    '\x3D',  // Size of ADD (61)
    ' ', 'I', ' ', 'h', 'a', 'v', 'e', ' ', 's', 'a', 'i', 'd', ' ',
    'i', 't', ' ', 't', 'w', 'i', 'c', 'e', ':', '\n',
    'T', 'h', 'a', 't', ' ',
    'a', 'l', 'o', 'n', 'e', ' ', 's', 'h', 'o', 'u', 'l', 'd', ' ',
    'e', 'n', 'c', 'o', 'u', 'r', 'a', 'g', 'e', ' ',
    't', 'h', 'e', ' ', 'c', 'r', 'e', 'w', '.', '\n',
// Window 3:
    VCD_TARGET,  // Win_Indicator: take source from decoded data
    '\x59',  // Source segment size: length of data decoded so far
    '\x00',  // Source segment position: start of decoded data
    '\x08',  // Length of the delta encoding
    '\x2C',  // Size of the target window
    '\x00',  // Delta_indicator (no compression)
    '\x00',  // length of data for ADDs and RUNs
    '\x03',  // length of instructions section
    '\x00',  // length of addresses for COPYs
    '\x23',  // VCD_COPY mode VCD_HERE, size 0
    '\x2C',  // Size of COPY (44)
    '\x58',  // HERE mode address (27+61 back from here_address)
// Window 4:
    VCD_TARGET,  // Win_Indicator: take source from decoded data
    '\x05',  // Source segment size: only 5 bytes needed for this COPY
    '\x2E',  // Source segment position: offset for COPY
    '\x09',  // Length of the delta encoding
    '\x07',  // Size of the target window
    '\x00',  // Delta_indicator (no compression)
    '\x00',  // length of data for ADDs and RUNs
    '\x04',  // length of instructions section
    '\x00',  // length of addresses for COPYs
    '\xA7',  // VCD_ADD size 2 + VCD_COPY mode SELF, size 5
    'h', 'r',
    '\x00',  // SELF mode address (start of source segment)
// Window 5:
    '\x00',  // Win_Indicator: No source segment (ADD only)
    '\x0F',  // Length of the delta encoding
    '\x09',  // Size of the target window
    '\x00',  // Delta_indicator (no compression)
    '\x00',  // length of data for ADDs and RUNs
    '\x0A',  // length of instructions section
    '\x00',  // length of addresses for COPYs
    '\x0A',       // VCD_ADD size 9
    'W', 'h', 'a', 't', ' ', 'I', ' ', 't', 'e',
// Window 6:
    '\x00',  // Win_Indicator: No source segment (RUN only)
    '\x08',  // Length of the delta encoding
    '\x02',  // Size of the target window
    '\x00',  // Delta_indicator (no compression)
    '\x00',  // length of data for ADDs and RUNs
    '\x03',  // length of instructions section
    '\x00',  // length of addresses for COPYs
    '\x00',  // VCD_RUN size 0
    '\x02',  // Size of RUN (2)
    'l',
// Window 7:
    '\x00',  // Win_Indicator: No source segment (ADD only)
    '\x22',  // Length of the delta encoding
    '\x1B',  // Size of the target window
    '\x00',  // Delta_indicator (no compression)
    '\x00',  // length of data for ADDs and RUNs
    '\x1D',  // length of instructions section
    '\x00',  // length of addresses for COPYs
    '\x01',  // VCD_ADD size 0
    '\x1B',  // Size of ADD (27)
    ' ', 'y', 'o', 'u', ' ',
    't', 'h', 'r', 'e', 'e', ' ', 't', 'i', 'm', 'e', 's', ' ', 'i', 's', ' ',
    't', 'r', 'u', 'e', '.', '\"', '\n',
  };

VCDiffInterleavedWindowDecoderTest::VCDiffInterleavedWindowDecoderTest() {
  UseInterleavedFileHeader();
  // delta_window_header_ is left blank.  All window headers and bodies are
  // lumped together in delta_window_body_.  This means that AddChecksum()
  // cannot be used to test the checksum feature.
  delta_window_body_.assign(kWindowBody, sizeof(kWindowBody));
}

TEST_F(VCDiffInterleavedWindowDecoderTest, Decode) {
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  EXPECT_TRUE(decoder_.DecodeChunk(delta_file_.data(),
                                   delta_file_.size(),
                                   &output_));
  EXPECT_TRUE(decoder_.FinishDecoding());
  EXPECT_EQ(expected_target_.c_str(), output_);
}

TEST_F(VCDiffInterleavedWindowDecoderTest, DecodeInTwoParts) {
  const size_t delta_file_size = delta_file_.size();
  for (size_t i = 1; i < delta_file_size; i++) {
    string output_chunk1, output_chunk2;
    decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
    EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[0],
                                     i,
                                     &output_chunk1));
    EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[i],
                                     delta_file_size - i,
                                     &output_chunk2));
    EXPECT_TRUE(decoder_.FinishDecoding());
    EXPECT_EQ(expected_target_.c_str(), output_chunk1 + output_chunk2);
  }
}

TEST_F(VCDiffInterleavedWindowDecoderTest, DecodeInThreeParts) {
  const size_t delta_file_size = delta_file_.size();
  for (size_t i = 1; i < delta_file_size - 1; i++) {
    for (size_t j = i + 1; j < delta_file_size; j++) {
      string output_chunk1, output_chunk2, output_chunk3;
      decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
      EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[0],
                                       i,
                                       &output_chunk1));
      EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[i],
                                       j - i,
                                       &output_chunk2));
      EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[j],
                                       delta_file_size - j,
                                       &output_chunk3));
      EXPECT_TRUE(decoder_.FinishDecoding());
      EXPECT_EQ(expected_target_.c_str(),
                output_chunk1 + output_chunk2 + output_chunk3);
    }
  }
}

typedef VCDiffInterleavedWindowDecoderTest
    VCDiffInterleavedWindowDecoderTestByteByByte;

TEST_F(VCDiffInterleavedWindowDecoderTestByteByByte, Decode) {
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  for (size_t i = 0; i < delta_file_.size(); ++i) {
    EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[i], 1, &output_));
  }
  EXPECT_TRUE(decoder_.FinishDecoding());
  EXPECT_EQ(expected_target_.c_str(), output_);
}

// Windows 3 and 4 use the VCD_TARGET flag, so decoder should signal an error.
TEST_F(VCDiffInterleavedWindowDecoderTestByteByByte, DecodeNoVcdTarget) {
  decoder_.SetAllowVcdTarget(false);
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  size_t i = 0;
  for (; i < delta_file_.size(); ++i) {
    if (!decoder_.DecodeChunk(&delta_file_[i], 1, &output_)) {
      break;
    }
  }
  // The failure should occur just at the position of the first VCD_TARGET.
  EXPECT_EQ(delta_file_header_.size() + 83, i);
  // The target data for the first two windows should have been output.
  EXPECT_EQ(expected_target_.substr(0, 89).c_str(), output_);
}

// The original version of VCDiffDecoder did not allow the caller to modify the
// contents of output_string between calls to DecodeChunk().  That restriction
// has been removed.  Verify that the same result is still produced if the
// output string is cleared after each call to DecodeChunk().  Use the window
// encoding because it refers back to the previously decoded target data, which
// is the feature that would fail if the restriction still applied.
//
TEST_F(VCDiffInterleavedWindowDecoderTest, OutputStringCanBeModified) {
  string temp_output;
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  for (size_t i = 0; i < delta_file_.size(); ++i) {
    EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[i], 1, &temp_output));
    output_.append(temp_output);
    temp_output.clear();
  }
  EXPECT_TRUE(decoder_.FinishDecoding());
  EXPECT_EQ(expected_target_.c_str(), output_);
}

TEST_F(VCDiffInterleavedWindowDecoderTest, OutputStringIsPreserved) {
  const string previous_data("Previous data");
  output_ = previous_data;
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  for (size_t i = 0; i < delta_file_.size(); ++i) {
    EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[i], 1, &output_));
  }
  EXPECT_TRUE(decoder_.FinishDecoding());
  EXPECT_EQ((previous_data + expected_target_).c_str(), output_);
}

// A decode job that tests the ability to COPY across the boundary between
// source data and target data.
class VCDiffStandardCrossDecoderTest : public VCDiffDecoderTest {
 protected:
  static const char kExpectedTarget[];
  static const char kWindowHeader[];
  static const char kWindowBody[];

  VCDiffStandardCrossDecoderTest();
  virtual ~VCDiffStandardCrossDecoderTest() {}
};

const char VCDiffStandardCrossDecoderTest::kWindowHeader[] = {
    VCD_SOURCE,  // Win_Indicator: take source from dictionary
    FirstByteOfStringLength(kDictionary),  // Source segment size
    SecondByteOfStringLength(kDictionary),
    '\x00',  // Source segment position: start of dictionary
    '\x15',  // Length of the delta encoding
    StringLengthAsByte(kExpectedTarget),  // Size of the target window
    '\x00',  // Delta_indicator (no compression)
    '\x07',  // length of data for ADDs and RUNs
    '\x06',  // length of instructions section
    '\x03'   // length of addresses for COPYs
  };

const char VCDiffStandardCrossDecoderTest::kWindowBody[] = {
    // Data for ADD (length 7)
    'S', 'p', 'i', 'd', 'e', 'r', 's',
    // Instructions and sizes (length 6)
    '\x01',  // VCD_ADD size 0
    '\x07',  // Size of ADD (7)
    '\x23',  // VCD_COPY mode VCD_HERE, size 0
    '\x19',  // Size of COPY (25)
    '\x14',  // VCD_COPY mode VCD_SELF, size 4
    '\x25',  // VCD_COPY mode VCD_HERE, size 5
    // Addresses for COPYs (length 3)
    '\x15',  // HERE mode address for 1st copy (21 back from here_address)
    '\x06',  // SELF mode address for 2nd copy
    '\x14'   // HERE mode address for 3rd copy
  };

const char VCDiffStandardCrossDecoderTest::kExpectedTarget[] =
    "Spiders in his hair.\n"
    "Spiders in the air.\n";

VCDiffStandardCrossDecoderTest::VCDiffStandardCrossDecoderTest() {
  UseStandardFileHeader();
  delta_window_header_.assign(kWindowHeader, sizeof(kWindowHeader));
  delta_window_body_.assign(kWindowBody, sizeof(kWindowBody));
  expected_target_.assign(kExpectedTarget);
}

TEST_F(VCDiffStandardCrossDecoderTest, Decode) {
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  EXPECT_TRUE(decoder_.DecodeChunk(delta_file_.data(),
                                   delta_file_.size(),
                                   &output_));
  EXPECT_TRUE(decoder_.FinishDecoding());
  EXPECT_EQ(expected_target_.c_str(), output_);
}

typedef VCDiffStandardCrossDecoderTest VCDiffStandardCrossDecoderTestByteByByte;

TEST_F(VCDiffStandardCrossDecoderTestByteByByte, Decode) {
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  for (size_t i = 0; i < delta_file_.size(); ++i) {
    EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[i], 1, &output_));
  }
  EXPECT_TRUE(decoder_.FinishDecoding());
  EXPECT_EQ(expected_target_.c_str(), output_);
}

// The same decode job that tests the ability to COPY across the boundary
// between source data and target data, but using the interleaved format rather
// than the standard format.
class VCDiffInterleavedCrossDecoderTest
    : public VCDiffStandardCrossDecoderTest {
 protected:
  VCDiffInterleavedCrossDecoderTest();
  virtual ~VCDiffInterleavedCrossDecoderTest() {}

 private:
  static const char kWindowHeader[];
  static const char kWindowBody[];
};

const char VCDiffInterleavedCrossDecoderTest::kWindowHeader[] = {
    VCD_SOURCE,  // Win_Indicator: take source from dictionary
    FirstByteOfStringLength(kDictionary),  // Source segment size
    SecondByteOfStringLength(kDictionary),
    '\x00',  // Source segment position: start of dictionary
    '\x15',  // Length of the delta encoding
    StringLengthAsByte(kExpectedTarget),  // Size of the target window
    '\x00',  // Delta_indicator (no compression)
    '\x00',  // length of data for ADDs and RUNs
    '\x10',  // length of instructions section
    '\x00',  // length of addresses for COPYs
  };

const char VCDiffInterleavedCrossDecoderTest::kWindowBody[] = {
    '\x01',  // VCD_ADD size 0
    '\x07',  // Size of ADD (7)
    // Data for ADD (length 7)
    'S', 'p', 'i', 'd', 'e', 'r', 's',
    '\x23',  // VCD_COPY mode VCD_HERE, size 0
    '\x19',  // Size of COPY (25)
    '\x15',  // HERE mode address for 1st copy (21 back from here_address)
    '\x14',  // VCD_COPY mode VCD_SELF, size 4
    '\x06',  // SELF mode address for 2nd copy
    '\x25',  // VCD_COPY mode VCD_HERE, size 5
    '\x14'   // HERE mode address for 3rd copy
  };

VCDiffInterleavedCrossDecoderTest::VCDiffInterleavedCrossDecoderTest() {
  UseInterleavedFileHeader();
  delta_window_header_.assign(kWindowHeader, sizeof(kWindowHeader));
  delta_window_body_.assign(kWindowBody, sizeof(kWindowBody));
}

TEST_F(VCDiffInterleavedCrossDecoderTest, Decode) {
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  EXPECT_TRUE(decoder_.DecodeChunk(delta_file_.data(),
                                   delta_file_.size(),
                                   &output_));
  EXPECT_TRUE(decoder_.FinishDecoding());
  EXPECT_EQ(expected_target_.c_str(), output_);
}

TEST_F(VCDiffInterleavedCrossDecoderTest, DecodeWithChecksum) {
  ComputeAndAddChecksum();
  InitializeDeltaFile();
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  EXPECT_TRUE(decoder_.DecodeChunk(delta_file_.data(),
                                   delta_file_.size(),
                                   &output_));
  EXPECT_TRUE(decoder_.FinishDecoding());
  EXPECT_EQ(expected_target_.c_str(), output_);
}

typedef VCDiffInterleavedCrossDecoderTest
    VCDiffInterleavedCrossDecoderTestByteByByte;

TEST_F(VCDiffInterleavedCrossDecoderTestByteByByte, Decode) {
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  for (size_t i = 0; i < delta_file_.size(); ++i) {
    EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[i], 1, &output_));
  }
  EXPECT_TRUE(decoder_.FinishDecoding());
  EXPECT_EQ(expected_target_.c_str(), output_);
}

TEST_F(VCDiffInterleavedCrossDecoderTestByteByByte, DecodeWithChecksum) {
  ComputeAndAddChecksum();
  InitializeDeltaFile();
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  for (size_t i = 0; i < delta_file_.size(); ++i) {
    EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[i], 1, &output_));
  }
  EXPECT_TRUE(decoder_.FinishDecoding());
  EXPECT_EQ(expected_target_.c_str(), output_);
}

// Test using a custom code table and custom cache sizes with interleaved
// format.
class VCDiffCustomCodeTableDecoderTest : public VCDiffInterleavedDecoderTest {
 protected:
  static const char kFileHeader[];
  static const char kWindowHeader[];
  static const char kWindowBody[];
  static const char kEncodedCustomCodeTable[];

  VCDiffCustomCodeTableDecoderTest();
  virtual ~VCDiffCustomCodeTableDecoderTest() {}
};

const char VCDiffCustomCodeTableDecoderTest::kFileHeader[] = {
    '\xD6',  // 'V' | '\x80'
    '\xC3',  // 'C' | '\x80'
    '\xC4',  // 'D' | '\x80'
    'S',   // SDCH version code
    '\x02'   // Hdr_Indicator: Use custom code table
  };

// Make a custom code table that includes exactly the instructions we need
// to encode the first test's data without using any explicit length values.
// Be careful not to replace any existing opcodes that have size 0,
// to ensure that the custom code table is valid (can express all possible
// values of inst (also known as instruction type) and mode with size 0.)
// This encoding uses interleaved format, which is easier to read.
//
// Here are the changes to the standard code table:
// ADD size 2 (opcode 3) => RUN size 2 (inst1[3] = VCD_RUN)
// ADD size 16 (opcode 17) => ADD size 27 (size1[17] = 27)
// ADD size 17 (opcode 18) => ADD size 61 (size1[18] = 61)
// COPY mode 0 size 18 (opcode 34) => COPY mode 0 size 28 (size1[34] = 28)
// COPY mode 1 size 18 (opcode 50) => COPY mode 1 size 44 (size1[50] = 44)
//
const char VCDiffCustomCodeTableDecoderTest::kEncodedCustomCodeTable[] = {
    '\xD6',  // 'V' | '\x80'
    '\xC3',  // 'C' | '\x80'
    '\xC4',  // 'D' | '\x80'
    'S',   // SDCH version code
    '\x00',  // Hdr_Indicator: no custom code table, no compression
    VCD_SOURCE,  // Win_Indicator: take source from dictionary
    static_cast<const char>((sizeof(VCDiffCodeTableData) >> 7) | 0x80),  // First byte of table length
    sizeof(VCDiffCodeTableData) & 0x7F,  // Second byte of table length
    '\x00',  // Source segment position: start of default code table
    '\x1F',  // Length of the delta encoding
    static_cast<const char>((sizeof(VCDiffCodeTableData) >> 7) | 0x80),  // First byte of table length
    sizeof(VCDiffCodeTableData) & 0x7F,  // Second byte of table length
    '\x00',  // Delta_indicator (no compression)
    '\x00',  // length of data for ADDs and RUNs (unused)
    '\x19',  // length of interleaved section
    '\x00',  // length of addresses for COPYs (unused)
    '\x05',  // VCD_ADD size 4
    // Data for ADD (length 4)
    VCD_RUN, VCD_ADD, VCD_ADD, VCD_RUN,
    '\x13',  // VCD_COPY mode VCD_SELF size 0
    '\x84',  // Size of copy: upper bits (512 - 4 + 17 = 525)
    '\x0D',  // Size of copy: lower bits
    '\x04',  // Address of COPY
    '\x03',  // VCD_ADD size 2
    // Data for ADD (length 2)
    '\x1B', '\x3D',
    '\x3F',  // VCD_COPY mode VCD_NEAR(0) size 15
    '\x84',  // Address of copy: upper bits (525 + 2 = 527)
    '\x0F',  // Address of copy: lower bits
    '\x02',  // VCD_ADD size 1
    // Data for ADD (length 1)
    '\x1C',
    '\x4F',  // VCD_COPY mode VCD_NEAR(1) size 15
    '\x10',  // Address of copy
    '\x02',  // VCD_ADD size 1
    // Data for ADD (length 1)
    '\x2C',
    '\x53',  // VCD_COPY mode VCD_NEAR(2) size 0
    '\x87',  // Size of copy: upper bits (256 * 4 - 51 = 973)
    '\x4D',  // Size of copy: lower bits
    '\x10'   // Address of copy
  };

// This is similar to VCDiffInterleavedDecoderTest, but uses the custom code
// table to eliminate the need to explicitly encode instruction sizes.
// Notice that NEAR(0) mode is used here where NEAR(1) mode was used in
// VCDiffInterleavedDecoderTest.  This is because the custom code table
// has the size of the NEAR cache set to 1; only the most recent
// COPY instruction is available.  This will also be a test of
// custom cache sizes.
const char VCDiffCustomCodeTableDecoderTest::kWindowHeader[] = {
    VCD_SOURCE,  // Win_Indicator: take source from dictionary
    FirstByteOfStringLength(kDictionary),  // Source segment size
    SecondByteOfStringLength(kDictionary),
    '\x00',  // Source segment position: start of dictionary
    '\x74',  // Length of the delta encoding
    FirstByteOfStringLength(kExpectedTarget),  // Size of the target window
    SecondByteOfStringLength(kExpectedTarget),
    '\x00',  // Delta_indicator (no compression)
    '\x00',  // length of data for ADDs and RUNs (unused)
    '\x6E',  // length of interleaved section
    '\x00'   // length of addresses for COPYs (unused)
  };

const char VCDiffCustomCodeTableDecoderTest::kWindowBody[] = {
    '\x22',  // VCD_COPY mode VCD_SELF, size 28
    '\x00',  // Address of COPY: Start of dictionary
    '\x12',  // VCD_ADD size 61
    // Data for ADD (length 61)
    ' ', 'I', ' ', 'h', 'a', 'v', 'e', ' ', 's', 'a', 'i', 'd', ' ',
    'i', 't', ' ', 't', 'w', 'i', 'c', 'e', ':', '\n',
    'T', 'h', 'a', 't', ' ',
    'a', 'l', 'o', 'n', 'e', ' ', 's', 'h', 'o', 'u', 'l', 'd', ' ',
    'e', 'n', 'c', 'o', 'u', 'r', 'a', 'g', 'e', ' ',
    't', 'h', 'e', ' ', 'c', 'r', 'e', 'w', '.', '\n',
    '\x32',  // VCD_COPY mode VCD_HERE, size 44
    '\x58',  // HERE mode address (27+61 back from here_address)
    '\xBF',  // VCD_ADD size 2 + VCD_COPY mode NEAR(0), size 5
    // Data for ADDs: 2nd section (length 2)
    'h', 'r',
    '\x2D',  // NEAR(0) mode address (45 after prior address)
    '\x0A',  // VCD_ADD size 9
    // Data for ADDs: 3rd section (length 9)
    'W', 'h', 'a', 't', ' ',
    'I', ' ', 't', 'e',
    '\x03',  // VCD_RUN size 2
    // Data for RUN: 4th section (length 1)
    'l',
    '\x11',  // VCD_ADD size 27
    // Data for ADD: 4th section (length 27)
    ' ', 'y', 'o', 'u', ' ',
    't', 'h', 'r', 'e', 'e', ' ', 't', 'i', 'm', 'e', 's', ' ', 'i', 's', ' ',
    't', 'r', 'u', 'e', '.', '\"', '\n'
  };

VCDiffCustomCodeTableDecoderTest::VCDiffCustomCodeTableDecoderTest() {
  delta_file_header_.assign(kFileHeader, sizeof(kFileHeader));
  delta_file_header_.push_back('\x01');  // NEAR cache size (custom)
  delta_file_header_.push_back('\x06');  // SAME cache size (custom)
  delta_file_header_.append(kEncodedCustomCodeTable,
                            sizeof(kEncodedCustomCodeTable));
  delta_window_header_.assign(kWindowHeader, sizeof(kWindowHeader));
  delta_window_body_.assign(kWindowBody, sizeof(kWindowBody));
}

TEST_F(VCDiffCustomCodeTableDecoderTest, CustomCodeTableEncodingMatches) {
  VCDiffCodeTableData custom_code_table(
    VCDiffCodeTableData::kDefaultCodeTableData);
  custom_code_table.inst1[3] = VCD_RUN;
  custom_code_table.size1[17] = 27;
  custom_code_table.size1[18] = 61;
  custom_code_table.size1[34] = 28;
  custom_code_table.size1[50] = 44;

  decoder_.StartDecoding(
      reinterpret_cast<const char*>(
          &VCDiffCodeTableData::kDefaultCodeTableData),
      sizeof(VCDiffCodeTableData::kDefaultCodeTableData));
  EXPECT_TRUE(decoder_.DecodeChunk(kEncodedCustomCodeTable,
                                   sizeof(kEncodedCustomCodeTable),
                                   &output_));
  EXPECT_TRUE(decoder_.FinishDecoding());
  EXPECT_EQ(sizeof(custom_code_table), output_.size());
  const VCDiffCodeTableData* decoded_table =
      reinterpret_cast<const VCDiffCodeTableData*>(output_.data());
  EXPECT_EQ(VCD_RUN, decoded_table->inst1[0]);
  EXPECT_EQ(VCD_RUN, decoded_table->inst1[3]);
  EXPECT_EQ(27, decoded_table->size1[17]);
  EXPECT_EQ(61, decoded_table->size1[18]);
  EXPECT_EQ(28, decoded_table->size1[34]);
  EXPECT_EQ(44, decoded_table->size1[50]);
  for (int i = 0; i < VCDiffCodeTableData::kCodeTableSize; ++i) {
    EXPECT_EQ(custom_code_table.inst1[i], decoded_table->inst1[i]);
    EXPECT_EQ(custom_code_table.inst2[i], decoded_table->inst2[i]);
    EXPECT_EQ(custom_code_table.size1[i], decoded_table->size1[i]);
    EXPECT_EQ(custom_code_table.size2[i], decoded_table->size2[i]);
    EXPECT_EQ(custom_code_table.mode1[i], decoded_table->mode1[i]);
    EXPECT_EQ(custom_code_table.mode2[i], decoded_table->mode2[i]);
  }
}

TEST_F(VCDiffCustomCodeTableDecoderTest, DecodeUsingCustomCodeTable) {
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  EXPECT_TRUE(decoder_.DecodeChunk(delta_file_.data(),
                                   delta_file_.size(),
                                   &output_));
  EXPECT_TRUE(decoder_.FinishDecoding());
  EXPECT_EQ(expected_target_.c_str(), output_);
}

TEST_F(VCDiffCustomCodeTableDecoderTest, IncompleteCustomCodeTable) {
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  EXPECT_TRUE(decoder_.DecodeChunk(delta_file_header_.data(),
                                   delta_file_header_.size() - 1,
                                   &output_));
  EXPECT_FALSE(decoder_.FinishDecoding());
  EXPECT_EQ("", output_);
}

typedef VCDiffCustomCodeTableDecoderTest
    VCDiffCustomCodeTableDecoderTestByteByByte;

TEST_F(VCDiffCustomCodeTableDecoderTestByteByByte, DecodeUsingCustomCodeTable) {
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  for (size_t i = 0; i < delta_file_.size(); ++i) {
    EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[i], 1, &output_));
  }
  EXPECT_TRUE(decoder_.FinishDecoding());
  EXPECT_EQ(expected_target_.c_str(), output_);
}

TEST_F(VCDiffCustomCodeTableDecoderTestByteByByte, IncompleteCustomCodeTable) {
  delta_file_.resize(delta_file_header_.size() - 1);
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  for (size_t i = 0; i < delta_file_.size(); ++i) {
    EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[i], 1, &output_));
  }
  EXPECT_FALSE(decoder_.FinishDecoding());
  EXPECT_EQ("", output_);
}

TEST_F(VCDiffCustomCodeTableDecoderTestByteByByte, CustomTableNoVcdTarget) {
  decoder_.SetAllowVcdTarget(false);
  decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
  for (size_t i = 0; i < delta_file_.size(); ++i) {
    EXPECT_TRUE(decoder_.DecodeChunk(&delta_file_[i], 1, &output_));
  }
  EXPECT_TRUE(decoder_.FinishDecoding());
  EXPECT_EQ(expected_target_.c_str(), output_);
}

#ifdef GTEST_HAS_DEATH_TEST

class VCDiffCustomCacheSizeTest : public VCDiffCustomCodeTableDecoderTest {
 protected:
  void CustomCacheSizeTest(int32_t near_value, int32_t same_value);
};

void VCDiffCustomCacheSizeTest::CustomCacheSizeTest(int32_t near_value,
                                                    int32_t same_value) {
  SCOPED_TRACE(testing::Message() << "Near value: " << near_value
                                  << ", same value: " << same_value);
  delta_file_header_.assign(kFileHeader, sizeof(kFileHeader));
  VarintBE<int32_t>::AppendToString(near_value, &delta_file_header_);
  VarintBE<int32_t>::AppendToString(same_value, &delta_file_header_);
  delta_file_header_.append(kEncodedCustomCodeTable,
                            sizeof(kEncodedCustomCodeTable));
  InitializeDeltaFile();
  EXPECT_DEBUG_DEATH({
    decoder_.StartDecoding(dictionary_.data(), dictionary_.size());
    EXPECT_FALSE(decoder_.DecodeChunk(delta_file_.data(),
                                      delta_file_.size(),
                                      &output_));
  }, "cache");
  EXPECT_EQ("", output_);
}

TEST_F(VCDiffCustomCacheSizeTest, BadCustomCacheSizes) {
  CustomCacheSizeTest(0x90, 0x90);
  CustomCacheSizeTest(INT_MAX, INT_MAX);
}

TEST_F(VCDiffCustomCacheSizeTest, BadCustomCacheSizesNoVcdTarget) {
  decoder_.SetAllowVcdTarget(false);
  CustomCacheSizeTest(0x90, 0x90);
  CustomCacheSizeTest(INT_MAX, INT_MAX);
}

#endif  // GTEST_HAS_DEATH_TEST

}  // namespace open_vcdiff
}  // unnamed namespace
