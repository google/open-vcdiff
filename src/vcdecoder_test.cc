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
#include "vcdecoder_test.h"
#include <string.h>  // strlen
#include "checksum.h"
#include "codetable.h"
#include "testing.h"
#include "varint_bigendian.h"
#include "vcdiff_defs.h"

namespace open_vcdiff {

const char VCDiffDecoderTest::kStandardFileHeader[] = {
    '\xD6',  // 'V' | '\x80'
    '\xC3',  // 'C' | '\x80'
    '\xC4',  // 'D' | '\x80'
    '\x00',  // Draft standard version number
    '\x00'   // Hdr_Indicator: no custom code table, no compression
  };

const char VCDiffDecoderTest::kInterleavedFileHeader[] = {
    '\xD6',  // 'V' | '\x80'
    '\xC3',  // 'C' | '\x80'
    '\xC4',  // 'D' | '\x80'
    'S',   // SDCH version code
    '\x00'   // Hdr_Indicator: no custom code table, no compression
  };

const char VCDiffDecoderTest::kDictionary[] =
  "\"Just the place for a Snark!\" the Bellman cried,\n"
  "As he landed his crew with care;\n"
  "Supporting each man on the top of the tide\n"
  "By a finger entwined in his hair.\n";

const char VCDiffDecoderTest::kExpectedTarget[] =
  "\"Just the place for a Snark! I have said it twice:\n"
  "That alone should encourage the crew.\n"
  "Just the place for a Snark! I have said it thrice:\n"
  "What I tell you three times is true.\"\n";

VCDiffDecoderTest::VCDiffDecoderTest() : fuzzer_(0), fuzzed_byte_position_(0) {
  dictionary_ = kDictionary;
  expected_target_ = kExpectedTarget;
}

void VCDiffDecoderTest::SetUp() {
  InitializeDeltaFile();
}

void VCDiffDecoderTest::UseStandardFileHeader() {
  delta_file_header_.assign(kStandardFileHeader,
                            sizeof(kStandardFileHeader));
}

void VCDiffDecoderTest::UseInterleavedFileHeader() {
  delta_file_header_.assign(kInterleavedFileHeader,
                            sizeof(kInterleavedFileHeader));
}

void VCDiffDecoderTest::InitializeDeltaFile() {
  delta_file_ = delta_file_header_ + delta_window_header_ + delta_window_body_;
}

char VCDiffDecoderTest::GetByteFromStringLength(const char* s,
                                                int which_byte) {
  char varint_buf[VarintBE<int32_t>::kMaxBytes];
  VarintBE<int32_t>::Encode(static_cast<int32_t>(strlen(s)), varint_buf);
  return varint_buf[which_byte];
}

void VCDiffDecoderTest::AddChecksum(VCDChecksum checksum) {
  int32_t checksum_as_int32 = static_cast<int32_t>(checksum);
  delta_window_header_[0] |= VCD_CHECKSUM;
  VarintBE<int32_t>::AppendToString(checksum_as_int32, &delta_window_header_);
  // Adjust delta window size to include checksum.
  // This method wouldn't work if adding to the length caused the VarintBE
  // value to spill over into another byte.  Luckily, this test data happens
  // not to cause such an overflow.
  delta_window_header_[4] += VarintBE<int32_t>::Length(checksum_as_int32);
}

void VCDiffDecoderTest::ComputeAndAddChecksum() {
  AddChecksum(ComputeAdler32(expected_target_.data(),
                             expected_target_.size()));
}

// Write the maximum expressible positive 32-bit VarintBE
// (0x7FFFFFFF) at the given offset in the delta window.
void VCDiffDecoderTest::WriteMaxVarintAtOffset(int offset,
                                               int bytes_to_replace) {
  static const char kMaxVarint[] = { '\x87', '\xFF', '\xFF', '\xFF', '\x7F' };
  delta_file_.replace(delta_file_header_.size() + offset,
                      bytes_to_replace,
                      kMaxVarint,
                      sizeof(kMaxVarint));
}

// Write a negative 32-bit VarintBE (0x80000000) at the given offset
// in the delta window.
void VCDiffDecoderTest::WriteNegativeVarintAtOffset(int offset,
                                                    int bytes_to_replace) {
  static const char kNegativeVarint[] = { '\x88', '\x80', '\x80', '\x80', '\x00' };
  delta_file_.replace(delta_file_header_.size() + offset,
                      bytes_to_replace,
                      kNegativeVarint,
                      sizeof(kNegativeVarint));
}

// Write a VarintBE that has too many continuation bytes
// at the given offset in the delta window.
void VCDiffDecoderTest::WriteInvalidVarintAtOffset(int offset,
                                                   int bytes_to_replace) {
  static const char kInvalidVarint[] = { '\x87', '\xFF', '\xFF', '\xFF', '\xFF', '\x7F' };
  delta_file_.replace(delta_file_header_.size() + offset,
                      bytes_to_replace,
                      kInvalidVarint,
                      sizeof(kInvalidVarint));
}

bool VCDiffDecoderTest::FuzzOneByteInDeltaFile() {
  static const struct Fuzzer {
    char _and;
    char _or;
    char _xor;
  } fuzzers[] = {
    { '\xff', '\x80', '\x00' },
    { '\xff', '\xff', '\x00' },
    { '\xff', '\x00', '\x80' },
    { '\xff', '\x00', '\xff' },
    { '\xff', '\x01', '\x00' },
    { '\x7f', '\x00', '\x00' },
  };

  for (; fuzzer_ < (sizeof(fuzzers) / sizeof(fuzzers[0])); ++fuzzer_) {
    for (; fuzzed_byte_position_ < delta_file_.size();
         ++fuzzed_byte_position_) {
      char fuzzed_byte = (((delta_file_[fuzzed_byte_position_]
                             & fuzzers[fuzzer_]._and)
                             | fuzzers[fuzzer_]._or)
                             ^ fuzzers[fuzzer_]._xor);
      if (fuzzed_byte != delta_file_[fuzzed_byte_position_]) {
        delta_file_[fuzzed_byte_position_] = fuzzed_byte;
        ++fuzzed_byte_position_;
        return true;
      }
    }
    fuzzed_byte_position_ = 0;
  }
  return false;
}

const char VCDiffStandardDecoderTest::kWindowHeader[] = {
    VCD_SOURCE,  // Win_Indicator: take source from dictionary
    FirstByteOfStringLength(kDictionary),  // Source segment size
    SecondByteOfStringLength(kDictionary),
    '\x00',  // Source segment position: start of dictionary
    '\x79',  // Length of the delta encoding
    FirstByteOfStringLength(kExpectedTarget),  // Size of the target window
    SecondByteOfStringLength(kExpectedTarget),
    '\x00',  // Delta_indicator (no compression)
    '\x64',  // length of data for ADDs and RUNs
    '\x0C',  // length of instructions section
    '\x03'  // length of addresses for COPYs
  };

const char VCDiffStandardDecoderTest::kWindowBody[] = {
    // Data for ADDs: 1st section (length 61)
    ' ', 'I', ' ', 'h', 'a', 'v', 'e', ' ', 's', 'a', 'i', 'd', ' ',
    'i', 't', ' ', 't', 'w', 'i', 'c', 'e', ':', '\n',
    'T', 'h', 'a', 't', ' ',
    'a', 'l', 'o', 'n', 'e', ' ', 's', 'h', 'o', 'u', 'l', 'd', ' ',
    'e', 'n', 'c', 'o', 'u', 'r', 'a', 'g', 'e', ' ',
    't', 'h', 'e', ' ', 'c', 'r', 'e', 'w', '.', '\n',
    // Data for ADDs: 2nd section (length 2)
    'h', 'r',
    // Data for ADDs: 3rd section (length 9)
    'W', 'h', 'a', 't', ' ',
    'I', ' ', 't', 'e',
    // Data for RUN: 4th section (length 1)
    'l',
    // Data for ADD: 4th section (length 27)
    ' ', 'y', 'o', 'u', ' ',
    't', 'h', 'r', 'e', 'e', ' ', 't', 'i', 'm', 'e', 's', ' ', 'i', 's', ' ',
    't', 'r', 'u', 'e', '.', '\"', '\n',
    // Instructions and sizes (length 13)
    '\x13',  // VCD_COPY mode VCD_SELF, size 0
    '\x1C',  // Size of COPY (28)
    '\x01',  // VCD_ADD size 0
    '\x3D',  // Size of ADD (61)
    '\x23',  // VCD_COPY mode VCD_HERE, size 0
    '\x2C',  // Size of COPY (44)
    '\xCB',  // VCD_ADD size 2 + VCD_COPY mode NEAR(1), size 5
    '\x0A',  // VCD_ADD size 9
    '\x00',  // VCD_RUN size 0
    '\x02',  // Size of RUN (2)
    '\x01',  // VCD_ADD size 0
    '\x1B',  // Size of ADD (27)
    // Addresses for COPYs (length 3)
    '\x00',  // Start of dictionary
    '\x58',  // HERE mode address for 2nd copy (27+61 back from here_address)
    '\x2D'   // NEAR(1) mode address for 2nd copy (45 after prior address)
  };

VCDiffStandardDecoderTest::VCDiffStandardDecoderTest() {
  UseStandardFileHeader();
  delta_window_header_.assign(kWindowHeader, sizeof(kWindowHeader));
  delta_window_body_.assign(kWindowBody, sizeof(kWindowBody));
}

const char VCDiffInterleavedDecoderTest::kWindowHeader[] = {
    VCD_SOURCE,  // Win_Indicator: take source from dictionary
    FirstByteOfStringLength(kDictionary),  // Source segment size
    SecondByteOfStringLength(kDictionary),
    '\x00',  // Source segment position: start of dictionary
    '\x79',  // Length of the delta encoding
    FirstByteOfStringLength(kExpectedTarget),  // Size of the target window
    SecondByteOfStringLength(kExpectedTarget),
    '\x00',  // Delta_indicator (no compression)
    '\x00',  // length of data for ADDs and RUNs (unused)
    '\x73',  // length of interleaved section
    '\x00'  // length of addresses for COPYs (unused)
  };

const char VCDiffInterleavedDecoderTest::kWindowBody[] = {
    '\x13',  // VCD_COPY mode VCD_SELF, size 0
    '\x1C',  // Size of COPY (28)
    '\x00',  // Address of COPY: Start of dictionary
    '\x01',  // VCD_ADD size 0
    '\x3D',  // Size of ADD (61)
    // Data for ADD (length 61)
    ' ', 'I', ' ', 'h', 'a', 'v', 'e', ' ', 's', 'a', 'i', 'd', ' ',
    'i', 't', ' ', 't', 'w', 'i', 'c', 'e', ':', '\n',
    'T', 'h', 'a', 't', ' ',
    'a', 'l', 'o', 'n', 'e', ' ', 's', 'h', 'o', 'u', 'l', 'd', ' ',
    'e', 'n', 'c', 'o', 'u', 'r', 'a', 'g', 'e', ' ',
    't', 'h', 'e', ' ', 'c', 'r', 'e', 'w', '.', '\n',
    '\x23',  // VCD_COPY mode VCD_HERE, size 0
    '\x2C',  // Size of COPY (44)
    '\x58',  // HERE mode address (27+61 back from here_address)
    '\xCB',  // VCD_ADD size 2 + VCD_COPY mode NEAR(1), size 5
    // Data for ADDs: 2nd section (length 2)
    'h', 'r',
    '\x2D',  // NEAR(1) mode address (45 after prior address)
    '\x0A',  // VCD_ADD size 9
    // Data for ADDs: 3rd section (length 9)
    'W', 'h', 'a', 't', ' ',
    'I', ' ', 't', 'e',
    '\x00',  // VCD_RUN size 0
    '\x02',  // Size of RUN (2)
    // Data for RUN: 4th section (length 1)
    'l',
    '\x01',  // VCD_ADD size 0
    '\x1B',  // Size of ADD (27)
    // Data for ADD: 4th section (length 27)
    ' ', 'y', 'o', 'u', ' ',
    't', 'h', 'r', 'e', 'e', ' ', 't', 'i', 'm', 'e', 's', ' ', 'i', 's', ' ',
    't', 'r', 'u', 'e', '.', '\"', '\n'
  };

VCDiffInterleavedDecoderTest::VCDiffInterleavedDecoderTest() {
  UseInterleavedFileHeader();
  delta_window_header_.assign(kWindowHeader, sizeof(kWindowHeader));
  delta_window_body_.assign(kWindowBody, sizeof(kWindowBody));
}

}  // namespace open_vcdiff
