// Copyright 2008 Google Inc. All Rights Reserved.
// Author: ajenjo@google.com (Lincoln Smith)
//
// Definition of an abstract class that describes the interface between the
// encoding engine (which finds the best string matches between the source and
// target data) and the code table writer.  The code table writer is passed a
// series of Add, Copy, and Run instructions and produces an output file in the
// desired format.

#ifndef OPEN_VCDIFF_CODETABLEWRITER_INTERFACE_H_
#define OPEN_VCDIFF_CODETABLEWRITER_INTERFACE_H_

#include <stddef.h>  // size_t

namespace open_vcdiff {

class OutputStringInterface;

// The method calls after construction should follow this pattern:
//    {{Add|Copy|Run}* Output}*
//
// Output() will produce an encoding using the given series of Add, Copy,
// and/or Run instructions.  One implementation of the interface
// (VCDiffCodeTableWriter) produces a VCDIFF delta window, but other
// implementations may be used to produce other output formats, or as test
// mocks, or to gather encoding statistics.
//
class CodeTableWriterInterface {
 public:
  virtual ~CodeTableWriterInterface() { }

  // Encode an ADD opcode with the "size" bytes starting at data
  virtual void Add(const char* data, size_t size) = 0;

  // Encode a COPY opcode with args "offset" (into dictionary) and "size" bytes.
  virtual void Copy(int32_t offset, size_t size) = 0;

  // Encode a RUN opcode for "size" copies of the value "byte".
  virtual void Run(size_t size, unsigned char byte) = 0;

  // Finishes encoding and appends the encoded delta window to the output
  // string.  The output string is not null-terminated and may contain embedded
  // '\0' characters.
  virtual void Output(OutputStringInterface* out) = 0;

  // Returns the number of target bytes processed, which is the sum of all the
  // size arguments passed to Add(), Copy(), and Run().
  virtual size_t target_length() const = 0;
};

}  // namespace open_vcdiff

#endif  // OPEN_VCDIFF_CODETABLEWRITER_INTERFACE_H_
