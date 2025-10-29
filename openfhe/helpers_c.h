#ifndef HELPERS_C_H
#define HELPERS_C_H

// This is an *internal* header file, not part of the public C-API.
// It is included by pke_common_c.cpp, bfv_c.cpp, bgv_c.cpp, and ckks_c.cpp
// to share C++ helper functions, using declarations, and error macros.

#include "pke_common_c.h"
#include <cstdlib>
#include <cstring>
#include <memory>
#include <openfhe/core/lattice/hal/default/dcrtpoly.h>
#include <openfhe/core/utils/serial.h>
#include <openfhe/core/utils/sertype.h>
#include <openfhe/pke/ciphertext-ser.h>
#include <openfhe/pke/ciphertext.h>
#include <openfhe/pke/cryptocontext-ser.h>
#include <openfhe/pke/cryptocontext.h>
#include <openfhe/pke/encoding/plaintext.h>
#include <openfhe/pke/gen-cryptocontext.h>
#include <openfhe/pke/key/key-ser.h>
#include <openfhe/pke/key/keypair.h>
#include <openfhe/pke/key/privatekey.h>
#include <openfhe/pke/key/publickey.h>
#include <openfhe/pke/openfhe.h>
#include <sstream>
#include <string>
#include <vector>

static inline char *DupString(const std::string &s) {
#ifdef _WIN32
  char *cstr = _strdup(s.c_str());
  // Add error checking if needed: if (!cstr) { /* handle */ }
  return cstr;
#else
  char *cstr = strdup(s.c_str());
  // Add error checking if needed: if (!cstr) { /* handle */ }
  return cstr;
#endif
}

// --- String Helper ---
// Helper to copy std::string to C string (caller must free using C.free or
// FreeString)
static inline char *CopyStringToC(const std::string &s) {
  char *cstr = (char *)malloc(s.length() + 1);
  if (!cstr)
    return nullptr; // Handle malloc failure
  std::strcpy(cstr, s.c_str());
  return cstr;
}

#endif // HELPERS_C_H
