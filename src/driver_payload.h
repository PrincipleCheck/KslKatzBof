#pragma once
// Placeholder for the vulnerable KslD.sys driver payload.
// Replace VKSLD_DATA and VKSLD_SIZE with the actual driver bytes and size,
// and update VKSLD_SHA256 in driver.c with the correct SHA-256 hash.
//
// SHA256: bd17231833aa369b3b2b6963899bf05dbefd673db270aec15446f2fab4a17b5a
//
// Note: The placeholder below only contains the MZ header (2 bytes).
// You must replace this with the full driver binary.

#include <stdint.h>
#include <stddef.h>

// VKSLD_SIZE as a preprocessor constant - no .data/.rodata entry
#define VKSLD_SIZE 2

// clang-format off
// NOTE: For large real payloads, pass driver bytes via BOF argument instead
// of embedding here, to avoid placing a large array in .rodata.
// For the placeholder (2 bytes) this is acceptable.
static const uint8_t VKSLD_DATA[] = {
    0x4d, 0x5a
};
// clang-format on
