#pragma once
#include "driver.h"

#define PFN_MASK 0xFFFFFFFFF000ULL

// Virtual-to-physical translation (page table walk with transition page support).
// Returns 0 on failure, physical address on success.
uint64_t vtp(HANDLE h, uint64_t dtb, uint64_t va);

// Process virtual memory read via physical translation.
Bytes proc_read(HANDLE h, uint64_t dtb, uint64_t va, size_t size);

// Convenience: read pointer from process VA.
uint64_t read_ptr(HANDLE h, uint64_t dtb, uint64_t va);

// Resolve RIP-relative address (LEA/MOV with disp32).
uint64_t resolve_rip(HANDLE h, uint64_t dtb, uint64_t va);

// Read UNICODE_STRING from struct at offset.
// Writes result into out (wchar_t[MAX_STR_LEN]).
void read_ustr(HANDLE h, uint64_t dtb, const uint8_t* data, size_t off, wchar_t* out, size_t out_len);

// Read ANSI_STRING from struct at offset.
// Writes result into out (char[MAX_STR_LEN]).
void read_astr(HANDLE h, uint64_t dtb, const uint8_t* data, size_t off, char* out, size_t out_len);

// Pattern scan in process memory.
// Returns the VA of the first match or 0.
uint64_t scan_first(HANDLE h, uint64_t dtb, uint64_t base, size_t size,
                    const uint8_t* pattern, size_t pattern_len);
