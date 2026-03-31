#include "memory.h"

// ----------------------------------------------------------------
// Page table walk: PML4 -> PDPT -> PD -> PT
// Returns 0 on failure, physical address on success.
// ----------------------------------------------------------------
uint64_t vtp(HANDLE h, uint64_t dtb, uint64_t va) {
    typedef struct { int shift; uint64_t large_mask; int can_be_large; } Level;
    static const Level levels[3] = {
        { 39, 0ULL,                 0 },  // PML4
        { 30, 0xFFFFC0000000ULL,    1 },  // PDPT (1GB page)
        { 21, 0xFFFFFFFE00000ULL,   1 },  // PD   (2MB page)
    };

    uint64_t table_base = dtb & PFN_MASK;
    int lvl;
    for (lvl = 0; lvl < 3; lvl++) {
        size_t idx = (va >> levels[lvl].shift) & 0x1FF;
        Bytes entry_data = phys_read(h, table_base + idx * 8, 8);
        if (Bytes_empty(&entry_data)) { Bytes_free(&entry_data); return 0; }
        uint64_t entry = rp(entry_data.data, 0);
        Bytes_free(&entry_data);

        if (!(entry & 1)) return 0;

        if (levels[lvl].can_be_large && (entry & 0x80)) {
            return (entry & levels[lvl].large_mask) | (va & ((1ULL << levels[lvl].shift) - 1));
        }
        table_base = entry & PFN_MASK;
    }

    // PT level
    size_t idx = (va >> 12) & 0x1FF;
    Bytes entry_data = phys_read(h, table_base + idx * 8, 8);
    if (Bytes_empty(&entry_data)) { Bytes_free(&entry_data); return 0; }
    uint64_t entry = rp(entry_data.data, 0);
    Bytes_free(&entry_data);

    // Present
    if (entry & 1)
        return (entry & PFN_MASK) | (va & 0xFFF);

    // Transition page (standby list, bit 11 set)
    if (entry & 0x800) {
        static const uint64_t masks[] = { 0xFFFFFF000ULL, 0xFFFFFFF000ULL, 0xFFFFFFFF000ULL, PFN_MASK };
        int m;
        for (m = 0; m < 4; m++) {
            uint64_t pa = (entry & masks[m]) | (va & 0xFFF);
            Bytes test = phys_read(h, pa & ~0xFFFULL, 16);
            if (!Bytes_empty(&test)) {
                int all_zero = 1;
                size_t bi;
                for (bi = 0; bi < 16; bi++) if (test.data[bi] != 0) { all_zero = 0; break; }
                Bytes_free(&test);
                if (!all_zero) return pa;
            } else { Bytes_free(&test); }
        }
        return (entry & 0xFFFFFF000ULL) | (va & 0xFFF);
    }

    return 0;
}

// ----------------------------------------------------------------
// Process virtual address read via physical translation
// ----------------------------------------------------------------
Bytes proc_read(HANDLE h, uint64_t dtb, uint64_t va, size_t size) {
    Bytes result = Bytes_alloc(size);
    result.size = 0;
    size_t off = 0;

    while (off < size) {
        uint64_t page_off = (va + off) & 0xFFF;
        size_t chunk = size - off;
        if (chunk > (size_t)(0x1000 - page_off)) chunk = (size_t)(0x1000 - page_off);

        uint64_t pa = vtp(h, dtb, va + off);
        if (!pa) {
            MSVCRT$memset(result.data + result.size, 0, chunk);
        } else {
            Bytes data = phys_read(h, pa, chunk);
            if (data.size >= chunk) {
                MSVCRT$memcpy(result.data + result.size, data.data, chunk);
            } else {
                MSVCRT$memset(result.data + result.size, 0, chunk);
            }
            Bytes_free(&data);
        }
        result.size += chunk;
        off += chunk;
    }
    return result;
}

// ----------------------------------------------------------------
// Read a single pointer from process VA
// ----------------------------------------------------------------
uint64_t read_ptr(HANDLE h, uint64_t dtb, uint64_t va) {
    Bytes d = proc_read(h, dtb, va, 8);
    uint64_t v = (d.size >= 8) ? rp(d.data, 0) : 0;
    Bytes_free(&d);
    return v;
}

// ----------------------------------------------------------------
// Resolve RIP-relative 32-bit displacement
// ----------------------------------------------------------------
uint64_t resolve_rip(HANDLE h, uint64_t dtb, uint64_t va) {
    Bytes d = proc_read(h, dtb, va, 4);
    if (d.size < 4) { Bytes_free(&d); return 0; }
    uint64_t v = va + 4 + ri(d.data, 0);
    Bytes_free(&d);
    return v;
}

// ----------------------------------------------------------------
// Read UNICODE_STRING { USHORT Length; USHORT MaxLength; PWSTR Buffer; }
// ----------------------------------------------------------------
void read_ustr(HANDLE h, uint64_t dtb, const uint8_t* data, size_t off, wchar_t* out, size_t out_len) {
    out[0] = L'\0';
    uint16_t length = rw(data, off);
    uint64_t buf    = rp(data, off + 8);
    if (!length || !buf) return;
    size_t wlen = length / sizeof(wchar_t);
    if (wlen >= out_len) wlen = out_len - 1;

    Bytes raw = proc_read(h, dtb, buf, wlen * sizeof(wchar_t));
    if (raw.size >= wlen * sizeof(wchar_t)) {
        MSVCRT$memcpy(out, raw.data, wlen * sizeof(wchar_t));
        out[wlen] = L'\0';
    }
    Bytes_free(&raw);
}

// ----------------------------------------------------------------
// Read ANSI_STRING { USHORT Length; USHORT MaxLength; PCHAR Buffer; }
// ----------------------------------------------------------------
void read_astr(HANDLE h, uint64_t dtb, const uint8_t* data, size_t off, char* out, size_t out_len) {
    out[0] = '\0';
    uint16_t length = rw(data, off);
    uint64_t buf    = rp(data, off + 8);
    if (!length || !buf) return;
    size_t len = length;
    if (len >= out_len) len = out_len - 1;

    Bytes raw = proc_read(h, dtb, buf, len);
    if (raw.size >= len) {
        MSVCRT$memcpy(out, raw.data, len);
        out[len] = '\0';
    }
    Bytes_free(&raw);
}

// ----------------------------------------------------------------
// Pattern scan across process memory in 64KB chunks
// ----------------------------------------------------------------
uint64_t scan_first(HANDLE h, uint64_t dtb, uint64_t base, size_t size,
                    const uint8_t* pattern, size_t pattern_len) {
    const size_t CHUNK = 0x10000;
    size_t off = 0;
    while (off < size) {
        size_t read_sz = CHUNK;
        if (read_sz > size - off) read_sz = size - off;
        Bytes data = proc_read(h, dtb, base + off, read_sz);
        if (data.size >= pattern_len) {
            size_t pos;
            for (pos = 0; pos + pattern_len <= data.size; pos++) {
                if (MSVCRT$memcmp(data.data + pos, pattern, pattern_len) == 0) {
                    Bytes_free(&data);
                    return base + off + pos;
                }
            }
        }
        Bytes_free(&data);
        off += CHUNK;
    }
    return 0;
}
