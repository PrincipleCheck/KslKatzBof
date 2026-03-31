#pragma once
#include "common.h"

// Driver IOCTL code
#define KSLD_IOCTL 0x222044

#pragma pack(push, 1)
typedef struct {
    uint32_t sub_cmd;
    uint32_t reserved;
    uint64_t address;
    uint64_t size;
    uint32_t mode;    // 1 = physical, 2 = virtual
    uint32_t padding;
} IoReadInput;

typedef struct {
    uint32_t sub_cmd;
    uint32_t reserved;
} IoSubCmd2;
#pragma pack(pop)

// Driver state
typedef struct {
    HANDLE   handle;
    wchar_t  orig_image_path[MAX_PATH];
    wchar_t  orig_allowed[1024];
    BOOL     driver_was_deployed;
    BOOL     service_was_created;
} DriverState;

BOOL setup_ksld(DriverState* state);
void cleanup_ksld(DriverState* state);

// Raw IOCTL
Bytes ioctl_raw(HANDLE h, const void* in_buf, DWORD in_size, DWORD out_size);

// SubCmd 2 (register dump)
Bytes subcmd2(HANDLE h);

// Physical / virtual reads
Bytes phys_read(HANDLE h, uint64_t addr, uint64_t size);
Bytes virt_read(HANDLE h, uint64_t addr, uint64_t size);
