// Minimal Windows WFP/NT kernel shims so clangd can parse without WDK headers.
// This is for IDE use only; real builds must use the actual WDK.
#ifndef DDM_WFP_COMPAT_SHIM_H
#define DDM_WFP_COMPAT_SHIM_H

#ifndef __has_include
#define __has_include(x) 0
#endif

#if !__has_include(<ntddk.h>)

#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <wchar.h>
#include <stdio.h>
#include <math.h>

typedef uint8_t UINT8;
typedef uint8_t UCHAR;
typedef uint16_t UINT16;
typedef uint16_t USHORT;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef int32_t NTSTATUS;
typedef uint32_t ULONG;
typedef int64_t LONG64;
typedef void *PVOID;
typedef void *HANDLE;
typedef unsigned char BOOLEAN;
typedef char CHAR;
typedef unsigned long long ULONGLONG;
typedef ULONGLONG *PULONGLONG;

typedef void *PDEVICE_OBJECT;
typedef struct _DRIVER_OBJECT *PDRIVER_OBJECT;
typedef struct _IRP *PIRP;
typedef BOOLEAN *PBOOLEAN;
typedef USHORT *PUSHORT;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    wchar_t *Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _ULARGE_INTEGER {
    ULONGLONG QuadPart;
} ULARGE_INTEGER;

typedef struct _IO_STACK_LOCATION {
    struct {
        struct {
            UINT32 IoControlCode;
            UINT32 InputBufferLength;
            UINT32 OutputBufferLength;
        } DeviceIoControl;
    } Parameters;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;

typedef struct _IRP {
    struct {
        void *SystemBuffer;
    } AssociatedIrp;
    struct {
        NTSTATUS Status;
        UINT64 Information;
    } IoStatus;
} IRP;

typedef struct _GUID {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t Data4[8];
} GUID;

#ifndef DEFINE_GUID
#define DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
    static const GUID name = {l, w1, w2, {b1, b2, b3, b4, b5, b6, b7, b8}}
#endif

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)0xC0000010L)
#define STATUS_TIME_EXPIRED ((NTSTATUS)0xC000007FL)
#define NT_SUCCESS(Status) ((Status) >= 0)

#ifndef NTAPI
#define NTAPI
#endif

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif

#define FILE_DEVICE_NETWORK 0x00000012
#define FILE_DEVICE_SECURE_OPEN 0x00000100

#define IRP_CREATE 0
#define IRP_CLOSE 2
#define IRP_DEVICE_CONTROL 14
#define IO_NO_INCREMENT 0

#define RPC_C_AUTHN_DEFAULT 0
#define FWP_WEIGHT_TYPE 0

// FWP value types (subset)
#define FWP_VALUE0_TYPE_UINT8 1
#define FWP_VALUE0_TYPE_UINT16 2
#define FWP_VALUE0_TYPE_UINT32 3
#define FWP_VALUE0_TYPE_UINT64 4

#define FWP_ACTION_PERMIT 0x0001
#define FWP_ACTION_BLOCK 0x0002
#define FWPS_RIGHT_ACTION_WRITE 0x0001
#define IOCTL_DDM_SET_AUDIT_MODE 0x800
#define IOCTL_DDM_GET_STATS 0x801

typedef struct _FWP_VALUE {
    UINT32 type;
    union {
        UINT8 uint8;
        UINT16 uint16;
        UINT32 uint32;
        UINT64 uint64;
    };
} FWP_VALUE;

typedef struct _FWP_CONDITION_VALUE {
    UINT32 type;
    union {
        UINT8 uint8;
        UINT16 uint16;
        UINT32 uint32;
        UINT64 uint64;
    };
} FWP_CONDITION_VALUE;

typedef struct _FWPM_DISPLAY_DATA {
    wchar_t *name;
    wchar_t *description;
} FWPM_DISPLAY_DATA;

typedef struct _FWPM_ACTION {
    GUID calloutKey;
} FWPM_ACTION;

typedef struct _FWPM_FILTER_CONDITION {
    GUID fieldKey;
    FWP_CONDITION_VALUE conditionValue;
} FWPM_FILTER_CONDITION;

typedef struct _FWPM_WEIGHT {
    UINT32 type;
    union {
        UINT32 uint32;
    };
} FWPM_WEIGHT;

typedef struct _FWPM_FILTER {
    FWPM_DISPLAY_DATA displayData;
    GUID layerKey;
    FWPM_ACTION action;
    FWPM_FILTER_CONDITION *filterCondition;
    UINT32 numFilterConditions;
    FWPM_WEIGHT weight;
} FWPM_FILTER;

typedef struct _FWPS_CLASSIFY_IN {
    struct {
        const UINT8 *dataBuffer;
        UINT32 dataLength;
    } *packetData;
} FWPS_CLASSIFY_IN;

typedef struct _FWPS_CLASSIFY_OUT {
    UINT32 actionType;
    UINT32 rights;
} FWPS_CLASSIFY_OUT;

typedef struct _FWPS_FILTER {
    GUID filterKey;
} FWPS_FILTER;

typedef struct _FWPS_CALLOUT {
    GUID calloutKey;
    void (*classifyFn)(void);
    void (*notifyFn)(void);
    void (*flowDeleteFn)(void);
} FWPS_CALLOUT;

typedef struct _FWPS_CALLOUT_NOTIFY_DATA {
    GUID calloutKey;
    UINT32 calloutId;
} FWPS_CALLOUT_NOTIFY_DATA;

static const GUID FWPM_CONDITION_IP_REMOTE_PORT = {0};
static const GUID FWPM_CONDITION_IP_PROTOCOL = {0};
static const GUID FWPM_LAYER_ALE_CONNECT_REDIRECT_V4 = {0};

static __inline UINT16 ntohs(UINT16 v) { return (UINT16)((v >> 8) | (v << 8)); }

// Basic kernel API shims (no-ops for IntelliSense)
static __inline void RtlZeroMemory(void *dst, size_t len) { memset(dst, 0, len); }

static __inline void RtlInitUnicodeString(PUNICODE_STRING us, const wchar_t *src) {
    if (!us) return;
    if (!src) {
        us->Length = us->MaximumLength = 0;
        us->Buffer = NULL;
        return;
    }
    size_t len = wcslen(src) * sizeof(wchar_t);
    us->Length = (USHORT)len;
    us->MaximumLength = (USHORT)(len + sizeof(wchar_t));
    us->Buffer = (wchar_t *)src;
}

static __inline NTSTATUS RtlStringCchCopyA(char *dst, size_t dstChars, const char *src) {
    if (!dst || !dstChars) return STATUS_INVALID_PARAMETER;
    strncpy(dst, src ? src : "", dstChars - 1);
    dst[dstChars - 1] = '\0';
    return STATUS_SUCCESS;
}

static __inline void KeQuerySystemTime(uint64_t *time) {
    if (time) *time = 0;
}

static __inline uint64_t KeQueryTickCount(void) { return 0; }

static __inline NTSTATUS IoCreateDevice(
    PDRIVER_OBJECT DriverObject,
    ULONG DeviceExtensionSize,
    PUNICODE_STRING DeviceName,
    ULONG DeviceType,
    ULONG DeviceCharacteristics,
    BOOLEAN Exclusive,
    PDEVICE_OBJECT *DeviceObject
) {
    (void)DriverObject; (void)DeviceExtensionSize; (void)DeviceName;
    (void)DeviceType; (void)DeviceCharacteristics; (void)Exclusive;
    if (DeviceObject) *DeviceObject = (PDEVICE_OBJECT)1;
    return STATUS_SUCCESS;
}

static __inline NTSTATUS IoCreateSymbolicLink(PUNICODE_STRING link, PUNICODE_STRING target) {
    (void)link; (void)target;
    return STATUS_SUCCESS;
}

static __inline void IoDeleteDevice(PDEVICE_OBJECT device) { (void)device; }

static __inline void IoSkipCurrentIrpStackLocation(PIRP Irp) { (void)Irp; }

static __inline NTSTATUS IoCallDriver(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    (void)DeviceObject; (void)Irp; return STATUS_SUCCESS;
}

static __inline void IoCompleteRequest(PIRP Irp, int PriorityBoost) {
    (void)Irp; (void)PriorityBoost;
}

static __inline PIO_STACK_LOCATION IoGetCurrentIrpStackLocation(PIRP Irp) {
    (void)Irp;
    static IO_STACK_LOCATION dummy;
    memset(&dummy, 0, sizeof(dummy));
    return &dummy;
}

static __inline LONG64 InterlockedIncrement64(LONG64 *Addend) {
    if (Addend) (*Addend)++;
    return Addend ? *Addend : 0;
}

static __inline void DbgPrint(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

static __inline NTSTATUS FwpsCalloutRegister(
    void (*classifyFn)(void),
    const GUID *calloutKey,
    UINT32 flags,
    UINT32 *calloutId
) {
    (void)classifyFn; (void)calloutKey; (void)flags;
    if (calloutId) *calloutId = 1;
    return STATUS_SUCCESS;
}

static __inline NTSTATUS FwpmFilterAdd(
    HANDLE engineHandle,
    const FWPM_FILTER *filter,
    void *sd,
    UINT64 *filterId
) {
    (void)engineHandle; (void)filter; (void)sd;
    if (filterId) *filterId = 1;
    return STATUS_SUCCESS;
}

static __inline NTSTATUS FwpmEngineOpen(
    const wchar_t *serverName,
    UINT32 authnService,
    void *authIdentity,
    void *session,
    HANDLE *engineHandle
) {
    (void)serverName; (void)authnService; (void)authIdentity; (void)session;
    if (engineHandle) *engineHandle = (HANDLE)1;
    return STATUS_SUCCESS;
}

static __inline NTSTATUS FwpmEngineClose(HANDLE engineHandle) {
    (void)engineHandle; return STATUS_SUCCESS;
}

#endif  // !__has_include(<ntddk.h>)

#endif  // DDM_WFP_COMPAT_SHIM_H
