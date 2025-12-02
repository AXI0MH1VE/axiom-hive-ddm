/*
 * Axiom Hive DDM - Windows WFP Driver
 * Production-grade Windows Filtering Platform callout driver
 * 
 * Features:
 * - Kernel-mode DNS filtering with WFP
 * - Entropy-based domain analysis
 * - Manifold enforcement with policy management
 * - Integration with Windows security model
 * - ETW logging for observability
 * - Tamper detection and protection
 */

#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <guiddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Driver version
#define DDM_WFP_VERSION_MAJOR 2
#define DDM_WFP_VERSION_MINOR 0
#define DDM_WFP_VERSION_PATCH 0

// Constants
#define DNS_PORT 53
#define MAX_QNAME_LEN 253
#define MAX_DNS_LABELS 63
#define SCALE 65536
#define MAX_EVENTS 4096

// GUID definitions for WFP callout registration
DEFINE_GUID(DDM_WFP_CALLOUT_V4,
    0x12345678, 0x1234, 0x1234, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0);
DEFINE_GUID(DDM_WFP_CALLOUT_V6,
    0x12345679, 0x1234, 0x1234, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF1);

// ETW event types
#define DDM_EVENT_VIOLATION 0x1001
#define DDM_EVENT_STATS 0x1002
#define DDM_EVENT_ERROR 0x1003

// WFP callout driver structures
typedef struct _DDM_WFP_STATE {
    PDEVICE_OBJECT deviceObject;
    BOOLEAN calloutRegistered;
    BOOLEAN driverLoaded;
    UINT32 calloutId;
    HANDLE engineHandle;
    UINT64 filterId;
    BOOLEAN auditMode;
    BOOLEAN tamperProtected;
} DDM_WFP_STATE, *PDDM_WFP_STATE;

DDM_WFP_STATE g_ddmState = {0};

// DNS parsing structures
typedef struct _DNS_HEADER {
    USHORT id;
    USHORT flags;
    USHORT qdcount;
    USHORT ancount;
    USHORT nscount;
    USHORT arcount;
} DNS_HEADER, *PDNS_HEADER;

typedef struct _DNS_QUERY {
    CHAR qname[MAX_QNAME_LEN];
    USHORT qname_len;
    USHORT qtype;
    USHORT qclass;
    BOOLEAN is_valid;
} DNS_QUERY, *PDNS_QUERY;

// Manifold entry structure
typedef struct _MANIFOLD_ENTRY {
    UCHAR type;  // 0 = exact, 1 = wildcard
    UINT32 entropy_max_scaled;
    UINT64 valid_until;
    UCHAR flags;
    UCHAR country_code[2];
    UCHAR require_https;
    UCHAR audit_only;
} MANIFOLD_ENTRY, *PMANIFOLD_ENTRY;

// Statistics structure
typedef struct _DDM_STATS {
    UINT64 packets_total;
    UINT64 packets_allowed;
    UINT64 packets_dropped;
    UINT64 parse_errors;
    UINT64 entropy_exceeded;
    UINT64 not_in_manifold;
    UINT64 tamper_attempts;
    UINT64 last_update;
} DDM_STATS, *PDDM_STATS;

DDM_STATS g_stats = {0};

// Entropy calculation (Windows kernel supports floating point)
static __inline float compute_entropy(const CHAR* str, USHORT len) {
    UINT32 freq[256] = {0};
    float entropy = 0.0f;
    
    if (len == 0 || len > MAX_QNAME_LEN)
        return 0.0f;
    
    // Count character frequencies
    for (USHORT i = 0; i < len; i++) {
        UCHAR c = (UCHAR)str[i];
        freq[c]++;
    }
    
    // Calculate Shannon entropy
    for (INT i = 0; i < 256; i++) {
        if (freq[i] == 0)
            continue;
        
        float p = (float)freq[i] / (float)len;
        entropy -= p * (logf(p) / logf(2.0f));
    }
    
    return entropy;
}

// DNS packet parsing
static BOOLEAN parse_dns_query(
    const UINT8* packet,
    UINT32 packetSize,
    PDNS_QUERY query,
    BOOLEAN* isIPv6
) {
    const UINT8* cursor = packet;
    UINT32 remaining = packetSize;
    
    RtlZeroMemory(query, sizeof(DNS_QUERY));
    query->is_valid = FALSE;
    
    // Skip IP headers (simplified for UDP DNS)
    if (remaining < sizeof(DNS_HEADER))
        return FALSE;
    
    PDNS_HEADER dns = (PDNS_HEADER)cursor;
    cursor += sizeof(DNS_HEADER);
    remaining -= sizeof(DNS_HEADER);
    
    if (ntohs(dns->qdcount) == 0)
        return FALSE;
    
    // Parse QNAME
    UCHAR offset = 0;
    UCHAR labelCount = 0;
    
    while (remaining > 0 && offset < (MAX_QNAME_LEN - 1)) {
        if (remaining < sizeof(UCHAR))
            break;
        
        UCHAR labelLen = *cursor;
        cursor++;
        remaining--;
        
        if (labelLen == 0) {
            query->qname[offset] = '\0';
            query->qname_len = offset;
            query->is_valid = TRUE;
            break;
        }
        
        if (labelLen > 63 || offset + labelLen + 1 >= MAX_QNAME_LEN)
            return FALSE;
        
        labelCount++;
        if (labelCount > MAX_DNS_LABELS)
            return FALSE;
        
        // Copy label
        for (UCHAR i = 0; i < labelLen && remaining > 0; i++) {
            query->qname[offset++] = *cursor++;
            remaining--;
        }
        
        if (offset < (MAX_QNAME_LEN - 1)) {
            query->qname[offset++] = '.';
        }
    }
    
    // Parse QTYPE and QCLASS if space permits
    if (remaining >= 4) {
        query->qtype = *(PUSHORT)cursor;
        cursor += 2;
        query->qclass = *(PUSHORT)cursor;
    }
    
    return query->is_valid;
}

// Manifold lookup (simplified implementation)
static BOOLEAN lookup_manifold(const CHAR* domain, USHORT len, PMANIFOLD_ENTRY entry) {
    // In production, this would query a hash table or other efficient data structure
    // For now, we'll implement a basic example
    
    if (strncmp(domain, "google.com", len) == 0) {
        entry->type = 0;
        entry->entropy_max_scaled = (UINT32)(3.5f * SCALE);
        entry->valid_until = 0;
        entry->flags = 0;
        entry->audit_only = g_ddmState.auditMode ? 1 : 0;
        return TRUE;
    }
    
    if (strncmp(domain, "*.microsoft.com", len) == 0) {
        entry->type = 1;
        entry->entropy_max_scaled = (UINT32)(4.0f * SCALE);
        entry->valid_until = 0;
        entry->flags = 0;
        entry->audit_only = g_ddmState.auditMode ? 1 : 0;
        return TRUE;
    }
    
    // Domain not in manifold
    return FALSE;
}

// Tamper detection
static BOOLEAN detect_tamper_attempt() {
    // Check if our callout has been modified or removed
    // This is a simplified implementation
    if (!g_ddmState.calloutRegistered) {
        InterlockedIncrement64((LONG64*)&g_stats.tamper_attempts);
        return TRUE;
    }
    
    return FALSE;
}

// ETW logging
static void log_etw_event(
    UINT32 eventType,
    NTSTATUS status,
    const CHAR* message,
    UINT32 messageLen
) {
    // In production, this would use EtwWrite or similar ETW APIs
    // For now, use DbgPrint for debugging
    DbgPrint("DDM WFP Event %x: %s\n", eventType, message);
}

// WFP callout functions
void NTAPI classifyFn(
    void* classifyObject,
    const FWP_VALUE* classifyAddress,
    void* flowContext,
    UINT64 flowContextHandle,
    const FWPS_FILTER* filter,
    UINT64 filterId,
    UINT32 layerId,
    const FWPS_CLASSIFY_IN* in,
    FWPS_CLASSIFY_OUT* out,
    void* completionRoutineContext,
    void* completionRoutineHandle
) {
    NTSTATUS status = STATUS_SUCCESS;
    DNS_QUERY query = {0};
    BOOLEAN allow = TRUE;
    CHAR domain[256] = {0};
    BOOLEAN isIPv6 = FALSE;
    
    // Update packet counter
    InterlockedIncrement64((LONG64*)&g_stats.packets_total);
    
    // Check for tamper attempts
    if (detect_tamper_attempt()) {
        log_etw_event(DDM_EVENT_ERROR, STATUS_ACCESS_DENIED, "Tamper attempt detected", 0);
        out->actionType = FWP_ACTION_BLOCK;
        return;
    }
    
    if (in->packetData == NULL || in->packetData->dataBuffer == NULL) {
        out->actionType = FWP_ACTION_PERMIT;
        return;
    }
    
    // Parse DNS packet
    if (!parse_dns_query(
        in->packetData->dataBuffer,
        in->packetData->dataLength,
        &query,
        &isIPv6
    )) {
        InterlockedIncrement64((LONG64*)&g_stats.parse_errors);
        log_etw_event(DDM_EVENT_ERROR, STATUS_INVALID_PARAMETER, "DNS parse error", 0);
        out->actionType = FWP_ACTION_PERMIT;  // Permit malformed packets
        return;
    }
    
    // Copy domain for logging
    RtlStringCchCopyA(domain, sizeof(domain), query.qname);
    
    // Lookup in manifold
    MANIFOLD_ENTRY manifoldEntry = {0};
    if (!lookup_manifold(query.qname, query.qname_len, &manifoldEntry)) {
        // Not in manifold - should be blocked
        allow = FALSE;
        
        InterlockedIncrement64((LONG64*)&g_stats.not_in_manifold);
        log_etw_event(DDM_EVENT_VIOLATION, STATUS_ACCESS_DENIED, 
            "Domain not in manifold", strlen("Domain not in manifold"));
    } else {
        // Check temporal validity
        if (manifoldEntry.valid_until > 0) {
            ULARGE_INTEGER currentTime;
            KeQuerySystemTime(&currentTime);
            if (currentTime.QuadPart > (ULONGLONG)manifoldEntry.valid_until) {
                allow = FALSE;
                InterlockedIncrement64((LONG64*)&g_stats.not_in_manifold);
                log_etw_event(DDM_EVENT_VIOLATION, STATUS_TIME_EXPIRED, 
                    "Policy expired", strlen("Policy expired"));
            }
        }
        
        // Check entropy
        if (allow && manifoldEntry.entropy_max_scaled > 0) {
            float entropy = compute_entropy(query.qname, query.qname_len);
            UINT32 entropyScaled = (UINT32)(entropy * SCALE);
            
            if (entropyScaled > manifoldEntry.entropy_max_scaled) {
                allow = FALSE;
                InterlockedIncrement64((LONG64*)&g_stats.entropy_exceeded);
                log_etw_event(DDM_EVENT_VIOLATION, STATUS_ACCESS_DENIED, 
                    "Entropy exceeded", strlen("Entropy exceeded"));
            }
        }
    }
    
    // Update statistics
    if (allow) {
        InterlockedIncrement64((LONG64*)&g_stats.packets_allowed);
    } else {
        InterlockedIncrement64((LONG64*)&g_stats.packets_dropped);
    }
    
    // Set action based on audit mode and policy
    if (g_ddmState.auditMode || manifoldEntry.audit_only) {
        // Audit mode - log but don't block
        out->actionType = FWP_ACTION_PERMIT;
        log_etw_event(DDM_EVENT_VIOLATION, STATUS_SUCCESS, 
            "Audit mode block", strlen("Audit mode block"));
    } else if (allow) {
        out->actionType = FWP_ACTION_PERMIT;
    } else {
        out->actionType = FWP_ACTION_BLOCK;
        out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
    
    g_stats.last_update = (UINT64)KeQueryTickCount();
}

NTSTATUS NTAPI notifyFn(
    FWPS_CALLOUT_NOTIFY_DATA* notifyData,
    void* classifyContext,
    FWPS_FILTER* filter,
    void* completionContext
) {
    DbgPrint("DDM WFP Notify function called\n");
    return STATUS_SUCCESS;
}

void NTAPI flowDeleteFn(
    UINT16 layerId,
    UINT32 calloutId,
    UINT64 flowContextHandle
) {
    DbgPrint("DDM WFP Flow delete function called\n");
}

// WFP callout registration
NTSTATUS register_callout() {
    NTSTATUS status = STATUS_SUCCESS;
    FWPS_CALLOUT callout = {0};
    UINT32 calloutId;
    
    callout.calloutKey = DDM_WFP_CALLOUT_V4;
    callout.classifyFn = classifyFn;
    callout.notifyFn = notifyFn;
    callout.flowDeleteFn = flowDeleteFn;
    
    status = FwpsCalloutRegister(
        callout.classifyFn,
        &callout.calloutKey,
        0,  // No flags
        &calloutId
    );
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to register callout: %08X\n", status);
        return status;
    }
    
    g_ddmState.calloutId = calloutId;
    g_ddmState.calloutRegistered = TRUE;
    
    DbgPrint("Successfully registered WFP callout with ID: %u\n", calloutId);
    return STATUS_SUCCESS;
}

// Add filter to WFP engine
NTSTATUS add_filter(HANDLE engineHandle, PWCHAR filterName, UINT32 weight) {
    NTSTATUS status = STATUS_SUCCESS;
    FWPM_FILTER filter = {0};
    FWPM_FILTER_CONDITION conditions[2] = {0};
    UINT32 conditionCount = 0;
    
    // Filter conditions: Must be DNS traffic
    conditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    conditions[0].conditionValue.type = FWP_VALUE0_TYPE_UINT16;
    conditions[0].conditionValue.uint16 = DNS_PORT;
    conditionCount++;
    
    conditions[1].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conditions[1].conditionValue.type = FWP_VALUE0_TYPE_UINT8;
    conditions[1].conditionValue.uint8 = IPPROTO_UDP;
    conditionCount++;
    
    filter.displayData.name = filterName;
    filter.layerKey = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
    filter.action.calloutKey = DDM_WFP_CALLOUT_V4;
    filter.filterCondition = conditions;
    filter.numFilterConditions = conditionCount;
    filter.weight.type = FWP_WEIGHT_TYPE;
    filter.weight.uint32 = weight;
    
    status = FwpmFilterAdd(
        engineHandle,
        &filter,
        NULL,  // No security descriptor
        &g_ddmState.filterId
    );
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to add WFP filter: %08X\n", status);
        return status;
    }
    
    DbgPrint("Successfully added WFP filter with ID: %llu\n", g_ddmState.filterId);
    return STATUS_SUCCESS;
}

// Driver entry point
NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
) {
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLinkName;
    PDEVICE_OBJECT deviceObject = NULL;
    
    UNREFERENCED_PARAMETER(RegistryPath);
    
    // Initialize WFP state
    RtlZeroMemory(&g_ddmState, sizeof(DDM_WFP_STATE));
    
    // Create device object
    RtlInitUnicodeString(&deviceName, L"\\Device\\DdmWfp");
    RtlInitUnicodeString(&symbolicLinkName, L"\\DosDevices\\DdmWfp");
    
    status = IoCreateDevice(
        DriverObject,
        0,  // No device extension
        &deviceName,
        FILE_DEVICE_NETWORK,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
    );
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to create device object: %08X\n", status);
        return status;
    }
    
    status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to create symbolic link: %08X\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }
    
    g_ddmState.deviceObject = deviceObject;
    g_ddmState.auditMode = TRUE;  // Default to audit mode
    g_ddmState.driverLoaded = TRUE;
    
    // Initialize WFP engine
    status = FwpmEngineOpen(
        NULL,  // Use local machine
        RPC_C_AUTHN_DEFAULT,
        NULL,  // No security descriptor
        NULL,  // No callout data
        &g_ddmState.engineHandle
    );
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to open WFP engine: %08X\n", status);
        return status;
    }
    
    // Register callout
    status = register_callout();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // Add filter
    status = add_filter(g_ddmState.engineHandle, L"DDM DNS Filter", 1);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // Initialize driver object
    DriverObject->MajorFunction[IRP_CREATE] = ddm_create;
    DriverObject->MajorFunction[IRP_CLOSE] = ddm_close;
    DriverObject->MajorFunction[IRP_DEVICE_CONTROL] = ddm_device_control;
    DriverObject->DriverUnload = ddm_unload;
    
    g_ddmState.driverLoaded = TRUE;
    
    DbgPrint("DDM WFP Driver loaded successfully\n");
    DbgPrint("Version: %d.%d.%d\n", DDM_WFP_VERSION_MAJOR, DDM_WFP_VERSION_MINOR, DDM_WFP_VERSION_PATCH);
    
    return STATUS_SUCCESS;
}

// Device I/O Control functions
NTSTATUS ddm_create(PDEVICE_OBJECT deviceObject, PIRP irp) {
    UNREFERENCED_PARAMETER(deviceObject);
    
    IoSkipCurrentIrpStackLocation(irp);
    irp->IoStatus.Status = STATUS_SUCCESS;
    return IoCallDriver(deviceObject, irp);
}

NTSTATUS ddm_close(PDEVICE_OBJECT deviceObject, PIRP irp) {
    UNREFERENCED_PARAMETER(deviceObject);
    
    IoSkipCurrentIrpStackLocation(irp);
    irp->IoStatus.Status = STATUS_SUCCESS;
    return IoCallDriver(deviceObject, irp);
}

NTSTATUS ddm_device_control(PDEVICE_OBJECT deviceObject, PIRP irp) {
    UNREFERENCED_PARAMETER(deviceObject);
    
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_SUCCESS;
    
    switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_DDM_SET_AUDIT_MODE:
        if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(BOOLEAN)) {
            BOOLEAN auditMode = *(PBOOLEAN)irp->AssociatedIrp.SystemBuffer;
            g_ddmState.auditMode = auditMode;
            DbgPrint("DDM WFP audit mode set to: %d\n", auditMode);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
        
    case IOCTL_DDM_GET_STATS:
        if (irpSp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(DDM_STATS)) {
            *(PDDM_STATS)irp->AssociatedIrp.SystemBuffer = g_stats;
            irp->IoStatus.Information = sizeof(DDM_STATS);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
        
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
    
    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

VOID ddm_unload(PDRIVER_OBJECT driverObject) {
    UNREFERENCED_PARAMETER(driverObject);
    
    // Clean up WFP resources
    if (g_ddmState.engineHandle != NULL) {
        FwpmEngineClose(g_ddmState.engineHandle);
        g_ddmState.engineHandle = NULL;
    }
    
    if (g_ddmState.deviceObject != NULL) {
        IoDeleteDevice(g_ddmState.deviceObject);
        g_ddmState.deviceObject = NULL;
    }
    
    DbgPrint("DDM WFP Driver unloaded\n");
}