/*
 * loader.cpp — BaddiesHV Usermode Loader
 *
 * Phase 6: Integrated KDMapper + shared page + memory R/W + overlay injection
 *
 * Usage:
 *   1. Run this loader (as admin)
 *   2. Select 'Load driver' to map BaddiesHV-Driver.sys
 *   3. Use menu for hypercall operations or inject overlay
 */

#include "../shared/hvcomm.h"
#include "injector.h"
#include <filesystem>
#include <intrin.h>
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <string>
#include <tlhelp32.h>
#include <vector>
#include <wchar.h>
#include <windows.h>

/* KDMapper headers */
#include "intel_driver.hpp"
#include "kdmapper.hpp"
#include "utils.hpp"

/* ============================================================================
 *  Global State
 * ============================================================================
 */

HV_SHARED_PAGE *g_SharedPage = nullptr;
bool g_Registered = false;

/* ============================================================================
 *  Helpers
 * ============================================================================
 */

static DWORD_PTR PinThreadToCore(DWORD coreIndex) {
  DWORD_PTR mask = (DWORD_PTR)1 << coreIndex;
  return SetThreadAffinityMask(GetCurrentThread(), mask);
}

static DWORD GetProcessIdByName(const wchar_t *name) {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE)
    return 0;

  PROCESSENTRY32 pe;
  pe.dwSize = sizeof(pe);
  if (Process32First(snap, &pe)) {
    do {
      if (_wcsicmp(pe.szExeFile, name) == 0) {
        CloseHandle(snap);
        return pe.th32ProcessID;
      }
    } while (Process32Next(snap, &pe));
  }
  CloseHandle(snap);
  return 0;
}

/* ============================================================================
 *  Hypercall Wrappers
 * ============================================================================
 */

static bool HvPing(UINT32 *outCoreIndex) {
  int regs[4] = {0};
  __cpuidex(regs, HV_CPUID_LEAF, HV_CMD_PING);
  if ((UINT32)regs[0] == HV_CPUID_LEAF && (UINT32)regs[1] == 1) {
    if (outCoreIndex)
      *outCoreIndex = (UINT32)regs[2];
    return true;
  }
  return false;
}

static bool HvDevirtualize() {
  int regs[4] = {0};
  __cpuidex(regs, HV_CPUID_LEAF, HV_CMD_DEVIRT);
  return ((UINT32)regs[0] == HV_STATUS_SUCCESS);
}

/*
 * HvRegisterSharedPage — Two-step VA registration via CPUID ECX encoding.
 *
 * MSVC x64 __cpuidex only lets us control EAX and ECX. We encode the
 * 48-bit shared page VA across two calls:
 *   Call 1: ECX = (VA[23:0]  << 8) | 0x10  (REGISTER_LO)
 *   Call 2: ECX = (VA[47:24] << 8) | 0x11  (REGISTER_HI)
 */
static bool HvRegisterSharedPage() {
  if (!g_SharedPage)
    return false;

  UINT64 va = (UINT64)g_SharedPage;
  UINT32 vaLo = (UINT32)(va & 0x00FFFFFF);
  UINT32 vaHi = (UINT32)((va >> 24) & 0x00FFFFFF);

  /* Pin to core 0 — both calls MUST hit the same VMCB because
   * REGISTER_LO stores temp data in that core's SoftwareReserved. */
  DWORD_PTR oldMask = PinThreadToCore(0);

  /* Step 1: Send low 24 bits */
  int regs1[4] = {0};
  UINT32 sub1 = HV_CMD_REGISTER_LO | (vaLo << 8);
  __cpuidex(regs1, HV_CPUID_LEAF, (int)sub1);

  if ((UINT32)regs1[0] != HV_STATUS_SUCCESS) {
    printf("[-] REGISTER_LO failed: 0x%08X\n", (UINT32)regs1[0]);
    SetThreadAffinityMask(GetCurrentThread(), oldMask);
    return false;
  }

  /* Step 2: Send high 24 bits — triggers translation + caching */
  int regs2[4] = {0};
  UINT32 sub2 = HV_CMD_REGISTER_HI | (vaHi << 8);
  __cpuidex(regs2, HV_CPUID_LEAF, (int)sub2);

  SetThreadAffinityMask(GetCurrentThread(), oldMask);

  if ((UINT32)regs2[0] == HV_STATUS_SUCCESS) {
    g_Registered = true;
    printf("[+] Registered! Reconstructed VA = 0x%llX\n",
           (UINT64)(UINT32)regs2[1] | ((UINT64)(UINT32)regs2[2] << 32));
    return true;
  }
  printf("[-] REGISTER_HI failed:\n"
         "    EAX (status) = 0x%08X\n"
         "    EBX (stage)  = %u  (1=PML4 2=PDPT 3=PD 4=PT)\n"
         "    ECX (CR3)    = 0x%llX\n"
         "    EDX (recon VA)= 0x%llX\n",
         (UINT32)regs2[0], (UINT32)regs2[1],
         (UINT64)(UINT32)regs2[2] | ((UINT64)(UINT32)regs2[3] << 32),
         (UINT64)(UINT32)regs2[3]);
  return false;
}

/* ============================================================================
 *  Test Functions
 * ============================================================================
 */

static UINT32 TestPingAllCores() {
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  DWORD numCores = si.dwNumberOfProcessors;

  printf("[*] Testing PING on %lu cores...\n", numCores);
  UINT32 responded = 0;

  for (DWORD i = 0; i < numCores; i++) {
    DWORD_PTR old = PinThreadToCore(i);
    UINT32 reported = 0;
    if (HvPing(&reported)) {
      printf("  [+] Core %2lu: active (reported %u)\n", i, reported);
      responded++;
    } else {
      printf("  [-] Core %2lu: NOT ACTIVE\n", i);
    }
    SetThreadAffinityMask(GetCurrentThread(), old);
  }

  printf("[*] Result: %u / %lu cores responded\n", responded, numCores);
  return responded;
}

static void TestDevirtualize() {
  printf("\n[*] Sending DEVIRT...\n");
  if (!HvDevirtualize()) {
    printf("[-] Devirt failed or HV not active\n");
    return;
  }
  printf("[+] Devirt acknowledged. Waiting 2s...\n");
  Sleep(2000);

  printf("[*] Verifying...\n");
  UINT32 active = TestPingAllCores();
  if (active == 0)
    printf("[+] SUCCESS: All cores devirtualized!\n");
  else
    printf("[!] WARNING: %u cores still active!\n", active);
}

static void TestRegisterSharedPage() {
  if (g_Registered) {
    printf("[*] Already registered.\n");
    return;
  }

  g_SharedPage =
      (HV_SHARED_PAGE *)VirtualAlloc(nullptr, sizeof(HV_SHARED_PAGE),
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!g_SharedPage) {
    printf("[-] VirtualAlloc failed.\n");
    return;
  }
  ZeroMemory(g_SharedPage, sizeof(HV_SHARED_PAGE));

  /* Pin both physical pages so they can't be paged out.
   * The VMEXIT handler accesses these pages at HIGH_IRQL where
   * page faults cannot be serviced. */
  VirtualLock(g_SharedPage, sizeof(HV_SHARED_PAGE));

  printf("[*] Shared page at VA = 0x%llX\n", (UINT64)g_SharedPage);
  printf("[*] Registering with HV...\n");

  if (HvRegisterSharedPage()) {
    printf("[+] Registered!\n");
  } else {
    printf("[-] Registration FAILED.\n");
    VirtualFree(g_SharedPage, 0, MEM_RELEASE);
    g_SharedPage = nullptr;
  }
}

static void TestReadMemory() {
  if (!g_Registered) {
    printf("[-] Register shared page first (option 4).\n");
    return;
  }

  printf("[*] Target process name: ");
  wchar_t name[256];
  if (wscanf_s(L"%255s", name, (unsigned)_countof(name)) != 1)
    return;

  DWORD pid = GetProcessIdByName(name);
  if (!pid) {
    printf("[-] Not found.\n");
    return;
  }
  printf("[+] PID: %lu\n", pid);

  printf("[*] Address (hex): ");
  UINT64 addr;
  if (scanf_s("%llx", &addr) != 1)
    return;

  /* Fill the request — data will be returned in g_SharedPage->data */
  g_SharedPage->request.magic = HV_MAGIC;
  g_SharedPage->request.command = HV_CMD_READ;
  g_SharedPage->request.pid = pid;
  g_SharedPage->request.address = addr;
  g_SharedPage->request.size = 64;
  g_SharedPage->request.result = 0;
  memset(g_SharedPage->data, 0, 64);

  DWORD_PTR oldMask = PinThreadToCore(0);
  int regs[4] = {0};
  __cpuidex(regs, HV_CPUID_LEAF, HV_CMD_READ);
  SetThreadAffinityMask(GetCurrentThread(), oldMask);

  if ((UINT32)regs[0] == HV_STATUS_SUCCESS) {
    printf("[+] Read OK. First 16 bytes:\n    ");
    for (int i = 0; i < 16; i++)
      printf("%02X ", g_SharedPage->data[i]);
    printf("\n");
  } else {
    printf("[-] Read failed. Status: 0x%08X\n", (UINT32)regs[0]);
  }
}

static void TestGetCr3() {
  if (!g_Registered) {
    printf("[-] Register shared page first (option 4).\n");
    return;
  }

  printf("[*] Process name: ");
  wchar_t name[256];
  if (wscanf_s(L"%255s", name, (unsigned)_countof(name)) != 1)
    return;

  DWORD pid = GetProcessIdByName(name);
  if (!pid) {
    printf("[-] Not found.\n");
    return;
  }

  g_SharedPage->request.magic = HV_MAGIC;
  g_SharedPage->request.command = HV_CMD_GET_CR3;
  g_SharedPage->request.pid = pid;
  g_SharedPage->request.result = 0;

  DWORD_PTR oldMask = PinThreadToCore(0);
  int regs[4] = {0};
  __cpuidex(regs, HV_CPUID_LEAF, HV_CMD_GET_CR3);
  SetThreadAffinityMask(GetCurrentThread(), oldMask);

  if ((UINT32)regs[0] == HV_STATUS_SUCCESS)
    printf("[+] CR3 for PID %lu = 0x%llX\n", pid, g_SharedPage->request.result);
  else
    printf("[-] Failed. Status: 0x%08X\n", (UINT32)regs[0]);
}

static void TestWriteMemory() {
  if (!g_Registered) {
    printf("[-] Register shared page first (option 4).\n");
    return;
  }

  /* Allocate a test buffer in OUR process to write to (safe test) */
  UINT8 *testBuf =
      (UINT8 *)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!testBuf) {
    printf("[-] VirtualAlloc failed.\n");
    return;
  }
  memset(testBuf, 0xAA, 64); /* Fill with 0xAA initially */

  printf("[*] Test buffer at VA = 0x%llX (filled with 0xAA)\n",
         (UINT64)testBuf);

  /* Write pattern 0xDE 0xAD 0xBE 0xEF ... via HV */
  UINT8 pattern[16] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
                       0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  memcpy(g_SharedPage->data, pattern, 16);

  /* Get our own PID */
  DWORD myPid = GetCurrentProcessId();
  printf("[*] Writing 16 bytes via HV to our own PID %lu...\n", myPid);

  g_SharedPage->request.magic = HV_MAGIC;
  g_SharedPage->request.command = HV_CMD_WRITE;
  g_SharedPage->request.pid = myPid;
  g_SharedPage->request.address = (UINT64)testBuf;
  g_SharedPage->request.size = 16;
  g_SharedPage->request.result = 0;

  DWORD_PTR oldMask = PinThreadToCore(0);
  int regs[4] = {0};
  __cpuidex(regs, HV_CPUID_LEAF, HV_CMD_WRITE);
  SetThreadAffinityMask(GetCurrentThread(), oldMask);

  if ((UINT32)regs[0] == HV_STATUS_SUCCESS) {
    printf("[+] Write OK! Verifying buffer contents:\n    ");
    for (int i = 0; i < 16; i++)
      printf("%02X ", testBuf[i]);
    printf("\n");

    /* Check if write actually took effect */
    bool match = (memcmp(testBuf, pattern, 16) == 0);
    printf("[%c] Write verification %s!\n", match ? '+' : '-',
           match ? "PASSED" : "FAILED");
  } else {
    printf("[-] Write failed. Status: 0x%08X\n", (UINT32)regs[0]);
  }

  VirtualFree(testBuf, 0, MEM_RELEASE);
}

/* ============================================================================
 *  Driver Loading via KDMapper
 * ============================================================================
 */

static std::wstring FindDriverPath() {
  /* Look for BaddiesHV.sys in common locations relative to the loader */
  wchar_t exePath[MAX_PATH];
  GetModuleFileNameW(NULL, exePath, MAX_PATH);
  std::filesystem::path exeDir = std::filesystem::path(exePath).parent_path();

  /* Search order: same dir, ../bin/Debug, ../bin/Release, ../x64/Debug,
   * ../x64/Release */
  std::vector<std::filesystem::path> searchPaths = {
      exeDir / L"BaddiesHV.sys",
      exeDir / L".." / L"BaddiesHV.sys",
      exeDir / L".." / L"bin" / L"Debug" / L"BaddiesHV.sys",
      exeDir / L".." / L"bin" / L"Release" / L"BaddiesHV.sys",
      exeDir / L".." / L"x64" / L"Debug" / L"BaddiesHV.sys",
      exeDir / L".." / L"x64" / L"Release" / L"BaddiesHV.sys",
  };

  for (const auto &p : searchPaths) {
    if (std::filesystem::exists(p))
      return std::filesystem::canonical(p).wstring();
  }
  return L"";
}

static bool LoadDriver() {
  /* Find the driver binary */
  std::wstring driverPath = FindDriverPath();
  if (driverPath.empty()) {
    printf("[-] BaddiesHV.sys not found.\n");
    printf("    Place it in the same folder as the loader.\n");
    printf("    Or enter path manually: ");
    wchar_t path[MAX_PATH];
    if (wscanf_s(L"%259s", path, (unsigned)_countof(path)) == 1) {
      driverPath = path;
    } else {
      return false;
    }
  }

  if (!std::filesystem::exists(driverPath)) {
    wprintf(L"[-] File not found: %s\n", driverPath.c_str());
    return false;
  }

  wprintf(L"[*] Driver: %s\n", driverPath.c_str());

  /* Step 1: Load the vulnerable Intel driver */
  printf("[*] Loading Intel driver...\n");
  if (!NT_SUCCESS(intel_driver::Load())) {
    printf("[-] Failed to load Intel driver.\n");
    return false;
  }
  printf("[+] Intel driver loaded.\n");

  /* Step 2: Read driver file */
  std::vector<uint8_t> raw_image;
  if (!kdmUtils::ReadFileToMemory(driverPath, &raw_image)) {
    printf("[-] Failed to read driver file.\n");
    intel_driver::Unload();
    return false;
  }
  printf("[+] Driver read (%llu bytes).\n",
         (unsigned long long)raw_image.size());

  /* Step 3: Map driver into kernel */
  printf("[*] Mapping driver...\n");
  NTSTATUS exitCode = 0;
  ULONG64 result =
      kdmapper::MapDriver(raw_image.data(), 0, 0, /* param1, param2 — unused */
                          false, /* free = false (driver stays loaded) */
                          true,  /* destroyHeader = true (stealth) */
                          kdmapper::AllocationMode::AllocatePool,
                          false,   /* PassAllocationAddressAsFirstParam */
                          nullptr, /* callback */
                          &exitCode);

  /* Step 4: Cleanup Intel driver */
  if (!NT_SUCCESS(intel_driver::Unload())) {
    printf("[!] Warning: failed to fully unload Intel driver.\n");
  }

  if (!result) {
    printf("[-] Failed to map driver.\n");
    return false;
  }

  printf("[+] Driver mapped! DriverEntry returned 0x%08X\n",
         (unsigned)exitCode);
  return NT_SUCCESS(exitCode);
}

/* ============================================================================
 *  Main
 * ============================================================================
 */

int main() {
  printf("========================================\n");
  printf("  BaddiesHV Loader v1.0                 \n");
  printf("========================================\n\n");

  UINT32 core = 0;
  if (!HvPing(&core)) {
    printf("[-] HV not active.\n");
    printf("[*] Would you like to load the driver? (y/n): ");
    int ch = getchar();
    while (getchar() != '\n')
      ; /* flush */
    if (ch == 'y' || ch == 'Y') {
      if (!LoadDriver()) {
        printf("[-] Driver loading failed.\n");
        return 1;
      }
      /* Verify HV is now active */
      Sleep(500);
      if (!HvPing(&core)) {
        printf("[-] HV still not responding after load.\n");
        return 1;
      }
    } else {
      printf("[-] Exiting.\n");
      return 1;
    }
  }
  printf("[+] HV active (core %u)\n\n", core);

  while (true) {
    printf("\n--- Menu ---\n");
    printf("  0. Load driver (KDMapper)\n");
    printf("  1. Ping all cores\n");
    printf("  2. Devirtualize\n");
    printf("  3. Exit (HV stays)\n");
    printf("  4. Register shared page\n");
    printf("  5. Read memory\n");
    printf("  6. Get CR3\n");
    printf("  7. Write memory test\n");
    printf("  8. Inject overlay\n");
    printf("  > ");

    int c = 0;
    if (scanf_s("%d", &c) != 1) {
      int ch;
      while ((ch = getchar()) != '\n' && ch != EOF)
        ;
      continue;
    }

    switch (c) {
    case 0:
      LoadDriver();
      break;
    case 1:
      TestPingAllCores();
      break;
    case 2:
      TestDevirtualize();
      return 0;
    case 3:
      return 0;
    case 4:
      TestRegisterSharedPage();
      break;
    case 5:
      TestReadMemory();
      break;
    case 6:
      TestGetCr3();
      break;
    case 7:
      TestWriteMemory();
      break;
    case 8: {
      /* Inject overlay */
      printf(
          "Enter game process name (e.g. DeadByDaylight-Win64-Shipping.exe): ");
      char procName[256];
      scanf_s("%255s", procName, (unsigned)sizeof(procName));

      wchar_t wProcName[256];
      size_t converted;
      mbstowcs_s(&converted, wProcName, procName, _TRUNCATE);

      DWORD pid = GetProcessIdByName(wProcName);
      if (pid == 0) {
        printf("[-] Process not found: %s\n", procName);
        break;
      }
      printf("[+] Found PID: %u\n", pid);

      /* Find overlay DLL next to loader */
      wchar_t exePath[MAX_PATH];
      GetModuleFileNameW(NULL, exePath, MAX_PATH);
      std::wstring dllPath(exePath);
      size_t lastSlash = dllPath.find_last_of(L"\\//");
      if (lastSlash != std::wstring::npos)
        dllPath = dllPath.substr(0, lastSlash + 1);
      dllPath += L"BaddiesHV-Overlay.dll";

      printf("[*] DLL path: %ls\n", dllPath.c_str());

      if (InjectOverlayDll(pid, dllPath)) {
        printf("\n[+] Injection successful! Loader can exit safely.\n");
        printf("[*] Press Enter to exit...\n");
        getchar();
        getchar();
        return 0;
      } else {
        printf("\n[-] Injection failed.\n");
      }
      break;
    }
    default:
      printf("Invalid.\n");
      break;
    }
  }
}
