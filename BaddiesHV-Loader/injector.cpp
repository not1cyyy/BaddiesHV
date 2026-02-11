/*
 * injector.cpp — HV-assisted PE manual mapper.
 *
 * Full injection pipeline:
 *   1. Read DLL from disk
 *   2. Allocate RWX in target via HV_CMD_ALLOC (polls for completion)
 *   3. Map PE sections via HV_CMD_WRITE
 *   4. Apply relocations
 *   5. Resolve imports via HV_CMD_FIND_MODULE + export table parsing
 *   6. Write self-resolving shellcode
 *   7. Hook target's Present() with 14-byte jmp to shellcode
 *   8. Erase PE header
 *
 * Rollback: zeros all written memory on failure.
 */

#include "injector.h"
#include "../shared/hvcomm.h"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <intrin.h>
#include <io.h>
#include <string>
#include <unordered_map>
#include <vector>
#include <windows.h>

/* ============================================================================
 *  Extern: shared page and registration state from loader.cpp
 * ============================================================================
 */

extern HV_SHARED_PAGE *g_SharedPage;
extern bool g_Registered;

/* Log to both console and file — survives BSOD */
static FILE *g_LogFile = nullptr;
#define LOG(fmt, ...)                                                          \
  do {                                                                         \
    printf(fmt, ##__VA_ARGS__);                                                \
    if (g_LogFile) {                                                           \
      fprintf(g_LogFile, fmt, ##__VA_ARGS__);                                  \
      fflush(g_LogFile);                                                       \
      _commit(_fileno(g_LogFile));                                             \
    }                                                                          \
  } while (0)

/* ============================================================================
 *  DJB2 Hash — matches driver-side Djb2HashWide
 * ============================================================================
 */

uint64_t Djb2HashWide(const wchar_t *str) {
  uint64_t hash = 5381;
  while (*str) {
    wchar_t c = *str++;
    if (c >= L'A' && c <= L'Z')
      c += 32;
    hash = ((hash << 5) + hash) + (uint64_t)c;
  }
  return hash;
}

/* ============================================================================
 *  HV Hypercall Helpers (local to injector)
 *  All CPUID hypercalls must execute on core 0 where shared page is registered.
 * ============================================================================
 */

static DWORD_PTR PinToCore(DWORD core) {
  return SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)1 << core);
}

static bool HvAllocMemory(uint32_t pid, uint64_t size, uint64_t *outBase) {
  if (!g_Registered || !g_SharedPage)
    return false;

  DWORD_PTR oldMask = PinToCore(0);

  g_SharedPage->request.magic = HV_MAGIC;
  g_SharedPage->request.command = HV_CMD_ALLOC;
  g_SharedPage->request.pid = pid;
  g_SharedPage->request.size = size;
  g_SharedPage->request.result = 0;

  int regs[4];
  __cpuidex(regs, HV_CPUID_LEAF, HV_CMD_ALLOC);

  if ((uint32_t)regs[0] != HV_STATUS_PENDING &&
      (uint32_t)regs[0] != HV_STATUS_SUCCESS) {
    LOG("    [-] HV_CMD_ALLOC failed: 0x%08X\n", (uint32_t)regs[0]);
    SetThreadAffinityMask(GetCurrentThread(), oldMask);
    return false;
  }

  /* Poll for completion — worker thread is async */
  for (int i = 0; i < 200; i++) {
    Sleep(50);
    __cpuidex(regs, HV_CPUID_LEAF, HV_CMD_PING);
    if (g_SharedPage->request.result != 0) {
      *outBase = g_SharedPage->request.result;
      SetThreadAffinityMask(GetCurrentThread(), oldMask);
      return true;
    }
  }

  SetThreadAffinityMask(GetCurrentThread(), oldMask);
  LOG("    [-] HV_CMD_ALLOC timed out\n");
  return false;
}

static bool HvWrite(uint32_t pid, uint64_t addr, const void *buf,
                    uint64_t size) {
  if (!g_Registered || !g_SharedPage)
    return false;

  DWORD_PTR oldMask = PinToCore(0);
  const uint8_t *src = (const uint8_t *)buf;
  while (size > 0) {
    uint64_t chunk = (size > HV_DATA_SIZE) ? HV_DATA_SIZE : size;

    g_SharedPage->request.magic = HV_MAGIC;
    g_SharedPage->request.command = HV_CMD_WRITE;
    g_SharedPage->request.pid = pid;
    g_SharedPage->request.address = addr;
    g_SharedPage->request.size = chunk;
    memcpy((void *)g_SharedPage->data, src, (size_t)chunk);

    int regs[4];
    __cpuidex(regs, HV_CPUID_LEAF, HV_CMD_WRITE);
    if ((uint32_t)regs[0] != HV_STATUS_SUCCESS) {
      LOG("    [-] HvWrite failed at 0x%llX: 0x%08X\n", addr,
          (uint32_t)regs[0]);
      SetThreadAffinityMask(GetCurrentThread(), oldMask);
      return false;
    }

    src += chunk;
    addr += chunk;
    size -= chunk;
  }
  SetThreadAffinityMask(GetCurrentThread(), oldMask);
  return true;
}

static bool HvRead(uint32_t pid, uint64_t addr, void *buf, uint64_t size) {
  if (!g_Registered || !g_SharedPage)
    return false;

  DWORD_PTR oldMask = PinToCore(0);
  uint8_t *dst = (uint8_t *)buf;
  while (size > 0) {
    uint64_t chunk = (size > HV_DATA_SIZE) ? HV_DATA_SIZE : size;

    g_SharedPage->request.magic = HV_MAGIC;
    g_SharedPage->request.command = HV_CMD_READ;
    g_SharedPage->request.pid = pid;
    g_SharedPage->request.address = addr;
    g_SharedPage->request.size = chunk;

    int regs[4];
    __cpuidex(regs, HV_CPUID_LEAF, HV_CMD_READ);
    if ((uint32_t)regs[0] != HV_STATUS_SUCCESS) {
      SetThreadAffinityMask(GetCurrentThread(), oldMask);
      return false;
    }

    memcpy(dst, (void *)g_SharedPage->data, (size_t)chunk);
    dst += chunk;
    addr += chunk;
    size -= chunk;
  }
  SetThreadAffinityMask(GetCurrentThread(), oldMask);
  return true;
}

/* Forward declaration — defined below */
static bool HvWriteSafe(uint32_t pid, uint64_t addr, const void *buf,
                        uint64_t size);

static bool HvZeroMemory(uint32_t pid, uint64_t addr, uint64_t size) {
  std::vector<uint8_t> zeros(HV_DATA_SIZE, 0);
  while (size > 0) {
    uint64_t chunk = (size > HV_DATA_SIZE) ? HV_DATA_SIZE : size;
    if (!HvWriteSafe(pid, addr, zeros.data(), chunk))
      return false;
    addr += chunk;
    size -= chunk;
  }
  return true;
}

static bool HvFindModule(uint32_t pid, const wchar_t *moduleName,
                         uint64_t *outBase) {
  if (!g_Registered || !g_SharedPage)
    return false;

  uint64_t hash = Djb2HashWide(moduleName);
  DWORD_PTR oldMask = PinToCore(0);

  g_SharedPage->request.magic = HV_MAGIC;
  g_SharedPage->request.command = HV_CMD_FIND_MODULE;
  g_SharedPage->request.pid = pid;
  g_SharedPage->request.address = hash; /* Hash goes in address field */
  g_SharedPage->request.result = 0;

  /* Readback verify — confirm the hash is actually in the shared page */
  uint64_t readback = g_SharedPage->request.address;
  LOG("      [dbg] HvFindModule: wrote hash=0x%llX readback=0x%llX %s\n", hash,
      readback, (hash == readback) ? "OK" : "MISMATCH!");

  int regs[4];
  __cpuidex(regs, HV_CPUID_LEAF, HV_CMD_FIND_MODULE);

  uint32_t status = (uint32_t)regs[0];
  uint64_t result = g_SharedPage->request.result;
  LOG("      [dbg] HvFindModule: status=0x%X result=0x%llX hash=0x%llX\n",
      status, result, hash);

  if (status == HV_STATUS_SUCCESS) {
    *outBase = result;
    SetThreadAffinityMask(GetCurrentThread(), oldMask);
    return true;
  }

  SetThreadAffinityMask(GetCurrentThread(), oldMask);
  return false;
}

/* Deferred safe read — goes through worker thread at PASSIVE_LEVEL.
 * Use for reading from file-backed module pages (ntdll exports, etc.)
 * that may not be resident. Page faults handled by OS. */
static bool HvReadSafe(uint32_t pid, uint64_t addr, void *buf, uint64_t size) {
  if (!g_Registered || !g_SharedPage)
    return false;

  DWORD_PTR oldMask = PinToCore(0);
  uint8_t *dst = (uint8_t *)buf;
  while (size > 0) {
    uint64_t chunk = (size > HV_DATA_SIZE) ? HV_DATA_SIZE : size;

    g_SharedPage->request.magic = HV_MAGIC;
    g_SharedPage->request.command = HV_CMD_READ_SAFE;
    g_SharedPage->request.pid = pid;
    g_SharedPage->request.address = addr;
    g_SharedPage->request.size = chunk;
    g_SharedPage->request.result = 0;

    int regs[4];
    __cpuidex(regs, HV_CPUID_LEAF, HV_CMD_READ_SAFE);

    if ((uint32_t)regs[0] != HV_STATUS_PENDING &&
        (uint32_t)regs[0] != HV_STATUS_SUCCESS) {
      SetThreadAffinityMask(GetCurrentThread(), oldMask);
      return false;
    }

    /* Poll for completion — worker thread processes at PASSIVE_LEVEL */
    bool done = false;
    for (int i = 0; i < 200; i++) {
      Sleep(1);
      __cpuidex(regs, HV_CPUID_LEAF, HV_CMD_PING);
      if (g_SharedPage->request.result != 0) {
        if (g_SharedPage->request.result == 1) { /* 1 = success */
          memcpy(dst, (void *)g_SharedPage->data, (size_t)chunk);
          done = true;
        }
        break;
      }
    }

    if (!done) {
      SetThreadAffinityMask(GetCurrentThread(), oldMask);
      return false;
    }

    dst += chunk;
    addr += chunk;
    size -= chunk;
  }
  SetThreadAffinityMask(GetCurrentThread(), oldMask);
  return true;
}

/* Deferred safe write — goes through worker thread at PASSIVE_LEVEL. */
static bool HvWriteSafe(uint32_t pid, uint64_t addr, const void *buf,
                        uint64_t size) {
  if (!g_Registered || !g_SharedPage)
    return false;

  DWORD_PTR oldMask = PinToCore(0);
  const uint8_t *src = (const uint8_t *)buf;
  while (size > 0) {
    uint64_t chunk = (size > HV_DATA_SIZE) ? HV_DATA_SIZE : size;

    g_SharedPage->request.magic = HV_MAGIC;
    g_SharedPage->request.command = HV_CMD_WRITE_SAFE;
    g_SharedPage->request.pid = pid;
    g_SharedPage->request.address = addr;
    g_SharedPage->request.size = chunk;
    g_SharedPage->request.result = 0;
    memcpy((void *)g_SharedPage->data, src, (size_t)chunk);

    static int s_writeChunk = 0;
    s_writeChunk++;
    if (s_writeChunk <= 3 || (s_writeChunk % 10) == 0)
      LOG("      [dbg] WriteSafe chunk #%d addr=0x%llX sz=%llu\n", s_writeChunk,
          addr, chunk);

    int regs[4];
    __cpuidex(regs, HV_CPUID_LEAF, HV_CMD_WRITE_SAFE);

    if ((uint32_t)regs[0] != HV_STATUS_PENDING &&
        (uint32_t)regs[0] != HV_STATUS_SUCCESS) {
      LOG("    [-] HvWriteSafe: CPUID returned 0x%08X (addr=0x%llX sz=%llu)\n",
          (uint32_t)regs[0], addr, chunk);
      SetThreadAffinityMask(GetCurrentThread(), oldMask);
      return false;
    }

    /* Poll for completion */
    bool done = false;
    for (int i = 0; i < 200; i++) {
      Sleep(1);
      __cpuidex(regs, HV_CPUID_LEAF, HV_CMD_PING);
      if (g_SharedPage->request.result != 0) {
        if (g_SharedPage->request.result == 1) /* 1 = success */
          done = true;
        break;
      }
    }

    if (!done) {
      LOG("    [-] HvWriteSafe: poll failed, result=0x%llX (addr=0x%llX)\n",
          g_SharedPage->request.result, addr);
      SetThreadAffinityMask(GetCurrentThread(), oldMask);
      return false;
    }

    src += chunk;
    addr += chunk;
    size -= chunk;
  }
  SetThreadAffinityMask(GetCurrentThread(), oldMask);
  return true;
}

/* ============================================================================
 *  PE Parsing Helpers
 * ============================================================================
 */

/* Cache of export data for a single module.
 * Reads ALL export names + RVAs in one batch, then resolves
 * any number of imports from it with zero additional VMEXITs.
 *
 * The old ResolveExport did ~1600 HvReadSafe calls per module
 * (one per export name). For 3 import DLLs that's ~5000 VMEXITs
 * just for name lookups, causing non-deterministic BSODs. */
struct ExportCache {
  uint64_t moduleBase;
  std::unordered_map<uint64_t, uint64_t> hashToAddr; /* djb2 hash → VA */

  bool Build(uint32_t pid, uint64_t base) {
    moduleBase = base;

    /* Read DOS header */
    IMAGE_DOS_HEADER dosHdr;
    if (!HvReadSafe(pid, base, &dosHdr, sizeof(dosHdr)))
      return false;
    if (dosHdr.e_magic != IMAGE_DOS_SIGNATURE)
      return false;

    /* Read NT headers */
    IMAGE_NT_HEADERS64 ntHdr;
    if (!HvReadSafe(pid, base + dosHdr.e_lfanew, &ntHdr, sizeof(ntHdr)))
      return false;
    if (ntHdr.Signature != IMAGE_NT_SIGNATURE)
      return false;

    /* Get export directory */
    auto &exportDir =
        ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.VirtualAddress == 0 || exportDir.Size == 0)
      return false;

    /* Read the ENTIRE export section in one bulk read.
     * All export tables and name strings live within this region. */
    uint32_t expRva = exportDir.VirtualAddress;
    uint32_t expSize = exportDir.Size;
    if (expSize > 2 * 1024 * 1024)
      expSize = 2 * 1024 * 1024; /* safety cap at 2MB */

    std::vector<uint8_t> expBuf(expSize);
    if (!HvReadSafe(pid, base + expRva, expBuf.data(), expSize)) {
      LOG("      [-] Failed bulk read of export dir (%u bytes)\n", expSize);
      return false;
    }

    /* Parse export directory from our local buffer */
    if (expSize < sizeof(IMAGE_EXPORT_DIRECTORY))
      return false;
    auto *exports = (IMAGE_EXPORT_DIRECTORY *)expBuf.data();

    uint32_t numNames = exports->NumberOfNames;
    if (numNames > 8192)
      numNames = 8192;
    uint32_t numFuncs = exports->NumberOfFunctions;
    if (numFuncs > 8192)
      numFuncs = 8192;

    /* Helper: convert RVA to offset within our expBuf */
    auto rvaToOfs = [&](uint32_t rva) -> int64_t {
      if (rva < expRva || rva >= expRva + expSize)
        return -1; /* outside the export section */
      return (int64_t)(rva - expRva);
    };

    /* Get pointers to the three export tables */
    int64_t namesOfs = rvaToOfs(exports->AddressOfNames);
    int64_t ordinalsOfs = rvaToOfs(exports->AddressOfNameOrdinals);
    int64_t funcsOfs = rvaToOfs(exports->AddressOfFunctions);
    if (namesOfs < 0 || ordinalsOfs < 0 || funcsOfs < 0)
      return false;

    /* Bounds check the tables */
    if ((uint64_t)namesOfs + numNames * 4 > expSize)
      return false;
    if ((uint64_t)ordinalsOfs + numNames * 2 > expSize)
      return false;
    if ((uint64_t)funcsOfs + numFuncs * 4 > expSize)
      return false;

    auto *nameRvas = (uint32_t *)(expBuf.data() + namesOfs);
    auto *ordinals = (uint16_t *)(expBuf.data() + ordinalsOfs);
    auto *funcRvas = (uint32_t *)(expBuf.data() + funcsOfs);

    /* Build hash map from names — all data is already in our local buffer */
    for (uint32_t i = 0; i < numNames; i++) {
      int64_t nOfs = rvaToOfs(nameRvas[i]);
      if (nOfs < 0)
        continue;

      const char *name = (const char *)(expBuf.data() + nOfs);
      /* Ensure null-terminated within buffer */
      size_t maxLen = expSize - (size_t)nOfs;
      size_t len = strnlen(name, maxLen);
      if (len == maxLen)
        continue; /* no null terminator found */

      /* DJB2 hash */
      uint64_t hash = 5381;
      for (size_t j = 0; j < len; j++)
        hash = ((hash << 5) + hash) + (uint64_t)(uint8_t)name[j];

      uint16_t ordinal = ordinals[i];
      if (ordinal < numFuncs)
        hashToAddr[hash] = base + funcRvas[ordinal];
    }

    LOG("      [+] Cached %zu exports from module at 0x%llX\n",
        hashToAddr.size(), base);
    return true;
  }

  uint64_t Resolve(uint64_t funcNameHash) const {
    auto it = hashToAddr.find(funcNameHash);
    return (it != hashToAddr.end()) ? it->second : 0;
  }
};

/* Per-module cache: avoids rebuilding for the same module */
static std::unordered_map<uint64_t, ExportCache> g_ExportCaches;

static uint64_t ResolveExport(uint32_t pid, uint64_t moduleBase,
                              uint64_t funcNameHash) {
  /* Check cache first */
  auto it = g_ExportCaches.find(moduleBase);
  if (it == g_ExportCaches.end()) {
    /* Build cache for this module */
    ExportCache cache;
    if (!cache.Build(pid, moduleBase))
      return 0;
    g_ExportCaches.emplace(moduleBase, std::move(cache));
    it = g_ExportCaches.find(moduleBase);
  }
  return it->second.Resolve(funcNameHash);
}

/* DJB2 hash of ASCII string */
static uint64_t Djb2HashAscii(const char *str) {
  uint64_t hash = 5381;
  while (*str) {
    hash = ((hash << 5) + hash) + (uint64_t)(uint8_t)*str++;
  }
  return hash;
}

/* ============================================================================
 *  Shellcode — Self-resolving DllMain caller
 *
 *  This shellcode:
 *   1. Uses lock cmpxchg one-shot guard to prevent double execution
 *   2. Walks PEB → Ldr → InMemoryOrderModuleList
 *   3. Finds kernel32.dll by hash
 *   4. Resolves CreateThread from kernel32 exports
 *   5. Calls CreateThread(DllMain, DLL_PROCESS_ATTACH)
 *   6. Restores original Present bytes (unhook)
 *   7. Jumps to original Present
 * ============================================================================
 */

#pragma pack(push, 1)
struct ShellcodeData {
  /* Filled by loader */
  uint64_t dllBase;              /* DLL entry point = DllMain VA  */
  uint64_t entryPointRva;        /* RVA of DLL entry point        */
  uint64_t originalPresent;      /* Original Present function VA  */
  uint8_t savedPresentBytes[14]; /* Saved prologue bytes         */
  uint64_t guard;                /* One-shot: 0 = not called yet  */
};
#pragma pack(pop)

/* Generate full shellcode dynamically as PIC */
static std::vector<uint8_t> BuildShellcode(const ShellcodeData & /* data */) {
  /*
   * Layout in target memory:
   *   [ShellcodeData] (sizeof(ShellcodeData) bytes)
   *   [shellcode]     (generated code)
   *
   * Shellcode is PIC using RIP-relative references back to ShellcodeData.
   */

  std::vector<uint8_t> code;

  auto emit = [&](std::initializer_list<uint8_t> bytes) {
    code.insert(code.end(), bytes);
  };

  auto emit_u32 = [&](uint32_t v) {
    code.push_back((uint8_t)(v >> 0));
    code.push_back((uint8_t)(v >> 8));
    code.push_back((uint8_t)(v >> 16));
    code.push_back((uint8_t)(v >> 24));
  };

  /* Reference position for RIP-relative addressing:
   * ShellcodeData starts at offset 0 in the alloc.
   * Code starts at offset sizeof(ShellcodeData).
   * Current RIP = allocBase + sizeof(ShellcodeData) + code.size() + instrLen
   * Target = allocBase + fieldOffset
   * disp32 = target - RIP = fieldOffset - (sizeof(ShellcodeData) + code.size()
   * + instrLen)
   */

  size_t dataSize = sizeof(ShellcodeData);

#define RIP_REL(fieldOffset, instrLen)                                         \
  (int32_t)((int64_t)(fieldOffset) -                                           \
            (int64_t)(dataSize + code.size() + (instrLen)))

  /* sub rsp, 0x28 — shadow space + alignment */
  emit({0x48, 0x83, 0xEC, 0x28});

  /* === One-shot guard === */
  /* lea rcx, [rip + disp32(guard)] */
  emit({0x48, 0x8D, 0x0D});
  emit_u32((uint32_t)RIP_REL(offsetof(ShellcodeData, guard), 7));

  /* xor eax, eax */
  emit({0x33, 0xC0});

  /* mov edx, 1 */
  emit({0xBA});
  emit_u32(1);

  /* lock cmpxchg [rcx], edx */
  emit({0xF0, 0x0F, 0xB1, 0x11});

  /* jnz skip_to_unhook (patched later) */
  size_t jnz_patch = code.size();
  emit({0x0F, 0x85}); /* jnz near rel32 */
  emit_u32(0);        /* placeholder */

  /* === Call DllMain === */
  /* mov rcx, [rip + disp32(dllBase)] — hModuleDLL */
  emit({0x48, 0x8B, 0x0D});
  emit_u32((uint32_t)RIP_REL(offsetof(ShellcodeData, dllBase), 7));

  /* mov rax, [rip + disp32(entryPointRva)] */
  emit({0x48, 0x8B, 0x05});
  emit_u32((uint32_t)RIP_REL(offsetof(ShellcodeData, entryPointRva), 7));

  /* add rax, rcx — rax = dllBase + entryPointRva = DllMain */
  emit({0x48, 0x01, 0xC8});

  /* mov edx, 1 — DLL_PROCESS_ATTACH */
  emit({0xBA});
  emit_u32(1);

  /* xor r8d, r8d — lpReserved = NULL */
  emit({0x45, 0x33, 0xC0});

  /* call rax */
  emit({0xFF, 0xD0});

  /* === Patch JNZ to skip here (unhook point) === */
  size_t unhook_target = code.size();
  uint32_t jnz_disp = (uint32_t)(unhook_target - (jnz_patch + 6));
  code[jnz_patch + 2] = (uint8_t)(jnz_disp >> 0);
  code[jnz_patch + 3] = (uint8_t)(jnz_disp >> 8);
  code[jnz_patch + 4] = (uint8_t)(jnz_disp >> 16);
  code[jnz_patch + 5] = (uint8_t)(jnz_disp >> 24);

  /* === Restore original Present bytes === */
  /* mov rdi, [rip + disp32(originalPresent)] */
  emit({0x48, 0x8B, 0x3D});
  emit_u32((uint32_t)RIP_REL(offsetof(ShellcodeData, originalPresent), 7));

  /* lea rsi, [rip + disp32(savedPresentBytes)] */
  emit({0x48, 0x8D, 0x35});
  emit_u32((uint32_t)RIP_REL(offsetof(ShellcodeData, savedPresentBytes), 7));

  /* mov ecx, 14 */
  emit({0xB9});
  emit_u32(14);

  /* rep movsb — copy saved bytes back to original Present */
  emit({0xF3, 0xA4});

  /* === Jump to original Present === */
  /* mov rax, [rip + disp32(originalPresent)] */
  emit({0x48, 0x8B, 0x05});
  emit_u32((uint32_t)RIP_REL(offsetof(ShellcodeData, originalPresent), 7));

  /* add rsp, 0x28 */
  emit({0x48, 0x83, 0xC4, 0x28});

  /* jmp rax */
  emit({0xFF, 0xE0});

#undef RIP_REL

  return code;
}

/* ============================================================================
 *  Main Injection Pipeline
 * ============================================================================
 */

bool InjectOverlayDll(uint32_t targetPid, const std::wstring &dllPath) {
  /* Open log file next to the loader executable */
  fopen_s(&g_LogFile, "injector_log.txt", "w");
  if (g_LogFile) {
    setvbuf(g_LogFile, NULL, _IONBF, 0); /* fully unbuffered */
    LOG("[*] Log file opened: injector_log.txt\n");
  }

  LOG("[*] Phase 6: HV-Assisted Manual Mapping\n");
  LOG("    Target PID: %u\n", targetPid);
  LOG("    DLL: %ls\n", dllPath.c_str());

  if (!g_Registered || !g_SharedPage) {
    LOG("    [-] Shared page not registered. Register first.\n");
    return false;
  }

  /* === Step 1: Read DLL from disk === */
  LOG("    [1/8] Reading DLL from disk...\n");
  std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
  if (!file.is_open()) {
    LOG("    [-] Failed to open DLL file\n");
    return false;
  }

  size_t fileSize = (size_t)file.tellg();
  file.seekg(0);
  std::vector<uint8_t> dllData(fileSize);
  file.read((char *)dllData.data(), fileSize);
  file.close();
  LOG("    [+] DLL read: %zu bytes\n", fileSize);

  /* Parse PE headers */
  auto *dosHdr = (IMAGE_DOS_HEADER *)dllData.data();
  if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
    LOG("    [-] Invalid DOS signature\n");
    return false;
  }

  auto *ntHdr = (IMAGE_NT_HEADERS64 *)(dllData.data() + dosHdr->e_lfanew);
  if (ntHdr->Signature != IMAGE_NT_SIGNATURE) {
    LOG("    [-] Invalid NT signature\n");
    return false;
  }

  uint64_t imageSize = ntHdr->OptionalHeader.SizeOfImage;
  uint64_t preferredBase = ntHdr->OptionalHeader.ImageBase;
  uint64_t entryPointRva = ntHdr->OptionalHeader.AddressOfEntryPoint;

  LOG("    [+] ImageSize=0x%llX, PreferredBase=0x%llX, EP_RVA=0x%llX\n",
      imageSize, preferredBase, entryPointRva);

  /* === Step 2: Allocate RWX in target === */
  LOG("    [2/8] Allocating memory in target process...\n");
  uint64_t allocBase = 0;

  /* Add space for shellcode at the end */
  uint64_t shellcodeReserve = 4096;
  uint64_t totalSize = imageSize + shellcodeReserve;

  if (!HvAllocMemory(targetPid, totalSize, &allocBase)) {
    LOG("    [-] HV_CMD_ALLOC failed\n");
    return false;
  }
  LOG("    [+] Allocated at 0x%llX (%llu bytes)\n", allocBase, totalSize);

  /* Track written ranges for rollback */
  struct WrittenRange {
    uint64_t addr;
    uint64_t size;
  };
  std::vector<WrittenRange> writtenRanges;

  auto rollback = [&]() {
    LOG("    [!] Rolling back %zu written ranges...\n", writtenRanges.size());
    for (auto &r : writtenRanges) {
      HvZeroMemory(targetPid, r.addr, r.size);
    }
  };

  /* Get section table — needed by both relocations and section mapping */
  auto *sections = IMAGE_FIRST_SECTION(ntHdr);

  /* === Step 3: Apply relocations to LOCAL buffer (before writing) === */
  LOG("    [3/8] Applying relocations (local)...\n");
  int64_t delta = (int64_t)(allocBase - preferredBase);
  auto &relocDir =
      ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

  if (delta != 0 && relocDir.VirtualAddress != 0) {

    /* Helper lambda: convert an RVA to a pointer in our local dllData.
     * Walks the section table to find the right file offset. */
    auto rvaToLocal = [&](uint32_t rva) -> uint8_t * {
      for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; i++) {
        uint32_t secStart = sections[i].VirtualAddress;
        uint32_t secEnd = secStart + sections[i].SizeOfRawData;
        if (rva >= secStart && rva < secEnd) {
          uint32_t fileOff = sections[i].PointerToRawData + (rva - secStart);
          return dllData.data() + fileOff;
        }
      }
      return nullptr;
    };

    /* Find relocation data in local file */
    uint8_t *relocData = rvaToLocal(relocDir.VirtualAddress);

    if (relocData) {
      uint8_t *current = relocData;
      uint8_t *end = relocData + relocDir.Size;

      int relocCount = 0;
      while (current < end) {
        auto *block = (IMAGE_BASE_RELOCATION *)current;
        if (block->SizeOfBlock == 0)
          break;

        uint32_t numEntries =
            (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
            sizeof(uint16_t);
        auto *entries = (uint16_t *)(current + sizeof(IMAGE_BASE_RELOCATION));

        for (uint32_t j = 0; j < numEntries; j++) {
          uint16_t type = entries[j] >> 12;
          uint16_t offset = entries[j] & 0xFFF;

          if (type == IMAGE_REL_BASED_DIR64) {
            uint32_t patchRva = block->VirtualAddress + offset;
            uint8_t *patchPtr = rvaToLocal(patchRva);
            if (patchPtr) {
              uint64_t *val = (uint64_t *)patchPtr;
              *val += delta;
              relocCount++;
            }
          } else if (type == IMAGE_REL_BASED_HIGHLOW) {
            uint32_t patchRva = block->VirtualAddress + offset;
            uint8_t *patchPtr = rvaToLocal(patchRva);
            if (patchPtr) {
              uint32_t *val = (uint32_t *)patchPtr;
              *val += (uint32_t)delta;
              relocCount++;
            }
          }
        }

        current += block->SizeOfBlock;
      }
      LOG("    [+] Applied %d relocations locally (delta=0x%llX)\n", relocCount,
          (uint64_t)delta);
    } else {
      LOG("    [!] Warning: reloc directory not found in sections\n");
    }
  } else {
    LOG("    [+] No relocations needed (delta=0 or no reloc dir)\n");
  }

  /* === Step 4: Map PE sections (with relocations already applied) === */
  LOG("    [4/8] Mapping PE sections...\n");

  /* Write PE headers */
  if (!HvWriteSafe(targetPid, allocBase, dllData.data(),
                   ntHdr->OptionalHeader.SizeOfHeaders)) {
    LOG("    [-] Failed to write PE headers\n");
    rollback();
    return false;
  }
  writtenRanges.push_back({allocBase, ntHdr->OptionalHeader.SizeOfHeaders});

  /* Write sections */
  for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; i++) {
    if (sections[i].SizeOfRawData == 0)
      continue;

    uint64_t destAddr = allocBase + sections[i].VirtualAddress;
    LOG("    [+] Section %.8s -> 0x%llX (%u bytes)\n", sections[i].Name,
        destAddr, sections[i].SizeOfRawData);

    if (!HvWriteSafe(targetPid, destAddr,
                     dllData.data() + sections[i].PointerToRawData,
                     sections[i].SizeOfRawData)) {
      LOG("    [-] Failed to write section %.8s\n", sections[i].Name);
      rollback();
      return false;
    }
    writtenRanges.push_back({destAddr, sections[i].SizeOfRawData});
  }

  /* === Step 5: Resolve imports ===
   * Uses HvFindModule to get remote module bases, then hash-based
   * ResolveExport to find each exported function address. */
  LOG("    [5/8] Resolving imports...\n");
  auto &importDir =
      ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

  if (importDir.VirtualAddress != 0 && importDir.Size != 0) {
    uint8_t *importData = nullptr;
    for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; i++) {
      if (importDir.VirtualAddress >= sections[i].VirtualAddress &&
          importDir.VirtualAddress <
              sections[i].VirtualAddress + sections[i].SizeOfRawData) {
        uint32_t ois = importDir.VirtualAddress - sections[i].VirtualAddress;
        importData = dllData.data() + sections[i].PointerToRawData + ois;
        break;
      }
    }

    if (importData) {
      auto *desc = (IMAGE_IMPORT_DESCRIPTOR *)importData;
      int importCount = 0;

      while (desc->Name != 0) {
        const char *dllName = nullptr;
        for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; i++) {
          if (desc->Name >= sections[i].VirtualAddress &&
              desc->Name <
                  sections[i].VirtualAddress + sections[i].SizeOfRawData) {
            uint32_t ois = desc->Name - sections[i].VirtualAddress;
            dllName = (const char *)(dllData.data() +
                                     sections[i].PointerToRawData + ois);
            break;
          }
        }

        if (!dllName) {
          desc++;
          continue;
        }

        /* Get remote base via HvFindModule */
        wchar_t wideName[256];
        size_t wlen = strlen(dllName);
        for (size_t i = 0; i <= wlen && i < 255; i++)
          wideName[i] = (wchar_t)dllName[i];
        wideName[255] = 0;

        uint64_t remoteBase = 0;
        if (!HvFindModule(targetPid, wideName, &remoteBase) ||
            remoteBase == 0) {

          /* Module not present — try to force-load it via
           * CreateRemoteThread(LoadLibraryA). This handles DLLs like
           * D3DCOMPILER_47.dll and SHELL32.dll that may not be loaded
           * in the target yet but are needed by our overlay DLL. */
          LOG("    [!] '%s' not in target — attempting LoadLibrary...\n",
              dllName);

          HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
          if (hProc) {
            /* Allocate string in target process */
            size_t nameLen = strlen(dllName) + 1;
            void *remoteName =
                VirtualAllocEx(hProc, nullptr, nameLen,
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (remoteName) {
              WriteProcessMemory(hProc, remoteName, dllName, nameLen, nullptr);
              HMODULE k32 = GetModuleHandleA("kernel32.dll");
              FARPROC pLoadLib = GetProcAddress(k32, "LoadLibraryA");
              HANDLE hThread = CreateRemoteThread(
                  hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)pLoadLib,
                  remoteName, 0, nullptr);
              if (hThread) {
                WaitForSingleObject(hThread, 10000);
                CloseHandle(hThread);
              }
              VirtualFreeEx(hProc, remoteName, 0, MEM_RELEASE);
            }
            CloseHandle(hProc);

            /* Retry HvFindModule after loading */
            if (HvFindModule(targetPid, wideName, &remoteBase) &&
                remoteBase != 0) {
              LOG("    [+] Loaded '%s' into target -> 0x%llX\n", dllName,
                  remoteBase);
              goto module_found;
            }
          }

          /* Still not found — abort on critical, skip otherwise */
          if (_stricmp(dllName, "KERNEL32.dll") == 0 ||
              _stricmp(dllName, "ntdll.dll") == 0) {
            LOG("    [FATAL] Critical module '%s' not resolved - aborting "
                "injection\n",
                dllName);
            return false;
          }

          LOG("    [!] Module not found in target (skipping): %s\n", dllName);
          desc++;
          continue;
        }
      module_found:

        LOG("    [+] %s -> 0x%llX\n", dllName, remoteBase);

        /* Walk ILT/IAT */
        uint32_t iltRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk
                                                   : desc->FirstThunk;
        uint32_t iatRva = desc->FirstThunk;

        uint8_t *iltData = nullptr;
        for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; i++) {
          if (iltRva >= sections[i].VirtualAddress &&
              iltRva < sections[i].VirtualAddress + sections[i].SizeOfRawData) {
            uint32_t ois = iltRva - sections[i].VirtualAddress;
            iltData = dllData.data() + sections[i].PointerToRawData + ois;
            break;
          }
        }

        if (iltData) {
          auto *thunks = (uint64_t *)iltData;
          std::vector<uint64_t> iatEntries;
          uint32_t thunkIdx = 0;
          bool iatOk = true;

          while (thunks[thunkIdx] != 0) {
            uint64_t thunkData = thunks[thunkIdx];
            uint64_t resolvedAddr = 0;

            if (thunkData & (1ULL << 63)) {
              /* Import by ordinal - skip */
              LOG("    [!] Ordinal import skipped\n");
            } else {
              /* Import by name - hash-based export resolution */
              uint32_t hintNameRva = (uint32_t)(thunkData & 0x7FFFFFFF);
              const char *funcName = nullptr;
              for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; i++) {
                if (hintNameRva >= sections[i].VirtualAddress &&
                    hintNameRva < sections[i].VirtualAddress +
                                      sections[i].SizeOfRawData) {
                  uint32_t ois = hintNameRva - sections[i].VirtualAddress;
                  funcName =
                      (const char *)(dllData.data() +
                                     sections[i].PointerToRawData + ois + 2);
                  break;
                }
              }
              if (funcName) {
                uint64_t nameHash = Djb2HashAscii(funcName);
                resolvedAddr = ResolveExport(targetPid, remoteBase, nameHash);
                if (resolvedAddr == 0) {
                  LOG("    [-] Failed: %s!%s\n", dllName, funcName);
                  iatOk = false;
                  break;
                }
                importCount++;
              }
            }

            iatEntries.push_back(resolvedAddr);
            thunkIdx++;
          }

          if (!iatOk) {
            rollback();
            return false;
          }

          if (!iatEntries.empty()) {
            uint64_t iatDest = allocBase + iatRva;
            uint64_t iatSize = iatEntries.size() * sizeof(uint64_t);
            LOG("      [+] Writing %zu IAT entries at 0x%llX\n",
                iatEntries.size(), iatDest);
            if (!HvWriteSafe(targetPid, iatDest, iatEntries.data(), iatSize)) {
              LOG("    [-] Failed to write IAT for %s\n", dllName);
              rollback();
              return false;
            }
          }
        }

        desc++;
      }
      LOG("    [+] Resolved %d imports\n", importCount);
    }
  } else {
    LOG("    [+] No imports to resolve\n");
  }

  /* === Step 6: Write shellcode === */
  LOG("    [6/8] Writing shellcode...\n");

  /* Find Present function in dxgi.dll */
  uint64_t dxgiBase = 0;
  if (!HvFindModule(targetPid, L"dxgi.dll", &dxgiBase)) {
    LOG("    [-] Failed to find dxgi.dll in target\n");
    rollback();
    return false;
  }
  LOG("    [+] dxgi.dll -> 0x%llX\n", dxgiBase);

  /* We need the Present VA. For now, we'll use our own swapchain discovery.
   * The overlay DLL itself handles hook installation after DllMain runs.
   * So we just need to trigger DllMain — we can hook a known game function.
   *
   * Actually, let's simplify: we hook NtQueryPerformanceCounter
   * (called by QueryPerformanceCounter) which is called constantly
   * by virtually every game/app for frame timing.
   * NtDelayExecution was tried but many processes never call Sleep().
   */
  uint64_t ntdllBase = 0;
  if (!HvFindModule(targetPid, L"ntdll.dll", &ntdllBase)) {
    LOG("    [-] Failed to find ntdll.dll in target\n");
    rollback();
    return false;
  }
  LOG("    [+] ntdll.dll -> 0x%llX\n", ntdllBase);

  /* Resolve NtQueryPerformanceCounter — universally called for timing */
  LOG("    [dbg] Resolving NtQueryPerformanceCounter export...\n");
  uint64_t hookTarget = ResolveExport(
      targetPid, ntdllBase, Djb2HashAscii("NtQueryPerformanceCounter"));
  if (hookTarget == 0) {
    LOG("    [-] Failed to resolve NtQueryPerformanceCounter\n");
    rollback();
    return false;
  }
  LOG("    [+] NtQueryPerformanceCounter -> 0x%llX\n", hookTarget);

  /* Read original bytes from hook target via deferred safe read */
  LOG("    [dbg] Reading 14 hook target bytes...\n");
  uint8_t savedBytes[14];
  if (!HvReadSafe(targetPid, hookTarget, savedBytes, sizeof(savedBytes))) {
    LOG("    [-] Failed to read hook target bytes\n");
    rollback();
    return false;
  }
  LOG("    [dbg] Hook bytes read OK\n");

  /* Build shellcode */
  ShellcodeData scData = {};
  scData.dllBase = allocBase;
  scData.entryPointRva = entryPointRva;
  scData.originalPresent = hookTarget; /* Reusing field name */
  memcpy(scData.savedPresentBytes, savedBytes, 14);
  scData.guard = 0;

  auto shellcode = BuildShellcode(scData);

  /* Write shellcode data + code to end of allocation */
  uint64_t shellcodeBase = allocBase + imageSize;
  LOG("    [+] Shellcode at 0x%llX (data=%zu + code=%zu bytes)\n",
      shellcodeBase, sizeof(ShellcodeData), shellcode.size());

  /* Write data struct first */
  LOG("    [dbg] Writing shellcode data struct...\n");
  if (!HvWriteSafe(targetPid, shellcodeBase, &scData, sizeof(scData))) {
    LOG("    [-] Failed to write shellcode data\n");
    rollback();
    return false;
  }
  writtenRanges.push_back({shellcodeBase, sizeof(scData)});
  LOG("    [dbg] Shellcode data written OK\n");

  /* Write code after data */
  uint64_t codeBase = shellcodeBase + sizeof(ShellcodeData);
  LOG("    [dbg] Writing shellcode code (%zu bytes)...\n", shellcode.size());
  if (!HvWriteSafe(targetPid, codeBase, shellcode.data(), shellcode.size())) {
    LOG("    [-] Failed to write shellcode code\n");
    rollback();
    return false;
  }
  writtenRanges.push_back({codeBase, shellcode.size()});
  LOG("    [dbg] Shellcode code written OK\n");

  /* === Step 7: Install hook on NtDelayExecution === */
  LOG("    [7/8] Installing inline hook...\n");

  /* Build 14-byte absolute jump: FF 25 00 00 00 00 [8-byte addr] */
  uint8_t hookPatch[14];
  hookPatch[0] = 0xFF;
  hookPatch[1] = 0x25;
  hookPatch[2] = 0x00;
  hookPatch[3] = 0x00;
  hookPatch[4] = 0x00;
  hookPatch[5] = 0x00;
  *(uint64_t *)(&hookPatch[6]) = codeBase;

  LOG("    [dbg] Writing hook patch (14 bytes) to 0x%llX via CR3-swap...\n",
      hookTarget);

  /* Make hook target page writable — triggers CoW and sets PTE write bit
   * so the CR3-swap write doesn't fault on a read-only PTE. */
  HANDLE hTarget = OpenProcess(PROCESS_VM_OPERATION, FALSE, targetPid);
  if (!hTarget) {
    LOG("    [-] OpenProcess failed for VirtualProtectEx: %u\n",
        GetLastError());
    rollback();
    return false;
  }
  DWORD oldProt = 0;
  if (!VirtualProtectEx(hTarget, (LPVOID)hookTarget, sizeof(hookPatch),
                        PAGE_EXECUTE_READWRITE, &oldProt)) {
    LOG("    [-] VirtualProtectEx failed: %u\n", GetLastError());
    CloseHandle(hTarget);
    rollback();
    return false;
  }
  LOG("    [dbg] Page protection changed to RWX (old=0x%X)\n", oldProt);

  if (!HvWrite(targetPid, hookTarget, hookPatch, sizeof(hookPatch))) {
    LOG("    [-] Failed to write hook\n");
    VirtualProtectEx(hTarget, (LPVOID)hookTarget, sizeof(hookPatch), oldProt,
                     &oldProt);
    CloseHandle(hTarget);
    rollback();
    return false;
  }

  /* Verify hook was written correctly by reading back */
  uint8_t verifyBytes[14] = {};
  if (HvReadSafe(targetPid, hookTarget, verifyBytes, 14)) {
    LOG("    [dbg] Hook readback: ");
    for (int i = 0; i < 14; i++)
      LOG("%02X ", verifyBytes[i]);
    LOG("\n");
    bool match = memcmp(verifyBytes, hookPatch, 14) == 0;
    LOG("    [%s] Hook verification %s\n", match ? "+" : "!",
        match ? "PASSED" : "FAILED - bytes don't match!");
  } else {
    LOG("    [!] Hook readback failed\n");
  }

  /* Dump original saved bytes and hook target address */
  LOG("    [dbg] Saved original bytes: ");
  for (int i = 0; i < 14; i++)
    LOG("%02X ", savedBytes[i]);
  LOG("\n");
  LOG("    [dbg] Hook JMP target (codeBase): 0x%llX\n", codeBase);
  LOG("    [dbg] DllMain VA = allocBase(0x%llX) + EP_RVA(0x%llX) = 0x%llX\n",
      allocBase, entryPointRva, allocBase + entryPointRva);

  /* Keep page RWX — shellcode needs to write original bytes back to unhook.
   * Do NOT restore oldProt here. */
  CloseHandle(hTarget);
  LOG("    [+] Hook installed! (page left RWX for shellcode unhook)\n");

  /* === Step 8: Erase PE header === */
  LOG("    [8/8] Erasing PE header...\n");
  HvZeroMemory(targetPid, allocBase, 0x1000);
  LOG("    [+] PE header erased\n");

  /* Release MDL-locked pages — no longer needed after injection.
   * Prevents PROCESS_HAS_LOCKED_PAGES BSOD if target exits. */
  {
    DWORD_PTR oldMask = PinToCore(0);
    g_SharedPage->request.magic = HV_MAGIC;
    g_SharedPage->request.command = HV_CMD_UNLOCK_MDL;
    int regs[4];
    __cpuidex(regs, HV_CPUID_LEAF, HV_CMD_UNLOCK_MDL);
    SetThreadAffinityMask(GetCurrentThread(), oldMask);
    LOG("    [+] MDL pages unlocked (status=0x%X)\n", (uint32_t)regs[0]);
  }

  LOG("\n[+] Injection complete! Overlay DLL mapped at 0x%llX\n", allocBase);
  LOG("[+] Waiting for hook to trigger (10 sec max)...\n");

  /* Poll the hook target to see if shellcode has fired (bytes restored) */
  for (int attempt = 0; attempt < 10; attempt++) {
    Sleep(1000);
    uint8_t checkBytes[14] = {};
    if (HvReadSafe(targetPid, hookTarget, checkBytes, 14)) {
      if (checkBytes[0] != 0xFF || checkBytes[1] != 0x25) {
        /* Hook bytes restored → shellcode ran! */
        LOG("[+] Hook triggered after ~%d seconds! DllMain was called.\n",
            attempt + 1);
        LOG("    Restored bytes: ");
        for (int i = 0; i < 14; i++)
          LOG("%02X ", checkBytes[i]);
        LOG("\n");
        return true;
      }
    }
    LOG("    [%d/10] Hook still active...\n", attempt + 1);
  }

  LOG("[!] Hook was NOT triggered after 10 seconds.\n");
  LOG("    Target process may not call NtQueryPerformanceCounter.\n");
  return true;
}
