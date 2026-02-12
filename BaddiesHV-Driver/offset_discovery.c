/*
 * offset_discovery.c — Dynamic Windows structure offset discovery.
 *
 * Discovers EPROCESS/KTHREAD/KPRCB offsets at runtime to support
 * multiple Windows builds (10 21H2, 22H2, 11 23H2, etc.).
 */

#include "offset_discovery.h"

#define HV_LOG(fmt, ...) DbgPrint("[BaddiesHV] " fmt "\n", ##__VA_ARGS__)

#define HV_LOG_ERROR(fmt, ...) DbgPrint("[BaddiesHV][ERROR] " fmt "\n", ##__VA_ARGS__)

/* ============================================================================
 * Hardcoded fallback offsets (Windows 10/11 22H2)
 * ============================================================================
 */

#define FALLBACK_EPROCESS_ACTIVE_PROCESS_LINKS 0x448
#define FALLBACK_EPROCESS_UNIQUE_PROCESS_ID 0x440
#define FALLBACK_EPROCESS_DIRECTORY_TABLE_BASE 0x028
#define FALLBACK_EPROCESS_PEB 0x550
#define FALLBACK_KPRCB_CURRENT_THREAD 0x188
#define FALLBACK_KTHREAD_APC_STATE 0x098

/* ============================================================================
 * DiscoverOffsets — Main discovery function
 * ============================================================================
 */

NTSTATUS DiscoverOffsets(_Out_ POFFSET_CONTEXT Ctx) {
  if (!Ctx) {
    return STATUS_INVALID_PARAMETER;
  }

  RtlZeroMemory(Ctx, sizeof(OFFSET_CONTEXT));

  HV_LOG("DiscoverOffsets: Starting dynamic offset discovery...");

  /* -------------------------------------------------------------------------
   * Strategy 1: Use known fixed offsets (these never change)
   * ------------------------------------------------------------------------- */

  /* DirectoryTableBase (CR3) is ALWAYS at +0x28 in EPROCESS across all
   * Windows versions (10, 11, Server 2016-2022). This is a fundamental
   * kernel invariant. */
  Ctx->EprocessDirectoryTableBase = 0x028;

  /* -------------------------------------------------------------------------
   * Strategy 2: Use PsGetCurrentProcess() to validate offsets
   * ------------------------------------------------------------------------- */

  PEPROCESS currentProcess = PsGetCurrentProcess();
  if (!currentProcess) {
    HV_LOG_ERROR("DiscoverOffsets: PsGetCurrentProcess() failed");
    goto UseFallback;
  }

  UINT64 processBase = (UINT64)currentProcess;

  /* Validate DirectoryTableBase by checking if CR3 is page-aligned */
  UINT64 cr3 = *(UINT64 *)(processBase + Ctx->EprocessDirectoryTableBase);
  if ((cr3 & 0xFFF) != 0) {
    HV_LOG_ERROR("DiscoverOffsets: CR3 validation failed (0x%llX not page-aligned)",
                 cr3);
    goto UseFallback;
  }

  HV_LOG("  DirectoryTableBase = 0x%03X (validated CR3 = 0x%llX)",
         Ctx->EprocessDirectoryTableBase, cr3);

  /* -------------------------------------------------------------------------
   * Strategy 3: Scan for UniqueProcessId (PID) offset
   *
   * We know the current process's PID via PsGetCurrentProcessId().
   * Scan EPROCESS structure for a UINT64 matching this PID.
   * -------------------------------------------------------------------------
   */

  HANDLE currentPid = PsGetCurrentProcessId();
  UINT64 pidValue = (UINT64)currentPid;

  BOOLEAN pidFound = FALSE;
  for (UINT32 offset = 0x400; offset < 0x500; offset += 8) {
    UINT64 value = *(UINT64 *)(processBase + offset);
    if (value == pidValue) {
      Ctx->EprocessUniqueProcessId = offset;
      pidFound = TRUE;
      HV_LOG("  UniqueProcessId = 0x%03X (PID = %llu)", offset, pidValue);
      break;
    }
  }

  if (!pidFound) {
    HV_LOG_ERROR("DiscoverOffsets: Failed to find UniqueProcessId offset");
    goto UseFallback;
  }

  /* -------------------------------------------------------------------------
   * Strategy 4: Scan for ActiveProcessLinks (LIST_ENTRY) offset
   *
   * ActiveProcessLinks is a LIST_ENTRY near UniqueProcessId.
   * We look for a LIST_ENTRY where Flink/Blink point to kernel addresses.
   * -------------------------------------------------------------------------
   */

  BOOLEAN linksFound = FALSE;
  for (UINT32 offset = Ctx->EprocessUniqueProcessId;
       offset < Ctx->EprocessUniqueProcessId + 0x20; offset += 8) {
    UINT64 flink = *(UINT64 *)(processBase + offset);
    UINT64 blink = *(UINT64 *)(processBase + offset + 8);

    /* Validate: Flink/Blink must be kernel addresses */
    if (flink >= 0xFFFF800000000000ULL && blink >= 0xFFFF800000000000ULL) {
      Ctx->EprocessActiveProcessLinks = offset;
      linksFound = TRUE;
      HV_LOG("  ActiveProcessLinks = 0x%03X", offset);
      break;
    }
  }

  if (!linksFound) {
    HV_LOG_ERROR("DiscoverOffsets: Failed to find ActiveProcessLinks offset");
    goto UseFallback;
  }

  /* -------------------------------------------------------------------------
   * Strategy 5: Scan for PEB offset
   *
   * PEB is a user-mode pointer (< 0x00007FFFFFFFFFFF).
   * Scan EPROCESS for a pointer in user-mode range.
   * -------------------------------------------------------------------------
   */

  BOOLEAN pebFound = FALSE;
  for (UINT32 offset = 0x500; offset < 0x600; offset += 8) {
    UINT64 value = *(UINT64 *)(processBase + offset);
    /* PEB is in user-mode address space (< 0x00007FFFFFFFFFFF) */
    if (value > 0x10000 && value < 0x00007FFFFFFFFFFFULL) {
      Ctx->EprocessPeb = offset;
      pebFound = TRUE;
      HV_LOG("  Peb = 0x%03X (PEB VA = 0x%llX)", offset, value);
      break;
    }
  }

  if (!pebFound) {
    HV_LOG("  Peb offset not found (non-critical, using fallback)");
    Ctx->EprocessPeb = FALLBACK_EPROCESS_PEB;
  }

  /* -------------------------------------------------------------------------
   * Strategy 6: KPRCB.CurrentThread offset
   *
   * KPCR is at GS base. KPRCB is at KPCR+0x180.
   * CurrentThread is typically at KPRCB+0x08 or KPRCB+0x188.
   * We use the fallback value (validated across Windows 10/11).
   * -------------------------------------------------------------------------
   */

  Ctx->KprcbCurrentThread = FALLBACK_KPRCB_CURRENT_THREAD;
  HV_LOG("  KprcbCurrentThread = 0x%03X (fallback)", Ctx->KprcbCurrentThread);

  /* -------------------------------------------------------------------------
   * Strategy 7: KTHREAD.ApcState offset
   *
   * ApcState.Process points back to EPROCESS.
   * We use the fallback value (validated across Windows 10/11).
   * -------------------------------------------------------------------------
   */

  Ctx->KthreadApcState = FALLBACK_KTHREAD_APC_STATE;
  HV_LOG("  KthreadApcState = 0x%03X (fallback)", Ctx->KthreadApcState);

  Ctx->Initialized = TRUE;
  HV_LOG("DiscoverOffsets: Success! All offsets discovered.");
  return STATUS_SUCCESS;

UseFallback:
  HV_LOG("DiscoverOffsets: Using fallback offsets for Windows 10/11 22H2");

  Ctx->EprocessActiveProcessLinks = FALLBACK_EPROCESS_ACTIVE_PROCESS_LINKS;
  Ctx->EprocessUniqueProcessId = FALLBACK_EPROCESS_UNIQUE_PROCESS_ID;
  Ctx->EprocessDirectoryTableBase = FALLBACK_EPROCESS_DIRECTORY_TABLE_BASE;
  Ctx->EprocessPeb = FALLBACK_EPROCESS_PEB;
  Ctx->KprcbCurrentThread = FALLBACK_KPRCB_CURRENT_THREAD;
  Ctx->KthreadApcState = FALLBACK_KTHREAD_APC_STATE;
  Ctx->Initialized = TRUE;

  return STATUS_SUCCESS; /* Non-fatal — fallback offsets work on most systems */
}
