/*
 * offset_discovery.h — Dynamic Windows structure offset discovery.
 *
 * Hardcoded offsets (e.g., EPROCESS.DirectoryTableBase = 0x28) break
 * on different Windows builds. This module discovers offsets at runtime
 * via pattern scanning and known relationships.
 *
 * Strategy:
 *   1. Use PsGetCurrentProcess() to get a known EPROCESS pointer
 *   2. Use known patterns (e.g., DirectoryTableBase is always at +0x28)
 *   3. Validate discovered offsets by checking field values
 *
 * Fallback: If discovery fails, use hardcoded offsets for Windows 10 22H2.
 */

#ifndef OFFSET_DISCOVERY_H
#define OFFSET_DISCOVERY_H

#include <ntifs.h>

/* ============================================================================
 * Offset Context — Discovered structure offsets
 * ============================================================================
 */

typedef struct _OFFSET_CONTEXT {
  /* EPROCESS offsets */
  UINT32 EprocessActiveProcessLinks;   /* LIST_ENTRY for process enumeration */
  UINT32 EprocessUniqueProcessId;      /* PID */
  UINT32 EprocessDirectoryTableBase;   /* CR3 (user-mode) */
  UINT32 EprocessPeb;                  /* PEB pointer */

  /* KPRCB offsets */
  UINT32 KprcbCurrentThread;           /* Offset from KPCR to current thread */

  /* KTHREAD offsets */
  UINT32 KthreadApcState;              /* ApcState.Process → EPROCESS */

  /* Validation flag */
  BOOLEAN Initialized;
} OFFSET_CONTEXT, *POFFSET_CONTEXT;

/* ============================================================================
 * Function Declarations
 * ============================================================================
 */

/*
 * DiscoverOffsets — Discover all structure offsets at runtime.
 *
 * Uses a combination of:
 *   - Known fixed offsets (DirectoryTableBase is always at +0x28)
 *   - PsGetCurrentProcess() to get a reference EPROCESS
 *   - Field validation (e.g., CR3 must be page-aligned)
 *
 * Returns:
 *   STATUS_SUCCESS if all offsets discovered and validated
 *   STATUS_UNSUCCESSFUL if discovery fails (falls back to hardcoded offsets)
 */
NTSTATUS DiscoverOffsets(_Out_ POFFSET_CONTEXT Ctx);

#endif /* OFFSET_DISCOVERY_H */
