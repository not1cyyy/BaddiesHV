/*
 * npt_protection.c — NPT-based memory protection implementation.
 *
 * Protects hypervisor structures (VMCB, MSRPM, Host Save Area) from
 * detection by marking their GPAs as non-present in the NPT.
 */

#include "npt_protection.h"
#include "svm.h"

#define HV_LOG(fmt, ...) DbgPrint("[BaddiesHV] " fmt "\n", ##__VA_ARGS__)

#define HV_LOG_ERROR(fmt, ...) DbgPrint("[BaddiesHV][ERROR] " fmt "\n", ##__VA_ARGS__)

/* ============================================================================
 * NptProtectRange — Mark a GPA range as non-present in NPT
 * ============================================================================
 */

NTSTATUS NptProtectRange(_In_ PNPT_CONTEXT NptCtx,
                         _Inout_ PNPT_PROTECTION_CONTEXT ProtCtx,
                         _In_ UINT64 Gpa, _In_ UINT64 Size) {

  if (!NptCtx || !NptCtx->Pml4 || !ProtCtx) {
    return STATUS_INVALID_PARAMETER;
  }

  /* Align GPA down to 2MB boundary, size up to 2MB multiple */
  UINT64 gpaAligned = Gpa & ~(NPT_PAGE_SIZE_2MB - 1);
  UINT64 endGpa = (Gpa + Size + NPT_PAGE_SIZE_2MB - 1) & ~(NPT_PAGE_SIZE_2MB - 1);
  UINT64 sizeAligned = endGpa - gpaAligned;

  HV_LOG("NptProtectRange: GPA 0x%llX size 0x%llX (aligned: 0x%llX - 0x%llX)",
         Gpa, Size, gpaAligned, endGpa);

  /* Walk NPT and protect each 2MB page */
  for (UINT64 gpa = gpaAligned; gpa < endGpa; gpa += NPT_PAGE_SIZE_2MB) {

    if (ProtCtx->RangeCount >= MAX_PROTECTED_RANGES) {
      HV_LOG_ERROR("NptProtectRange: Too many protected ranges (max %u)",
                   MAX_PROTECTED_RANGES);
      return STATUS_INSUFFICIENT_RESOURCES;
    }

    UINT32 pml4Idx = (UINT32)NPT_PML4_INDEX(gpa);
    UINT32 pdptIdx = (UINT32)NPT_PDPT_INDEX(gpa);
    UINT32 pdIdx = (UINT32)NPT_PD_INDEX(gpa);

    /* --- Walk to PD level --- */
    PNPT_ENTRY pml4 = NptCtx->Pml4;
    if (!(pml4[pml4Idx] & NPT_PRESENT)) {
      HV_LOG_ERROR("NptProtectRange: PML4[%u] not present for GPA 0x%llX",
                   pml4Idx, gpa);
      return STATUS_UNSUCCESSFUL;
    }

    UINT64 pdptPa = pml4[pml4Idx] & NPT_PFN_MASK;
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)pdptPa;
    PNPT_ENTRY pdpt = (PNPT_ENTRY)MmGetVirtualForPhysical(pa);
    if (!pdpt) {
      HV_LOG_ERROR("NptProtectRange: Cannot map PDPT PA 0x%llX", pdptPa);
      return STATUS_UNSUCCESSFUL;
    }

    if (!(pdpt[pdptIdx] & NPT_PRESENT)) {
      HV_LOG_ERROR("NptProtectRange: PDPT[%u] not present for GPA 0x%llX",
                   pdptIdx, gpa);
      return STATUS_UNSUCCESSFUL;
    }

    UINT64 pdPa = pdpt[pdptIdx] & NPT_PFN_MASK;
    pa.QuadPart = (LONGLONG)pdPa;
    PNPT_ENTRY pd = (PNPT_ENTRY)MmGetVirtualForPhysical(pa);
    if (!pd) {
      HV_LOG_ERROR("NptProtectRange: Cannot map PD PA 0x%llX", pdPa);
      return STATUS_UNSUCCESSFUL;
    }

    /* --- Backup original PDE and clear PRESENT bit --- */
    UINT64 originalPde = pd[pdIdx];
    if (!(originalPde & NPT_PRESENT)) {
      HV_LOG("NptProtectRange: PD[%u] already non-present for GPA 0x%llX",
             pdIdx, gpa);
      continue; /* Already protected or unmapped */
    }

    /* Clear PRESENT bit (guest cannot access this page) */
    pd[pdIdx] = originalPde & ~NPT_PRESENT;

    /* Record protected range for cleanup */
    UINT32 idx = ProtCtx->RangeCount++;
    ProtCtx->Ranges[idx].Gpa = gpa;
    ProtCtx->Ranges[idx].Size = NPT_PAGE_SIZE_2MB;
    ProtCtx->Ranges[idx].OriginalPde = originalPde;
    ProtCtx->Ranges[idx].PdIndex = pdIdx;
    ProtCtx->Ranges[idx].PdptIndex = pdptIdx;
    ProtCtx->Ranges[idx].Pml4Index = pml4Idx;

    HV_LOG("  Protected 2MB page at GPA 0x%llX (PML4[%u] PDPT[%u] PD[%u])",
           gpa, pml4Idx, pdptIdx, pdIdx);
  }

  return STATUS_SUCCESS;
}

/* ============================================================================
 * NptUnprotectRange — Restore access to a protected range
 * ============================================================================
 */

NTSTATUS NptUnprotectRange(_In_ PNPT_CONTEXT NptCtx,
                           _Inout_ PNPT_PROTECTION_CONTEXT ProtCtx,
                           _In_ UINT64 Gpa) {

  if (!NptCtx || !NptCtx->Pml4 || !ProtCtx) {
    return STATUS_INVALID_PARAMETER;
  }

  UINT64 gpaAligned = Gpa & ~(NPT_PAGE_SIZE_2MB - 1);

  /* Find the protected range */
  for (UINT32 i = 0; i < ProtCtx->RangeCount; i++) {
    if (ProtCtx->Ranges[i].Gpa == gpaAligned) {
      PPROTECTED_RANGE range = &ProtCtx->Ranges[i];

      /* Walk to PD and restore original PDE */
      PNPT_ENTRY pml4 = NptCtx->Pml4;
      UINT64 pdptPa = pml4[range->Pml4Index] & NPT_PFN_MASK;
      PHYSICAL_ADDRESS pa;
      pa.QuadPart = (LONGLONG)pdptPa;
      PNPT_ENTRY pdpt = (PNPT_ENTRY)MmGetVirtualForPhysical(pa);
      if (!pdpt)
        return STATUS_UNSUCCESSFUL;

      UINT64 pdPa = pdpt[range->PdptIndex] & NPT_PFN_MASK;
      pa.QuadPart = (LONGLONG)pdPa;
      PNPT_ENTRY pd = (PNPT_ENTRY)MmGetVirtualForPhysical(pa);
      if (!pd)
        return STATUS_UNSUCCESSFUL;

      /* Restore original PDE */
      pd[range->PdIndex] = range->OriginalPde;

      HV_LOG("NptUnprotectRange: Restored GPA 0x%llX", gpaAligned);

      /* Remove from list (shift remaining entries) */
      for (UINT32 j = i; j < ProtCtx->RangeCount - 1; j++) {
        ProtCtx->Ranges[j] = ProtCtx->Ranges[j + 1];
      }
      ProtCtx->RangeCount--;

      return STATUS_SUCCESS;
    }
  }

  HV_LOG_ERROR("NptUnprotectRange: GPA 0x%llX not found in protected ranges",
               gpaAligned);
  return STATUS_NOT_FOUND;
}

/* ============================================================================
 * NptProtectHypervisorStructures — Protect all hypervisor structures
 * ============================================================================
 */

NTSTATUS NptProtectHypervisorStructures(
    _In_ PNPT_CONTEXT NptCtx, _Out_ PNPT_PROTECTION_CONTEXT ProtCtx,
    _In_ PVCPU_DATA *VcpuArray, _In_ UINT32 ProcessorCount,
    _In_ UINT64 MsrpmPa, _In_ UINT64 MsrpmSize) {

  NTSTATUS status;

  if (!NptCtx || !ProtCtx || !VcpuArray) {
    return STATUS_INVALID_PARAMETER;
  }

  RtlZeroMemory(ProtCtx, sizeof(NPT_PROTECTION_CONTEXT));

  HV_LOG("NptProtectHypervisorStructures: Protecting %u CPUs + MSRPM",
         ProcessorCount);

  /* --- Protect MSRPM (global, shared across all CPUs) --- */
  status = NptProtectRange(NptCtx, ProtCtx, MsrpmPa, MsrpmSize);
  if (!NT_SUCCESS(status)) {
    HV_LOG_ERROR("Failed to protect MSRPM at PA 0x%llX (0x%08X)", MsrpmPa,
                 status);
    return status;
  }

  /* --- Protect per-CPU structures --- */
  for (UINT32 i = 0; i < ProcessorCount; i++) {
    PVCPU_DATA vcpu = VcpuArray[i];
    if (!vcpu)
      continue;

    /* Protect Guest VMCB */
    status = NptProtectRange(NptCtx, ProtCtx, vcpu->GuestVmcbPa.QuadPart,
                             sizeof(VMCB));
    if (!NT_SUCCESS(status)) {
      HV_LOG_ERROR("CPU %u: Failed to protect Guest VMCB at PA 0x%llX", i,
                   vcpu->GuestVmcbPa.QuadPart);
      /* Non-fatal — continue protecting other structures */
    }

    /* Protect Host VMCB */
    status = NptProtectRange(NptCtx, ProtCtx, vcpu->HostVmcbPa.QuadPart,
                             sizeof(VMCB));
    if (!NT_SUCCESS(status)) {
      HV_LOG_ERROR("CPU %u: Failed to protect Host VMCB at PA 0x%llX", i,
                   vcpu->HostVmcbPa.QuadPart);
    }

    /* Protect Host Save Area */
    status =
        NptProtectRange(NptCtx, ProtCtx, vcpu->HostSaveAreaPa.QuadPart, PAGE_SIZE);
    if (!NT_SUCCESS(status)) {
      HV_LOG_ERROR("CPU %u: Failed to protect Host Save Area at PA 0x%llX", i,
                   vcpu->HostSaveAreaPa.QuadPart);
    }
  }

  HV_LOG("NptProtectHypervisorStructures: Protected %u ranges",
         ProtCtx->RangeCount);

  return STATUS_SUCCESS;
}

/* ============================================================================
 * NptUnprotectAll — Unprotect all ranges (cleanup)
 * ============================================================================
 */

VOID NptUnprotectAll(_In_ PNPT_CONTEXT NptCtx,
                     _Inout_ PNPT_PROTECTION_CONTEXT ProtCtx) {

  if (!NptCtx || !ProtCtx) {
    return;
  }

  HV_LOG("NptUnprotectAll: Restoring %u protected ranges", ProtCtx->RangeCount);

  /* Unprotect in reverse order (LIFO) */
  while (ProtCtx->RangeCount > 0) {
    UINT32 idx = ProtCtx->RangeCount - 1;
    PPROTECTED_RANGE range = &ProtCtx->Ranges[idx];

    /* Walk to PD and restore original PDE */
    PNPT_ENTRY pml4 = NptCtx->Pml4;
    UINT64 pdptPa = pml4[range->Pml4Index] & NPT_PFN_MASK;
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)pdptPa;
    PNPT_ENTRY pdpt = (PNPT_ENTRY)MmGetVirtualForPhysical(pa);
    if (pdpt) {
      UINT64 pdPa = pdpt[range->PdptIndex] & NPT_PFN_MASK;
      pa.QuadPart = (LONGLONG)pdPa;
      PNPT_ENTRY pd = (PNPT_ENTRY)MmGetVirtualForPhysical(pa);
      if (pd) {
        pd[range->PdIndex] = range->OriginalPde;
      }
    }

    ProtCtx->RangeCount--;
  }

  HV_LOG("NptUnprotectAll: All ranges restored");
}
