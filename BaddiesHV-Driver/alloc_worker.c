/*
 * alloc_worker.c — Deferred memory allocation worker thread.
 *
 * The VMEXIT handler runs in SVM host mode with interrupts disabled.
 * It CANNOT call kernel APIs (KeSetEvent, ZwAllocateVirtualMemory, etc).
 * This worker thread runs at PASSIVE_LEVEL and polls a volatile flag.
 *
 * Flow:
 *   1. VMEXIT handler receives HV_CMD_ALLOC
 *   2. Sets g_HvData.AllocPid/AllocSize, writes AllocReady = 1
 *   3. Returns HV_STATUS_PENDING to guest
 *   4. Worker sees AllocReady==1, does KeStackAttachProcess +
 * ZwAllocateVirtualMemory
 *   5. Sets g_HvData.AllocResult, AllocStatus = 1 (done) or -1 (failed)
 *   6. Loader polls: issues HV_CMD_PING, VMEXIT handler checks AllocStatus
 *      and writes result back to shared page
 */

#include "../shared/hvcomm.h"
#include "svm.h"

#define HV_LOG(fmt, ...)                                                       \
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[BaddiesHV] " fmt "\n",  \
             ##__VA_ARGS__)

#define HV_LOG_ERROR(fmt, ...)                                                 \
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,                          \
             "[BaddiesHV][ERROR] " fmt "\n", ##__VA_ARGS__)

/* ============================================================================
 *  Worker Thread Routine — polls AllocReady flag
 * ============================================================================
 */

static VOID AllocWorkerThread(_In_ PVOID Context) {
  UNREFERENCED_PARAMETER(Context);

  HV_LOG("AllocWorker: thread started (PASSIVE_LEVEL, polling mode)");

  /* Poll interval: 1ms in 100ns units */
  LARGE_INTEGER interval;
  interval.QuadPart = -10000LL; /* 1ms */

  while (TRUE) {
    /* Check for shutdown first */
    if (g_HvData.AllocShutdown) {
      HV_LOG("AllocWorker: shutdown signal received");
      break;
    }

    /* NOTE: SharedPageMapRequest handling removed.
     * HV_SHARED_PAGE is exactly 4096 bytes (one page), so
     * the CR3 swap fallback in svm.c is page-fault-safe.
     * MmMapIoSpace on already-cached RAM can cause bugchecks
     * from cache attribute conflicts. */

    /* Check if VMEXIT handler posted a deferred read request */
    if (InterlockedCompareExchange(&g_HvData.DeferReadReady, 0, 1) == 1) {
      /* === Process deferred safe-read request === */
      UINT32 readPid = g_HvData.DeferReadPid;
      UINT64 readAddr = g_HvData.DeferReadAddr;
      UINT64 readSize = g_HvData.DeferReadSize;

      if (readSize > sizeof(g_HvData.DeferReadBuf))
        readSize = sizeof(g_HvData.DeferReadBuf);

      PEPROCESS readProcess = NULL;
      NTSTATUS status =
          PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)readPid, &readProcess);
      if (NT_SUCCESS(status)) {
        KAPC_STATE readApc;
        KeStackAttachProcess(readProcess, &readApc);

        /* Read at PASSIVE_LEVEL — page faults handled normally by OS.
         * This is safe for file-backed pages (ntdll exports, etc.) */
        __try {
          RtlCopyMemory(g_HvData.DeferReadBuf, (PVOID)readAddr,
                        (SIZE_T)readSize);
          InterlockedExchange(&g_HvData.DeferReadStatus, 1); /* success */
        } __except (EXCEPTION_EXECUTE_HANDLER) {
          HV_LOG_ERROR("DeferRead: exception reading 0x%llX (%llu bytes)",
                       readAddr, readSize);
          InterlockedExchange(&g_HvData.DeferReadStatus, -1); /* failed */
        }

        KeUnstackDetachProcess(&readApc);
        ObDereferenceObject(readProcess);
      } else {
        HV_LOG_ERROR("DeferRead: PsLookupProcessByProcessId failed (0x%08X)",
                     status);
        InterlockedExchange(&g_HvData.DeferReadStatus, -1);
      }
      continue; /* Check for more requests immediately */
    }

    /* Check if VMEXIT handler posted a deferred write request */
    if (InterlockedCompareExchange(&g_HvData.DeferWriteReady, 0, 1) == 1) {
      UINT32 writePid = g_HvData.DeferWritePid;
      UINT64 writeAddr = g_HvData.DeferWriteAddr;
      UINT64 writeSize = g_HvData.DeferWriteSize;

      if (writeSize > sizeof(g_HvData.DeferWriteBuf))
        writeSize = sizeof(g_HvData.DeferWriteBuf);

      PEPROCESS writeProcess = NULL;
      NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)writePid,
                                                   &writeProcess);
      if (NT_SUCCESS(status)) {
        KAPC_STATE writeApc;
        KeStackAttachProcess(writeProcess, &writeApc);

        __try {
          /* Probe first to trigger any necessary page faults and
           * validate that the range is writable user-mode memory */
          ProbeForWrite((PVOID)writeAddr, (SIZE_T)writeSize, 1);
          RtlCopyMemory((PVOID)writeAddr, g_HvData.DeferWriteBuf,
                        (SIZE_T)writeSize);
          InterlockedExchange(&g_HvData.DeferWriteStatus, 1); /* success */
        } __except (EXCEPTION_EXECUTE_HANDLER) {
          HV_LOG_ERROR("DeferWrite: exception writing 0x%llX (%llu bytes)",
                       writeAddr, writeSize);
          InterlockedExchange(&g_HvData.DeferWriteStatus, -1); /* failed */
        }

        KeUnstackDetachProcess(&writeApc);
        ObDereferenceObject(writeProcess);
      } else {
        HV_LOG_ERROR("DeferWrite: PsLookupProcessByProcessId failed (0x%08X)",
                     status);
        InterlockedExchange(&g_HvData.DeferWriteStatus, -1);
      }
      continue;
    }

    /* Check if loader signaled to unlock MDL-locked alloc pages */
    if (InterlockedCompareExchange(&g_HvData.UnlockMdlReady, 0, 1) == 1) {
      if (g_HvData.AllocMdl) {
        PMDL mdl = (PMDL)g_HvData.AllocMdl;
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        g_HvData.AllocMdl = NULL;
        HV_LOG("AllocWorker: MDL unlocked by loader signal");
      }
      continue;
    }

    /* Check if VMEXIT handler posted an alloc request */
    if (InterlockedCompareExchange(&g_HvData.AllocReady, 0, 1) != 1) {
      /* No request — sleep briefly and retry */
      KeDelayExecutionThread(KernelMode, FALSE, &interval);
      continue;
    }

    /* === Process allocation request === */
    UINT32 pid = g_HvData.AllocPid;
    SIZE_T size = (SIZE_T)g_HvData.AllocSize;

    HV_LOG("AllocWorker: allocating %llu bytes for PID %u", (UINT64)size, pid);

    /* Look up the target EPROCESS */
    PEPROCESS targetProcess = NULL;
    NTSTATUS status =
        PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &targetProcess);
    if (!NT_SUCCESS(status)) {
      HV_LOG_ERROR("AllocWorker: PsLookupProcessByProcessId failed (0x%08X)",
                   status);
      g_HvData.AllocResult = 0;
      InterlockedExchange(&g_HvData.AllocStatus, -1);
      continue;
    }

    /* Attach to target process context */
    KAPC_STATE apcState;
    KeStackAttachProcess(targetProcess, &apcState);

    /* Allocate RWX memory in the target process */
    PVOID baseAddress = NULL;
    status = ZwAllocateVirtualMemory(NtCurrentProcess(), &baseAddress, 0, &size,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);

    if (NT_SUCCESS(status)) {
      /* Pre-fault pages: touch every page while still attached.
       * ZwAllocateVirtualMemory returns demand-zero pages (PTEs marked
       * not-present). We must force them resident so
       * HvReadProcessMemory/HvWriteProcessMemory can access them
       * from VMEXIT context (GIF=0, no page fault handling). */
      volatile UINT8 *p = (volatile UINT8 *)baseAddress;
      for (SIZE_T off = 0; off < size; off += 0x1000) {
        p[off] = 0; /* Triggers demand-page fault at PASSIVE_LEVEL */
      }
      HV_LOG("AllocWorker: pre-faulted %llu pages", (UINT64)(size / 0x1000));

      /* Lock pages in physical memory via MDL.
       * This prevents the working set trimmer from evicting our pages
       * during the multi-step injection process (relocations, imports, etc.)
       * which involves hundreds of HvRead/HvWrite hypercalls over time. */
      PMDL mdl = IoAllocateMdl(baseAddress, (ULONG)size, FALSE, FALSE, NULL);
      if (mdl) {
        __try {
          MmProbeAndLockPages(mdl, UserMode, IoWriteAccess);
          g_HvData.AllocMdl = (PVOID)mdl;
          HV_LOG("AllocWorker: pages locked via MDL (%llu pages)",
                 (UINT64)(size / 0x1000));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
          HV_LOG_ERROR("AllocWorker: MmProbeAndLockPages failed");
          IoFreeMdl(mdl);
          /* Continue without locking — pages are pre-faulted but unlocked */
        }
      }
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(targetProcess);

    if (NT_SUCCESS(status)) {
      HV_LOG("AllocWorker: allocated at 0x%llX (%llu bytes)",
             (UINT64)(ULONG_PTR)baseAddress, (UINT64)size);
      g_HvData.AllocResult = (UINT64)(ULONG_PTR)baseAddress;
      InterlockedExchange(&g_HvData.AllocStatus, 1); /* 1 = success */
    } else {
      HV_LOG_ERROR("AllocWorker: ZwAllocateVirtualMemory failed (0x%08X)",
                   status);
      g_HvData.AllocResult = 0;
      InterlockedExchange(&g_HvData.AllocStatus, -1); /* -1 = failed */
    }
  }

  HV_LOG("AllocWorker: thread exiting");
  PsTerminateSystemThread(STATUS_SUCCESS);
}

/* ============================================================================
 *  Init / Shutdown
 * ============================================================================
 */

NTSTATUS HvAllocWorkerInit(VOID) {
  g_HvData.AllocShutdown = FALSE;
  g_HvData.AllocReady = 0;
  g_HvData.AllocResult = 0;
  g_HvData.AllocStatus = 0;

  NTSTATUS status =
      PsCreateSystemThread(&g_HvData.AllocThreadHandle, THREAD_ALL_ACCESS, NULL,
                           NULL, NULL, AllocWorkerThread, NULL);

  if (!NT_SUCCESS(status)) {
    HV_LOG_ERROR("AllocWorkerInit: PsCreateSystemThread failed (0x%08X)",
                 status);
    return status;
  }

  /* Get thread object for cleanup */
  status = ObReferenceObjectByHandle(
      g_HvData.AllocThreadHandle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode,
      &g_HvData.AllocThreadObj, NULL);

  if (!NT_SUCCESS(status)) {
    HV_LOG_ERROR("AllocWorkerInit: ObReferenceObjectByHandle failed (0x%08X)",
                 status);
    InterlockedExchange(&g_HvData.AllocShutdown, TRUE);
    ZwClose(g_HvData.AllocThreadHandle);
    return status;
  }

  HV_LOG("AllocWorkerInit: worker thread created successfully");
  return STATUS_SUCCESS;
}

VOID HvAllocWorkerShutdown(VOID) {
  if (!g_HvData.AllocThreadObj)
    return;

  HV_LOG("AllocWorkerShutdown: signaling worker to exit...");
  InterlockedExchange(&g_HvData.AllocShutdown, TRUE);

  /* Wait for thread to exit (5 second timeout) */
  LARGE_INTEGER timeout;
  timeout.QuadPart = -50000000LL; /* 5 seconds in 100ns units */
  KeWaitForSingleObject(g_HvData.AllocThreadObj, Executive, KernelMode, FALSE,
                        &timeout);

  /* Release any MDL-locked pages to prevent PROCESS_HAS_LOCKED_PAGES BSOD */
  if (g_HvData.AllocMdl) {
    PMDL mdl = (PMDL)g_HvData.AllocMdl;
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    g_HvData.AllocMdl = NULL;
    HV_LOG("AllocWorkerShutdown: MDL unlocked and freed");
  }

  ObDereferenceObject(g_HvData.AllocThreadObj);
  ZwClose(g_HvData.AllocThreadHandle);
  g_HvData.AllocThreadObj = NULL;
  g_HvData.AllocThreadHandle = NULL;

  HV_LOG("AllocWorkerShutdown: complete");
}
