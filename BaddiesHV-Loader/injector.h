/*
 * injector.h — HV-assisted PE manual mapper interface.
 *
 * Provides InjectOverlayDll() which:
 *   1. Reads overlay DLL from disk
 *   2. Allocates RWX memory in target via HV_CMD_ALLOC
 *   3. Maps PE sections + relocations via HV_CMD_WRITE
 *   4. Resolves imports via HV_CMD_FIND_MODULE + HV_CMD_READ
 *   5. Writes shellcode + hooks Present to trigger DllMain
 *   6. Erases PE header post-injection
 *
 * On failure, rolls back all written memory (zeros out).
 */

#pragma once
#include <cstdint>
#include <string>

/* Main injection entry point */
bool InjectOverlayDll(uint32_t targetPid, const std::wstring &dllPath);

/* DJB2 hash helper — must match driver-side hash */
uint64_t Djb2HashWide(const wchar_t *str);
