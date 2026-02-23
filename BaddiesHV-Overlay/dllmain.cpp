/*
 * dllmain.cpp — BaddiesHV Internal DX11 Overlay
 *
 * Hooks IDXGISwapChain::Present via inline code hook (14-byte jmp [rip+0]).
 * Renders ImGui overlay on each frame.
 *
 * Controls:
 *   INSERT — toggle menu visibility
 *   END    — unhook and unload DLL
 */

#include <Windows.h>
#include <atomic>
#include <cstdio>
#include <d3d11.h>
#include <dxgi.h>

#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd,
                                                             UINT msg,
                                                             WPARAM wParam,
                                                             LPARAM lParam);

/* ============================================================================
 *  Inline Hook Engine — 14-byte absolute jmp [rip+0]
 * ============================================================================
 *
 * Overwrites the function prologue with:
 *   FF 25 00 00 00 00   jmp [rip+0]
 *   <8-byte address>    target
 *
 * Original bytes are saved to a trampoline that re-executes them, then
 * jumps back to original+14 to continue the function.
 */

#pragma pack(push, 1)
struct AbsJmp {
  BYTE opcode[6] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00}; // jmp [rip+0]
  void *target = nullptr;
};
#pragma pack(pop)
static_assert(sizeof(AbsJmp) == 14, "AbsJmp must be exactly 14 bytes");

struct InlineHook {
  void *targetFunc = nullptr; // function we hooked
  BYTE savedBytes[14] = {};   // original prologue
  void *trampoline = nullptr; // executable trampoline for calling original

  bool Install(void *func, void *detour) {
    targetFunc = func;

    // Save original bytes
    memcpy(savedBytes, func, 14);

    // Build trampoline: saved bytes + jmp back to original+14
    trampoline = VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
    if (!trampoline)
      return false;

    memcpy(trampoline, savedBytes, 14);
    auto *jmpBack =
        reinterpret_cast<AbsJmp *>(static_cast<BYTE *>(trampoline) + 14);
    memcpy(jmpBack->opcode, "\xFF\x25\x00\x00\x00\x00", 6);
    jmpBack->target = static_cast<BYTE *>(func) + 14;

    // Patch original function with jmp to detour
    DWORD oldProt;
    VirtualProtect(func, 14, PAGE_EXECUTE_READWRITE, &oldProt);

    auto *patch = reinterpret_cast<AbsJmp *>(func);
    memcpy(patch->opcode, "\xFF\x25\x00\x00\x00\x00", 6);
    patch->target = detour;

    VirtualProtect(func, 14, oldProt, &oldProt);
    return true;
  }

  void Remove() {
    if (!targetFunc)
      return;
    DWORD oldProt;
    VirtualProtect(targetFunc, 14, PAGE_EXECUTE_READWRITE, &oldProt);
    memcpy(targetFunc, savedBytes, 14);
    VirtualProtect(targetFunc, 14, oldProt, &oldProt);

    if (trampoline) {
      VirtualFree(trampoline, 0, MEM_RELEASE);
      trampoline = nullptr;
    }
    targetFunc = nullptr;
  }
};

/* ============================================================================
 *  Globals
 * ============================================================================
 */

static HMODULE g_Module = nullptr;
static ID3D11Device *g_Device = nullptr;
static ID3D11DeviceContext *g_Context = nullptr;
static ID3D11RenderTargetView *g_RTV = nullptr;
static IDXGISwapChain *g_SwapChain = nullptr;
static HWND g_GameWindow = nullptr;
static WNDPROC g_OrigWndProc = nullptr;
static bool g_Initialized = false;
static bool g_ShowMenu = true;
static std::atomic<bool> g_NeedsReinit = false;
static std::atomic<bool> g_ShouldUnload = false;

static InlineHook g_PresentHook;
static InlineHook g_ResizeHook;

using PresentFn = HRESULT(STDMETHODCALLTYPE *)(IDXGISwapChain *, UINT, UINT);
using ResizeBuffersFn = HRESULT(STDMETHODCALLTYPE *)(IDXGISwapChain *, UINT,
                                                     UINT, UINT, DXGI_FORMAT,
                                                     UINT);

/* ============================================================================
 *  ImGui Theme — Dark + Cyan accents
 * ============================================================================
 */

static void ApplyTheme() {
  ImGuiStyle &s = ImGui::GetStyle();
  ImVec4 *c = s.Colors;

  s.WindowRounding = 8.0f;
  s.FrameRounding = 4.0f;
  s.GrabRounding = 4.0f;
  s.PopupRounding = 4.0f;
  s.ScrollbarRounding = 4.0f;
  s.WindowBorderSize = 1.0f;
  s.FrameBorderSize = 0.0f;
  s.WindowPadding = ImVec2(12, 12);
  s.FramePadding = ImVec2(8, 4);
  s.ItemSpacing = ImVec2(8, 6);

  c[ImGuiCol_WindowBg] = ImVec4(0.08f, 0.08f, 0.10f, 0.94f);
  c[ImGuiCol_TitleBg] = ImVec4(0.06f, 0.06f, 0.08f, 1.00f);
  c[ImGuiCol_TitleBgActive] = ImVec4(0.00f, 0.40f, 0.50f, 1.00f);
  c[ImGuiCol_Border] = ImVec4(0.00f, 0.60f, 0.70f, 0.30f);
  c[ImGuiCol_FrameBg] = ImVec4(0.12f, 0.12f, 0.15f, 1.00f);
  c[ImGuiCol_FrameBgHovered] = ImVec4(0.00f, 0.50f, 0.60f, 0.40f);
  c[ImGuiCol_FrameBgActive] = ImVec4(0.00f, 0.55f, 0.65f, 0.67f);
  c[ImGuiCol_CheckMark] = ImVec4(0.00f, 0.85f, 0.95f, 1.00f);
  c[ImGuiCol_SliderGrab] = ImVec4(0.00f, 0.70f, 0.80f, 1.00f);
  c[ImGuiCol_SliderGrabActive] = ImVec4(0.00f, 0.85f, 0.95f, 1.00f);
  c[ImGuiCol_Button] = ImVec4(0.00f, 0.45f, 0.55f, 0.60f);
  c[ImGuiCol_ButtonHovered] = ImVec4(0.00f, 0.55f, 0.65f, 0.80f);
  c[ImGuiCol_ButtonActive] = ImVec4(0.00f, 0.65f, 0.75f, 1.00f);
  c[ImGuiCol_Header] = ImVec4(0.00f, 0.50f, 0.60f, 0.31f);
  c[ImGuiCol_HeaderHovered] = ImVec4(0.00f, 0.55f, 0.65f, 0.80f);
  c[ImGuiCol_HeaderActive] = ImVec4(0.00f, 0.60f, 0.70f, 1.00f);
  c[ImGuiCol_Tab] = ImVec4(0.00f, 0.35f, 0.45f, 0.86f);
  c[ImGuiCol_TabHovered] = ImVec4(0.00f, 0.55f, 0.65f, 0.80f);
  c[ImGuiCol_TabActive] = ImVec4(0.00f, 0.50f, 0.60f, 1.00f);
  c[ImGuiCol_Text] = ImVec4(0.90f, 0.92f, 0.94f, 1.00f);
  c[ImGuiCol_TextDisabled] = ImVec4(0.45f, 0.47f, 0.50f, 1.00f);
  c[ImGuiCol_ScrollbarBg] = ImVec4(0.06f, 0.06f, 0.08f, 0.53f);
  c[ImGuiCol_ScrollbarGrab] = ImVec4(0.20f, 0.22f, 0.25f, 1.00f);
}

/* ============================================================================
 *  Release / Create Render Target
 * ============================================================================
 */

static void ReleaseRenderTarget() {
  if (g_RTV) {
    g_RTV->Release();
    g_RTV = nullptr;
  }
}

static bool CreateRenderTarget() {
  ID3D11Texture2D *backBuffer = nullptr;
  if (FAILED(g_SwapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer))))
    return false;
  HRESULT hr = g_Device->CreateRenderTargetView(backBuffer, nullptr, &g_RTV);
  backBuffer->Release();
  return SUCCEEDED(hr);
}

/* ============================================================================
 *  WndProc Hook
 * ============================================================================
 */

static LRESULT CALLBACK HookedWndProc(HWND hWnd, UINT msg, WPARAM wParam,
                                      LPARAM lParam) {
  /* Toggle menu */
  if (msg == WM_KEYDOWN && wParam == VK_INSERT) {
    g_ShowMenu = !g_ShowMenu;
    return 0;
  }
  /* Unload */
  if (msg == WM_KEYDOWN && wParam == VK_END) {
    g_ShouldUnload = true;
    return 0;
  }
  /* ImGui input */
  if (g_ShowMenu && ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
    return 0;

  return CallWindowProcW(g_OrigWndProc, hWnd, msg, wParam, lParam);
}

/* ============================================================================
 *  ImGui Init (called lazily on first Present)
 * ============================================================================
 */

static bool InitImGui(IDXGISwapChain *pSwapChain) {
  g_SwapChain = pSwapChain;

  if (FAILED(pSwapChain->GetDevice(IID_PPV_ARGS(&g_Device))))
    return false;
  g_Device->GetImmediateContext(&g_Context);

  DXGI_SWAP_CHAIN_DESC desc;
  pSwapChain->GetDesc(&desc);
  g_GameWindow = desc.OutputWindow;

  if (!CreateRenderTarget())
    return false;

  /* Hook WndProc */
  g_OrigWndProc = reinterpret_cast<WNDPROC>(SetWindowLongPtrW(
      g_GameWindow, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(HookedWndProc)));

  /* ImGui setup */
  ImGui::CreateContext();
  ImGui_ImplWin32_Init(g_GameWindow);
  ImGui_ImplDX11_Init(g_Device, g_Context);
  ApplyTheme();

  g_Initialized = true;
  return true;
}

/* ============================================================================
 *  Cleanup
 * ============================================================================
 */

static void Cleanup() {
  if (g_Initialized) {
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    g_Initialized = false;
  }

  ReleaseRenderTarget();

  /* Restore WndProc */
  if (g_OrigWndProc && g_GameWindow) {
    SetWindowLongPtrW(g_GameWindow, GWLP_WNDPROC,
                      reinterpret_cast<LONG_PTR>(g_OrigWndProc));
    g_OrigWndProc = nullptr;
  }

  /* Remove hooks */
  g_PresentHook.Remove();
  g_ResizeHook.Remove();

  /* Release D3D refs */
  if (g_Context) {
    g_Context->Release();
    g_Context = nullptr;
  }
  if (g_Device) {
    g_Device->Release();
    g_Device = nullptr;
  }
}

/* ============================================================================
 *  Hooked Present
 * ============================================================================
 */

static HRESULT STDMETHODCALLTYPE HookedPresent(IDXGISwapChain *pSwapChain,
                                               UINT SyncInterval, UINT Flags) {
  /* Lazy init on first call */
  if (!g_Initialized) {
    if (!InitImGui(pSwapChain)) {
      /* Init failed — call original and don't retry every frame */
      auto original = reinterpret_cast<PresentFn>(g_PresentHook.trampoline);
      return original(pSwapChain, SyncInterval, Flags);
    }
  }

  /* Reinit after ResizeBuffers */
  if (g_NeedsReinit.exchange(false)) {
    CreateRenderTarget();
  }

  /* Render ImGui */
  ImGui_ImplDX11_NewFrame();
  ImGui_ImplWin32_NewFrame();
  ImGui::NewFrame();

  if (g_ShowMenu) {
    ImGui::SetNextWindowSize(ImVec2(380, 260), ImGuiCond_FirstUseEver);
    ImGui::Begin("BaddiesHV Overlay", &g_ShowMenu, ImGuiWindowFlags_NoCollapse);
    ImGui::Text("Status: Active");
    ImGui::Separator();

    static bool feature1 = false;
    static bool feature2 = false;
    static float slider1 = 1.0f;

    ImGui::Checkbox("Feature A", &feature1);
    ImGui::Checkbox("Feature B", &feature2);
    ImGui::SliderFloat("Value", &slider1, 0.0f, 10.0f);
    ImGui::Separator();

    ImGui::TextDisabled("INSERT = toggle | END = unload");
    ImGui::End();
  }

  ImGui::Render();

  g_Context->OMSetRenderTargets(1, &g_RTV, nullptr);
  ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

  /* Call original Present */
  auto original = reinterpret_cast<PresentFn>(g_PresentHook.trampoline);
  return original(pSwapChain, SyncInterval, Flags);
}

/* ============================================================================
 *  Hooked ResizeBuffers
 * ============================================================================
 */

static HRESULT STDMETHODCALLTYPE HookedResizeBuffers(IDXGISwapChain *pSwapChain,
                                                     UINT BufferCount,
                                                     UINT Width, UINT Height,
                                                     DXGI_FORMAT Format,
                                                     UINT Flags) {
  /* Must release ALL references before ResizeBuffers */
  ReleaseRenderTarget();
  if (g_Initialized) {
    ImGui_ImplDX11_InvalidateDeviceObjects();
  }

  auto original = reinterpret_cast<ResizeBuffersFn>(g_ResizeHook.trampoline);
  HRESULT hr = original(pSwapChain, BufferCount, Width, Height, Format, Flags);

  /* Signal reinit on next Present */
  if (SUCCEEDED(hr)) {
    g_NeedsReinit = true;
  }
  return hr;
}

/* ============================================================================
 *  SwapChain Discovery — Dummy device approach (safe inside game process)
 * ============================================================================
 */

static void *GetSwapChainVTableEntry(UINT index) {
  /* Create a temporary hidden window for the dummy swapchain */
  WNDCLASSEXW wc = {sizeof(WNDCLASSEXW),
                    CS_CLASSDC,
                    DefWindowProcW,
                    0,
                    0,
                    GetModuleHandleW(nullptr),
                    nullptr,
                    nullptr,
                    nullptr,
                    nullptr,
                    L"BHV_Dummy",
                    nullptr};
  RegisterClassExW(&wc);
  HWND hWnd =
      CreateWindowExW(0, wc.lpszClassName, L"", WS_OVERLAPPED, 0, 0, 100, 100,
                      nullptr, nullptr, wc.hInstance, nullptr);

  DXGI_SWAP_CHAIN_DESC desc = {};
  desc.BufferCount = 1;
  desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
  desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
  desc.OutputWindow = hWnd;
  desc.SampleDesc.Count = 1;
  desc.Windowed = TRUE;
  desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

  IDXGISwapChain *pSwapChain = nullptr;
  ID3D11Device *pDevice = nullptr;
  D3D_FEATURE_LEVEL fl;

  HRESULT hr = D3D11CreateDeviceAndSwapChain(
      nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, nullptr, 0,
      D3D11_SDK_VERSION, &desc, &pSwapChain, &pDevice, &fl, nullptr);

  void *result = nullptr;
  if (SUCCEEDED(hr) && pSwapChain) {
    /* Read vtable pointer array */
    void **vtable = *reinterpret_cast<void ***>(pSwapChain);
    result = vtable[index];
    pSwapChain->Release();
  }
  if (pDevice)
    pDevice->Release();

  DestroyWindow(hWnd);
  UnregisterClassW(wc.lpszClassName, wc.hInstance);
  return result;
}

/* ============================================================================
 *  Init Thread — spawned from DllMain, does all heavy lifting
 * ============================================================================
 */

static DWORD WINAPI InitThread(LPVOID lpParam) {
  /* Give the game a moment to finish initializing */
  Sleep(2000);

  /* Get Present (index 8) and ResizeBuffers (index 13) addresses */
  void *pPresent = GetSwapChainVTableEntry(8);
  void *pResize = GetSwapChainVTableEntry(13);

  if (!pPresent || !pResize) {
    FreeLibraryAndExitThread(g_Module, 1);
    return 1;
  }

  /* Install hooks */
  if (!g_PresentHook.Install(pPresent, &HookedPresent)) {
    FreeLibraryAndExitThread(g_Module, 1);
    return 1;
  }
  if (!g_ResizeHook.Install(pResize, &HookedResizeBuffers)) {
    g_PresentHook.Remove();
    FreeLibraryAndExitThread(g_Module, 1);
    return 1;
  }

  /* Wait for unload signal */
  while (!g_ShouldUnload) {
    Sleep(100);
  }

  /* Clean shutdown */
  Cleanup();
  Sleep(200); /* Let any in-flight Present calls finish */
  FreeLibraryAndExitThread(g_Module, 0);
  return 0;
}

/* ============================================================================
 *  DllMain — Minimal: just spawn init thread
 * ============================================================================
 */

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID /*reserved*/) {
  if (reason == DLL_PROCESS_ATTACH) {
    g_Module = hModule;
    DisableThreadLibraryCalls(hModule);
    HANDLE hThread = CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
    if (hThread)
      CloseHandle(hThread);
  }
  return TRUE;
}
