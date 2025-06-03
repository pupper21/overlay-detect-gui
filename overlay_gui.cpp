
#include <windows.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <sstream>

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
std::wstring ToLower(const std::wstring& s);
std::wstring GetProcessPath(DWORD pid);
bool IsSuspiciousOverlay(HWND hwnd);
std::wstring OverlayScanResults();

#define ID_SCAN 1

HWND hEdit;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
    const wchar_t CLASS_NAME[] = L"OverlayDetectApp";
    WNDCLASS wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(
        0, CLASS_NAME, L"OverlayDetect GUI (64-bit)",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 600, 400,
        NULL, NULL, hInstance, NULL
    );

    if (!hwnd) return 0;

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:
            CreateWindow(L"BUTTON", L"Scan Now",
                         WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                         10, 10, 100, 30,
                         hwnd, (HMENU)ID_SCAN, NULL, NULL);

            hEdit = CreateWindowEx(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                   WS_CHILD | WS_VISIBLE | WS_VSCROLL |
                                   ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
                                   10, 50, 560, 300,
                                   hwnd, NULL, NULL, NULL);
            break;

        case WM_COMMAND:
            if (LOWORD(wParam) == ID_SCAN) {
                std::wstring results = OverlayScanResults();
                SetWindowText(hEdit, results.c_str());
            }
            break;

        case WM_DESTROY:
            PostQuitMessage(0);
            break;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

std::wstring GetWindowTitle(HWND hwnd) {
    wchar_t title[256] = {};
    GetWindowTextW(hwnd, title, 256);
    return std::wstring(title);
}

std::wstring GetProcessPath(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    wchar_t path[MAX_PATH] = {};
    if (hProcess) {
        GetModuleFileNameExW(hProcess, NULL, path, MAX_PATH);
        CloseHandle(hProcess);
    }
    return std::wstring(path);
}

std::wstring ToLower(const std::wstring& s) {
    std::wstring out = s;
    for (auto& c : out) c = towlower(c);
    return out;
}

bool IsSafeApp(const std::wstring& proc) {
    std::vector<std::wstring> safe = {
        L"obs", L"discord", L"steam", L"xbox", L"wireless", L"nvidia",
        L"radeon", L"amd", L"rtx", L"gamebar", L"corsair", L"razer"
    };
    for (const auto& word : safe) {
        if (proc.find(word) != std::wstring::npos) return true;
    }
    return false;
}

bool IsSuspiciousOverlay(HWND hwnd) {
    if (!IsWindowVisible(hwnd)) return false;
    LONG exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);
    if ((exStyle & WS_EX_LAYERED) && (exStyle & WS_EX_TOPMOST)) {
        BYTE alpha = 255;
        COLORREF colorKey = 0;
        DWORD flags = 0;
        if (GetLayeredWindowAttributes(hwnd, &colorKey, &alpha, &flags) && alpha < 50) {
            DWORD pid = 0;
            GetWindowThreadProcessId(hwnd, &pid);
            std::wstring path = ToLower(GetProcessPath(pid));
            return !IsSafeApp(path);
        }
    }
    return false;
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    std::wstringstream* output = reinterpret_cast<std::wstringstream*>(lParam);
    if (IsSuspiciousOverlay(hwnd)) {
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        *output << L"[!] Suspicious Overlay Detected:
";
        *output << L"    HWND: 0x" << hwnd << L"
";
        *output << L"    Title: " << GetWindowTitle(hwnd) << L"
";
        *output << L"    PID: " << pid << L"
";
        *output << L"    Process Path: " << GetProcessPath(pid) << L"

";
    }
    return TRUE;
}

std::wstring OverlayScanResults() {
    std::wstringstream output;
    EnumWindows(EnumWindowsProc, (LPARAM)&output);
    std::wstring result = output.str();
    return result.empty() ? L"No suspicious overlays detected." : result;
}
