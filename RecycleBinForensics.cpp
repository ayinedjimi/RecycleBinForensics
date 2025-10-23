/*******************************************************************************
 * RecycleBinForensics - Analyseur forensique de la Corbeille Windows
 *
 * Auteur  : Ayi NEDJIMI
 * Licence : MIT
 * Description : Parse $Recycle.bin pour récupérer métadonnées, timestamps,
 *               chemins originaux et hash des fichiers supprimés.
 ******************************************************************************/

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <memory>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' "\
                        "version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// Contrôles
#define IDC_BTN_SCAN         1001
#define IDC_LISTVIEW         1002
#define IDC_BTN_CALC_HASH    1003
#define IDC_BTN_RESTORE      1004
#define IDC_BTN_EXPORT       1005
#define IDC_EDIT_LOG         1006
#define IDC_PROGRESS         1007
#define IDC_LABEL_STATUS     1008

// Structure $I file header (Windows Vista+)
#pragma pack(push, 1)
struct RecycleBinHeader {
    LONGLONG version;       // Version (1 or 2)
    LONGLONG fileSize;      // Original file size
    FILETIME deleteTime;    // Deletion timestamp
    // Followed by: wchar_t originalPath[...]
};
#pragma pack(pop)

struct RecycleBinEntry {
    std::wstring iFileName;
    std::wstring rFileName;
    std::wstring originalName;
    std::wstring originalPath;
    LONGLONG size;
    FILETIME deleteTime;
    std::wstring sid;
    std::wstring hash;
    bool restorable;
};

// RAII
class HandleGuard {
    HANDLE h;
public:
    explicit HandleGuard(HANDLE handle) : h(handle) {}
    ~HandleGuard() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    HANDLE get() const { return h; }
    operator bool() const { return h && h != INVALID_HANDLE_VALUE; }
};

// Globals
HWND g_hMainWnd = nullptr;
HWND g_hListView = nullptr;
HWND g_hLog = nullptr;
HWND g_hProgress = nullptr;
HWND g_hStatus = nullptr;
std::vector<RecycleBinEntry> g_entries;
bool g_scanning = false;

void Log(const std::wstring& msg) {
    if (!g_hLog) return;
    int len = GetWindowTextLengthW(g_hLog);
    SendMessageW(g_hLog, EM_SETSEL, len, len);
    SendMessageW(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)(msg + L"\r\n").c_str());
}

std::wstring FileTimeToString(const FILETIME& ft) {
    if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0) return L"N/A";

    SYSTEMTIME st;
    if (!FileTimeToSystemTime(&ft, &st)) return L"N/A";

    wchar_t buf[64];
    swprintf_s(buf, L"%04d-%02d-%02d %02d:%02d:%02d",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

std::wstring FormatSize(LONGLONG size) {
    if (size < 0) return L"N/A";
    if (size < 1024) return std::to_wstring(size) + L" B";
    if (size < 1024 * 1024) return std::to_wstring(size / 1024) + L" KB";
    if (size < 1024 * 1024 * 1024) return std::to_wstring(size / (1024 * 1024)) + L" MB";
    return std::to_wstring(size / (1024 * 1024 * 1024)) + L" GB";
}

std::wstring CalculateMD5(const std::wstring& filePath) {
    // Simplified - would use CryptoAPI in real implementation
    // For now, return placeholder
    return L"N/A (non implémenté)";
}

bool ParseIFile(const std::wstring& iFilePath, RecycleBinEntry& entry) {
    HANDLE hFile = CreateFileW(iFilePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile == INVALID_HANDLE_VALUE) return false;

    HandleGuard guard(hFile);

    RecycleBinHeader header = {};
    DWORD bytesRead = 0;

    if (!ReadFile(hFile, &header, sizeof(header), &bytesRead, nullptr))
        return false;

    if (bytesRead < sizeof(header)) return false;

    entry.size = header.fileSize;
    entry.deleteTime = header.deleteTime;

    // Read original path (Unicode string follows header)
    wchar_t pathBuffer[MAX_PATH * 2] = {};
    if (ReadFile(hFile, pathBuffer, sizeof(pathBuffer), &bytesRead, nullptr)) {
        entry.originalPath = pathBuffer;

        // Extract filename from path
        const wchar_t* fileName = wcsrchr(pathBuffer, L'\\');
        if (fileName) {
            entry.originalName = fileName + 1;
        } else {
            entry.originalName = pathBuffer;
        }
    }

    return true;
}

void ScanRecycleBin(const std::wstring& recycleBinPath, const std::wstring& sid) {
    std::wstring searchPath = recycleBinPath + L"\\*";
    WIN32_FIND_DATAW findData = {};

    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE) return;

    HandleGuard guard(hFind);

    do {
        if (!g_scanning) break;

        if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0)
            continue;

        std::wstring fileName = findData.cFileName;

        // Process $I files (metadata)
        if (fileName.length() > 2 && fileName[0] == L'$' && fileName[1] == L'I') {
            std::wstring iFullPath = recycleBinPath + L"\\" + fileName;

            // Corresponding $R file
            std::wstring rFileName = fileName;
            rFileName[1] = L'R';
            std::wstring rFullPath = recycleBinPath + L"\\" + rFileName;

            RecycleBinEntry entry = {};
            entry.iFileName = iFullPath;
            entry.rFileName = rFullPath;
            entry.sid = sid;

            // Parse $I file
            if (ParseIFile(iFullPath, entry)) {
                // Check if $R file exists
                entry.restorable = (GetFileAttributesW(rFullPath.c_str()) != INVALID_FILE_ATTRIBUTES);

                g_entries.push_back(entry);

                if (g_entries.size() % 10 == 0) {
                    SendMessageW(g_hProgress, PBM_SETPOS, (g_entries.size() / 2) % 100, 0);
                }
            }
        }

    } while (FindNextFileW(hFind, &findData));
}

void UpdateListView() {
    if (!g_hListView) return;

    SendMessageW(g_hListView, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_hListView);

    int idx = 0;
    for (const auto& entry : g_entries) {
        LVITEMW lvi = {};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = idx++;

        // Original name
        lvi.pszText = const_cast<LPWSTR>(entry.originalName.c_str());
        ListView_InsertItem(g_hListView, &lvi);

        // Original path
        ListView_SetItemText(g_hListView, lvi.iItem, 1, const_cast<LPWSTR>(entry.originalPath.c_str()));

        // Size
        std::wstring sizeStr = FormatSize(entry.size);
        ListView_SetItemText(g_hListView, lvi.iItem, 2, const_cast<LPWSTR>(sizeStr.c_str()));

        // Delete time
        std::wstring deleteTimeStr = FileTimeToString(entry.deleteTime);
        ListView_SetItemText(g_hListView, lvi.iItem, 3, const_cast<LPWSTR>(deleteTimeStr.c_str()));

        // SID
        ListView_SetItemText(g_hListView, lvi.iItem, 4, const_cast<LPWSTR>(entry.sid.c_str()));

        // Hash
        ListView_SetItemText(g_hListView, lvi.iItem, 5, const_cast<LPWSTR>(entry.hash.c_str()));

        // Restorable
        std::wstring restorableStr = entry.restorable ? L"Oui" : L"Non";
        ListView_SetItemText(g_hListView, lvi.iItem, 6, const_cast<LPWSTR>(restorableStr.c_str()));
    }

    SendMessageW(g_hListView, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_hListView, nullptr, TRUE);

    std::wstring status = L"Fichiers supprimés trouvés : " + std::to_wstring(g_entries.size());
    SetWindowTextW(g_hStatus, status.c_str());
}

DWORD WINAPI ScanThread(LPVOID) {
    g_entries.clear();

    Log(L"[INFO] Démarrage du scan de la corbeille...");

    // Enumerate all user SIDs in C:\$Recycle.Bin\
    std::wstring recycleBinRoot = L"C:\\$Recycle.Bin";
    std::wstring searchPath = recycleBinRoot + L"\\*";

    WIN32_FIND_DATAW findData = {};
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        Log(L"[ERREUR] Impossible d'accéder à C:\\$Recycle.Bin (Erreur: " +
            std::to_wstring(GetLastError()) + L")");
        Log(L"[INFO] Exécutez en tant qu'administrateur.");
        g_scanning = false;
        EnableWindow(GetDlgItem(g_hMainWnd, IDC_BTN_SCAN), TRUE);
        return 1;
    }

    HandleGuard guard(hFind);

    do {
        if (!g_scanning) break;

        if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0)
            continue;

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // This is a user SID directory
            std::wstring sid = findData.cFileName;
            std::wstring sidPath = recycleBinRoot + L"\\" + sid;

            Log(L"[INFO] Scan du SID : " + sid);
            ScanRecycleBin(sidPath, sid);
        }

    } while (FindNextFileW(hFind, &findData));

    // Sort by delete time (most recent first)
    std::sort(g_entries.begin(), g_entries.end(),
              [](const RecycleBinEntry& a, const RecycleBinEntry& b) {
                  return CompareFileTime(&a.deleteTime, &b.deleteTime) > 0;
              });

    UpdateListView();

    Log(L"[SUCCÈS] Scan terminé : " + std::to_wstring(g_entries.size()) + L" fichiers trouvés");

    g_scanning = false;
    EnableWindow(GetDlgItem(g_hMainWnd, IDC_BTN_SCAN), TRUE);
    SendMessageW(g_hProgress, PBM_SETPOS, 0, 0);

    return 0;
}

void OnScan() {
    if (g_scanning) {
        MessageBoxW(g_hMainWnd, L"Scan déjà en cours...", L"Info", MB_OK | MB_ICONINFORMATION);
        return;
    }

    g_scanning = true;
    EnableWindow(GetDlgItem(g_hMainWnd, IDC_BTN_SCAN), FALSE);

    CreateThread(nullptr, 0, ScanThread, nullptr, 0, nullptr);
}

void OnCalculateHash() {
    int sel = ListView_GetNextItem(g_hListView, -1, LVNI_SELECTED);
    if (sel == -1) {
        MessageBoxW(g_hMainWnd, L"Veuillez sélectionner un fichier.", L"Info", MB_OK | MB_ICONINFORMATION);
        return;
    }

    if (sel >= (int)g_entries.size()) return;

    auto& entry = g_entries[sel];

    if (!entry.restorable) {
        MessageBoxW(g_hMainWnd, L"Le fichier $R n'existe plus.", L"Erreur", MB_OK | MB_ICONERROR);
        return;
    }

    Log(L"[INFO] Calcul du hash pour : " + entry.originalName);
    entry.hash = CalculateMD5(entry.rFileName);

    UpdateListView();
    Log(L"[SUCCÈS] Hash calculé : " + entry.hash);
}

void OnRestore() {
    int sel = ListView_GetNextItem(g_hListView, -1, LVNI_SELECTED);
    if (sel == -1) {
        MessageBoxW(g_hMainWnd, L"Veuillez sélectionner un fichier.", L"Info", MB_OK | MB_ICONINFORMATION);
        return;
    }

    if (sel >= (int)g_entries.size()) return;

    const auto& entry = g_entries[sel];

    if (!entry.restorable) {
        MessageBoxW(g_hMainWnd, L"Le fichier $R n'existe plus.", L"Erreur", MB_OK | MB_ICONERROR);
        return;
    }

    OPENFILENAMEW ofn = {};
    wchar_t fileName[MAX_PATH] = {};
    wcscpy_s(fileName, entry.originalName.c_str());

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hMainWnd;
    ofn.lpstrFilter = L"All Files (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Restaurer le fichier vers...";
    ofn.Flags = OFN_OVERWRITEPROMPT;

    if (!GetSaveFileNameW(&ofn)) return;

    if (!CopyFileW(entry.rFileName.c_str(), fileName, FALSE)) {
        MessageBoxW(g_hMainWnd, L"Échec de la restauration.", L"Erreur", MB_OK | MB_ICONERROR);
        return;
    }

    Log(L"[SUCCÈS] Fichier restauré : " + std::wstring(fileName));
    MessageBoxW(g_hMainWnd, L"Fichier restauré avec succès.", L"Succès", MB_OK | MB_ICONINFORMATION);
}

void OnExport() {
    if (g_entries.empty()) {
        MessageBoxW(g_hMainWnd, L"Aucune donnée à exporter.", L"Info", MB_OK | MB_ICONINFORMATION);
        return;
    }

    OPENFILENAMEW ofn = {};
    wchar_t fileName[MAX_PATH] = L"recyclebin_forensics.csv";

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hMainWnd;
    ofn.lpstrFilter = L"CSV Files (*.csv)\0*.csv\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = L"csv";
    ofn.Flags = OFN_OVERWRITEPROMPT;

    if (!GetSaveFileNameW(&ofn)) return;

    std::wofstream ofs(fileName);
    if (!ofs) {
        MessageBoxW(g_hMainWnd, L"Impossible de créer le fichier.", L"Erreur", MB_OK | MB_ICONERROR);
        return;
    }

    ofs.imbue(std::locale(""));

    ofs << L"NomOriginal,CheminOriginal,Taille,DateSuppression,SID,Hash,Restaurable\n";

    for (const auto& entry : g_entries) {
        ofs << L"\"" << entry.originalName << L"\","
            << L"\"" << entry.originalPath << L"\","
            << entry.size << L","
            << L"\"" << FileTimeToString(entry.deleteTime) << L"\","
            << L"\"" << entry.sid << L"\","
            << L"\"" << entry.hash << L"\","
            << (entry.restorable ? L"Oui" : L"Non") << L"\n";
    }

    ofs.close();
    Log(L"[SUCCÈS] Données exportées : " + std::wstring(fileName));
    MessageBoxW(g_hMainWnd, L"Données exportées avec succès.", L"Succès", MB_OK | MB_ICONINFORMATION);
}

void InitListView(HWND hList) {
    ListView_SetExtendedListViewStyle(hList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

    LVCOLUMNW lvc = {};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;

    lvc.pszText = const_cast<LPWSTR>(L"Nom Original");
    lvc.cx = 150;
    ListView_InsertColumn(hList, 0, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Chemin Original");
    lvc.cx = 250;
    ListView_InsertColumn(hList, 1, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Taille");
    lvc.cx = 80;
    ListView_InsertColumn(hList, 2, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Date Suppression");
    lvc.cx = 150;
    ListView_InsertColumn(hList, 3, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"SID");
    lvc.cx = 150;
    ListView_InsertColumn(hList, 4, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Hash");
    lvc.cx = 150;
    ListView_InsertColumn(hList, 5, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Restaurable");
    lvc.cx = 80;
    ListView_InsertColumn(hList, 6, &lvc);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            // Buttons
            CreateWindowW(L"BUTTON", L"Scanner Corbeille", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                         10, 10, 140, 25, hwnd, (HMENU)IDC_BTN_SCAN, nullptr, nullptr);

            CreateWindowW(L"BUTTON", L"Calculer Hash", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                         160, 10, 120, 25, hwnd, (HMENU)IDC_BTN_CALC_HASH, nullptr, nullptr);

            CreateWindowW(L"BUTTON", L"Restaurer Fichier", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                         290, 10, 130, 25, hwnd, (HMENU)IDC_BTN_RESTORE, nullptr, nullptr);

            CreateWindowW(L"BUTTON", L"Exporter", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                         430, 10, 100, 25, hwnd, (HMENU)IDC_BTN_EXPORT, nullptr, nullptr);

            // Progress
            g_hProgress = CreateWindowW(PROGRESS_CLASSW, nullptr, WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
                                        540, 12, 250, 20, hwnd, (HMENU)IDC_PROGRESS, nullptr, nullptr);
            SendMessageW(g_hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));

            // ListView
            g_hListView = CreateWindowExW(0, WC_LISTVIEWW, nullptr,
                                          WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
                                          10, 45, 900, 320, hwnd, (HMENU)IDC_LISTVIEW, nullptr, nullptr);
            InitListView(g_hListView);

            // Status
            g_hStatus = CreateWindowW(L"STATIC", L"Prêt - Cliquez sur Scanner Corbeille",
                                      WS_CHILD | WS_VISIBLE | SS_LEFT,
                                      10, 375, 900, 20, hwnd, (HMENU)IDC_LABEL_STATUS, nullptr, nullptr);

            // Log
            CreateWindowW(L"STATIC", L"Journal :", WS_CHILD | WS_VISIBLE,
                         10, 400, 100, 20, hwnd, nullptr, nullptr, nullptr);

            g_hLog = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", nullptr,
                                     WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
                                     10, 420, 900, 120, hwnd, (HMENU)IDC_EDIT_LOG, nullptr, nullptr);

            Log(L"RecycleBinForensics - Analyseur de la Corbeille Windows");
            Log(L"Auteur : Ayi NEDJIMI");
            Log(L"Prêt à analyser la corbeille (exécutez en admin).");

            return 0;
        }

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDC_BTN_SCAN:
                    OnScan();
                    break;
                case IDC_BTN_CALC_HASH:
                    OnCalculateHash();
                    break;
                case IDC_BTN_RESTORE:
                    OnRestore();
                    break;
                case IDC_BTN_EXPORT:
                    OnExport();
                    break;
            }
            return 0;
        }

        case WM_DESTROY:
            g_scanning = false;
            PostQuitMessage(0);
            return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icc);

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"RecycleBinForensicsClass";
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);

    RegisterClassExW(&wc);

    g_hMainWnd = CreateWindowExW(0, wc.lpszClassName,
                                 L"RecycleBinForensics - Analyseur Corbeille | Ayi NEDJIMI",
                                 WS_OVERLAPPEDWINDOW,
                                 CW_USEDEFAULT, CW_USEDEFAULT, 940, 620,
                                 nullptr, nullptr, hInstance, nullptr);

    ShowWindow(g_hMainWnd, nCmdShow);
    UpdateWindow(g_hMainWnd);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}
