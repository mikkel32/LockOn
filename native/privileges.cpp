#include <windows.h>
#include <vector>
#include <string>

extern "C" {

bool IsSystem() {
    wchar_t buf[256];
    DWORD len = GetEnvironmentVariableW(L"USERNAME", buf, 256);
    if (len == 0 || len >= 256) {
        len = 256;
        if (!GetUserNameW(buf, &len))
            return false;
    }
    return _wcsicmp(buf, L"SYSTEM") == 0;
}

bool AdjustProcessPrivileges(const std::vector<std::wstring>& privilegeNames)
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    for (const auto& name : privilegeNames) {
        LUID luid;
        if (LookupPrivilegeValueW(NULL, name.c_str(), &luid)) {
            TOKEN_PRIVILEGES tp = {};
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
    }

    CloseHandle(hToken);
    return GetLastError() == ERROR_SUCCESS;
}

bool EnableImpersonation()
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &hToken))
        return false;

    HANDLE hDupToken = NULL;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hDupToken)) {
        CloseHandle(hToken);
        return false;
    }
    BOOL ok = ImpersonateLoggedOnUser(hDupToken);
    CloseHandle(hDupToken);
    CloseHandle(hToken);
    return ok;
}

bool ElevatePrivilegesAndImpersonate()
{
    std::vector<std::wstring> privs = {
        SE_DEBUG_NAME, SE_IMPERSONATE_NAME, SE_ASSIGNPRIMARYTOKEN_NAME,
        SE_INCREASE_QUOTA_NAME, SE_TCB_NAME
    };
    AdjustProcessPrivileges(privs);
    if (!IsSystem())
        return true;
    return EnableImpersonation();
}

DWORD GetCurrentSessionId()
{
    DWORD dwSessionId = -1;
    ProcessIdToSessionId(GetCurrentProcessId(), &dwSessionId);
    return dwSessionId;
}

bool HasPrivilege(const std::wstring& privName)
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return false;

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hToken);
        return false;
    }
    std::vector<BYTE> buffer(dwSize);
    if (!GetTokenInformation(hToken, TokenPrivileges, buffer.data(), dwSize, &dwSize)) {
        CloseHandle(hToken);
        return false;
    }
    PTOKEN_PRIVILEGES privs = (PTOKEN_PRIVILEGES)buffer.data();

    LUID luid;
    LookupPrivilegeValueW(NULL, privName.c_str(), &luid);

    for (DWORD i = 0; i < privs->PrivilegeCount; ++i) {
        if (privs->Privileges[i].Luid.LowPart == luid.LowPart && privs->Privileges[i].Luid.HighPart == luid.HighPart) {
            CloseHandle(hToken);
            return (privs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
        }
    }
    CloseHandle(hToken);
    return false;
}

}

// Usage Example:
std::vector<std::wstring> allPrivs = {
    SE_DEBUG_NAME, SE_SHUTDOWN_NAME, SE_TCB_NAME, SE_ASSIGNPRIMARYTOKEN_NAME,
    SE_TAKE_OWNERSHIP_NAME, SE_LOAD_DRIVER_NAME, SE_SYSTEMTIME_NAME,
    SE_BACKUP_NAME, SE_RESTORE_NAME, SE_INCREASE_QUOTA_NAME,
    SE_SECURITY_NAME, SE_SYSTEM_ENVIRONMENT_NAME, SE_CHANGE_NOTIFY_NAME,
    SE_REMOTE_SHUTDOWN_NAME, SE_UNDOCK_NAME, SE_SYNC_AGENT_NAME,
    SE_ENABLE_DELEGATION_NAME, SE_MANAGE_VOLUME_NAME, SE_IMPERSONATE_NAME,
    SE_CREATE_GLOBAL_NAME, SE_AUDIT_NAME, SE_SYSTEM_PROFILE_NAME
};
// AdjustProcessPrivileges(allPrivs);
