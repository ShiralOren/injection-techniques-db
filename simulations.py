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
# Step data registry
# ─────────────────────────────────────────────────────────────────────────────

SIMULATION_STEPS = {
    "iat_hooking":          IAT_STEPS,
    "classic_dll_injection": DLL_INJECTION_STEPS,
    "process_hollowing":    HOLLOWING_STEPS,
    "apc_injection":        APC_STEPS,
    "thread_hijacking":     HIJACK_STEPS,
    "reflective_dll":       REFLECTIVE_STEPS,
    "atom_bombing":         ATOM_STEPS,
    "ntdll_unhooking":      UNHOOK_STEPS,
}
