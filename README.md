# ⚡ Windows Malware Techniques DB

> An interactive, always-growing reference tool for security researchers — covering Windows injection, hooking, APC abuse, EDR evasion, and more.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078d7?logo=windows)
![Techniques](https://img.shields.io/badge/Techniques-20%2B-critical)
![GUI](https://img.shields.io/badge/GUI-CustomTkinter-blueviolet)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Actively%20Updated-brightgreen)

---

## What Is This?

A desktop GUI application that acts as a personal reference database for Windows offensive security techniques. Each entry is written to be actually understood — not just listed. You get:

- A clear explanation of **how and why** the technique works
- A numbered **step-by-step breakdown** of the execution flow
- A real **C/C++ code example** with syntax highlighting
- An **interactive simulation** you can run directly in the app
- **Detection methods** and the MITRE ATT&CK reference

Think of it as your offline, interactive version of ATT&CK — but focused on Windows internals depth over breadth.

---

## Techniques Covered

### Process Injection
| # | Technique | Difficulty | MITRE |
|---|-----------|------------|-------|
| 1 | Classic DLL Injection (`CreateRemoteThread`) | Beginner | T1055.001 |
| 2 | Shellcode Injection (`VirtualAllocEx`) | Beginner | T1055 |
| 3 | Process Hollowing | Advanced | T1055.012 |
| 4 | Process Doppelgänging | Expert | T1055.013 |

### Hooking
| # | Technique | Difficulty | MITRE |
|---|-----------|------------|-------|
| 5 | Keylogger via `SetWindowsHookEx` | Intermediate | T1056.001 |
| 6 | IAT Hooking | Intermediate | T1574.012 |

### Thread Manipulation
| # | Technique | Difficulty | MITRE |
|---|-----------|------------|-------|
| 7 | APC Queue Injection — Early Bird | Advanced | T1055.004 |
| 8 | Thread Hijacking | Advanced | T1055.003 |

### Advanced Evasion
| # | Technique | Difficulty | MITRE |
|---|-----------|------------|-------|
| 9  | Reflective DLL Injection | Expert | T1055.001 |
| 10 | Atom Bombing | Expert | T1055 |
| 11 | NTDLL Unhooking | Expert | T1562.001 |
| 12 | Heaven's Gate (WOW64 Escape) | Expert | T1055.012 |
| 13 | Direct Syscalls / Hell's Gate | Expert | T1562.001 |
| 14 | Module Stomping | Expert | T1055.001 |
| 15 | ETW Patching | Intermediate | T1562.006 |
| 16 | AMSI Bypass (`AmsiScanBuffer` patch) | Intermediate | T1562.001 |

### Persistence
| # | Technique | Difficulty | MITRE |
|---|-----------|------------|-------|
| 17 | COM Hijacking | Intermediate | T1546.015 |
| 18 | Registry Run Key Persistence | Beginner | T1547.001 |

### Credential Access
| # | Technique | Difficulty | MITRE |
|---|-----------|------------|-------|
| 19 | LSASS Memory Dumping | Advanced | T1003.001 |

> More techniques are added regularly — contributions and suggestions are welcome.

---

## Features

- **Dark cyberpunk UI** — built with CustomTkinter, looks at home on any security researcher's desktop
- **Live search + category filter** in the sidebar
- **4 tabs per technique**: Overview · Code · Simulate · Detection
- **Syntax-highlighted code viewer** with a one-click copy button
- **Interactive simulations**:
  - Keylogger demo: type in the input box and watch `vkCode` / `scanCode` captured in real time
  - Shellcode injection: calls real `VirtualAlloc` / `VirtualProtect` and shows the allocated address and page permissions (no execution)
  - All other techniques: animated step-by-step walkthroughs with Prev / Next / Auto Play controls

---

## Installation

**Requirements:** Python 3.10+, Windows

```bash
git clone https://github.com/ShiralOren/injection-techniques-db.git
cd injection-techniques-db
pip install -r requirements.txt
python main.py
```

That's it — no build step, no admin rights needed.

---

## Project Structure

```
injection-techniques-db/
├── main.py           # Entry point
├── app.py            # GUI — CustomTkinter layout and tab logic
├── techniques.py     # Technique database (descriptions, code, detection)
├── simulations.py    # Simulation data and live-demo logic
└── requirements.txt
```

---

## Roadmap

Techniques planned for upcoming updates:

- [ ] Ghost Writing (WPM-free shellcode write via ROP)
- [ ] Module Overloading (stomp a DLL that's already expected to be present)
- [ ] Transacted Hollowing
- [ ] Stack Spoofing / Return Address Spoofing
- [ ] Kernel Callback Abuse (PsSetLoadImageNotifyRoutine)
- [ ] DCOM lateral movement
- [ ] SAM / SYSTEM hive offline credential extraction
- [ ] Token impersonation & privilege escalation
- [ ] Kerberoasting / AS-REP Roasting
- [ ] Named pipe impersonation

Have a technique you want added? Open an issue.

---

## Disclaimer

This tool is intended for **educational and defensive security research only**. All simulations are safe demonstrations — no malicious code is executed. Understanding offensive techniques is essential for building effective defenses.

---

## License

MIT — free to use, modify, and share with attribution.
