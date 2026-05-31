# ⚡ Windows Malware Techniques DB

> An interactive, always-growing reference tool for security researchers — covering Windows injection, hooking, APC abuse, EDR evasion, and more.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078d7?logo=windows)
![Techniques](https://img.shields.io/badge/Techniques-10%2B-critical)
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

| # | Technique | Category | Difficulty | MITRE |
|---|-----------|----------|------------|-------|
| 1 | Keylogger via `SetWindowsHookEx` | Hooking | Intermediate | T1056.001 |
| 2 | IAT Hooking | Hooking | Intermediate | T1574.012 |
| 3 | Classic DLL Injection (`CreateRemoteThread`) | Process Injection | Beginner | T1055.001 |
| 4 | Process Hollowing | Process Injection | Advanced | T1055.012 |
| 5 | Shellcode Injection (`VirtualAllocEx`) | Process Injection | Beginner | T1055 |
| 6 | APC Queue Injection — Early Bird | Thread Manipulation | Advanced | T1055.004 |
| 7 | Thread Hijacking | Thread Manipulation | Advanced | T1055.003 |
| 8 | Reflective DLL Injection | Advanced Evasion | Expert | T1055.001 |
| 9 | Atom Bombing | Advanced Evasion | Expert | T1055 |
| 10 | NTDLL Unhooking | Advanced Evasion | Expert | T1562.001 |

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

- [ ] Process Doppelgänging
- [ ] Heaven's Gate (32→64 bit transition abuse)
- [ ] Direct Syscalls / Hell's Gate
- [ ] Module Stomping
- [ ] Ghost Writing
- [ ] ETW Patching
- [ ] AMSI Bypass techniques
- [ ] COM hijacking
- [ ] Registry / scheduled task persistence
- [ ] Credential access (LSASS dumping methods)

Have a technique you want added? Open an issue.

---

## Disclaimer

This tool is intended for **educational and defensive security research only**. All simulations are safe demonstrations — no malicious code is executed. Understanding offensive techniques is essential for building effective defenses.

---

## License

MIT — free to use, modify, and share with attribution.
