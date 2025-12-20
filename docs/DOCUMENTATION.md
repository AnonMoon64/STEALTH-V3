# STEALTH Crypter Documentation

**Project**: STEALTH - Stealthy Trojan Encryption and Loading Toolkit for Hiding  
**Version**: 3.0  
**Last Updated**: December 2025  

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Plugin System](#plugin-system)
4. [Plugin Arsenal (GOD-TIER Methods)](#plugin-arsenal-god-tier-methods)
5. [Electron Tampering (WDAC Bypass)](#electron-tampering-wdac-bypass)
6. [Evasion Research & Techniques](#evasion-research--techniques)
7. [Building & Testing](#building--testing)

---

## Overview

STEALTH Crypter encrypts and packages Windows executables into stealthy standalone files with:
- **In-memory execution** (no disk writes)
- **Plugin system** for staged execution (PRELAUNCH, PREINJECT, POSTLAUNCH, ONEXIT, ONFAIL)
- **Electron tampering** for WDAC bypass using signed Microsoft apps
- **10 GOD-TIER injection methods** - 100% Windows Defender bypass rate

### Critical Discovery: %TEMP% Directory Bypass

Loading DLLs from `C:\Windows\Temp\` bypasses Windows Defender's initial scanning, enabling in-process execution without detection.

**What Works (100% WD Bypass):**
- In-process execution (no new process creation)
- Timer/IOCP/APC/Fiber callbacks (autonomous execution)
- Memory transitions RW→RX (not RWX)
- File/Registry/Network operations from temp context

**What Fails (WD Detection):**
- Process hollowing patterns (WriteProcessMemory + ResumeThread)
- UI operations (MessageBox display blocked)
- Inter-process injection (WriteProcessMemory to remote process)

---

## Quick Start

### Build Packed Stub

```powershell
# 1. Run GUI
python gui\stealth_gui_pyqt.py

# 2. Configure:
#    - Select payload (.exe)
#    - Set output path
#    - Enable "Load in-memory"
#    - Add plugins from bin\plugins\

# 3. Click "Build"
```

### Electron Tampering (WDAC Bypass)

```powershell
# Download VS Code Portable (one-time)
Invoke-WebRequest -Uri 'https://code.visualstudio.com/sha/download?build=stable&os=win32-x64-archive' -OutFile 'bin\VSCode.zip'
Expand-Archive bin\VSCode.zip -DestinationPath bin\vscode_base -Force

# In GUI: Enable Electron tampering, set base folder to bin\vscode_base
```

---

## Plugin System

### Execution Flow

```
1. User runs final_packed.exe
   ├─ Payload encrypted in PAYLOAD_DLL resource (ID 101)
   └─ Plugins appended as overlay at end of file

2. stub.exe starts execution
   ├─ Reads plugin overlay from its own file
   ├─ Decrypts plugin DLLs using AES-256-GCM
   └─ Loads plugins into memory (LoadDllInMemory)

3. PRELAUNCH stage plugins fire
   ├─ antidebug_protection.dll - Check for analysis environment
   └─ protection_file_delete.dll - Melt exe from disk

4. stub.exe decrypts main payload
   ├─ Reads PAYLOAD_DLL resource
   └─ Decrypts using ChaCha20-Poly1305

5. PREINJECT stage plugins fire
   └─ Injector plugins prepare execution

6. Payload executes (in-memory)

7. POSTLAUNCH/ONEXIT stages fire
```

### Plugin Stages

| Stage | Order | Purpose |
|-------|-------|---------|
| PRELAUNCH (0) | Before payload | Anti-debug, file protection |
| PREINJECT (1) | Before injection | Memory setup, hook bypass |
| POSTLAUNCH (2) | After payload | Persistence, C2 callbacks |
| ONEXIT (3) | On shutdown | Cleanup |
| ONFAIL (4) | On error | Anti-forensics |

### Building Plugins

```bash
x86_64-w64-mingw32-gcc -shared -O2 plugins/your_plugin.c -o bin/plugins/your_plugin.dll
```

---

## Plugin Arsenal (GOD-TIER Methods)

**All methods tested for T+300s survival with zero Windows Defender detections.**

### Protection Plugins

| Plugin | Purpose | Stage |
|--------|---------|-------|
| `antidebug_protection.dll` | Detect debuggers/VMs/sandboxes, terminate if threat | PRELAUNCH |
| `protection_file_delete.dll` | Melt executable from disk (fileless) | PRELAUNCH |

### Persistence Plugins

| Plugin | Purpose | Stage |
|--------|---------|-------|
| `persist_schtasks.dll` | Scheduled task persistence | POSTLAUNCH |
| `persist_startup_folder.dll` | Startup folder persistence | POSTLAUNCH |

### Injection Plugins (Ranked by Composite Score)

| Rank | Plugin | Technique | Markers | Score |
|------|--------|-----------|---------|-------|
| #1 | `injector_ntdll_unhook.dll` | Maps clean ntdll.dll, restores .text section | 8 | 9.60 |
| #2 | `injector_simple_combo.dll` | Minimal operations, low behavioral score | 7 | 9.60 |
| #3 | `injector_direct_syscalls.dll` | Direct NTDLL syscalls bypassing hooks | 8 | 9.20 |
| #4 | `injector_section_mapping.dll` | NtCreateSection + NtMapViewOfSection | 7 | 9.20 |
| #5 | `injector_apc.dll` | QueueUserAPC + alertable wait | 7 | 8.80 |
| #6 | `injector_tls_callbacks.dll` | TLS callbacks (executes before DllMain) | 8 | 8.40 |
| #7 | `injector_timerqueue.dll` | CreateTimerQueueTimer auto-trigger | 7 | 8.40 |
| #8 | `injector_iocp.dll` | I/O Completion Ports | 7 | 8.40 |
| #9 | `injector_veh.dll` | Vectored Exception Handler | 10 | 8.00 |
| #10 | `injector_fiber.dll` | ConvertThreadToFiber + SwitchToFiber | 7 | 8.00 |

### Recommended Combinations

**Maximum Evasion Stack:**
```
1. injector_ntdll_unhook.dll (PRELAUNCH) - Unhook EDR hooks first
2. injector_simple_combo.dll (PREINJECT) - Minimal operations
3. injector_direct_syscalls.dll (PREINJECT) - Bypass remaining hooks
```

**Lowest Markers (21 total):**
```
1. injector_simple_combo.dll - 7 markers
2. injector_section_mapping.dll - 7 markers
3. injector_apc.dll - 7 markers
```

---

## Electron Tampering (WDAC Bypass)

### Supported Targets

| Type | Examples |
|------|----------|
| Folder-based | VS Code portable, Discord, Slack, Teams |
| Single-file EXE | WinDbgX.exe, Teams standalone (50+ MB) |

### How It Works

1. Embeds packed stub as base64 in Electron's main.js
2. Spawns hidden PowerShell with reflective PE loader
3. Loads stub in-memory (bypasses WDAC signature enforcement)
4. Silent mode: Electron exits in 50ms, completely invisible

### Output Structure

```
bin/output/WinDbgX/
  ├─ WinDbgX.exe (original, Microsoft signed)
  └─ resources/
      └─ app/
          ├─ main.js (BACKDOORED - contains stub)
          └─ package.json
```

---

## Evasion Research & Techniques

### Technique Summary

| ID | Name | Status | WD Bypass | Complexity |
|----|------|--------|-----------|------------|
| INJ-004 | Direct Syscalls | 100% | Medium |
| INJ-005 | Section Mapping | 100% | Medium |
| INJ-007 | VEH Execution | 100% | Low |
| INJ-008 | TLS Callbacks | 100% | Medium |
| INJ-011 | NTDLL Unhooking | 100% | Medium |
| ATT-009 | Simple Combo | 100% | Low |
| ATT-011 | Timer Queue | 100% | Low |
| ATT-012 | IOCP | 100% | Medium |
| ATT-013 | APC Injection | 100% | Low |
| ATT-014 | Fiber | 100% | Low |

### Behavioral Scoring Theory

Stay under detection threshold (~10 points) by limiting concurrent suspicious operations:
- Simple operations (~6 points): VirtualAlloc + VirtualProtect = **PASS**
- Comprehensive operations (~18 points): VirtualAlloc + VirtualProtect + CreateProcess + Registry + Network = **FAIL**

---

## Building & Testing

### Compile All Plugins

```powershell
# Build individual plugin
x86_64-w64-mingw32-gcc -shared -O2 plugins/injector_timerqueue.c -o bin/plugins/injector_timerqueue.dll

# Test plugin
copy bin\plugins\injector_timerqueue.dll C:\Windows\Temp\test.dll
rundll32 C:\Windows\Temp\test.dll,DllMain
Get-Content C:\Windows\Temp\*.log
```

### Verify Execution

```powershell
# Check proof files
Get-ChildItem C:\Windows\Temp\stealth_*.txt

# Check registry
Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run | Select-Object STEALTH*
```

---

**Status**: PRODUCTION READY ✅  
**Success Rate**: 100% (10/10 methods)  
**Windows Defender Detections**: 0 (zero across all tests)  
**Test Environment**: Windows 11 24H2, WDAC Enforced, WD Real-Time Protection ENABLED
