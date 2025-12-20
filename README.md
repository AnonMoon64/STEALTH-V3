# STEALTH Crypter
Stealthy Trojan Encryption and Loading Toolkit for Hiding

## Overview
STEALTH Crypter encrypts and packages Windows executables into stealthy standalone files with on-disk or in-memory execution, persistence, and file size inflation using junk URLs.

### Features
- **Payload Encryption**: ChaCha20-Poly1305 encryption with a user-specified or random key.
- **Execution Modes**:
   - On-disk: Decrypts and runs as a file.
   - In-memory: Reflective loading without disk writes.
- **Plugin System**: Append custom DLL plugins with multiple execution stages (PRELAUNCH, PREINJECT, POSTLAUNCH, ONEXIT, ONFAIL).
- **Self-Deletion (Melt)**: Deletes the executable from disk after loading into memory.
- **Anti-Debug**: Detects debuggers and terminates if analysis environment detected.
- **Persistence**: Adds to Windows Startup folder or scheduled tasks.
- **File Size Inflation**: Adds junk URLs (0-500 MB).
- **Custom Icon**: Supports `.ico`, `.png`, `.jpg`, etc. (applied before plugin overlay).
- **GUI**: Built with PyQt6/PyQt5.

## Requirements
- Windows (10/11)
- Python 3.6+
- Python packages: `PyQt6`, `Pillow`, `pywin32`
- MinGW-w64 compiler
- Optional: `rcedit-x64.exe` for icons

## Setup
1. **Clone Repo**:
   ```bash
   git clone <repo-url>
   cd STEALTH
   ```
2. **Install Python Dependencies**:
   ```bash
   pip install PyQt6 Pillow pywin32
   ```
3. **Run GUI**:
   ```bash
   cd gui
   python stealth_gui_pyqt.py
   ```

## Plugin System

### Plugin Stages
Plugins execute in the following order:

| Stage | Value | When it Runs |
|-------|-------|--------------|
| PRELAUNCH | 0 | Before payload injection (melt, antidebug) |
| PREINJECT | 1 | Just before injection starts |
| POSTLAUNCH | 2 | After payload is running (persistence, UI) |
| ONEXIT | 3 | When process exits normally |
| ONFAIL | 4 | If payload execution fails |

### Available Plugins

**Protection:**
- `protection_file_delete.dll` - **Melt**: Deletes executable after loading (stealth mode)
- `antidebug_protection.dll` - Detects debuggers, terminates if found

**Injection Methods:**
- `injector_timerqueue.dll` - Timer queue APC injection
- `injector_timerqueue_advanced.dll` - Advanced timer with anti-detection
- `injector_fiber.dll` - Fiber-based execution
- `injector_apc.dll` - APC injection
- `injector_veh.dll` - VEH-based execution
- `injector_section_mapping.dll` - Section mapping injection
- `injector_iocp.dll` - I/O completion port injection
- `injector_ntdll_unhook.dll` - Unhooks NTDLL before injection
- `injector_tls_callbacks.dll` - TLS callback abuse

**Persistence:**
- `persist_startup_folder.dll` - Adds to Startup folder
- `persist_schtasks.dll` - Scheduled task persistence
- `persist_registry.dll` - Registry persistence

### Plugin Configuration

The GUI auto-detects appropriate stages:
- **protection_** or **antidebug_** plugins → PRELAUNCH (stage 0)
- **persist_** plugins → POSTLAUNCH (stage 2)
- **injector_** plugins → PREINJECT (stage 1)

Enable debug logging for plugins:
```
set STEALTH_MELT_DEBUG=1          # Melt plugin logging
set STEALTH_ANTIDEBUG_DEBUG=1     # Antidebug plugin logging
set STEALTH_PLUGIN_LOGS=1         # Plugin loader logging
```

## Melt Plugin (Self-Deletion)

The melt plugin achieves fileless execution by deleting the executable after loading:

**Methods (in order of preference):**
1. `FILE_FLAG_DELETE_ON_CLOSE` - Marks for deletion when handles close
2. Rename-delete - Moves to temp with random name, then deletes
3. `cmd.exe` fallback - Uses `choice` command for delay (less monitored than `ping`)

**EDR Evasion:**
- No VBScript files written to disk
- No wscript.exe spawned (heavily monitored)
- Logging disabled by default
- Randomized 1-3 second jitter on delays

## Usage
1. **Launch GUI**: Run `python gui/stealth_gui_pyqt.py`
2. **Select Payload**: Choose an `.exe` file
3. **Add Plugins**: Select DLLs from `bin/plugins/`, set stage/order
4. **Configure**: Set output path, key, junk size, in-memory mode
5. **Build**: Click "Build" to generate the packed executable
6. **Test**: Run the output (recommend testing in a VM first)

## Documentation

See `docs/DOCUMENTATION.md` for complete documentation including:
- Detailed plugin architecture
- Injection method comparisons
- EDR evasion techniques
- Electron tampering guide (currently disabled - in development)

## Project Structure
```
STEALTH/
├── gui/
│   ├── stealth_gui_pyqt.py    # Main GUI
│   └── stealth_gui_backend.py # Backend logic
├── src/
│   ├── stub/stub.c            # Runtime loader
│   ├── core/stealth_cryptor.c # Encryption & packing
│   └── stub/template.c        # In-memory DLL
├── plugins/                   # Plugin source files (.c)
├── bin/
│   ├── plugins/               # Compiled plugin DLLs
│   ├── stub.exe               # Compiled stub
│   ├── stealth_cryptor.exe    # Compiled packer
│   └── output/                # Generated executables
├── docs/                      # Documentation
└── data/                      # GUI settings
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Plugins not loading | Check GUI log for "Appending plugins" message |
| Melt not working | Ensure stage=0 (PRELAUNCH), check `%TEMP%\stealth_melt.log` |
| Antidebug blocking | Running in debugger? Disable antidebug plugin for testing |
| Icon not applied | Ensure `rcedit-x64.exe` is in `bin/` |
| File too small | Check if plugins were appended (should be 200KB+ with plugins) |

## Notes
- **Stealth**: Minimizes disk writes; plugins load in-memory
- **Testing**: Always test in an isolated VM first
- **Plugin Order**: Lower order values execute first within same stage
- **Safety**: For educational and authorized security testing only

## License
Educational use only, as-is, no warranty. Use responsibly.
