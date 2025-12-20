# STEALTH Crypter
Stealthy Trojan Encryption and Loading Toolkit for Hiding

## Overview
STEALTH Crypter encrypts and packages Windows executables into stealthy standalone files with on-disk or in-memory execution, persistence, and file size inflation using junk URLs.

### Features
- **Payload Encryption**: AES/ChaCha encryption with a user-specified key.
- **Execution Modes**:
   - On-disk: Decrypts and runs as a file.
   - In-memory without disk writes.
- **Plugin System**: Append custom DLL plugins to the stub; supports multiple execution stages (PRELAUNCH, POSTLAUNCH, etc.).
- **Persistence**: Adds to Windows Startup folder.
- **File Size Inflation**: Adds junk URLs (0-500 MB).
- **Custom Icon**: Supports `.ico`, `.png`, `.jpg`, etc. (icon is now applied before plugin overlay for compatibility).
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
   cd STEALTH-main
   ```
2. **Install Python Dependencies**:
   ```bash
   pip install PyQt6 Pillow pywin32
   ```
3. **Compile C Components**:
   - `stub.c`:
     ```bash
     x86_64-w64-mingw32-gcc -o stub.exe stub.c
     .\stub.exe
     ```
   - `stealth_cryptor.c`:
     ```bash
     x86_64-w64-mingw32-gcc -o stealth_cryptor.exe stealth_cryptor.c
     ```
   - `template.c`:
     ```bash
     x86_64-w64-mingw32-gcc -shared -o template.dll template.c -mwindows
     ```
4. **(Optional) Get `rcedit-x64.exe`**:
   - Place in project folder for icon support.
5. **Run GUI**:
   ```bash
   python stealth_gui.py
   ```
   **Build to .exe**:
   ```bash
   pip install pyinstaller
   pyinstaller --onefile --noconsole --icon=icon\icon.ico --add-data "audio;audio" stealth_gui.py
   ```

## Usage
1. **Launch GUI**:
   Run `dist\stealth_gui_pyqt.py` or `pyton stealth_gui_pyqt.py`.
2. **Select Payload**:
   Choose an `.exe`.
3. **Configure Output**:
   - Path: Defaults to `output`.
   - Filename: e.g., `encrypted`.
   - Extension: `.exe`, `.scr`, `.com`.
4. **Set Icon (Optional)**:
   Select an icon (`.ico`, `.png`, etc.).
5. **Add Plugins (Optional)**:
   Use the GUI to select one or more DLL plugins and set their execution stage/order. Plugins are appended to the stub and loaded at runtime.
6. **Configure Encryption**:
   - Key: Default Random.
   - Junk URLs: 0-500 MB (default: 100).
   - Persistence: Enable for Startup.
   - In-Memory: Enable for no disk writes.
7. **Encrypt**:
   Click "Build" to generate `output\encrypted.exe`.
8. **Run Output**:
   ```bash
   cd output
   .\encrypted.exe
   ```

## Documentation

Detailed documentation is available in the `docs/` folder:
- `ELECTRON_SINGLE_EXE_SUPPORT.md` - Electron tampering guide (folder & single-EXE support, WDAC bypass)
- `PLUGIN_ARCHITECTURE_FINAL.md` - Plugin system architecture
- `INJECTOR_METHODS_GUIDE.md` - GOD-TIER injection methods
- `FINAL_SUMMARY.md` - Complete project summary

## Electron Tampering (WDAC Bypass)

The packer includes Electron app tampering for bypassing strict WDAC enforcement:

**Supported Targets:**
- **Folder-based**: VS Code portable, Discord, Slack, Teams (must contain `resources/` folder)
- **Single-file EXE**: WinDbgX.exe, standalone Electron apps (typically 50+ MB, auto-detected)

**How to Use:**
1. Build your packed payload first
2. Click "Browse Electron Target" and select:
   - **Folder option**: For VS Code portable, Discord folders
   - **Single EXE option**: For WinDbgX.exe, Teams standalone
3. Enable "Silent mode" (recommended - victim sees no window)
4. Click "Tamper Electron App"
5. Deploy the entire output folder (maintains Microsoft signature)

**What it does:**
- Embeds your packed stub as base64 in Electron's main.js
- Spawns hidden PowerShell with reflective PE loader
- Loads stub in-memory (bypasses WDAC signature enforcement)
- Silent mode: Electron exits in 50ms, completely invisible

**Important:** The target must be a valid Electron app. The GUI will validate:
- Folders must have `resources/app` or `resources/app.asar`
- Single EXEs must be 20+ MB and contain Electron markers

See `docs/ELECTRON_SINGLE_EXE_SUPPORT.md` for complete details.

## Project Structure
- `gui/stealth_gui_pyqt.py`: GUI scripts.
- `gui/stealth_gui_backend.py`: GUI backend logic.
- `src/stub/stub.c`: Runtime loader.
- `src/core/stealth_cryptor.c`: Encrypts payload and appends plugins.
- `src/stub/template.c`: In-memory execution DLL.
- `plugins/`: Source for custom plugins (DLLs).
- `bin/plugins/`: Compiled plugin DLLs for appending.
- `docs/`: Documentation files.
- `audio/notification.wav`: GUI sound.
- `icon/icon.ico`: GUI icon (optional).

## Notes
- **Stealth**: Minimizes disk writes; junk URLs evade detection.
- **Plugin Overlay**: Icon is applied before plugin overlay is appended; do not patch icon after build or plugins will be stripped.
- **Limits**: Needs MinGW-w64; in-memory targets `explorer.exe`.
- **Safety**: For educational use only.

## Troubleshooting
- **GUI Fails**: Check dependencies and files.
- **Encryption Fails**: Verify payload and compiled files.
- **Icon Issues**: Ensure `rcedit-x64.exe` is present. Icon is now applied before plugin overlay.
- **Plugins Not Loading**: Make sure plugins are selected in the GUI and appended during build. Do not patch icon after build.

## License
Educational use only, as-is, no warranty. Use responsibly.
