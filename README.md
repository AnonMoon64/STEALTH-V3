# STEALTH Crypter
Stealthy Trojan Encryption and Loading Toolkit for Hiding

## Overview
STEALTH Crypter encrypts and packages Windows executables into stealthy standalone files with on-disk or in-memory execution, persistence, and file size inflation using junk URLs.

### Features
- **Payload Encryption**: XOR encryption with a user-specified key.
- **Execution Modes**:
  - On-disk: Decrypts and runs as a file.
  - In-memory without disk writes.
- **Persistence**: Adds to Windows Startup folder.
- **File Size Inflation**: Adds junk URLs (0-500 MB).
- **Custom Icon**: Supports `.ico`, `.png`, `.jpg`, etc.
- **GUI**: Built with PyQt6.

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
   cd STEALTH-Crypter
   ```
2. **Install Python Dependencies**:
   ```bash
   pip install PyQt6 Pillow pywin32
   ```
3. **Compile C Components**:
   - `stub_generator.c`:
     ```bash
     x86_64-w64-mingw32-gcc -o stub_generator.exe stub_generator.c
     .\stub_generator.exe
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
   Run `dist\stealth_gui.exe`.
2. **Select Payload**:
   Choose an `.exe`.
3. **Configure Output**:
   - Path: Defaults to `output`.
   - Filename: e.g., `encrypted`.
   - Extension: `.exe`, `.scr`, `.com`.
4. **Set Icon (Optional)**:
   Select an icon (`.ico`, `.png`, etc.).
5. **Configure Encryption**:
   - Key: Default Random.
   - Junk URLs: 0-500 MB (default: 100).
   - Persistence: Enable for Startup.
   - In-Memory: Enable for no disk writes.
6. **Encrypt**:
   Click "Encrypt" to generate `output\encrypted.exe`.
7. **Run Output**:
   ```bash
   cd output
   .\encrypted.exe
   ```

## Project Structure
- `stealth_gui.py`: GUI script.
- `stub_generator.c`: Creates `stub.exe`.
- `stealth_cryptor.c`: Encrypts payload.
- `template.c`: In-memory execution DLL.
- `audio\notification.wav`: GUI sound.
- `icon\icon.ico`: GUI icon (optional).

## Notes
- **Stealth**: Minimizes disk writes; junk URLs evade detection.
- **Limits**: Needs MinGW-w64; in-memory targets `explorer.exe`.
- **Safety**: For educational use only.

## Troubleshooting
- **GUI Fails**: Check dependencies and files.
- **Encryption Fails**: Verify payload and compiled files.
- **Icon Issues**: Ensure `rcedit-x64.exe` is present.

## License
Educational use only, as-is, no warranty. Use responsibly.
