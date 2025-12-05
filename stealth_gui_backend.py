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

    def __init__(self, cmd, env=None, parent=None):
        super().__init__(parent)
        self.cmd = cmd
        self.env = env or os.environ.copy()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        rc = -1
        try:
            try:
                diag = {
                    'cwd': os.getcwd(),
                    'cmd': self.cmd,
                    'plugin_dir': self.env.get('PLUGIN_DIR'),
                    'env': dict(self.env),
                }
                env_path = Path.cwd() / 'stealth_gui_last_run_env.json'
                with open(env_path, 'w', encoding='utf-8') as ef:
                    json.dump(diag, ef, indent=2)
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
        cryptor = Path.cwd() / 'stealth_cryptor.exe'
        if not cryptor.exists() and warn_fn:
            warn_fn('`stealth_cryptor.exe` not found in current directory; build it first.')
        cmd = [str(cryptor), str(payload), str(output), key, junk_mb, persistence, load_in_mem_flag]
        return cmd, key, generated

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

    def start_process(self, cmd, plugin_dir=None, disable_plugins_default=False):
        env = os.environ.copy()
        if plugin_dir:
            env['PLUGIN_DIR'] = plugin_dir
        else:
            env.pop('PLUGIN_DIR', None)  # ensure stale value is cleared
            if disable_plugins_default:
                env['PLUGIN_DIR_DISABLE'] = "1"
        worker = SubprocessWorker(cmd, env=env)
        worker.line.connect(self.line)
        worker.finished_rc.connect(self.finished_rc)
        worker.start()
        self._worker = worker
        return worker
