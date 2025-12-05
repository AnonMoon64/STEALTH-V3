#!/usr/bin/env python3
"""
A modern PyQt GUI for the STEALTH toolset.
- Tries to import PyQt6, falls back to PyQt5.
- Provides fields for payload, output, key, options: dry-run, no-persist, no-hooks, disk-only.
- Shows a confirmation dialog before running potentially dangerous operations.
- Runs `stealth_cryptor.exe` and `stub.exe` via subprocess; in dry-run mode it only simulates commands.

Keep this as a script (you said you may package later).
"""
import sys
import os
import shutil
import subprocess
from pathlib import Path
from functools import partial
import json
from pathlib import Path as _Path

# Visible settings file in workspace for predictable persistence
SETTINGS_FILE = _Path.cwd() / 'stealth_gui_settings.json'

# Try PyQt6 then PyQt5
try:
    from PyQt6 import QtWidgets, QtCore, QtGui
    QtSignal = QtCore.pyqtSignal
    using = 'PyQt6'
except Exception:
    try:
        from PyQt5 import QtWidgets, QtCore, QtGui
        QtSignal = QtCore.pyqtSignal
        using = 'PyQt5'
    except Exception:
        print("PyQt5 or PyQt6 is required. Install one (you mentioned PyQt is installed).")
        raise

APP_NAME = "STEALTH GUI"

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(760, 420)
        self._build_ui()
        # Load persistent settings (last paths, plugins, options)
        try:
            self.load_settings()
        except Exception:
            pass

    def _build_ui(self):
        w = QtWidgets.QWidget()
        self.setCentralWidget(w)
        layout = QtWidgets.QVBoxLayout()
        w.setLayout(layout)

        header = QtWidgets.QLabel(f"<h2>{APP_NAME}</h2><small>Modern PyQt front-end — dry-run and safety first</small>")
        layout.addWidget(header)

        form = QtWidgets.QFormLayout()
        self.payload_edit = QtWidgets.QLineEdit()
        self.payload_btn = QtWidgets.QPushButton("Browse...")
        self.payload_btn.clicked.connect(partial(self._pick_file, self.payload_edit))
        payload_h = QtWidgets.QHBoxLayout(); payload_h.addWidget(self.payload_edit); payload_h.addWidget(self.payload_btn)
        form.addRow("Payload:", payload_h)

        self.output_edit = QtWidgets.QLineEdit(str(Path.cwd() / "out_stub.exe"))
        self.output_btn = QtWidgets.QPushButton("Browse...")
        self.output_btn.clicked.connect(partial(self._pick_save, self.output_edit))
        output_h = QtWidgets.QHBoxLayout(); output_h.addWidget(self.output_edit); output_h.addWidget(self.output_btn)
        form.addRow("Output:", output_h)

        self.key_edit = QtWidgets.QLineEdit()
        self.key_edit.setPlaceholderText("Optional hex key (if empty, a random key will be generated)")
        form.addRow("Key (hex):", self.key_edit)

        # Junk size input (MB)
        self.junk_spin = QtWidgets.QSpinBox()
        self.junk_spin.setRange(0, 500)
        self.junk_spin.setValue(0)
        form.addRow("Junk size (MB):", self.junk_spin)

        options_h = QtWidgets.QHBoxLayout()
        self.dry_run_cb = QtWidgets.QCheckBox("Dry run (no execution)")
        # Persistence moved to plugins; GUI no longer shows a persistence checkbox
        self.in_memory_cb = QtWidgets.QCheckBox("Load in-memory (opt-in)")
        self.in_memory_cb.setChecked(True)
        options_h.addWidget(self.dry_run_cb)
        options_h.addWidget(self.in_memory_cb)
        form.addRow("Options:", options_h)

        # Plugins UI (select multiple plugin DLLs)
        self.plugins_list = QtWidgets.QListWidget()
        plugins_h = QtWidgets.QHBoxLayout()
        self.add_plugin_btn = QtWidgets.QPushButton("Add Plugin...")
        self.add_plugin_btn.clicked.connect(self._add_plugin)
        self.remove_plugin_btn = QtWidgets.QPushButton("Remove Selected")
        self.remove_plugin_btn.clicked.connect(self._remove_plugin)
        self.plugins_list.itemDoubleClicked.connect(self._edit_plugin_item)
        plugins_h.addWidget(self.add_plugin_btn)
        plugins_h.addWidget(self.remove_plugin_btn)
        form.addRow("Plugins:", self.plugins_list)
        form.addRow("", plugins_h)

        layout.addLayout(form)

        # Buttons
        btn_h = QtWidgets.QHBoxLayout()
        self.run_btn = QtWidgets.QPushButton("Build (crypt & stub)")
        self.run_btn.clicked.connect(self.on_run)
        self.sim_btn = QtWidgets.QPushButton("Simulate (show command)")
        self.sim_btn.clicked.connect(self.on_simulate)
        btn_h.addWidget(self.run_btn)
        btn_h.addWidget(self.sim_btn)
        layout.addLayout(btn_h)

        self.log = QtWidgets.QTextEdit()
        self.log.setReadOnly(True)
        layout.addWidget(self.log)

        footer = QtWidgets.QLabel("Note: This GUI invokes local executables like `stealth_cryptor.exe`. Test safely in an isolated VM.")
        layout.addWidget(footer)

    def _pick_file(self, lineedit):
        p, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select file", str(Path.cwd()))
        if p:
            lineedit.setText(p)

    def _pick_save(self, lineedit):
        p, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Select output", str(Path.cwd() / "out_stub.exe"))
        if p:
            lineedit.setText(p)

    def _add_plugin(self):
        p, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select plugin DLL", str(Path.cwd()), "DLL Files (*.dll);;All Files (*)")
        if p:
            # Avoid duplicates
            existing = [self.plugins_list.item(i).text() for i in range(self.plugins_list.count())]
            if p in existing:
                self._log_warning("Plugin already added")
                return
            # Ask for stage and order
            dlg = QtWidgets.QDialog(self)
            dlg.setWindowTitle("Plugin Stage/Order")
            v = QtWidgets.QVBoxLayout(dlg)
            v.addWidget(QtWidgets.QLabel(f"Configure stage/order for plugin: {Path(p).name}"))
            stage_cb = QtWidgets.QComboBox()
            stage_cb.addItems(["PRELAUNCH", "PREINJECT", "POSTLAUNCH", "ONEXIT", "ONFAIL"])
            order_spin = QtWidgets.QSpinBox()
            order_spin.setRange(0, 65535)
            order_spin.setValue(0)
            form = QtWidgets.QFormLayout()
            form.addRow("Stage:", stage_cb)
            form.addRow("Order:", order_spin)
            v.addLayout(form)
            buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.StandardButton.Ok | QtWidgets.QDialogButtonBox.StandardButton.Cancel)
            v.addWidget(buttons)
            buttons.accepted.connect(dlg.accept)
            buttons.rejected.connect(dlg.reject)
            if dlg.exec() == QtWidgets.QDialog.DialogCode.Accepted:
                # store real path in UserRole+1, stage/order in UserRole, and display a friendly label
                item = QtWidgets.QListWidgetItem()
                item.setData(QtCore.Qt.ItemDataRole.UserRole, (stage_cb.currentIndex(), order_spin.value()))
                item.setData(QtCore.Qt.ItemDataRole.UserRole + 1, p)
                stage_names = ["PRELAUNCH", "PREINJECT", "POSTLAUNCH", "ONEXIT", "ONFAIL"]
                item.setText(f"{Path(p).name} [{stage_names[stage_cb.currentIndex()]}:{order_spin.value()}]")
                self.plugins_list.addItem(item)
            else:
                self._log_info("Plugin add cancelled")

    def _remove_plugin(self):
        for item in self.plugins_list.selectedItems():
            self.plugins_list.takeItem(self.plugins_list.row(item))

    def _validate_inputs(self):
        payload = Path(self.payload_edit.text() or "")
        out = Path(self.output_edit.text() or "")
        if not payload.exists() or not payload.is_file():
            self._log_error("Payload path invalid or missing")
            return None
        if not out.parent.exists():
            try:
                out.parent.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                self._log_error(f"Cannot create output directory: {e}")
                return None
        return payload, out

    def _confirm_action(self):
        # Confirm with a checkbox (safety gating)
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle("Confirm Operation")
        v = QtWidgets.QVBoxLayout(dlg)
        v.addWidget(QtWidgets.QLabel("This will run local build tools that may create persistence or execute payloads.\nOnly proceed inside an isolated test VM.\nDo you understand and want to continue?"))
        cb = QtWidgets.QCheckBox("I understand and will test in an isolated environment")
        v.addWidget(cb)
        buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.StandardButton.Ok | QtWidgets.QDialogButtonBox.StandardButton.Cancel)
        v.addWidget(buttons)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        res = dlg.exec()
        return res == QtWidgets.QDialog.DialogCode.Accepted and cb.isChecked()

    def _build_command(self):
        payload, out = self._validate_inputs() or (None, None)
        if not payload:
            return None
        key = self.key_edit.text().strip()
        # If no key provided, generate a random 32-byte key hex
        if not key:
            try:
                key = os.urandom(32).hex()
                self._log_info(f"Generated random key: {key}")
                # set and persist generated key so GUI remembers it
                try:
                    self.key_edit.setText(key)
                    self.save_settings()
                except Exception:
                    pass
            except Exception:
                self._log_warning("Could not generate random key — please provide a 64-char hex key")

        # positional invocation expected by legacy stealth_cryptor: <payload> <output> <key_hex> <junk_mb> <persistence> <load_in_memory>
        cryptor = Path.cwd() / 'stealth_cryptor.exe'
        if not cryptor.exists():
            self._log_warning("`stealth_cryptor.exe` not found in current directory; you must build it first (see build script)")

        junk_mb = str(self.junk_spin.value())
        # Persistence is managed via plugins; default to '0' (no persistence)
        persistence = '0'
        load_in_memory = '1' if self.in_memory_cb.isChecked() else '0'

        crypt_cmd = [str(cryptor), str(payload), str(out), key, junk_mb, persistence, load_in_memory]
        # Dry run is a GUI-local option — we don't pass it to the legacy cryptor
        # Note: the legacy `stealth_cryptor.exe` discovers plugins by scanning a local
        # `plugins\*.dll` folder. We do NOT pass `--plugin` flags (those are unsupported).
        return crypt_cmd

    def load_settings(self):
        # Prefer explicit JSON settings file in workspace for easier testing/debugging
        try:
            if SETTINGS_FILE.exists():
                with open(SETTINGS_FILE, 'r', encoding='utf-8') as fh:
                    data = json.load(fh)
                payload = data.get('payload')
                output = data.get('output')
                key = data.get('key')
                junk = data.get('junk', 0)
                in_memory = data.get('in_memory', True)
                plugins = data.get('plugins', [])
                if payload:
                    self.payload_edit.setText(payload)
                if output:
                    self.output_edit.setText(output)
                if key:
                    self.key_edit.setText(key)
                try:
                    self.junk_spin.setValue(int(junk))
                except Exception:
                    pass
                try:
                    self.in_memory_cb.setChecked(bool(in_memory))
                except Exception:
                    pass
                if plugins:
                    stage_names = ["PRELAUNCH", "PREINJECT", "POSTLAUNCH", "ONEXIT", "ONFAIL"]
                    for it in plugins:
                        p = it.get('path')
                        stage = int(it.get('stage', 0))
                        order = int(it.get('order', 0))
                        if not p:
                            continue
                        item = QtWidgets.QListWidgetItem()
                        item.setData(QtCore.Qt.ItemDataRole.UserRole, (stage, order))
                        item.setData(QtCore.Qt.ItemDataRole.UserRole + 1, p)
                        item.setText(f"{Path(p).name} [{stage_names[stage]}:{order}]")
                        self.plugins_list.addItem(item)
                return
        except Exception:
            pass
        # Fallback to QSettings if JSON file not present
        try:
            settings = QtCore.QSettings('STEALTH', 'GUI')
            payload = settings.value('payload', type=str)
            output = settings.value('output', type=str)
            key = settings.value('key', type=str)
            junk = settings.value('junk', 0, type=int)
            in_memory = settings.value('in_memory', True, type=bool)
            plugins_json = settings.value('plugins', '', type=str)
            if payload:
                self.payload_edit.setText(payload)
            if output:
                self.output_edit.setText(output)
            if key:
                self.key_edit.setText(key)
            try:
                self.junk_spin.setValue(int(junk))
            except Exception:
                pass
            try:
                self.in_memory_cb.setChecked(bool(in_memory))
            except Exception:
                pass
            if plugins_json:
                try:
                    items = json.loads(plugins_json)
                    stage_names = ["PRELAUNCH", "PREINJECT", "POSTLAUNCH", "ONEXIT", "ONFAIL"]
                    for it in items:
                        p = it.get('path')
                        stage = int(it.get('stage', 0))
                        order = int(it.get('order', 0))
                        if not p:
                            continue
                        item = QtWidgets.QListWidgetItem()
                        item.setData(QtCore.Qt.ItemDataRole.UserRole, (stage, order))
                        item.setData(QtCore.Qt.ItemDataRole.UserRole + 1, p)
                        item.setText(f"{Path(p).name} [{stage_names[stage]}:{order}]")
                        self.plugins_list.addItem(item)
                except Exception:
                    pass
        except Exception:
            pass

    def save_settings(self):
        # Save explicit JSON file for easier inspection and predictability
        try:
            data = {
                'payload': self.payload_edit.text(),
                'output': self.output_edit.text(),
                'key': self.key_edit.text(),
                'junk': int(self.junk_spin.value()),
                'in_memory': bool(self.in_memory_cb.isChecked()),
                'plugins': []
            }
            for i in range(self.plugins_list.count()):
                it = self.plugins_list.item(i)
                if not it:
                    continue
                data_role = it.data(QtCore.Qt.ItemDataRole.UserRole) or (0, 0)
                stored = it.data(QtCore.Qt.ItemDataRole.UserRole + 1) or ''
                data['plugins'].append({'path': stored, 'stage': int(data_role[0]), 'order': int(data_role[1])})
            with open(SETTINGS_FILE, 'w', encoding='utf-8') as fh:
                json.dump(data, fh, indent=2)
            return
        except Exception:
            pass
        # Fallback to QSettings if file save fails
        try:
            settings = QtCore.QSettings('STEALTH', 'GUI')
            settings.setValue('payload', self.payload_edit.text())
            settings.setValue('output', self.output_edit.text())
            settings.setValue('key', self.key_edit.text())
            settings.setValue('junk', int(self.junk_spin.value()))
            settings.setValue('in_memory', bool(self.in_memory_cb.isChecked()))
            items = []
            for i in range(self.plugins_list.count()):
                it = self.plugins_list.item(i)
                if not it:
                    continue
                data_role = it.data(QtCore.Qt.ItemDataRole.UserRole) or (0, 0)
                stored = it.data(QtCore.Qt.ItemDataRole.UserRole + 1) or ''
                items.append({'path': stored, 'stage': int(data_role[0]), 'order': int(data_role[1])})
            settings.setValue('plugins', json.dumps(items))
        except Exception:
            pass

    def closeEvent(self, event):
        try:
            self.save_settings()
        except Exception:
            pass
        return super().closeEvent(event)

    def _prepare_plugins_folder(self):
        """Stage selected plugin DLLs into a temporary plugins directory and return (temp_dir, copied_paths).
        The packer will be invoked with the environment variable `PLUGIN_DIR` set to this temp_dir so only
        staged plugins are included. The caller must cleanup the returned temp_dir via `_cleanup_plugins_folder`.
        """
        # If no plugins selected, skip creating a folder entirely
        if self.plugins_list.count() == 0:
            return None, []
        cwd = Path.cwd()
        # create a deterministic temp dir under workspace so packer can read files
        import time, random
        rnd = random.randint(1000, 9999)
        plugins_dir = cwd / f'plugins_gui_{int(time.time())}_{rnd}'
        copied = []
        try:
            plugins_dir.mkdir(parents=True, exist_ok=False)
        except Exception as e:
            self._log_warning(f"Could not create temporary plugins folder: {e}")
            return None, copied

        for i in range(self.plugins_list.count()):
            item = self.plugins_list.item(i)
            stored = item.data(QtCore.Qt.ItemDataRole.UserRole + 1)
            if stored:
                src = Path(stored)
            else:
                # If no stored path, try to parse the displayed text as a filename in cwd
                src = Path(item.text())
            if not src.exists():
                self._log_warning(f"Plugin not found: {src}")
                continue
            dest = plugins_dir / src.name
            try:
                shutil.copy2(str(src), str(dest))
                copied.append(str(dest))
                # write metadata file next to copied plugin so packer can pick up stage/order
                try:
                    stage, order = (0, 0)
                    data = item.data(QtCore.Qt.ItemDataRole.UserRole)
                    if data:
                        stage, order = data
                    meta_path = plugins_dir / (src.name + '.meta')
                    with open(meta_path, 'w', encoding='utf-8') as mf:
                        mf.write(f"stage={stage}\n")
                        mf.write(f"order={order}\n")
                    copied.append(str(meta_path))
                except Exception:
                    pass
            except Exception as e:
                self._log_warning(f"Failed to copy plugin {src} -> {dest}: {e}")
        return str(plugins_dir), copied

    def _cleanup_plugins_folder(self, temp_dir, copied=None, backups=None):
        # If we created a temporary plugins dir, remove it entirely.
        if not temp_dir:
            return
        try:
            shutil.rmtree(temp_dir)
        except Exception:
            pass
        return

    def _edit_plugin_item(self, item):
        # Edit stage/order for an existing item
        if not item: return
        stored = item.data(QtCore.Qt.ItemDataRole.UserRole + 1)
        if stored:
            path = Path(stored)
        else:
            path = Path(item.text())
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle("Edit Plugin Stage/Order")
        v = QtWidgets.QVBoxLayout(dlg)
        v.addWidget(QtWidgets.QLabel(f"Edit plugin: {path.name}"))
        stage_cb = QtWidgets.QComboBox()
        stage_cb.addItems(["PRELAUNCH", "PREINJECT", "POSTLAUNCH", "ONEXIT", "ONFAIL"])
        order_spin = QtWidgets.QSpinBox()
        order_spin.setRange(0, 65535)
        data = item.data(QtCore.Qt.ItemDataRole.UserRole)
        if data:
            stage_cb.setCurrentIndex(data[0])
            order_spin.setValue(data[1])
        form = QtWidgets.QFormLayout()
        form.addRow("Stage:", stage_cb)
        form.addRow("Order:", order_spin)
        v.addLayout(form)
        buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.StandardButton.Ok | QtWidgets.QDialogButtonBox.StandardButton.Cancel)
        v.addWidget(buttons)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        if dlg.exec() == QtWidgets.QDialog.DialogCode.Accepted:
            item.setData(QtCore.Qt.ItemDataRole.UserRole, (stage_cb.currentIndex(), order_spin.value()))
            stage_names = ["PRELAUNCH", "PREINJECT", "POSTLAUNCH", "ONEXIT", "ONFAIL"]
            item.setText(f"{path.name} [{stage_names[stage_cb.currentIndex()]}:{order_spin.value()}]")

    def on_simulate(self):
        cmd = self._build_command()
        if not cmd:
            return
        self._log_info("Simulated command:")
        self._log_info(' '.join(f'"{c}"' for c in cmd))

    def _run_subprocess(self, cmd):
        # Run subprocess and stream output to log
        try:
            self._log_info(f"Running: {cmd[0]}")
            # Diagnostic: log working directory and PLUGIN_DIR so we can reproduce environment issues
            try:
                cwd = os.getcwd()
                self._log_info(f"CWD: {cwd}")
                plugin_dir = os.environ.get('PLUGIN_DIR')
                if plugin_dir:
                    self._log_info(f"PLUGIN_DIR (env): {plugin_dir}")
                    try:
                        files = list(Path(plugin_dir).glob('*'))
                        self._log_info(f"PLUGIN_DIR contains {len(files)} entries")
                        for f in files[:20]:
                            self._log_info(f" - {f.name} ({f.stat().st_size} bytes)")
                    except Exception:
                        self._log_warning("Could not enumerate PLUGIN_DIR contents")
                else:
                    self._log_info("PLUGIN_DIR not set in environment")
                # Dump full environment + command to a diagnostic file for debugging GUI-launched runs
                try:
                    diag = {
                        'cwd': cwd,
                        'cmd': cmd,
                        'plugin_dir': plugin_dir,
                        'env': dict(os.environ)
                    }
                    import json
                    env_path = Path.cwd() / 'stealth_gui_last_run_env.json'
                    with open(env_path, 'w', encoding='utf-8') as ef:
                        json.dump(diag, ef, indent=2)
                    self._log_info(f"Wrote GUI env dump to: {env_path}")
                except Exception:
                    self._log_warning("Could not write GUI env dump file")
            except Exception:
                pass
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            if p.stdout is not None:
                for line in p.stdout:
                    self._log(line.rstrip())
            p.wait()
            rc = p.returncode
            # If the process exited with a NTSTATUS-like code (high bit set), show hex and hint
            try:
                u32 = rc & 0xFFFFFFFF
            except Exception:
                u32 = rc
            if isinstance(u32, int) and u32 >= 0x80000000:
                # Map a few well-known NTSTATUS codes to friendly names
                status_map = {
                    0xC0000005: 'STATUS_ACCESS_VIOLATION',
                    0xC0000374: 'STATUS_HEAP_CORRUPTION',
                    0xC0000008: 'STATUS_INVALID_HANDLE',
                    0xC0000096: 'STATUS_ILLEGAL_INSTRUCTION'
                }
                human = status_map.get(u32, None)
                if human:
                    self._log_error(f"Process exited with NTSTATUS {hex(u32)} ({human})")
                else:
                    self._log_error(f"Process exited with NTSTATUS {hex(u32)}")
                self._log_error("This usually indicates a crash in the child process (heap corruption, access violation, etc.). Try running the executable directly in a debugger or a console to capture more details.")
                # On NTSTATUS crash, also write the same diagnostic file (if not already) to help offline analysis
                try:
                    diag_path = Path.cwd() / 'stealth_gui_last_run_env.json'
                    if not diag_path.exists():
                        diag = {'cwd': os.getcwd(), 'cmd': cmd, 'plugin_dir': os.environ.get('PLUGIN_DIR'), 'env': dict(os.environ)}
                        import json
                        with open(diag_path, 'w', encoding='utf-8') as ef:
                            json.dump(diag, ef, indent=2)
                        self._log_info(f"Wrote GUI env dump to: {diag_path}")
                except Exception:
                    pass
            else:
                if rc != 0:
                    self._log_error(f"Process exited: {rc}")
                    self._log_error("Cryptor failed — aborting")
                else:
                    self._log_info(f"Process exited: {rc}")
            return p.returncode
        except FileNotFoundError:
            self._log_error(f"Executable not found: {cmd[0]}")
            return -1
        except Exception as e:
            self._log_error(str(e))
            return -1

    class SubprocessWorker(QtCore.QObject):
        """Worker that runs a subprocess on a Python thread and emits Qt signals for output and completion."""
        line = QtSignal(str)
        finished_rc = QtSignal(int)

        def __init__(self, cmd, parent=None):
            super().__init__(parent)
            self.cmd = cmd
            self._thread = None

        def start(self):
            import threading
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()

        def _run(self):
            try:
                try:
                    cwd = os.getcwd()
                    plugin_dir = os.environ.get('PLUGIN_DIR')
                    diag = {'cwd': cwd, 'cmd': self.cmd, 'plugin_dir': plugin_dir, 'env': dict(os.environ)}
                    import json
                    env_path = Path.cwd() / 'stealth_gui_last_run_env.json'
                    with open(env_path, 'w', encoding='utf-8') as ef:
                        json.dump(diag, ef, indent=2)
                except Exception:
                    pass

                # Use blocking run() like the original non-PyQt GUI so we capture full stderr for debugging
                try:
                    creation_flags = 0
                    if hasattr(subprocess, 'CREATE_NO_WINDOW'):
                        creation_flags = subprocess.CREATE_NO_WINDOW
                    result = subprocess.run(self.cmd, capture_output=True, text=True, creationflags=creation_flags)
                except Exception:
                    # Fall back to Popen if run() is not available or fails
                    p = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    out, err = p.communicate()
                    from types import SimpleNamespace
                    result = SimpleNamespace(returncode=p.returncode, stdout=out, stderr=err)

                # Emit captured stdout lines
                try:
                    if result.stdout:
                        for ln in result.stdout.splitlines():
                            try:
                                self.line.emit(ln)
                            except Exception:
                                pass
                except Exception:
                    pass
                # Emit captured stderr as error lines for easier debugging (match old GUI behavior)
                try:
                    if result.stderr:
                        for ln in result.stderr.splitlines():
                            try:
                                self.line.emit(f"[ERR] {ln}")
                            except Exception:
                                pass
                except Exception:
                    pass

                rc = result.returncode
                try:
                    self.finished_rc.emit(rc)
                except Exception:
                    pass
            except Exception:
                try:
                    self.line.emit(f"[ERR] Worker exception: {exc}")
                except Exception:
                    pass
                try:
                    self.finished_rc.emit(-1)
                except Exception:
                    pass

    def on_run(self):
        if not self._confirm_action():
            self._log_warning("Operation cancelled by user")
            return
        cmd = self._build_command()
        if not cmd:
            return
        if self.dry_run_cb.isChecked():
            self._log_info("Dry run enabled — no external commands will be executed")
            self._log_info(' '.join(cmd))
            return
        # Ensure `stub.exe` exists and warn if missing (we embed whatever `stub.exe` is present)
        stub_path = Path.cwd() / 'stub.exe'
        if not stub_path.exists():
            self._log_warning("`stub.exe` not found in workspace — packer will embed whatever stub is present. Build `stub.exe` first for GUI (no console) behavior.")

        # Prepare plugins folder (stage selected plugin DLLs into a temporary folder)
        plugins_temp_dir, copied = self._prepare_plugins_folder()
        # If we created a temp dir, set PLUGIN_DIR so the packer only sees staged plugins
        prev_plugin_dir = os.environ.get('PLUGIN_DIR')
        if plugins_temp_dir:
            os.environ['PLUGIN_DIR'] = plugins_temp_dir
            self._log_info(f"Staged plugins into temporary folder: {plugins_temp_dir}")
        # Execute cryptor asynchronously so GUI stays responsive
        self._log_info("Starting packer in background...")
        self._log_info(' '.join(f'"{c}"' for c in cmd))
        self.run_btn.setEnabled(False)
        self.sim_btn.setEnabled(False)
        self._worker = MainWindow.SubprocessWorker(cmd)
        worker = self._worker
        # forward worker output to GUI log
        worker.line.connect(self._log)

        def _on_finished(rc):
            try:
                if isinstance(rc, int) and rc >= 0:
                    # If NTSTATUS-like code, the previous synchronous path handled hex; replicate here
                    try:
                        u32 = rc & 0xFFFFFFFF
                    except Exception:
                        u32 = rc
                    if isinstance(u32, int) and u32 >= 0x80000000:
                        status_map = {
                            0xC0000005: 'STATUS_ACCESS_VIOLATION',
                            0xC0000374: 'STATUS_HEAP_CORRUPTION',
                            0xC0000008: 'STATUS_INVALID_HANDLE',
                            0xC0000096: 'STATUS_ILLEGAL_INSTRUCTION'
                        }
                        human = status_map.get(u32, None)
                        if human:
                            self._log_error(f"Process exited with NTSTATUS {hex(u32)} ({human})")
                        else:
                            self._log_error(f"Process exited with NTSTATUS {hex(u32)}")
                        self._log_error("This usually indicates a crash in the child process (heap corruption, access violation, etc.). Try running the executable directly in a debugger or a console to capture more details.")
                        # ensure env dump exists
                        try:
                            diag_path = Path.cwd() / 'stealth_gui_last_run_env.json'
                            if not diag_path.exists():
                                import json
                                diag = {'cwd': os.getcwd(), 'cmd': cmd, 'plugin_dir': os.environ.get('PLUGIN_DIR'), 'env': dict(os.environ)}
                                with open(diag_path, 'w', encoding='utf-8') as ef:
                                    json.dump(diag, ef, indent=2)
                                self._log_info(f"Wrote GUI env dump to: {diag_path}")
                        except Exception:
                            pass
                    else:
                        if rc != 0:
                            self._log_error(f"Process exited: {rc}")
                            self._log_error("Cryptor failed — aborting")
                        else:
                            self._log_info(f"Process exited: {rc}")
                else:
                    self._log_error(f"Cryptor failed — aborting (rc={rc})")
            finally:
                # Cleanup temp plugins folder
                try:
                    self._cleanup_plugins_folder(plugins_temp_dir, copied)
                except Exception:
                    pass
                # restore previous PLUGIN_DIR env var
                try:
                    if prev_plugin_dir is None:
                        if 'PLUGIN_DIR' in os.environ:
                            del os.environ['PLUGIN_DIR']
                    else:
                        os.environ['PLUGIN_DIR'] = prev_plugin_dir
                except Exception:
                    pass
                # Re-enable buttons
                try:
                    self.run_btn.setEnabled(True)
                    self.sim_btn.setEnabled(True)
                except Exception:
                    pass
                # Release worker reference
                try:
                    self._worker = None
                except Exception:
                    pass

        worker.finished_rc.connect(_on_finished)
        worker.start()
        # Keep a reference so GC doesn't collect the worker while running
        self._worker = worker

    def _collect_logs(self, pid, payload_out):
        # Read plugin and debug logs from %TEMP% and append tail to GUI log
        temp_dir = Path(os.getenv('TEMP') or os.getenv('TMP') or '.')
        plugin_log = temp_dir / 'stealth_plugin.log'
        debug_log = temp_dir / 'stealth_debug.log'
        for f in (plugin_log, debug_log):
            if f.exists():
                try:
                    with open(f, 'r', encoding='utf-8', errors='ignore') as fh:
                        lines = fh.read().splitlines()
                        tail = lines[-200:]
                        self._log_info(f"=== {f.name} (last {len(tail)} lines) ===")
                        for ln in tail:
                            self._log(ln)
                except Exception as e:
                    self._log_warning(f"Could not read {f}: {e}")

    def _log(self, s):
        self.log.append(s)

    def _log_info(self, s):
        self._log(f"[INFO] {s}")

    def _log_warning(self, s):
        self._log(f"[WARN] {s}")

    def _log_error(self, s):
        self._log(f"[ERROR] {s}")


def main():
    app = QtWidgets.QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
