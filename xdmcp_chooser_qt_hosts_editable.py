#!/usr/bin/env python3
"""
xdmcp_chooser_qt_hosts_editable.py
XDMCP / XPRA Chooser (Qt) — mit editierbarem X-Display und konfigurierbarem Hostfile-Pfad



 * Copyright (C) 2025 konstizockt
 *
 * Dieses Programm ist freie Software: Sie können es unter den Bedingungen
 * der GNU General Public License, wie von der Free Software Foundation,
 * Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren Version,
 * weiterverbreiten und/oder modifizieren.
 *
 * Dieses Programm wird in der Hoffnung verbreitet, dass es nützlich sein wird,
 * jedoch OHNE JEDE GEWÄHRLEISTUNG; sogar ohne die implizite Gewährleistung
 * der MARKTREIFE oder der VERWENDBARKEIT FÜR EINEN BESTIMMTEN ZWECK.
 * Weitere Details finden Sie in der GNU General Public License.
 *
 * Sie sollten eine Kopie der GNU General Public License zusammen mit diesem
 * Programm erhalten haben. Falls nicht, siehe <https://www.gnu.org/licenses/>.



Features:
 - GUI-Feld für X-Display
 - GUI-Feld / Datei-Dialog für Hostfile-Pfad
 - Einstellungen in ~/.xdmcp_chooser_qt.conf
 - eigenes Passwortfenster für sudo X -query
 - Terminal-Ausgabe wird live angezeigt
 - laufende XDMCP-Sitzung kann beendet werden
 - Lokale X-Server erkennen, Hostliste verwalten, Scan optional
"""



import sys, os, socket, threading, subprocess, json
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QListWidget, QRadioButton, QButtonGroup, QMessageBox,
    QInputDialog, QFileDialog, QTextEdit, QDialog
)
from PyQt5.QtCore import Qt

CHOOSER_CONFIG = os.path.expanduser('~/.xdmcp_chooser_qt.conf')
DEFAULT_HOSTS_PATH = os.path.expanduser('~/.xdmcp_hosts')

# --- Utility functions ---
def scan_host_udp(ip, timeout=0.2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(b'XDMCP\x00', (ip, 177))
        sock.recvfrom(1024)
        return True
    except:
        return False
    finally:
        sock.close()

def parse_range(text):
    text = text.strip()
    if '-' in text:
        base = '.'.join(text.split('.')[:3])
        start = int(text.split('.')[-1].split('-')[0])
        end = int(text.split('-')[-1])
        return [f"{base}.{i}" for i in range(start, end+1)]
    return [text]

def detect_local_xservers():
    servers = []
    try:
        output = subprocess.check_output(['ps', '-e', '-o', 'cmd']).decode(errors='ignore')
        for line in output.splitlines():
            if 'X ' in line or 'Xorg' in line:
                for p in line.split():
                    if p.startswith(':') and p[1:].isdigit():
                        servers.append(f"localhost {p}")
    except Exception:
        pass
    seen = set(); res = []
    for s in servers:
        if s not in seen:
            seen.add(s); res.append(s)
    return res

def load_hosts_from(path):
    hosts = []
    if os.path.exists(path):
        try:
            with open(path, 'r') as f:
                for ln in f:
                    ln = ln.strip()
                    if ln and not ln.startswith('#'):
                        hosts.append(ln)
        except Exception:
            pass
    return hosts

def save_hosts_to(path, hosts):
    try:
        d = os.path.dirname(path)
        if d and not os.path.exists(d):
            os.makedirs(d, exist_ok=True)
        with open(path, 'w') as f:
            for h in hosts:
                f.write(h.strip() + "\n")
        return True
    except Exception:
        return False

def load_chooser_config():
    cfg = {}
    if os.path.exists(CHOOSER_CONFIG):
        try:
            with open(CHOOSER_CONFIG,'r') as f:
                cfg = json.load(f)
        except Exception:
            cfg = {}
    return cfg

def save_chooser_config(cfg):
    try:
        with open(CHOOSER_CONFIG,'w') as f:
            json.dump(cfg, f, indent=2)
        return True
    except Exception:
        return False

# --- Terminal-Fenster für XDMCP ---
class TerminalWindow(QDialog):
    def __init__(self, cmd, password=None):
        super().__init__()
        self.setWindowTitle("XDMCP Session")
        self.resize(800, 600)
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.text = QTextEdit()
        self.text.setReadOnly(True)
        self.layout.addWidget(self.text)

        self.stop_btn = QPushButton("Stop Session")
        self.stop_btn.clicked.connect(self.stop_process)
        self.layout.addWidget(self.stop_btn)

        self.cmd = cmd
        self.process = None
        self.password = password

        self.start_process()

    def start_process(self):
        def run():
            try:
                if self.password:
                    self.process = subprocess.Popen(
                        self.cmd,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1
                    )
                    # Passwort nur einmal senden
                    self.process.stdin.write(self.password + '\n')
                    self.process.stdin.flush()
                else:
                    self.process = subprocess.Popen(
                        self.cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1
                    )
                for line in self.process.stdout:
                    self.text.append(line.rstrip())
            except Exception as e:
                self.text.append(f"Error: {e}")
        threading.Thread(target=run, daemon=True).start()

    def stop_process(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.text.append("Session terminated.")

# --- Main GUI ---
class ChooserQt(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("XDMCP / XPRA Chooser — editable display & hostfile")
        self.resize(640, 480)

        cfg = load_chooser_config()
        self.hosts_path = cfg.get('hosts_path', DEFAULT_HOSTS_PATH)
        self.x_display = cfg.get('x_display', ':1')
        self.xpra_user = cfg.get('xpra_user', os.getlogin() if hasattr(os, 'getlogin') else 'user')

        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        # Hostfile path chooser
        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("Hostfile (one host per line):"))
        self.path_edit = QLineEdit(self.hosts_path)
        path_layout.addWidget(self.path_edit)
        self.path_btn = QPushButton("Choose...")
        self.path_btn.clicked.connect(self.choose_hostfile)
        path_layout.addWidget(self.path_btn)
        self.layout.addLayout(path_layout)

        # X-display & xpra user
        disp_layout = QHBoxLayout()
        disp_layout.addWidget(QLabel("X display for X -query (e.g. :1):"))
        self.display_edit = QLineEdit(self.x_display)
        self.display_edit.setMaximumWidth(80)
        disp_layout.addWidget(self.display_edit)
        disp_layout.addWidget(QLabel("  xpra user:"))
        self.xpra_user_edit = QLineEdit(self.xpra_user)
        self.xpra_user_edit.setMaximumWidth(160)
        disp_layout.addWidget(self.xpra_user_edit)
        self.save_cfg_btn = QPushButton("Save Settings")
        self.save_cfg_btn.clicked.connect(self.save_settings)
        disp_layout.addWidget(self.save_cfg_btn)
        self.layout.addLayout(disp_layout)

        # Subnet scan
        top_layout = QHBoxLayout()
        top_layout.addWidget(QLabel("Subnet (opt., e.g. 192.168.178.1-254):"))
        self.subnet_edit = QLineEdit(cfg.get('last_subnet','192.168.178.1-254'))
        top_layout.addWidget(self.subnet_edit)
        self.scan_button = QPushButton("Scan")
        self.scan_button.clicked.connect(self.start_scan)
        top_layout.addWidget(self.scan_button)
        self.layout.addLayout(top_layout)

        # Host list
        self.list_widget = QListWidget()
        self.layout.addWidget(self.list_widget)
        self.status_label = QLabel("Ready.")
        self.layout.addWidget(self.status_label)

        # Host management
        manage_layout = QHBoxLayout()
        self.add_btn = QPushButton("Add Host")
        self.add_btn.clicked.connect(self.add_host_dialog)
        self.remove_btn = QPushButton("Remove Selected")
        self.remove_btn.clicked.connect(self.remove_selected)
        self.save_btn = QPushButton("Save Hosts")
        self.save_btn.clicked.connect(self.save_hostfile)
        manage_layout.addWidget(self.add_btn)
        manage_layout.addWidget(self.remove_btn)
        manage_layout.addWidget(self.save_btn)
        self.layout.addLayout(manage_layout)

        # Connection mode
        mode_layout = QHBoxLayout()
        self.xdmcp_radio = QRadioButton("XDMCP (X -query)")
        self.xdmcp_radio.setChecked(True)
        self.xpra_radio = QRadioButton("Xpra (ssh)")
        self.mode_group = QButtonGroup()
        self.mode_group.addButton(self.xdmcp_radio); self.mode_group.addButton(self.xpra_radio)
        mode_layout.addWidget(self.xdmcp_radio); mode_layout.addWidget(self.xpra_radio)
        self.layout.addLayout(mode_layout)

        xpra_layout = QHBoxLayout()
        xpra_layout.addWidget(QLabel("xpra display:"))
        self.xpra_display_edit = QLineEdit(cfg.get('xpra_display','100'))
        self.xpra_display_edit.setMaximumWidth(80)
        xpra_layout.addWidget(self.xpra_display_edit)
        self.layout.addLayout(xpra_layout)

        # Action buttons
        act_layout = QHBoxLayout()
        self.connect_btn = QPushButton("Connect")
        self.connect_btn.clicked.connect(self.connect_selected)
        self.refresh_btn = QPushButton("Refresh (reload hosts)")
        self.refresh_btn.clicked.connect(self.reload_list)
        self.quit_btn = QPushButton("Quit")
        self.quit_btn.clicked.connect(self.close)
        act_layout.addWidget(self.connect_btn); act_layout.addWidget(self.refresh_btn); act_layout.addWidget(self.quit_btn)
        self.layout.addLayout(act_layout)

        self.reload_list()

    # --- Hostfile management ---
    def choose_hostfile(self):
        fn, _ = QFileDialog.getSaveFileName(self, "Choose hostfile path", self.hosts_path, "Text files (*.txt);;All files (*)")
        if fn:
            self.path_edit.setText(fn)
            self.hosts_path = fn
            self.reload_list()

    def save_settings(self):
        self.hosts_path = self.path_edit.text().strip() or DEFAULT_HOSTS_PATH
        self.x_display = self.display_edit.text().strip() or ':1'
        self.xpra_user = self.xpra_user_edit.text().strip() or self.xpra_user
        cfg = {
            'hosts_path': self.hosts_path,
            'x_display': self.x_display,
            'xpra_user': self.xpra_user,
            'xpra_display': self.xpra_display_edit.text().strip(),
            'last_subnet': self.subnet_edit.text().strip()
        }
        ok = save_chooser_config(cfg)
        if ok:
            self.status_label.setText(f"Settings saved to {CHOOSER_CONFIG}")
        else:
            QMessageBox.critical(self, "Save failed", f"Could not write {CHOOSER_CONFIG}")

    def reload_list(self):
        self.list_widget.clear()
        for s in detect_local_xservers():
            self.list_widget.addItem(s)
        hosts = load_hosts_from(self.hosts_path)
        for h in hosts:
            self.list_widget.addItem(h)
        self.status_label.setText(f"Loaded {len(hosts)} hosts from {self.hosts_path}")

    def add_host_dialog(self):
        text, ok = QInputDialog.getText(self, "Add Host", "Host (IP or hostname):")
        if ok and text.strip():
            self.list_widget.addItem(text.strip())
            self.status_label.setText("Added host: " + text.strip())

    def remove_selected(self):
        items = self.list_widget.selectedItems()
        if not items:
            QMessageBox.warning(self, "Remove", "No selection")
            return
        for it in items:
            if str(it.text()).startswith("localhost "):
                QMessageBox.warning(self, "Remove", "Cannot remove detected local X servers.")
                continue
            self.list_widget.takeItem(self.list_widget.row(it))
        self.status_label.setText("Removed selected host(s)")

    def save_hostfile(self):
        hosts = []
        for i in range(self.list_widget.count()):
            txt = self.list_widget.item(i).text()
            if not txt.startswith("localhost "):
                hosts.append(txt)
        ok = save_hosts_to(self.hosts_path, hosts)
        if ok:
            self.status_label.setText(f"Saved {len(hosts)} hosts to {self.hosts_path}")
        else:
            QMessageBox.critical(self, "Save failed", f"Could not write {self.hosts_path}")

    def start_scan(self):
        self.scan_button.setEnabled(False)
        self.status_label.setText("Scanning subnet...")
        threading.Thread(target=self._scan_thread, daemon=True).start()

    def _scan_thread(self):
        ips = parse_range(self.subnet_edit.text())
        found = []
        for ip in ips:
            if scan_host_udp(ip):
                found.append(ip)
        self.list_widget.clear()
        for s in detect_local_xservers():
            self.list_widget.addItem(s)
        hosts = load_hosts_from(self.hosts_path)
        for h in hosts:
            self.list_widget.addItem(h)
        for ip in found:
            if ip not in hosts:
                self.list_widget.addItem(ip)
        self.status_label.setText(f"Scan complete: {len(found)} discovered (added to list)")
        self.scan_button.setEnabled(True)

    # --- Sudo Passwort-Popup ---
    def ask_sudo_password(self):
        password, ok = QInputDialog.getText(
            self, "Sudo Password",
            "Enter your sudo password:",
            QLineEdit.Password
        )
        if ok and password:
            return password
        return None

    # --- Connect logic ---
    def connect_selected(self):
        items = self.list_widget.selectedItems()
        if not items:
            QMessageBox.warning(self, "Connect", "Please select a host first.")
            return
        sel = items[0].text()

        if sel.startswith("localhost "):
            display = sel.split()[1]
            if self.xdmcp_radio.isChecked():
                try:
                    env = os.environ.copy()
                    env['DISPLAY'] = display
                    subprocess.Popen(['startplasma-x11'], env=env)
                    self.status_label.setText(f"Started local session on {display}")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to start local session: {e}")
            else:
                try:
                    subprocess.Popen(['xpra', 'attach', display])
                    self.status_label.setText(f"xpra attach {display}")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to attach xpra: {e}")
            return

        ip = sel
        x_display = self.display_edit.text().strip() or ':1'
        if self.xdmcp_radio.isChecked():
            password = self.ask_sudo_password()
            if not password:
                self.status_label.setText("Sudo password not provided, canceled.")
                return
            cmd = ['sudo', '-S', 'X', '-query', ip, x_display]
            term = TerminalWindow(cmd, password)
            term.show()
        else:
            user = self.xpra_user_edit.text().strip() or self.xpra_user
            display = self.xpra_display_edit.text().strip() or '100'
            cmd = ['xpra', 'attach', f"ssh:{user}@{ip}:{display}"]
            try:
                subprocess.Popen(cmd)
                self.status_label.setText("Started: " + " ".join(cmd))
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not start command: {e}")

import logging
LOGFILE = os.path.expanduser("~/.xdmcp_chooser_qt.log")
logging.basicConfig(
    filename=LOGFILE,
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logging.info("=== XDMCP Chooser gestartet ===")

def main():
    app = QApplication(sys.argv)
    try:
        w = ChooserQt()
        w.show()
        sys.exit(app.exec_())
    except Exception as e:
        logging.exception("Fatal error in ChooserQt")
        QMessageBox.critical(None, "Fatal Error",
                             f"Chooser crashed:\n{e}\n\nBitte prüfe das Logfile:\n{LOGFILE}")
        sys.exit(1)

if __name__ == '__main__':
    main()
