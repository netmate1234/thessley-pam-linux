"""Thessley Login admin: a small window to see and manage phone login on this computer.

Runs as the ordinary user. Everything that needs root goes through one polkit prompt (pkexec admin-helper); the
two steps that need a typed secret (adding a phone, linking the keyring) open a terminal, so no password ever
passes through this window.

    thessley-pam-admin
"""

import datetime
import json
import os
import shlex
import shutil
import subprocess
import sys
import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

HELPER = "/usr/local/lib/thessley-pam/admin-helper"
UUID = "thessley-passkey-login@eagleeye-intelligence.com"
EXTENSION_DIR = f"/usr/share/gnome-shell/extensions/{UUID}"
GREETER = "/etc/gdm3/greeter.dconf-defaults"
PAM_DIR = "/etc/pam.d"
ADMIN_CMD = "sudo /usr/local/sbin/thessley-pam"
TERMINALS = (("gnome-terminal", ["--"]), ("ptyxis", ["--"]), ("x-terminal-emulator", ["-e"]), ("xterm", ["-e"]))

OK, WARN, OFF = "ok", "warn", "off"
ICONS = {OK: "object-select-symbolic", WARN: "dialog-warning-symbolic", OFF: "window-close-symbolic"}


def _read(path: str) -> str:
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def _security_dir_has_module() -> bool:
    return any(os.path.exists(os.path.join(d, "pam_thessley_authtok.so"))
               for d in ("/lib/x86_64-linux-gnu/security", "/usr/lib/x86_64-linux-gnu/security", "/lib/security",
                         "/usr/lib/security", "/lib/aarch64-linux-gnu/security", "/usr/lib/aarch64-linux-gnu/security"))


def session_extension_enabled() -> bool:
    try:
        out = subprocess.run(["gsettings", "get", "org.gnome.shell", "enabled-extensions"], capture_output=True,
                             text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return False
    return UUID in out


def local_status(pam_dir: str = PAM_DIR, extension_dir: str = EXTENSION_DIR, greeter: str = GREETER,
                 session_enabled=session_extension_enabled, module_present=_security_dir_has_module) -> list[tuple[str, str, str]]:
    """What can be seen without root: (title, OK/WARN/OFF, one line of explanation)."""
    gdm = _read(os.path.join(pam_dir, "gdm-thessley"))
    sudo = _read(os.path.join(pam_dir, "sudo"))
    rows = []
    if gdm and os.path.isdir(extension_dir):
        if UUID in _read(greeter):
            rows.append(("QR code on the login screen", OK, "Installed and switched on. The password box still works."))
        else:
            rows.append(("QR code on the login screen", WARN, "Installed, but not switched on for the login screen."))
    else:
        rows.append(("QR code on the login screen", OFF, "Not installed (sudo ./install-login.sh in thessley-pam-linux)."))
    rows.append(("QR code on your lock screen", OK if session_enabled() else OFF,
                 "Switched on for your account." if session_enabled()
                 else f"Switch it on with:  gnome-extensions enable {UUID}"))
    rows.append(("Phone approval for sudo", OK if "thessley" in sudo else OFF,
                 "sudo asks your phone after the password." if "thessley" in sudo else "sudo does not ask your phone."))
    wired = "pam_thessley_authtok" in gdm and module_present()
    rows.append(("Keyring unlock after a phone login", OK if wired else OFF,
                 "Wired into the login. Needs your password sealed in the TPM (see below)." if wired
                 else "Not wired in (sudo ./install-keyring.sh, then install-login.sh)."))
    return rows


def when(ts) -> str:
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "never"


class Backend:
    """Talks to the root helper through pkexec. Replaced by a fake in tests."""

    def _run(self, *args: str) -> dict:
        try:
            out = subprocess.run(["pkexec", HELPER, *args], capture_output=True, text=True, timeout=180)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"error": f"Could not run pkexec: {exc}"}
        if out.returncode in (126, 127):
            return {"error": "Cancelled."}
        try:
            return json.loads(out.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return {"error": (out.stderr or out.stdout).strip()[-200:] or "No answer from the helper."}

    def state(self) -> dict:
        return self._run("state")

    def remove_phone(self, credential_id: str) -> dict:
        return self._run("remove-phone", credential_id)

    def keyring_forget(self) -> dict:
        return self._run("keyring-forget")


def open_in_terminal(command: str) -> bool:
    """Run `command` in a terminal window that waits for a keypress before it closes."""
    script = f'{command}; echo; read -r -p "Press Enter to close this window. "'
    for name, opt in TERMINALS:
        path = shutil.which(name)
        if path:
            subprocess.Popen([path, *opt, "bash", "-c", script], start_new_session=True)
            return True
    return False


class AdminWindow(Adw.ApplicationWindow):
    def __init__(self, app, backend=None, status=local_status):
        super().__init__(application=app, title="Thessley Login", default_width=640, default_height=760)
        self.backend = backend or Backend()
        self.status_fn = status
        self.data: dict | None = None
        self.toasts = Adw.ToastOverlay()
        view = Adw.ToolbarView()
        header = Adw.HeaderBar()
        add = Gtk.Button(icon_name="list-add-symbolic", tooltip_text="Add a phone")
        add.connect("clicked", self.add_phone)
        header.pack_start(add)
        refresh = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text="Reload")
        refresh.connect("clicked", lambda *_: self.reload(privileged=True))
        header.pack_end(refresh)
        view.add_top_bar(header)
        self.page = Adw.PreferencesPage()
        view.set_content(self.page)
        self.toasts.set_child(view)
        self.set_content(self.toasts)
        self.groups: list[Adw.PreferencesGroup] = []
        self.render()

    # ---- drawing -------------------------------------------------------------------------------------------------

    def _fresh_group(self, title: str, description: str = "") -> Adw.PreferencesGroup:
        g = Adw.PreferencesGroup(title=title, description=description)
        self.page.add(g)
        self.groups.append(g)
        return g

    def render(self) -> None:
        for g in self.groups:
            self.page.remove(g)
        self.groups = []

        g = self._fresh_group("Login on this computer")
        for title, state, text in self.status_fn():
            row = Adw.ActionRow(title=title, subtitle=text)
            row.add_prefix(Gtk.Image(icon_name=ICONS[state]))
            g.add(row)
        if self.data and self.data.get("passwordless_sudo"):
            row = Adw.ActionRow(title="sudo needs no password", subtitle="Passwordless sudo is on for your account, so "
                                "the phone step never runs. Remove the NOPASSWD line from /etc/sudoers.d to use it.")
            row.add_prefix(Gtk.Image(icon_name=ICONS[WARN]))
            g.add(row)

        g = self._fresh_group("Phones that may approve logins")
        if self.data is None:
            row = Adw.ActionRow(title="Sign in to see your phones", subtitle="Reading them needs administrator rights.")
            btn = Gtk.Button(label="Unlock", valign=Gtk.Align.CENTER)
            btn.add_css_class("suggested-action")
            btn.connect("clicked", lambda *_: self.reload(privileged=True))
            row.add_suffix(btn)
            g.add(row)
        elif not self.data["phones"]:
            g.add(Adw.ActionRow(title="No phone is enrolled", subtitle="Press + at the top to add one."))
        else:
            for p in self.data["phones"]:
                row = Adw.ActionRow(title=p["label"] or "Unnamed phone",
                                    subtitle=f"added {when(p['enrolled_at'])} · last used {when(p['last_used'])} · {p['credential_id']}")
                trash = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER, tooltip_text="Remove this phone")
                trash.add_css_class("flat")
                trash.connect("clicked", self.confirm_remove, p)
                row.add_suffix(trash)
                g.add(row)

        g = self._fresh_group("Keyring", "The GNOME keyring holds saved Wi-Fi, browser and app passwords.")
        if self.data is None:
            g.add(Adw.ActionRow(title="Sign in first", subtitle="The sealed password can only be checked as administrator."))
        else:
            k = self.data["keyring"]
            if not k["sealed"]:
                row = Adw.ActionRow(title="Not linked", subtitle="A phone login leaves the keyring locked. Linking seals "
                                    "your login password in the TPM; it is released only after the phone approves.")
            elif k["readable"]:
                row = Adw.ActionRow(title="Linked", subtitle="A phone login unlocks the keyring.")
                row.add_prefix(Gtk.Image(icon_name=ICONS[OK]))
            else:
                row = Adw.ActionRow(title="Linked, but the TPM will not open it",
                                    subtitle="The Secure Boot state probably changed since it was sealed. Link it again.")
                row.add_prefix(Gtk.Image(icon_name=ICONS[WARN]))
            link = Gtk.Button(label="Link…" if not k["sealed"] or not k["readable"] else "Link again…", valign=Gtk.Align.CENTER)
            link.connect("clicked", self.link_keyring)
            row.add_suffix(link)
            if k["sealed"]:
                forget = Gtk.Button(label="Forget", valign=Gtk.Align.CENTER)
                forget.add_css_class("destructive-action")
                forget.connect("clicked", self.confirm_forget)
                row.add_suffix(forget)
            g.add(row)

    def toast(self, text: str) -> None:
        self.toasts.add_toast(Adw.Toast(title=text))

    # ---- actions -------------------------------------------------------------------------------------------------

    def reload(self, privileged: bool = False) -> bool:
        """Re-read the status; with `privileged`, also the phones and the keyring (one polkit prompt)."""
        if not privileged:
            self.render()
            return False

        def work():
            result = self.backend.state()
            GLib.idle_add(self.loaded, result)
        threading.Thread(target=work, daemon=True).start()
        return False

    def loaded(self, result: dict) -> bool:
        if "error" in result:
            self.toast(result["error"])
        else:
            self.data = result
        self.render()
        return False

    def add_phone(self, *_):
        if not open_in_terminal(f"{ADMIN_CMD} enroll"):
            self.toast("No terminal found. Run:  sudo thessley-pam enroll")
            return
        self.toast("Scan the code in the terminal window, then press Reload.")

    def link_keyring(self, *_):
        if not open_in_terminal(f"{ADMIN_CMD} keyring-link"):
            self.toast("No terminal found. Run:  sudo thessley-pam keyring-link")
            return
        self.toast("Type your login password in the terminal window, then press Reload.")

    def _confirm(self, heading: str, body: str, verb: str, then) -> None:
        dialog = Adw.AlertDialog(heading=heading)
        dialog.set_body(body)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("go", verb)
        dialog.set_response_appearance("go", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.connect("response", lambda _d, r: then() if r == "go" else None)
        dialog.present(self)

    def confirm_remove(self, _btn, phone: dict) -> None:
        self._confirm(f"Remove {phone['label'] or 'this phone'}?",
                      "It will no longer be able to approve logins or sudo on this computer. The app on the phone "
                      "keeps its entry until you remove it there too.",
                      "Remove", lambda: self._do(lambda: self.backend.remove_phone(phone["credential_id"]), "Removed."))

    def confirm_forget(self, *_) -> None:
        self._confirm("Forget the sealed password?",
                      "A phone login will leave the keyring locked until you link it again.",
                      "Forget", lambda: self._do(self.backend.keyring_forget, "Forgotten."))

    def _do(self, action, done_text: str) -> None:
        def work():
            result = action()
            fresh = self.backend.state() if "error" not in result else None
            GLib.idle_add(self.done, result, fresh, done_text)
        threading.Thread(target=work, daemon=True).start()

    def done(self, result: dict, fresh, done_text: str) -> bool:
        if "error" in result:
            self.toast(result["error"])
        else:
            self.toast(done_text)
            if fresh and "error" not in fresh:
                self.data = fresh
        self.render()
        return False


class AdminApp(Adw.Application):
    def __init__(self, backend=None, status=local_status):
        super().__init__(application_id=os.environ.get("THESSLEY_ADMIN_APP_ID", "se.thessley.PamAdmin"),
                         flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.backend, self.status = backend, status

    def do_activate(self):
        win = self.props.active_window or AdminWindow(self, self.backend, self.status)
        win.present()


def main() -> int:
    return AdminApp().run(sys.argv[:1])


if __name__ == "__main__":
    sys.exit(main())
