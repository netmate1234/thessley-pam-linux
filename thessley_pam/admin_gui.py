"""Thessley Login admin: a small window to see and manage phone login on this computer.

Runs as the ordinary user. Everything that needs root goes through one polkit prompt (pkexec admin-helper); the
two steps that need a typed secret (adding a phone, linking the keyring) open a terminal, so no password ever
passes through this window.

    thessley-pam-admin

What it can switch, each with its own switch: the QR code on the login screen, the QR code on your lock screen,
the phone step for sudo, and the keyring unlock after a phone login. Each phone has a switch (allowed to approve
or not) and a bin (forget it). The keyring link can be forgotten.
"""

import datetime
import json
import os
import re
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
PKEXEC_WAIT = 300  # seconds a person gets to type the administrator password

OK, WARN, OFF = "ok", "warn", "off"
ICONS = {OK: "object-select-symbolic", WARN: "dialog-warning-symbolic", OFF: "window-close-symbolic"}

# key, title; the first three can be switched with admin rights, "lock-qr" by you alone.
SWITCHES = (
    ("login-qr", "QR code on the login screen"),
    ("lock-qr", "QR code on your lock screen"),
    ("sudo-phone", "Phone approval for sudo"),
    ("keyring-unlock", "Keyring unlock after a phone login"),
)
NEEDS_ADMIN = {"login-qr", "sudo-phone", "keyring-unlock"}


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


def set_lock_qr(on: bool) -> bool:
    """Your own lock-screen switch: no administrator needed. True if it worked."""
    try:
        r = subprocess.run(["gnome-extensions", "enable" if on else "disable", UUID], capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0


def sudo_without_password() -> bool:
    """True if `sudo` runs for this account without asking (a NOPASSWD rule). Then the window needs no
    administrator prompt at all: it runs the helper through sudo."""
    try:
        return subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def polkit_problem(pam_dir: str = PAM_DIR) -> str:
    """Why the administrator password prompt cannot work on this computer, if we can tell from here (and sudo
    does not already do the job without one).

    A pam_yubico line with the `debug` option in common-auth writes its debug text on standard output. The
    polkit prompt reads the PAM helper's standard output as a protocol, so every such line makes GNOME abort the
    sign-in ("Unknown line ... from helper") and no prompt ever appears.
    """
    if pam_dir == PAM_DIR and sudo_without_password():
        return ""
    for line in _read(os.path.join(pam_dir, "common-auth")).splitlines():
        if line.lstrip().startswith("#"):
            continue
        if re.search(r"\bpam_yubico\.so\b", line) and re.search(r"\bdebug\b", line):
            return ("The administrator password prompt is broken on this computer: the pam_yubico line in "
                    "/etc/pam.d/common-auth has the option 'debug', whose text makes every GNOME sign-in prompt "
                    "abort. Remove the word 'debug' from that line (as administrator, from a terminal), then "
                    "press Unlock again.")
    return ""


def local_status(pam_dir: str = PAM_DIR, extension_dir: str = EXTENSION_DIR, greeter: str = GREETER,
                 session_enabled=session_extension_enabled, module_present=_security_dir_has_module) -> list[tuple[str, str, str, str]]:
    """What can be seen without root: (key, title, OK/WARN/OFF, one line of explanation), one row per switch."""
    titles = dict(SWITCHES)
    gdm = _read(os.path.join(pam_dir, "gdm-thessley"))
    sudo = _read(os.path.join(pam_dir, "sudo"))
    installed = bool(gdm) and os.path.isdir(extension_dir)
    rows = []
    if installed:
        on = UUID in _read(greeter)
        rows.append(("login-qr", titles["login-qr"], OK if on else OFF,
                     "On. The password box still works." if on else "Installed, but switched off for the login screen."))
    else:
        rows.append(("login-qr", titles["login-qr"], OFF, "Not installed (sudo ./install-login.sh in thessley-pam-linux)."))
    lock_on = session_enabled()
    rows.append(("lock-qr", titles["lock-qr"], OK if lock_on else OFF,
                 "On for your account." if lock_on else "Off for your account."))
    sudo_live = any(l.split()[:1] == ["auth"] and "pam-helper" in l for l in sudo.splitlines())
    rows.append(("sudo-phone", titles["sudo-phone"], OK if sudo_live else OFF,
                 "sudo asks your phone after the password." if sudo_live else "sudo does not ask your phone."))
    keyring_live = any(l.split()[:1] == ["auth"] and "pam_thessley_authtok" in l for l in gdm.splitlines())
    rows.append(("keyring-unlock", titles["keyring-unlock"], OK if keyring_live and module_present() else OFF,
                 "Wired into the login. Needs your password sealed in the TPM (see below)." if keyring_live and module_present()
                 else "Not wired in."))
    return rows


def when(ts) -> str:
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "never"


class Backend:
    """Talks to the root helper through pkexec. Replaced by a fake in tests."""

    def __init__(self, use_sudo=sudo_without_password):
        self.use_sudo = use_sudo
        self._sudo = None

    def command(self, *args: str) -> list[str]:
        """sudo when it needs no password (no prompt at all), otherwise pkexec (one administrator prompt)."""
        if self._sudo is None:
            self._sudo = bool(self.use_sudo())
        return (["sudo", "-n", HELPER] if self._sudo else ["pkexec", HELPER]) + list(args)

    def _run(self, *args: str) -> dict:
        try:
            out = subprocess.run(self.command(*args), capture_output=True, text=True, timeout=PKEXEC_WAIT)
        except subprocess.TimeoutExpired:
            return {"error": "The administrator sign-in timed out. If no password box appeared, see the warning at the top."}
        except OSError as exc:
            return {"error": f"Could not run pkexec: {exc}"}
        if out.returncode == 126:
            return {"error": "Cancelled."}
        if out.returncode == 127:
            return {"error": "Not authorised."}
        try:
            return json.loads(out.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return {"error": (out.stderr or out.stdout).strip()[-200:] or "No answer from the helper."}

    def state(self) -> dict:
        return self._run("state")

    def remove_phone(self, credential_id: str) -> dict:
        return self._run("remove-phone", credential_id)

    def set_phone(self, credential_id: str, enabled: bool) -> dict:
        return self._run("set-phone", credential_id, "on" if enabled else "off")

    def set_feature(self, name: str, on: bool) -> dict:
        return self._run("set-feature", name, "on" if on else "off")

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
    def __init__(self, app, backend=None, status=local_status, problem=polkit_problem, lock_switch=set_lock_qr):
        super().__init__(application=app, title="Thessley Login", default_width=680, default_height=820)
        self.backend = backend or Backend()
        self.status_fn, self.problem_fn, self.lock_switch = status, problem, lock_switch
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

    def _fresh_group(self, title: str = "", description: str = "") -> Adw.PreferencesGroup:
        g = Adw.PreferencesGroup(title=title, description=description)
        self.page.add(g)
        self.groups.append(g)
        return g

    def _switch(self, active: bool, sensitive: bool, on_toggle, tooltip: str = "") -> Gtk.Switch:
        sw = Gtk.Switch(active=active, sensitive=sensitive, valign=Gtk.Align.CENTER, tooltip_text=tooltip or None)
        sw.connect("state-set", lambda _s, state: on_toggle(state) or False)  # False: let the switch show the new state
        return sw

    def render(self) -> None:
        for g in self.groups:
            self.page.remove(g)
        self.groups = []

        problem = self.problem_fn()
        if problem:
            g = self._fresh_group()
            row = Adw.ActionRow(title="Administrator sign-in is broken", subtitle=problem)
            row.add_prefix(Gtk.Image(icon_name=ICONS[WARN]))
            row.set_subtitle_selectable(True)
            row.set_subtitle_lines(0)
            g.add(row)

        g = self._fresh_group("Login on this computer")
        features = (self.data or {}).get("features", {})
        server_keys = {"login-qr": "login_qr", "sudo-phone": "sudo_phone", "keyring-unlock": "keyring_unlock"}
        for key, title, state, text in self.status_fn():
            if key in server_keys and features.get(server_keys[key]) in ("on", "off"):
                state = OK if features[server_keys[key]] == "on" else OFF  # the helper saw the real file
            row = Adw.ActionRow(title=title, subtitle=text)
            row.add_prefix(Gtk.Image(icon_name=ICONS[state]))
            if key == "lock-qr":
                known = os.path.isdir(EXTENSION_DIR) or state == OK
                row.add_suffix(self._switch(state == OK, known, lambda on: self.toggle_lock(on), "Your own lock screen"))
            elif key in NEEDS_ADMIN:
                if features.get(server_keys[key]) in ("on", "off"):
                    row.add_suffix(self._switch(state == OK, True, lambda on, k=key: self.toggle_feature(k, on)))
                else:
                    row.set_subtitle(text + " Unlock below to change this.")
                    row.add_suffix(self._switch(state == OK, False, lambda on: None))
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
                off = p.get("disabled")
                row = Adw.ActionRow(title=(p["label"] or "Unnamed phone") + ("  (switched off)" if off else ""),
                                    subtitle=f"added {when(p['enrolled_at'])} · last used {when(p['last_used'])} · {p['credential_id']}")
                row.add_suffix(self._switch(not off, True, lambda on, cid=p["credential_id"]: self.toggle_phone(cid, on),
                                            "Allowed to approve logins and sudo"))
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
                forget = Gtk.Button(label="Forget", valign=Gtk.Align.CENTER, tooltip_text="Delete the sealed password")
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
        if self.problem_fn():
            self.toast("Fix the administrator sign-in first (see the warning at the top).")
        if not (isinstance(self.backend, Backend) and self.backend.command("x")[0] == "sudo"):
            self.toast("Waiting for the administrator password…")

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

    def toggle_lock(self, on: bool) -> None:
        if not self.lock_switch(on):
            self.toast("Could not change your lock-screen setting.")
        GLib.idle_add(self.render)

    def toggle_feature(self, key: str, on: bool) -> None:
        self._do(lambda: self.backend.set_feature(key, on), "Switched on." if on else "Switched off.")

    def toggle_phone(self, credential_id: str, on: bool) -> None:
        self._do(lambda: self.backend.set_phone(credential_id, on), "Phone allowed." if on else "Phone switched off.")

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
                      "Its key is forgotten here: it can never approve logins or sudo on this computer again, and "
                      "adding it back means scanning a new code. The app on the phone keeps its entry until you remove "
                      "it there too. To keep the key but stop it approving, switch it off instead.",
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
    def __init__(self, backend=None, status=local_status, problem=polkit_problem, lock_switch=set_lock_qr):
        super().__init__(application_id=os.environ.get("THESSLEY_ADMIN_APP_ID", "se.thessley.PamAdmin"),
                         flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.backend, self.status, self.problem, self.lock_switch = backend, status, problem, lock_switch

    def do_activate(self):
        win = self.props.active_window or AdminWindow(self, self.backend, self.status, self.problem, self.lock_switch)
        win.present()


def main() -> int:
    return AdminApp().run(sys.argv[:1])


if __name__ == "__main__":
    sys.exit(main())
