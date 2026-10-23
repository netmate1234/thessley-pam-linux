// Thessley Passkey Login: a QR code under the password field on the GNOME login and lock screens.
//
// Works like a fingerprint reader does in GNOME: next to the password conversation (gdm-password), GDM runs a
// second, background PAM conversation, here gdm-thessley. Its only auth step is pam-helper --login, which
// prints one line "THESSLEY-QR thessleypam://login?..." and waits for the phone's signed approval. This
// extension turns that line into a QR code. Whichever conversation succeeds first logs in, so typing the
// password always keeps working.
//
// Only users listed in /etc/thessley-pam-enrolled get the background conversation; nobody else sees a QR
// code or any change. If the phone conversation ends (timeout, deny, phone unreachable) it is restarted, with
// a minimum spacing so a fast-failing helper can't spin.
//
// Patches GNOME Shell 50's gdm/util.js ShellUserVerifier and gdm/authPrompt.js AuthPrompt. Every override
// calls straight through for any service other than gdm-thessley.

import Clutter from 'gi://Clutter';
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import St from 'gi://St';

import {Extension, InjectionManager} from 'resource:///org/gnome/shell/extensions/extension.js';
import * as AuthPrompt from 'resource:///org/gnome/shell/gdm/authPrompt.js';
import * as GdmUtil from 'resource:///org/gnome/shell/gdm/util.js';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import {QrCode} from 'resource:///org/gnome/shell/ui/qrCode.js';

const SERVICE = 'gdm-thessley';
const MARKER = 'THESSLEY-QR ';
const ENROLLED = '/etc/thessley-pam-enrolled';
const MIN_RESTART_SPACING_MS = 5000;
// The link creates a dense QR code, so keep modules large enough to scan while leaving room for
// the username and authentication controls above it. A 320 px code gives about 6 px per module.
function qrSize() {
    const height = Main.layoutManager.primaryMonitor?.height ?? 1080;
    return Math.max(280, Math.min(420, Math.round(height * 0.32)));
}

function isEnrolled(userName) {
    if (!userName)
        return false;
    try {
        const [, bytes] = GLib.file_get_contents(ENROLLED);
        return new TextDecoder().decode(bytes).split('\n').includes(userName);
    } catch {
        return false; // no list: nobody is enrolled
    }
}

function cancelRestart(verifier) {
    if (verifier._thessleyRestartId) {
        GLib.source_remove(verifier._thessleyRestartId);
        verifier._thessleyRestartId = 0;
    }
}

function startPhoneService(verifier) {
    const hasVerifier = Boolean(verifier._userVerifier);
    const enrolled = isEnrolled(verifier._userName);
    const active = verifier._activeServices.has(SERVICE);
    const unavailable = verifier._unavailableServices.has(SERVICE);
    if (!hasVerifier || !enrolled || active || unavailable || verifier._thessleyStarting) {
        console.log(`[Thessley] QR start skipped: verifier=${hasVerifier} enrolled=${enrolled} active=${active} unavailable=${unavailable} starting=${Boolean(verifier._thessleyStarting)}`);
        return;
    }
    console.log('[Thessley] Starting QR PAM conversation');
    verifier._thessleyStarting = true;
    verifier._thessleyStartedAt = GLib.get_monotonic_time() / 1000;
    verifier._startService(SERVICE)
        .catch(logError)
        .finally(() => verifier._thessleyStarting = false);
}

export default class ThessleyPasskeyLogin extends Extension {
    enable() {
        this._injections = new InjectionManager();
        const extensionPath = this.path;
        console.log(`[Thessley] Extension enabled in mode ${Main.sessionMode.currentMode}`);
        const verifierProto = GdmUtil.ShellUserVerifier.prototype;
        const promptProto = AuthPrompt.AuthPrompt.prototype;

        // Start our conversation alongside the fingerprint one.
        this._injections.overrideMethod(verifierProto, '_startBackgroundServices', orig => function (...args) {
            orig.call(this, ...args);
            startPhoneService(this);
        });

        // UnlockDialog can begin a verifier without going through the greeter's
        // background-service setup. Start the phone flow when the verifier itself
        // begins, after it has selected the user; the guard makes this safe alongside
        // the greeter hook above.
        this._injections.overrideMethod(verifierProto, 'begin', orig => function (...args) {
            const result = orig.call(this, ...args);
            startPhoneService(this);
            return result;
        });

        // Unlock uses asynchronous reauthentication-channel setup. At begin(),
        // _userVerifier may not exist yet; _beginVerification runs only after
        // that channel is ready and the username has been selected.
        this._injections.overrideMethod(verifierProto, '_beginVerification', orig => function (...args) {
            const result = orig.call(this, ...args);
            startPhoneService(this);
            return result;
        });

        // Our conversation's only message is the QR line; never queue it as on-screen text.
        this._injections.overrideMethod(verifierProto, '_onInfo', orig => function (client, serviceName, info) {
            if (serviceName !== SERVICE)
                return orig.call(this, client, serviceName, info);
            if (info.startsWith(MARKER)) {
                console.log('[Thessley] QR link received from PAM');
                this.emit('thessley-qr', info.slice(MARKER.length).trim());
            }
            return undefined;
        });

        this._injections.overrideMethod(verifierProto, '_onProblem', orig => function (client, serviceName, problem) {
            if (serviceName === SERVICE)
                return undefined;
            return orig.call(this, client, serviceName, problem);
        });

        // A failed phone conversation must not count as a failed login, reset the dialog or touch the
        // password field: hide the QR code and start a fresh request, spaced out.
        this._injections.overrideMethod(verifierProto, '_verificationFailed', orig => function (serviceName, shouldRetry) {
            if (serviceName !== SERVICE)
                return orig.call(this, serviceName, shouldRetry);
            this._activeServices.delete(SERVICE);
            this.emit('thessley-qr', null);
            cancelRestart(this);
            const elapsed = GLib.get_monotonic_time() / 1000 - (this._thessleyStartedAt ?? 0);
            const delay = Math.max(0, MIN_RESTART_SPACING_MS - elapsed);
            this._thessleyRestartId = GLib.timeout_add(GLib.PRIORITY_DEFAULT, delay, () => {
                this._thessleyRestartId = 0;
                startPhoneService(this);
                return GLib.SOURCE_REMOVE;
            });
            return Promise.resolve();
        });

        for (const name of ['cancel', 'clear', '_onReset', 'destroy']) {
            this._injections.overrideMethod(verifierProto, name, orig => function (...args) {
                cancelRestart(this);
                this.emit?.('thessley-qr', null);
                return orig.call(this, ...args);
            });
        }

        // Show the QR code in whichever prompt (login screen or lock screen) owns the verifier.
        this._injections.overrideMethod(promptProto, 'begin', orig => function (...args) {
            if (!this._thessleyQrSignalId && this._userVerifier) {
                this._thessleyQrSignalId = this._userVerifier.connect('thessley-qr',
                    (_v, url) => showQr(this, url, extensionPath));
            }
            const result = orig.call(this, ...args);
            // The unlock dialog does not always start background PAM services through
            // ShellUserVerifier._startBackgroundServices (the greeter does). Start the
            // phone conversation here too; startPhoneService guards duplicate starts.
            if (this._userVerifier)
                startPhoneService(this._userVerifier);
            return result;
        });

        this._injections.overrideMethod(promptProto, '_onDestroy', orig => function (...args) {
            if (this._thessleyQrSignalId && this._userVerifier)
                this._userVerifier.disconnect(this._thessleyQrSignalId);
            this._thessleyQrSignalId = 0;
            return orig.call(this, ...args);
        });
    }

    disable() {
        this._injections?.clear();
        this._injections = null;
    }
}

function showQr(prompt, url, extensionPath) {
    if (!url) {
        prompt._thessleyBox?.hide();
        return;
    }
    if (!prompt._thessleyBox) {
        const box = new St.BoxLayout({
            orientation: Clutter.Orientation.VERTICAL,
            x_align: Clutter.ActorAlign.CENTER,
            x_expand: false,
            y_expand: false,
            style_class: 'thessley-qr-box',
        });
        const brand = new St.BoxLayout({
            orientation: Clutter.Orientation.HORIZONTAL,
            x_align: Clutter.ActorAlign.CENTER,
            style_class: 'thessley-qr-brand',
        });
        const logo = new St.Icon({
            gicon: Gio.icon_new_for_string(`${extensionPath}/logo.png`),
            icon_size: 36,
            style_class: 'thessley-qr-logo',
        });
        brand.add_child(logo);
        brand.add_child(new St.Label({
            text: 'Or scan with Thessley Passkey',
            x_align: Clutter.ActorAlign.CENTER,
            style_class: 'thessley-qr-label',
        }));
        box.add_child(brand);
        const size = qrSize();
        const qr = new QrCode({
            width: size,
            height: size,
            x_expand: false,
            y_expand: false,
            url,
            style_class: 'qr-code thessley-qr-code',
        });
        box.add_child(qr);
        // Keep the QR within GNOME's input well. Adding it directly to AuthPrompt puts it
        // beside the full-height user well and can make the prompt allocate a blank panel
        // beneath the code on the greeter.
        (prompt._inputWell ?? prompt).add_child(box);
        prompt._thessleyBox = box;
        prompt._thessleyQr = qr;
        box.connect('destroy', () => {
            prompt._thessleyBox = null;
            prompt._thessleyQr = null;
        });
    } else {
        prompt._thessleyQr.url = url;
    }
    prompt._thessleyBox.show();
}
