#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Native macOS non-activating floating 2FA & One-Click Autofill HUD for Camoufox Studio browser windows.
# - Uses NSWindowStyleMaskNonactivatingPanel so clicking Fill Email / Fill Password / Fill 2FA
#   NEVER steals focus from the active Firefox input field!
# - Computes live RFC 6238 SHA-1 TOTP codes locally every 500ms.
# - Only visible while its owning browser PID is frontmost (so 13 open browsers never stack 13 HUDs!).
# - Reads secrets from a 0600 payload file and deletes it immediately on startup (never exposed in ps args).

import base64
import hashlib
import hmac
import json
import os
import struct
import subprocess
import sys
import time

import AppKit
import Foundation
import objc


def compute_totp(secret_or_uri: str, step_offset: int = 0):
    raw = (secret_or_uri or "").strip()
    if not raw:
        return None, 0
    if raw.lower().startswith("otpauth://"):
        import urllib.parse
        q = urllib.parse.parse_qs(urllib.parse.urlparse(raw).query)
        raw = (q.get("secret") or [""])[0]
    cleaned = "".join(ch for ch in raw.upper() if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    if len(cleaned) < 8:
        return None, 0
    pad = "=" * ((8 - len(cleaned) % 8) % 8)
    try:
        key = base64.b32decode(cleaned + pad)
    except Exception:
        return None, 0
    now = int(time.time())
    step = (now // 30) + step_offset
    remaining = 30 - (now % 30)
    msg = struct.pack(">Q", step)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code_int:06d}", remaining


def is_pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def paste_into_active_input(text: str, press_enter: bool = False):
    if not text:
        return
    pb = AppKit.NSPasteboard.generalPasteboard()
    prev = pb.stringForType_(AppKit.NSPasteboardTypeString)
    pb.clearContents()
    pb.setString_forType_(text, AppKit.NSPasteboardTypeString)

    script = 'tell application "System Events" to keystroke "v" using command down'
    if press_enter:
        script = (
            'tell application "System Events"\n'
            '  keystroke "v" using command down\n'
            '  delay 0.08\n'
            '  key code 36\n'
            'end tell'
        )
    subprocess.Popen(["osascript", "-e", script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def restore():
        if prev is not None:
            cur = pb.stringForType_(AppKit.NSPasteboardTypeString)
            if cur == text:
                pb.clearContents()
                pb.setString_forType_(prev, AppKit.NSPasteboardTypeString)

    Foundation.NSTimer.scheduledTimerWithTimeInterval_repeats_block_(0.45, False, lambda _t: restore())


class DraggableHudView(AppKit.NSView):
    def mouseDown_(self, event):
        win = self.window()
        if win:
            win.performWindowDragWithEvent_(event)


class HudController(Foundation.NSObject):
    def initWithPayload_(self, payload):
        self = objc.super(HudController, self).init()
        if self is None:
            return None
        self.payload = payload
        self.target_pid = int(payload.get("pid") or 0)
        self.serial = str(payload.get("serial") or "•")
        self.email = str(payload.get("email") or "").strip()
        self.password = str(payload.get("password") or "")
        self.totp_secret = str(payload.get("totp") or "").strip()
        self.has_totp = compute_totp(self.totp_secret)[0] is not None
        self.dismissed = False
        self.flash_until = 0.0
        self.flash_text = ""
        self.panel = None
        self.totp_btn = None
        self.status_lbl = None
        self._build_panel()
        return self

    @objc.python_method
    def _make_btn(self, title, x, y, w, h, action, bg_rgba, fg_rgba=(1.0, 1.0, 1.0, 0.96), font_size=11.5, mono=False):
        btn = AppKit.NSButton.alloc().initWithFrame_(Foundation.NSMakeRect(x, y, w, h))
        btn.setTitle_(title)
        btn.setBezelStyle_(AppKit.NSBezelStyleInline)
        btn.setBordered_(False)
        btn.setWantsLayer_(True)
        btn.layer().setBackgroundColor_(AppKit.NSColor.colorWithCalibratedRed_green_blue_alpha_(*bg_rgba).CGColor())
        btn.layer().setCornerRadius_(7.0)
        font = (
            AppKit.NSFont.monospacedDigitSystemFontOfSize_weight_(font_size, AppKit.NSFontWeightBold)
            if mono
            else AppKit.NSFont.systemFontOfSize_weight_(font_size, AppKit.NSFontWeightSemibold)
        )
        attrs = {
            AppKit.NSFontAttributeName: font,
            AppKit.NSForegroundColorAttributeName: AppKit.NSColor.colorWithCalibratedRed_green_blue_alpha_(*fg_rgba),
        }
        btn.setAttributedTitle_(Foundation.NSAttributedString.alloc().initWithString_attributes_(title, attrs))
        btn.setTarget_(self)
        btn.setAction_(action)
        return btn

    @objc.python_method
    def _set_btn_text(self, btn, title, fg_rgba=(1.0, 1.0, 1.0, 0.96), font_size=12.0, mono=True):
        font = (
            AppKit.NSFont.monospacedDigitSystemFontOfSize_weight_(font_size, AppKit.NSFontWeightBold)
            if mono
            else AppKit.NSFont.systemFontOfSize_weight_(font_size, AppKit.NSFontWeightSemibold)
        )
        attrs = {
            AppKit.NSFontAttributeName: font,
            AppKit.NSForegroundColorAttributeName: AppKit.NSColor.colorWithCalibratedRed_green_blue_alpha_(*fg_rgba),
        }
        btn.setAttributedTitle_(Foundation.NSAttributedString.alloc().initWithString_attributes_(title, attrs))

    @objc.python_method
    def _build_panel(self):
        # Compute dynamic width based on available fields
        h = 38
        x = 10
        controls = []

        # Serial badge
        badge_text = f"#{self.serial}"
        badge_w = max(36, 16 + len(badge_text) * 8)
        badge = AppKit.NSTextField.labelWithString_(badge_text)
        badge.setFrame_(Foundation.NSMakeRect(x, 8, badge_w, 22))
        badge.setAlignment_(AppKit.NSTextAlignmentCenter)
        badge.setFont_(AppKit.NSFont.boldSystemFontOfSize_(11.5))
        badge.setTextColor_(AppKit.NSColor.whiteColor())
        badge.setWantsLayer_(True)
        badge.layer().setBackgroundColor_(AppKit.NSColor.colorWithCalibratedRed_green_blue_alpha_(0.05, 0.58, 0.53, 1.0).CGColor())
        badge.layer().setCornerRadius_(11.0)
        controls.append(badge)
        x += badge_w + 8

        if self.email:
            btn_email = self._make_btn("⚡ 填账号", x, 6, 70, 26, "onFillEmail:", (0.15, 0.39, 0.92, 0.92))
            controls.append(btn_email)
            x += 76

        if self.password:
            btn_pass = self._make_btn("⚡ 填密码", x, 6, 70, 26, "onFillPass:", (0.22, 0.25, 0.34, 0.95))
            controls.append(btn_pass)
            x += 76

        if self.has_totp:
            self.totp_btn = self._make_btn(
                "2FA ------ · --s", x, 6, 134, 26, "onCopyTotp:",
                (0.06, 0.34, 0.31, 0.95), (0.56, 0.98, 0.88, 1.0), 12.0, True
            )
            controls.append(self.totp_btn)
            x += 140

            btn_fill_totp = self._make_btn("⚡ 填2FA", x, 6, 66, 26, "onFillTotp:", (0.05, 0.58, 0.53, 0.95))
            controls.append(btn_fill_totp)
            x += 72

        close_btn = self._make_btn("×", x, 7, 24, 24, "onCloseHud:", (0.30, 0.32, 0.38, 0.65), (0.85, 0.88, 0.92, 0.9), 13.0, False)
        controls.append(close_btn)
        x += 32

        total_w = x
        screen = AppKit.NSScreen.mainScreen()
        sf = screen.visibleFrame() if screen else Foundation.NSMakeRect(0, 0, 1440, 900)
        px = sf.origin.x + sf.size.width - total_w - 28
        py = sf.origin.y + sf.size.height - h - 18

        style = (
            AppKit.NSWindowStyleMaskBorderless
            | AppKit.NSWindowStyleMaskNonactivatingPanel
            | AppKit.NSWindowStyleMaskUtilityWindow
        )
        panel = AppKit.NSPanel.alloc().initWithContentRect_styleMask_backing_defer_(
            Foundation.NSMakeRect(px, py, total_w, h),
            style,
            AppKit.NSBackingStoreBuffered,
            False,
        )
        panel.setLevel_(AppKit.NSFloatingWindowLevel)
        panel.setFloatingPanel_(True)
        panel.setBecomesKeyOnlyIfNeeded_(True)
        panel.setHidesOnDeactivate_(False)
        panel.setOpaque_(False)
        panel.setBackgroundColor_(AppKit.NSColor.clearColor())
        panel.setHasShadow_(True)
        panel.setCollectionBehavior_(
            AppKit.NSWindowCollectionBehaviorCanJoinAllSpaces
            | AppKit.NSWindowCollectionBehaviorFullScreenAuxiliary
        )

        root = DraggableHudView.alloc().initWithFrame_(Foundation.NSMakeRect(0, 0, total_w, h))
        root.setWantsLayer_(True)
        root.layer().setBackgroundColor_(AppKit.NSColor.colorWithCalibratedRed_green_blue_alpha_(0.08, 0.10, 0.14, 0.93).CGColor())
        root.layer().setCornerRadius_(12.0)
        root.layer().setBorderWidth_(1.0)
        root.layer().setBorderColor_(AppKit.NSColor.colorWithCalibratedRed_green_blue_alpha_(0.13, 0.72, 0.65, 0.55).CGColor())

        for ctrl in controls:
            root.addSubview_(ctrl)

        panel.setContentView_(root)
        self.panel = panel
        self._refresh_totp()

    @objc.python_method
    def _flash(self, msg: str):
        self.flash_text = msg
        self.flash_until = time.time() + 1.1
        self._refresh_totp()

    @objc.python_method
    def _refresh_totp(self):
        if not self.totp_btn:
            return
        if time.time() < self.flash_until and self.flash_text:
            self._set_btn_text(self.totp_btn, self.flash_text, (1.0, 0.96, 0.65, 1.0), 11.5, False)
            return
        code, rem = compute_totp(self.totp_secret)
        if code:
            formatted = f"2FA {code[:3]} {code[3:]} · {rem:02d}s"
            fg = (1.0, 0.72, 0.35, 1.0) if rem <= 6 else (0.56, 0.98, 0.88, 1.0)
            self._set_btn_text(self.totp_btn, formatted, fg, 12.0, True)

    def onFillEmail_(self, _sender):
        paste_into_active_input(self.email, press_enter=False)
        self._flash("✓ 已填入账号")

    def onFillPass_(self, _sender):
        paste_into_active_input(self.password, press_enter=False)
        self._flash("✓ 已填入密码")

    def onCopyTotp_(self, _sender):
        code, _rem = compute_totp(self.totp_secret)
        if code:
            pb = AppKit.NSPasteboard.generalPasteboard()
            pb.clearContents()
            pb.setString_forType_(code, AppKit.NSPasteboardTypeString)
            self._flash(f"✓ 已复制 {code}")

    def onFillTotp_(self, _sender):
        code, _rem = compute_totp(self.totp_secret)
        if code:
            paste_into_active_input(code, press_enter=False)
            self._flash(f"✓ 已填 {code}")

    def onCloseHud_(self, _sender):
        self.dismissed = True
        if self.panel:
            self.panel.orderOut_(None)
        AppKit.NSApplication.sharedApplication().terminate_(None)

    def onTick_(self, _timer):
        if self.dismissed or not is_pid_alive(self.target_pid):
            AppKit.NSApplication.sharedApplication().terminate_(None)
            return
        self._refresh_totp()
        front = AppKit.NSWorkspace.sharedWorkspace().frontmostApplication()
        front_pid = front.processIdentifier() if front else -1
        if front_pid == self.target_pid:
            if not self.panel.isVisible():
                self.panel.orderFrontRegardless()
        else:
            if self.panel.isVisible():
                self.panel.orderOut_(None)


def main():
    if len(sys.argv) < 2:
        sys.exit(1)
    payload_path = sys.argv[1]
    try:
        with open(payload_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    finally:
        try:
            os.remove(payload_path)
        except OSError:
            pass

    app = AppKit.NSApplication.sharedApplication()
    # Accessory policy = no Dock icon, no menu bar takeover
    app.setActivationPolicy_(AppKit.NSApplicationActivationPolicyAccessory)

    ctrl = HudController.alloc().initWithPayload_(payload)
    Foundation.NSTimer.scheduledTimerWithTimeInterval_target_selector_userInfo_repeats_(
        0.4, ctrl, "onTick:", None, True
    )
    app.run()


if __name__ == "__main__":
    main()
