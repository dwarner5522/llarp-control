#!/usr/bin/env python3
"""LLARP Control: a small GTK front end for llarpd.

Turns the daemon on and off, shows its log output and network address, manages
the list of bootstrap files handed to it via LLARP_BOOTSTRAP_FILEPATHS, and can
run it as an exit node. Shares its settings and the running daemon with llarpctl.
"""

import subprocess
import sys
import threading
import time
from pathlib import Path

import cairo
import gi

gi.require_version("Gdk", "3.0")
gi.require_version("Gtk", "3.0")
from gi.repository import Gdk, GLib, Gtk, Pango  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
import llarp_core as core  # noqa: E402
from llarp_core import LlarpError  # noqa: E402

APP_NAME = "LLARP Control"
MAX_LOG_LINES = 5000

# colours sampled from the Lokinet logo artwork: near-black backdrop, lime -> green -> teal diamond
LIME = (0x6F / 255, 0xB3 / 255, 0x4C / 255)
GREEN = (0x12 / 255, 0x87 / 255, 0x41 / 255)
TEAL = (0x00 / 255, 0x62 / 255, 0x61 / 255)

THEME_CSS = b"""
@define-color llarp_bg #191919;
@define-color llarp_surface #202120;
@define-color llarp_raised #2a2c2a;
@define-color llarp_hover #333733;
@define-color llarp_border #393d39;
@define-color llarp_well #111211;
@define-color llarp_text #e4e8e2;
@define-color llarp_dim #8e968c;
@define-color llarp_lime #6fb34c;
@define-color llarp_bright #86cf5f;
@define-color llarp_green #128741;
@define-color llarp_teal #006261;

window, dialog, .background, messagedialog, filechooser, filechooser .sidebar {
    background-color: @llarp_bg;
    color: @llarp_text;
}
label { color: @llarp_text; }
.dim-label, label.dim-label { color: @llarp_dim; opacity: 1; }
*:selected, selection, entry selection, textview text selection {
    background-color: @llarp_green;
    color: #ffffff;
}

/* header */
label.brand { color: @llarp_lime; font-size: 20px; font-weight: 800; letter-spacing: 3px; }
.status { font-weight: bold; font-size: 15px; }
.on, .vpn-on { color: @llarp_bright; }
.off { color: @llarp_dim; }
.busy, .vpn-wait { color: #d6b450; }
.err, .vpn-bad { color: #e5675c; }
.bs-name { font-weight: bold; }
.addr { font-family: monospace; }

/* tabs */
notebook { background-color: transparent; }
notebook > header { background-color: @llarp_bg; border-color: @llarp_border; box-shadow: none; }
notebook > header tab {
    color: @llarp_dim; background: transparent; border: none; box-shadow: none;
    padding: 6px 16px; min-height: 24px;
}
notebook > header tab label { color: @llarp_dim; }
notebook > header tab:hover { box-shadow: inset 0 -3px alpha(@llarp_lime, 0.35); }
notebook > header tab:hover label { color: @llarp_text; }
notebook > header tab:checked { box-shadow: inset 0 -3px @llarp_lime; }
notebook > header tab:checked label { color: @llarp_lime; font-weight: bold; }
notebook > stack:not(:only-child) { background-color: @llarp_surface; border-color: @llarp_border; }

/* panels and lists */
frame > border, .frame { border-color: @llarp_border; border-radius: 4px; }
frame.exit-panel > border {
    border-color: alpha(@llarp_lime, 0.55);
    background-color: alpha(@llarp_green, 0.10);
}
list, list row, listbox, listbox row { background-color: @llarp_surface; color: @llarp_text; }
list row:hover { background-color: @llarp_raised; }
scrolledwindow, viewport { background-color: transparent; }
separator { background-color: @llarp_border; }

/* text inputs */
entry {
    background-image: none; background-color: @llarp_well; color: @llarp_text;
    border-color: @llarp_border; box-shadow: none; caret-color: @llarp_lime;
}
entry:focus { border-color: @llarp_lime; box-shadow: inset 0 0 0 1px alpha(@llarp_lime, 0.6); }
entry:disabled { background-color: @llarp_surface; color: @llarp_dim; }
entry image { color: @llarp_dim; }

/* buttons */
button {
    background-image: none; background-color: @llarp_raised; color: @llarp_text;
    border-color: @llarp_border; box-shadow: none; text-shadow: none; -gtk-icon-shadow: none;
}
button label { color: inherit; }
button:hover { background-color: @llarp_hover; border-color: @llarp_green; }
button:active, button:checked { background-color: @llarp_green; border-color: @llarp_lime; color: #ffffff; }
button:disabled { background-color: @llarp_surface; border-color: @llarp_raised; color: #5c625b; }
button:disabled label { color: #5c625b; }
button.flat { background-color: transparent; border-color: transparent; color: @llarp_dim; }
button.flat:hover { background-color: @llarp_raised; color: @llarp_lime; }
button.suggested-action, dialog .dialog-action-area button:last-child {
    background-image: linear-gradient(to right, @llarp_lime, @llarp_green);
    border-color: @llarp_lime; color: #0d1a0d;
}

/* switches: the logo's gradient */
switch {
    background-image: none; background-color: #2d302d; border-color: @llarp_border;
    color: transparent; box-shadow: none;
}
switch:checked {
    background-image: linear-gradient(to right, @llarp_lime, @llarp_green 55%, @llarp_teal);
    border-color: @llarp_green;
}
switch slider {
    background-image: none; background-color: #cfd5cd; border-color: #0f100f; box-shadow: none;
}
switch:checked slider { background-color: #f3f8f0; }
switch:disabled { opacity: 0.5; }

/* check boxes */
check {
    background-image: none; background-color: @llarp_well; border-color: @llarp_border;
    color: transparent; box-shadow: none;
}
check:hover { border-color: @llarp_lime; }
check:checked { background-color: @llarp_green; border-color: @llarp_lime; color: #ffffff; }
checkbutton label { color: @llarp_text; }

/* combo + menus + tooltips */
combobox button.combo { background-color: @llarp_raised; }
menu, .menu, .context-menu, popover, popover.background {
    background-color: @llarp_raised; color: @llarp_text; border-color: @llarp_border;
}
menuitem { color: @llarp_text; }
menuitem:hover { background-color: @llarp_green; color: #ffffff; }
tooltip, tooltip.background {
    background-color: #0e0f0e; color: @llarp_text; border: 1px solid @llarp_green; border-radius: 4px;
}
tooltip label { color: @llarp_text; }

/* log: green terminal on black */
textview, textview text { background-color: #0d0e0d; color: #a9d991; }
textview.log, textview.log text { font-family: monospace; font-size: 10pt; }

scrollbar { background-color: transparent; border: none; }
scrollbar slider { background-color: #3d423c; border-radius: 6px; min-width: 7px; min-height: 7px; }
scrollbar slider:hover { background-color: @llarp_green; }
"""


def draw_diamond(cr, size, glow=True):
    """The logo's motif: a glowing diamond shaded lime -> teal."""
    c = size / 2
    r = size * (0.36 if glow else 0.48)
    if glow:
        halo = cairo.RadialGradient(c, c, r * 0.4, c, c, size / 2)
        halo.add_color_stop_rgba(0, *LIME, 0.55)
        halo.add_color_stop_rgba(1, *LIME, 0.0)
        cr.set_source(halo)
        cr.paint()
    cr.move_to(c, c - r)
    cr.line_to(c + r, c)
    cr.line_to(c, c + r)
    cr.line_to(c - r, c)
    cr.close_path()
    fill = cairo.LinearGradient(c - r, c, c + r, c)
    fill.add_color_stop_rgb(0, *LIME)
    fill.add_color_stop_rgb(0.5, *GREEN)
    fill.add_color_stop_rgb(1, *TEAL)
    cr.set_source(fill)
    cr.fill()


def diamond_pixbuf(size):
    surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, size, size)
    draw_diamond(cairo.Context(surface), size, glow=False)
    return Gdk.pixbuf_get_from_surface(surface, 0, 0, size, size)
INITIAL_LOG_BYTES = 256 * 1024  # how much of an existing log to show on open


class BootstrapRow(Gtk.ListBoxRow):
    def __init__(self, app, entry):
        super().__init__()
        self.entry = entry
        box = Gtk.Box(spacing=8, margin=6)

        check = Gtk.CheckButton(active=entry.get("enabled", True))
        check.set_tooltip_text("Use this bootstrap")
        check.connect("toggled", lambda w: app.set_bootstrap_enabled(entry, w.get_active()))
        box.pack_start(check, False, False, 0)

        text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        name = Gtk.Label(label=entry["name"], xalign=0)
        name.get_style_context().add_class("bs-name")
        text.pack_start(name, False, False, 0)
        detail = Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.MIDDLE)
        detail.get_style_context().add_class("dim-label")
        ok, summary, details = core.describe_bootstrap(entry)
        if ok:
            detail.set_text(summary)
            detail.set_tooltip_text("\n".join(details))
        else:
            detail.set_markup(f"<span foreground='#e5675c'>{GLib.markup_escape_text(summary)}</span>")
        text.pack_start(detail, False, False, 0)
        box.pack_start(text, True, True, 0)

        remove = Gtk.Button.new_from_icon_name("user-trash-symbolic", Gtk.IconSize.BUTTON)
        remove.set_relief(Gtk.ReliefStyle.NONE)
        remove.set_tooltip_text("Remove")
        remove.connect("clicked", lambda _: app.remove_bootstrap(entry))
        box.pack_end(remove, False, False, 0)
        self.add(box)


class App(Gtk.Window):
    def __init__(self):
        super().__init__(title=APP_NAME)
        self.set_default_size(820, 640)
        self.set_icon_list([diamond_pixbuf(n) for n in (16, 32, 48, 64, 128)])
        self.ctl = core.Controller()
        self.restart_pending = False
        self.was_running = self.ctl.is_running()
        self.log_tail = {"ino": None, "pos": 0}

        css = Gtk.CssProvider()
        css.load_from_data(THEME_CSS)
        Gtk.StyleContext.add_provider_for_screen(
            self.get_screen(), css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10, margin=12)
        self.add(root)
        root.pack_start(self.build_power_bar(), False, False, 0)
        root.pack_start(self.build_address_bar(), False, False, 0)
        root.pack_start(self.build_vpn_bar(), False, False, 0)
        root.pack_start(self.build_exit_panel(), False, False, 0)

        notebook = Gtk.Notebook()
        notebook.append_page(self.build_bootstrap_page(), Gtk.Label(label="Bootstraps"))
        notebook.append_page(self.build_log_page(), Gtk.Label(label="Log"))
        notebook.append_page(self.build_settings_page(), Gtk.Label(label="Settings"))
        root.pack_start(notebook, True, True, 0)
        self.notebook = notebook

        self.connect("delete-event", self.on_close)
        self.refresh_bootstraps()
        self.tail_log(initial=True)
        self.refresh_all()
        GLib.timeout_add(500, self.poll_log)
        GLib.timeout_add_seconds(1, self.tick)

        others = self.ctl.unmanaged_pids()
        if others:
            self.ctl.note(
                f"llarpd is already running outside this app (pid {', '.join(map(str, others))}). "
                "Stop it first or the new instance will fail to bind."
            )

    # ---- power bar

    def build_power_bar(self):
        bar = Gtk.Box(spacing=12)
        logo = Gtk.DrawingArea()
        logo.set_size_request(34, 34)
        logo.connect("draw", lambda w, cr: draw_diamond(cr, min(w.get_allocated_width(), w.get_allocated_height())))
        bar.pack_start(logo, False, False, 0)
        title = Gtk.Label(label="LLARP", xalign=0)
        title.get_style_context().add_class("brand")
        bar.pack_start(title, False, False, 0)

        self.status_label = Gtk.Label(xalign=0)
        self.status_label.get_style_context().add_class("status")
        bar.pack_start(self.status_label, True, True, 0)

        self.restart_btn = Gtk.Button(label="Restart")
        self.restart_btn.set_tooltip_text("Restart llarpd to apply bootstrap/setting changes")
        self.restart_btn.connect("clicked", lambda _: self.restart())
        bar.pack_end(self.restart_btn, False, False, 0)

        self.power = Gtk.Switch(valign=Gtk.Align.CENTER)
        self.power.set_tooltip_text("Turn llarpd on / off")
        self.power_handler = self.power.connect("notify::active", self.on_power_toggled)
        bar.pack_end(self.power, False, False, 0)
        return bar

    def build_address_bar(self):
        bar = Gtk.Box(spacing=8)
        bar.pack_start(Gtk.Label(label="Address:"), False, False, 0)
        self.addr_label = Gtk.Label(xalign=0, selectable=True, ellipsize=Pango.EllipsizeMode.MIDDLE)
        self.addr_label.get_style_context().add_class("addr")
        bar.pack_start(self.addr_label, True, True, 0)
        self.addr_copy = Gtk.Button.new_from_icon_name("edit-copy-symbolic", Gtk.IconSize.BUTTON)
        self.addr_copy.set_relief(Gtk.ReliefStyle.NONE)
        self.addr_copy.set_tooltip_text("Copy address")
        self.addr_copy.connect("clicked", lambda _: self.copy_address())
        bar.pack_start(self.addr_copy, False, False, 0)

        self.exit_switch = Gtk.Switch(valign=Gtk.Align.CENTER)
        self.exit_switch.set_tooltip_text("Let other LLARP users route their internet traffic through this machine")
        self.exit_handler = self.exit_switch.connect("notify::active", self.on_exit_toggled)
        bar.pack_end(self.exit_switch, False, False, 0)
        bar.pack_end(Gtk.Label(label="Exit node"), False, False, 0)
        return bar

    def build_vpn_bar(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        bar = Gtk.Box(spacing=8)
        bar.pack_start(Gtk.Label(label="VPN via exit:"), False, False, 0)
        self.vpn_combo = Gtk.ComboBoxText.new_with_entry()
        self.vpn_combo.set_hexpand(True)
        self.vpn_entry = self.vpn_combo.get_child()
        self.vpn_entry.set_placeholder_text("exit address, e.g. abc…xyz.loki or name.loki")
        self.vpn_entry.get_style_context().add_class("addr")
        self.vpn_entry.connect("activate", lambda _: self.vpn_switch.set_active(True))
        bar.pack_start(self.vpn_combo, True, True, 0)

        auth = Gtk.Button.new_from_icon_name("dialog-password-symbolic", Gtk.IconSize.BUTTON)
        auth.set_relief(Gtk.ReliefStyle.NONE)
        auth.set_tooltip_text("Auth code for a private exit")
        auth.connect("clicked", lambda _: self.edit_exit_auth())
        bar.pack_start(auth, False, False, 0)
        forget = Gtk.Button.new_from_icon_name("user-trash-symbolic", Gtk.IconSize.BUTTON)
        forget.set_relief(Gtk.ReliefStyle.NONE)
        forget.set_tooltip_text("Remove this exit from the saved list")
        forget.connect("clicked", lambda _: self.forget_exit())
        bar.pack_start(forget, False, False, 0)

        self.vpn_switch = Gtk.Switch(valign=Gtk.Align.CENTER)
        self.vpn_switch.set_tooltip_text("Send all your internet traffic through this exit node")
        self.vpn_handler = self.vpn_switch.connect("notify::active", self.on_vpn_toggled)
        bar.pack_end(self.vpn_switch, False, False, 0)
        box.pack_start(bar, False, False, 0)

        self.vpn_status = Gtk.Label(xalign=0)
        box.pack_start(self.vpn_status, False, False, 0)
        self.fill_vpn_combo()
        return box

    def fill_vpn_combo(self):
        """Reload the saved exits list, keeping whatever is typed in the entry."""
        typed = self.vpn_entry.get_text()
        self.vpn_combo.remove_all()
        for e in self.ctl.saved_exits():
            self.vpn_combo.append_text(e["address"])
        current = self.ctl.settings.get("use_exit")
        self.vpn_entry.set_text(current or typed or "")

    def on_vpn_toggled(self, switch, _param):
        ctl = self.ctl
        try:
            if switch.get_active():
                text = self.vpn_entry.get_text()
                if not text.strip():
                    raise LlarpError("Type or pick an exit address first.")
                ctl.set_vpn(text)
            else:
                ctl.set_vpn(None)
        except LlarpError as e:
            self.error(str(e))
            self.set_check(switch, self.vpn_handler, not switch.get_active())
            return
        self.fill_vpn_combo()
        if ctl.is_running():
            ctl.note("restarting llarpd to apply VPN change")
            self.restart()
        elif switch.get_active():
            self.start_daemon()
        self.refresh_all()

    def selected_exit(self):
        try:
            return self.ctl.normalize_exit(self.vpn_entry.get_text())
        except LlarpError as e:
            self.error(str(e))
            return None

    def edit_exit_auth(self):
        address = self.selected_exit()
        if not address:
            return
        dlg = Gtk.Dialog(title="Exit auth code", transient_for=self, modal=True)
        dlg.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Save", Gtk.ResponseType.OK)
        dlg.set_default_response(Gtk.ResponseType.OK)
        area = dlg.get_content_area()
        area.set_spacing(6)
        area.set_border_width(10)
        label = Gtk.Label(xalign=0, wrap=True)
        label.set_markup(
            f"Auth code for <tt>{GLib.markup_escape_text(address)}</tt>\n"
            "Only needed for private exits. Leave empty for public ones."
        )
        area.add(label)
        code = Gtk.Entry(activates_default=True, visibility=False, width_chars=40)
        code.set_text(self.ctl.exit_auth(address) or "")
        area.add(code)
        show = Gtk.CheckButton(label="Show")
        show.connect("toggled", lambda w: code.set_visibility(w.get_active()))
        area.add(show)
        dlg.show_all()
        resp = dlg.run()
        value = code.get_text().strip()
        dlg.destroy()
        if resp != Gtk.ResponseType.OK:
            return
        try:
            self.ctl.remember_exit(address, value)
        except LlarpError as e:
            self.error(str(e))
            return
        self.fill_vpn_combo()
        if self.ctl.settings.get("use_exit") == address and self.ctl.is_running():
            self.ctl.note("restarting llarpd to apply new exit auth code")
            self.restart()
        self.refresh_all()

    def forget_exit(self):
        address = self.selected_exit()
        if not address:
            return
        try:
            self.ctl.forget_exit(address)
        except LlarpError as e:
            self.error(str(e))
            return
        self.vpn_entry.set_text("")
        self.fill_vpn_combo()

    def refresh_vpn(self):
        st = self.ctl.vpn_status()
        self.set_check(self.vpn_switch, self.vpn_handler, st["state"] != "off")
        self.vpn_combo.set_sensitive(st["state"] == "off")
        ctx = self.vpn_status.get_style_context()
        for c in ("vpn-on", "vpn-wait", "vpn-bad", "dim-label"):
            ctx.remove_class(c)
        ctx.add_class(
            {"on": "vpn-on", "connecting": "vpn-wait", "pending": "vpn-wait", "trouble": "vpn-bad"}.get(
                st["state"], "dim-label"
            )
        )
        prefix = {"on": "● Connected: ", "trouble": "● Problem: ", "connecting": "● ", "pending": "● "}.get(
            st["state"], ""
        )
        self.vpn_status.set_text(prefix + st["detail"])

    def build_exit_panel(self):
        frame = Gtk.Frame()
        frame.get_style_context().add_class("exit-panel")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, margin=8)
        self.exit_info = Gtk.Label(xalign=0, wrap=True, selectable=True)
        box.pack_start(self.exit_info, False, False, 0)
        row = Gtk.Box(spacing=6)
        self.fwd_status = Gtk.Label(xalign=0, wrap=True)
        row.pack_start(self.fwd_status, True, True, 0)
        self.fwd_remove = Gtk.Button(label="Remove NAT…")
        self.fwd_remove.set_tooltip_text("Delete the NAT/forwarding rules this app added (asks for your password)")
        self.fwd_remove.connect("clicked", lambda _: self.set_forwarding(False))
        row.pack_end(self.fwd_remove, False, False, 0)
        self.fwd_enable = Gtk.Button(label="Enable forwarding…")
        self.fwd_enable.connect("clicked", lambda _: self.set_forwarding(True))
        row.pack_end(self.fwd_enable, False, False, 0)
        box.pack_start(row, False, False, 0)
        frame.add(box)
        frame.set_no_show_all(True)
        box.show_all()
        self.exit_panel = frame
        return frame

    @staticmethod
    def set_check(widget, handler, active):
        widget.handler_block(handler)
        widget.set_active(active)
        widget.handler_unblock(handler)

    def on_power_toggled(self, switch, _param):
        if switch.get_active():
            self.start_daemon()
        else:
            self.stop_daemon()

    # ---- periodic refresh

    def refresh_all(self):
        self.update_status()
        self.refresh_address()
        self.refresh_exit_panel()
        self.refresh_vpn()

    def update_status(self):
        ctl = self.ctl
        running = ctl.is_running()
        ctx = self.status_label.get_style_context()
        for c in ("on", "off", "busy", "err"):
            ctx.remove_class(c)
        if running and (ctl.stopping() or self.restart_pending):
            text, cls = ("Restarting…" if self.restart_pending else "Stopping…"), "busy"
        elif running:
            st = ctl.state()
            uptime = core.format_uptime(time.time() - st.get("started_at", time.time()))
            text = f"Running · pid {ctl.pid()} · up {uptime}"
            if ctl.settings.get("exit_node"):
                text += " · exit node"
            if ctl.changes_pending():
                text += " · restart to apply changes"
            cls = "on"
        else:
            text, cls = "Stopped", "off"
        self.status_label.set_text(text)
        ctx.add_class(cls)
        self.restart_btn.set_sensitive(running and not ctl.stopping())
        self.set_check(self.power, self.power_handler, running and not ctl.stopping())

    def tick(self):
        ctl = self.ctl
        if ctl.reload_if_changed():  # llarpctl changed something
            self.refresh_bootstraps()
            self.sync_settings_widgets()
            self.fill_vpn_combo()
        ctl.enforce_stop_timeout()
        running = ctl.is_running()
        if self.was_running and not running:
            self.on_daemon_exit()
        self.was_running = running
        self.refresh_all()
        return True

    def on_daemon_exit(self):
        st = self.ctl.state()
        if self.restart_pending:
            self.restart_pending = False
            self.start_daemon()
        elif not st.get("stop_requested_at"):
            self.notebook.set_current_page(1)
            self.error("llarpd stopped unexpectedly. See the Log tab for details.")

    # ---- daemon control

    def start_daemon(self):
        if self.ctl.is_running():
            return
        try:
            self.ctl.start()
        except LlarpError as e:
            self.error(str(e))
        self.was_running = self.ctl.is_running()
        self.refresh_all()

    def stop_daemon(self):
        if self.ctl.request_stop():
            self.refresh_all()

    def restart(self):
        if self.ctl.is_running():
            self.restart_pending = True
            self.ctl.request_stop()
            self.refresh_all()
        else:
            self.start_daemon()

    def on_close(self, *_):
        if not self.ctl.is_running():
            return False
        dlg = Gtk.MessageDialog(
            transient_for=self,
            message_type=Gtk.MessageType.QUESTION,
            text="llarpd is still running",
            secondary_text="Leave it running in the background (control it later with llarpctl or by reopening "
            "this window), or stop it?",
        )
        dlg.add_buttons("Cancel", 0, "Stop and quit", 2, "Leave running", 1)
        resp = dlg.run()
        dlg.destroy()
        if resp == 2:
            self.ctl.request_stop()
            return False
        return resp != 1

    # ---- address

    def refresh_address(self):
        addr, kind = self.ctl.address()
        if addr:
            self.addr_label.set_text(addr)
            self.addr_label.set_tooltip_text(
                "Permanent address (from key file)"
                if kind == "permanent"
                else "Temporary address: it changes every time llarpd starts. "
                "Enable “Keep the same address” in Settings to make it permanent."
            )
        else:
            self.addr_label.set_text(kind)
            self.addr_label.set_tooltip_text(
                "Enable “Keep the same address” in Settings to make it permanent." if "random" in kind else None
            )
        self.addr_copy.set_sensitive(bool(addr))

    def copy_address(self):
        addr, _ = self.ctl.address()
        if addr:
            Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).set_text(addr, -1)

    def on_persist_toggled(self, check):
        try:
            self.ctl.set_persistent_address(check.get_active())
        except LlarpError as e:
            self.error(str(e))
            self.set_check(check, self.persist_handler, not check.get_active())
        self.refresh_all()

    # ---- exit node

    def on_exit_toggled(self, switch, _param):
        on = switch.get_active()
        try:
            self.ctl.set_exit_node(on)
        except LlarpError as e:
            self.error(str(e))
            self.set_check(switch, self.exit_handler, not on)
            return
        self.sync_settings_widgets()
        if self.ctl.is_running():
            self.ctl.note("restarting llarpd to apply exit mode")
            self.restart()
        self.refresh_all()

    def refresh_exit_panel(self):
        ctl = self.ctl
        on = bool(ctl.settings.get("exit_node"))
        self.set_check(self.exit_switch, self.exit_handler, on)
        self.exit_panel.set_visible(on)
        if not on:
            return
        addr, _ = ctl.address()
        running = ctl.is_running()
        if addr and running:
            self.exit_info.set_markup(
                "Other users can route through you by adding this to their config:\n"
                f"<tt>[network]\nexit-node={GLib.markup_escape_text(addr)}</tt>"
            )
        elif addr:
            self.exit_info.set_markup(f"Exit address: <tt>{GLib.markup_escape_text(addr)}</tt> (start llarpd to serve)")
        else:
            self.exit_info.set_text("Exit address is created when llarpd starts.")

        target, why = ctl.nat_target()
        fwd = "on" if core.ip_forward_enabled() else "<b>off</b>"
        if target is None:
            nat = f"unknown ({why})"
        elif ctl.nat_applied() == target:
            nat = f"set up for {target[0]} via {target[1]}"
        else:
            nat = f"not set up by this app for {target[0]} via {target[1]}"
        self.fwd_status.set_markup(f"IP forwarding: {fwd} · NAT: {GLib.markup_escape_text(nat)}")
        self.fwd_enable.set_sensitive(target is not None)
        self.fwd_enable.set_tooltip_text(
            why or "Turn on IP forwarding and NAT the tunnel range out to the internet (asks for your password)"
        )
        self.fwd_remove.set_sensitive(target is not None)

    def set_forwarding(self, enable):
        ctl = self.ctl
        target, why = ctl.nat_target()
        if target is None:
            self.error(f"Can't change forwarding: {why}.")
            return
        script = ctl.forwarding_script(enable, target)
        try:
            argv = ctl.privileged_command(script, graphical=True)
        except LlarpError as e:
            self.error(str(e))
            return
        what = "enabling forwarding" if enable else "removing NAT rules"
        ctl.note(f"{what}: {script}")

        def work():
            try:
                res = subprocess.run(argv, capture_output=True, text=True)
            except OSError as e:
                GLib.idle_add(self.error, f"Failed to run {argv[0]}: {e}")
                return
            GLib.idle_add(done, res)

        def done(res):
            for line in (res.stdout + res.stderr).splitlines():
                ctl.note(f"  {line}")
            if res.returncode == 0:
                ctl.mark_nat(target if enable else None)
                ctl.note(f"{what}: done")
            elif res.returncode in (126, 127):
                ctl.note(f"{what}: cancelled")
            else:
                self.error(f"{what.capitalize()} failed (exit {res.returncode}). See the Log tab.")
            self.refresh_exit_panel()
            return False

        threading.Thread(target=work, daemon=True).start()

    # ---- bootstraps page

    def build_bootstrap_page(self):
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, margin=10)
        hint = Gtk.Label(xalign=0, wrap=True)
        hint.set_markup(
            "Bootstrap files are signed router contacts (<tt>.signed</tt>) used to join the network. "
            "Checked entries are passed to llarpd at start. With none checked, llarpd uses its config "
            "and built-in fallbacks."
        )
        page.pack_start(hint, False, False, 0)

        buttons = Gtk.Box(spacing=6)
        for label, cb in (
            ("Add file…", self.add_bootstrap_file),
            ("Add from URL…", self.add_bootstrap_url),
            ("Add bundled…", self.add_bootstrap_bundled),
        ):
            b = Gtk.Button(label=label)
            b.connect("clicked", lambda _, cb=cb: cb())
            buttons.pack_start(b, False, False, 0)
        page.pack_start(buttons, False, False, 0)

        self.bs_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        placeholder = Gtk.Label(label="No bootstraps added yet.", margin=20)
        placeholder.get_style_context().add_class("dim-label")
        placeholder.show()
        self.bs_list.set_placeholder(placeholder)
        scroll = Gtk.ScrolledWindow()
        scroll.add(self.bs_list)
        frame = Gtk.Frame()
        frame.add(scroll)
        page.pack_start(frame, True, True, 0)

        # drag-and-drop .signed files onto the list
        self.bs_list.drag_dest_set(Gtk.DestDefaults.ALL, [], 0)
        self.bs_list.drag_dest_add_uri_targets()
        self.bs_list.connect("drag-data-received", self.on_drop)
        return page

    def refresh_bootstraps(self):
        for child in self.bs_list.get_children():
            self.bs_list.remove(child)
        for entry in self.ctl.settings["bootstraps"]:
            self.bs_list.add(BootstrapRow(self, entry))
        self.bs_list.show_all()

    def set_bootstrap_enabled(self, entry, enabled):
        self.ctl.set_bootstrap_enabled(entry, enabled)
        self.update_status()

    def remove_bootstrap(self, entry):
        self.ctl.remove_bootstrap(entry)
        self.refresh_bootstraps()
        self.update_status()

    def guarded(self, fn, *args):
        """Run a controller call, showing LlarpError as a dialog. Returns success."""
        try:
            fn(*args)
        except LlarpError as e:
            self.error(str(e))
            return False
        self.refresh_bootstraps()
        self.update_status()
        return True

    def add_bootstrap_file(self):
        dlg = Gtk.FileChooserDialog(title="Add bootstrap file", transient_for=self, action=Gtk.FileChooserAction.OPEN)
        dlg.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Add", Gtk.ResponseType.OK)
        dlg.set_select_multiple(True)
        flt = Gtk.FileFilter()
        flt.set_name("Signed RCs (*.signed)")
        flt.add_pattern("*.signed")
        dlg.add_filter(flt)
        any_filter = Gtk.FileFilter()
        any_filter.set_name("All files")
        any_filter.add_pattern("*")
        dlg.add_filter(any_filter)
        if dlg.run() == Gtk.ResponseType.OK:
            for f in dlg.get_filenames():
                self.guarded(self.ctl.add_bootstrap_path, f)
        dlg.destroy()

    def on_drop(self, _w, _ctx, _x, _y, data, _info, _time):
        for uri in data.get_uris():
            fname, _ = GLib.filename_from_uri(uri)
            self.guarded(self.ctl.add_bootstrap_path, fname)

    def add_bootstrap_url(self):
        dlg = Gtk.Dialog(title="Add bootstrap from URL", transient_for=self, modal=True)
        dlg.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Download", Gtk.ResponseType.OK)
        dlg.set_default_response(Gtk.ResponseType.OK)
        area = dlg.get_content_area()
        area.set_spacing(6)
        area.set_border_width(10)
        area.add(Gtk.Label(label="URL of a .signed bootstrap file:", xalign=0))
        url_entry = Gtk.Entry(activates_default=True, width_chars=50, placeholder_text="https://…/bootstrap.signed")
        area.add(url_entry)
        dlg.show_all()
        resp = dlg.run()
        url = url_entry.get_text().strip()
        dlg.destroy()
        if resp != Gtk.ResponseType.OK or not url:
            return
        self.ctl.note(f"downloading {url}")

        def fetch():
            try:
                data, name = self.ctl.fetch_url(url)
            except LlarpError as e:
                GLib.idle_add(self.error, str(e))
                return
            GLib.idle_add(lambda: self.guarded(self.ctl.add_bootstrap_bytes, data, name) and False)

        threading.Thread(target=fetch, daemon=True).start()

    def add_bootstrap_bundled(self):
        files = self.ctl.bundled_bootstraps()
        if not files:
            self.error(f"No bundled bootstrap files found in {core.BUNDLED_DIR}")
            return
        menu = Gtk.Menu()
        for f in files:
            ok, summary, _ = core.describe_bootstrap({"file": str(f)})
            item = Gtk.MenuItem(label=f"{f.name}  ({summary.split(' · ')[1] if ok else 'invalid'})")
            item.connect("activate", lambda _, f=f: self.guarded(self.ctl.add_bootstrap_path, f))
            menu.append(item)
        menu.show_all()
        menu.popup_at_pointer(None)

    # ---- log page

    def build_log_page(self):
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, margin=10)
        self.log_buf = Gtk.TextBuffer()
        self.log_view = Gtk.TextView(buffer=self.log_buf, editable=False, cursor_visible=False, monospace=True)
        self.log_view.get_style_context().add_class("log")
        self.log_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        scroll = Gtk.ScrolledWindow()
        scroll.add(self.log_view)
        page.pack_start(scroll, True, True, 0)

        row = Gtk.Box(spacing=6)
        self.autoscroll = Gtk.CheckButton(label="Auto-scroll", active=True)
        row.pack_start(self.autoscroll, False, False, 0)
        path = Gtk.Label(label=str(core.LOG_FILE), selectable=True, ellipsize=Pango.EllipsizeMode.START)
        path.get_style_context().add_class("dim-label")
        row.pack_start(path, True, True, 0)
        clear = Gtk.Button(label="Clear view")
        clear.connect("clicked", lambda _: self.log_buf.set_text(""))
        row.pack_end(clear, False, False, 0)
        page.pack_start(row, False, False, 0)
        return page

    def poll_log(self):
        self.tail_log()
        return True

    def tail_log(self, initial=False):
        """Append new bytes of the shared log file to the view (handles rotation)."""
        t = self.log_tail
        try:
            st = core.LOG_FILE.stat()
        except OSError:
            return
        if st.st_ino != t["ino"] or st.st_size < t["pos"]:
            if t["ino"] is not None:
                self.log_buf.set_text("")  # new run: llarpd log was rotated
            t["ino"] = st.st_ino
            t["pos"] = max(0, st.st_size - INITIAL_LOG_BYTES) if initial else 0
        if st.st_size == t["pos"]:
            return
        with open(core.LOG_FILE, "rb") as f:
            f.seek(t["pos"])
            chunk = f.read()
        cut = chunk.rfind(b"\n") + 1
        t["pos"] += cut
        if cut:
            self.append_log(chunk[:cut].decode(errors="replace"))

    def append_log(self, text):
        buf = self.log_buf
        buf.insert(buf.get_end_iter(), text)
        excess = buf.get_line_count() - MAX_LOG_LINES
        if excess > 0:
            buf.delete(buf.get_start_iter(), buf.get_iter_at_line(excess))
        if self.autoscroll.get_active():
            buf.place_cursor(buf.get_end_iter())
            self.log_view.scroll_to_mark(buf.get_insert(), 0, False, 0, 0)

    # ---- settings page

    def build_settings_page(self):
        grid = Gtk.Grid(column_spacing=10, row_spacing=10, margin=14)
        self.setting_entries = {}

        def path_row(row, label, key, action):
            grid.attach(Gtk.Label(label=label, xalign=1), 0, row, 1, 1)
            entry = Gtk.Entry(text=self.ctl.settings[key], hexpand=True)
            entry.connect("changed", lambda w: self.set_setting(key, w.get_text()))
            grid.attach(entry, 1, row, 1, 1)
            browse = Gtk.Button(label="Browse…")

            def pick(_):
                dlg = Gtk.FileChooserDialog(title=label, transient_for=self, action=action)
                dlg.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Select", Gtk.ResponseType.OK)
                dlg.set_filename(entry.get_text())
                if dlg.run() == Gtk.ResponseType.OK:
                    entry.set_text(dlg.get_filename())
                dlg.destroy()

            browse.connect("clicked", pick)
            grid.attach(browse, 2, row, 1, 1)
            self.setting_entries[key] = entry

        path_row(0, "llarpd binary", "llarpd", Gtk.FileChooserAction.OPEN)
        path_row(1, "Config file", "config", Gtk.FileChooserAction.SAVE)

        grid.attach(Gtk.Label(label="Log level", xalign=1), 0, 2, 1, 1)
        self.level_combo = Gtk.ComboBoxText()
        for lv in core.LOG_LEVELS:
            self.level_combo.append(lv, lv)
        self.level_combo.set_active_id(self.ctl.settings.get("log_level", "info"))
        self.level_handler = self.level_combo.connect(
            "changed", lambda w: self.set_setting("log_level", w.get_active_id())
        )
        grid.attach(self.level_combo, 1, 2, 1, 1)

        self.router_check = Gtk.CheckButton(label="Router mode (--router) — run as a relay instead of a client")
        self.router_check.set_active(self.ctl.settings.get("router_mode", False))
        self.router_handler = self.router_check.connect("toggled", self.on_router_toggled)
        grid.attach(self.router_check, 1, 3, 2, 1)

        self.persist_check = Gtk.CheckButton(label="Keep the same .loki address across restarts")
        self.persist_check.set_tooltip_text(
            f"Stores a key file in llarpd's data dir via conf.d/{core.OVERRIDE_NAME}. Required for an exit node."
        )
        self.persist_check.set_active(self.ctl.keyfile_path() is not None)
        self.persist_handler = self.persist_check.connect("toggled", self.on_persist_toggled)
        grid.attach(self.persist_check, 1, 4, 2, 1)

        gen = Gtk.Button(label="Generate default config")
        gen.set_tooltip_text("Run llarpd --generate for the config path above (won't overwrite an existing file)")
        gen.connect("clicked", lambda _: self.generate_config())
        grid.attach(gen, 1, 5, 1, 1)

        note = Gtk.Label(xalign=0, wrap=True)
        note.get_style_context().add_class("dim-label")
        note.set_text(
            "Changes take effect the next time llarpd starts. "
            "Everything here can also be done from a terminal or over SSH with llarpctl."
        )
        grid.attach(note, 1, 6, 2, 1)
        return grid

    def sync_settings_widgets(self):
        """Reflect settings changed elsewhere (llarpctl, exit toggle) in the widgets."""
        s = self.ctl.settings
        for key, entry in self.setting_entries.items():
            if entry.get_text() != s[key] and not entry.has_focus():
                entry.set_text(s[key])
        self.level_combo.handler_block(self.level_handler)
        self.level_combo.set_active_id(s.get("log_level", "info"))
        self.level_combo.handler_unblock(self.level_handler)
        self.set_check(self.router_check, self.router_handler, s.get("router_mode", False))
        self.set_check(self.persist_check, self.persist_handler, self.ctl.keyfile_path() is not None)

    def on_router_toggled(self, check):
        try:
            self.ctl.set_router_mode(check.get_active())
        except LlarpError as e:
            self.error(str(e))
            self.set_check(check, self.router_handler, not check.get_active())
        self.refresh_all()

    def set_setting(self, key, value):
        if self.ctl.settings.get(key) == value:
            return
        try:
            self.ctl.set_setting(key, value)
        except LlarpError as e:
            self.error(str(e))
        if key == "config":
            self.set_check(self.persist_check, self.persist_handler, self.ctl.keyfile_path() is not None)
        self.refresh_all()

    def generate_config(self):
        try:
            cfg, output = self.ctl.generate_config()
        except LlarpError as e:
            self.error(str(e))
            return
        for line in output.splitlines():
            self.ctl.note(line)
        self.info(f"Generated {cfg}")

    # ---- dialogs

    def _msg(self, kind, text):
        dlg = Gtk.MessageDialog(transient_for=self, message_type=kind, buttons=Gtk.ButtonsType.OK, text=text)
        dlg.run()
        dlg.destroy()
        return False

    def error(self, text):
        return self._msg(Gtk.MessageType.ERROR, text)

    def info(self, text):
        return self._msg(Gtk.MessageType.INFO, text)


def main():
    # dark Adwaita as the base (also darkens file pickers and dialogs), our palette on top
    settings = Gtk.Settings.get_default()
    settings.set_property("gtk-theme-name", "Adwaita")
    settings.set_property("gtk-application-prefer-dark-theme", True)
    win = App()
    win.connect("destroy", Gtk.main_quit)
    win.show_all()
    Gtk.main()


if __name__ == "__main__":
    main()
