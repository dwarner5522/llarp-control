# LLARP Control

A GTK desktop control panel (`llarp_gui.py`) and a command line tool (`llarpctl`) for
[llarpd](https://github.com/majestrate/llarp), the stakeless Lokinet fork. Both share
the same settings and the same running daemon, so you can switch between them freely.

- Turn llarpd on and off, see your node's `.loki` address and keep it permanent
- Add, enable and remove bootstrap files (from a file, a URL or the bundled ones)
- Turn the node into an exit node, with IP forwarding and NAT set up for you
- Use a `.loki` exit node as a VPN for all your internet traffic
- Run headless on a VPS over SSH, with optional systemd autostart

## Requirements

- Python 3
- `llarpd` installed (with `cap_net_admin,cap_net_bind_service` so it can create its tunnel)
- For the GUI only: GTK 3 and PyGObject (`sudo apt install python3-gi gir1.2-gtk-3.0`)

## Install

```sh
git clone https://github.com/dwarner5522/llarp-control.git
cd llarp-control
./install.sh          # for the current user: ~/.local/share/llarp-control, ~/.local/bin/llarpctl
sudo ./install.sh     # system-wide: /opt/llarp-control, /usr/local/bin/llarpctl
```

Start the GUI with `python3 ~/.local/share/llarp-control/llarp_gui.py`
(or `/opt/llarp-control/llarp_gui.py` for a system-wide install).

## AppImage

`LLARP_Control-*-x86_64.AppImage` is a single file with the GUI and llarpctl. It uses the
system's Python 3 and GTK 3, and llarpd still has to be installed separately.

```sh
chmod +x LLARP_Control-*-x86_64.AppImage
./LLARP_Control-*-x86_64.AppImage              # the GUI
./LLARP_Control-*-x86_64.AppImage ctl status   # llarpctl
```

Build it with `./make-appimage.sh` (needs [appimagetool](https://github.com/AppImage/appimagetool/releases)).

## VPS bundle (builds llarpd too)

The easiest way: download the prebuilt bundle from the
[latest release](https://github.com/dwarner5522/llarp-control/releases/latest) straight onto the VPS:

```sh
wget https://github.com/dwarner5522/llarp-control/releases/latest/download/llarp-control-bundle.tar.gz
```

To make your own bundle instead, `make-bundle.sh` packs the llarpd source (with submodules), llarpctl and a one-shot
installer into `llarp-control-bundle.tar.gz`. It expects an llarp checkout at `../llarp`,
or pass its path:

```sh
git clone --recursive https://github.com/majestrate/llarp.git ../llarp
./make-bundle.sh ../llarp
```

On the VPS:

```sh
tar xzf llarp-control-bundle.tar.gz
cd llarp-control-bundle
sudo ./install.sh            # or: sudo ./install.sh --autostart --user root
```

That installs build dependencies (apt, dnf or pacman), builds and installs llarpd,
installs llarpctl, generates a config, adds the opennet bootstrap and starts llarpd.
See `./install.sh --help` and `bundle/README.txt`.

## Umbrel app

`umbrel/` holds the LLARP app for Umbrel (umbrelOS 1.x and Umbrel 0.5.4): an image with llarpd and a
web control page. It runs as a router node (`.snode`) by default; a switch turns it into a client node
whose `.loki` address leads to the Umbrel login page. Install it from the
[dwarner5522 app store](https://github.com/dwarner5522/umbrel-app-store) (`dwarner-llarp`).

The image `ghcr.io/dwarner5522/llarp-umbrel` is built for amd64 and arm64 by
`.github/workflows/umbrel-image.yml` when a tag like `umbrel-v1.0.0` is pushed.

## Command line

```sh
llarpctl status                  # running? address? modes
llarpctl start | stop | restart
llarpctl address
llarpctl log -f
llarpctl bootstrap add opennet.signed
llarpctl exit on && llarpctl fwd enable   # become an exit node
llarpctl vpn <address>.loki             # route traffic through an exit
llarpctl vpn off
llarpctl persist on              # keep the same .loki address
llarpctl autostart on            # systemd service
llarpctl --help
```

## Notes

- Router (relay) mode needs a public IP. On a VPS it's found automatically. Behind a home
  router, set it with `llarpctl set public_ip auto` (or Settings → Public IP in the GUI) and
  forward that UDP port (default 1090) on the router to this machine.
- The VPN client and the exit node must run compatible llarpd versions. If the exit
  answers but its replies can't be read, compare `llarpd --version` on both machines.
- Settings, state and the llarpd log live in `~/.config/llarp-gui/`.
