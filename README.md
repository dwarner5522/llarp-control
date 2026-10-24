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

- The VPN client and the exit node must run compatible llarpd versions. If the exit
  answers but its replies can't be read, compare `llarpd --version` on both machines.
- Settings, state and the llarpd log live in `~/.config/llarp-gui/`.
