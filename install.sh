#!/bin/sh
# Install llarpctl (and the GUI, if GTK is available) for the current user.
#   ./install.sh            -> ~/.local/share/llarp-control, command in ~/.local/bin
#   sudo ./install.sh       -> /opt/llarp-control, command in /usr/local/bin
set -e
src=$(cd "$(dirname "$0")" && pwd)
if [ "$(id -u)" = 0 ]; then
    dest=/opt/llarp-control; bindir=/usr/local/bin
else
    dest=$HOME/.local/share/llarp-control; bindir=$HOME/.local/bin
fi
mkdir -p "$dest" "$bindir"
install -m 644 "$src/llarp_core.py" "$dest/"
install -m 755 "$src/llarpctl" "$dest/"
ln -sf "$dest/llarpctl" "$bindir/llarpctl"
bundled=$src/../llarp/contrib/bootstrap
if [ -d "$bundled" ]; then
    mkdir -p "$dest/bootstrap"
    install -m 644 "$bundled"/*.signed "$dest/bootstrap/"
fi
echo "installed: $bindir/llarpctl"

if python3 -c 'import gi; gi.require_version("Gtk", "3.0")' 2>/dev/null; then
    install -m 755 "$src/llarp_gui.py" "$dest/"
    echo "installed GUI: $dest/llarp_gui.py"
fi

command -v llarpd >/dev/null || echo "note: llarpd not found in PATH; set it with: llarpctl set llarpd /path/to/llarpd"
case ":$PATH:" in *":$bindir:"*) ;; *) echo "note: add $bindir to your PATH";; esac
