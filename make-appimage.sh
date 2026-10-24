#!/usr/bin/env bash
# Build LLARP_Control-<version>-x86_64.AppImage: the GUI, llarpctl and the bundled
# bootstrap files. Uses the system's python3 + GTK 3; llarpd stays installed separately
# (it needs setcap'd network capabilities, which can't work from inside an AppImage).
#
#   ./make-appimage.sh [path/to/llarp/repo] [output-dir]
# Needs appimagetool in PATH (or APPIMAGETOOL=/path/to/appimagetool).
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=${1:-$HERE/../llarp}
OUTDIR=$(realpath -m "${2:-$HERE/..}")
TOOL=${APPIMAGETOOL:-$(command -v appimagetool || true)}
[ -x "$TOOL" ] || { echo "appimagetool not found; get it from https://github.com/AppImage/appimagetool/releases" >&2; exit 1; }
VERSION=$(git -C "$HERE" describe --tags --always --dirty 2>/dev/null || echo dev)
VERSION=${VERSION#v}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
APPDIR=$WORK/LLARP_Control.AppDir
APP=$APPDIR/usr/share/llarp-control
mkdir -p "$APP/bootstrap"

install -m 755 "$HERE/appimage/AppRun" "$APPDIR/AppRun"
install -m 644 "$HERE/appimage/llarp-control.desktop" "$APPDIR/"
install -m 644 "$HERE/llarp_core.py" "$APP/"
install -m 755 "$HERE/llarp_gui.py" "$HERE/llarpctl" "$APP/"
if [ -d "$REPO/contrib/bootstrap" ]; then
    install -m 644 "$REPO"/contrib/bootstrap/*.signed "$APP/bootstrap/"
else
    echo "warning: no llarp checkout at $REPO; the AppImage won't include bundled bootstraps" >&2
fi

# icon: the app's diamond logo on its dark background
python3 - "$HERE" "$APPDIR/llarp-control.png" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
import cairo
import llarp_gui
size = 256
surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, size, size)
cr = cairo.Context(surface)
r = size * 0.18
cr.new_sub_path()
for x, y, a in ((size - r, r, -90), (size - r, size - r, 0), (r, size - r, 90), (r, r, 180)):
    cr.arc(x, y, r, a * 3.14159265 / 180, (a + 90) * 3.14159265 / 180)
cr.close_path()
cr.set_source_rgb(0x19 / 255, 0x19 / 255, 0x19 / 255)
cr.fill()
llarp_gui.draw_diamond(cr, size, glow=True)
surface.write_to_png(sys.argv[2])
PY
mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"
cp "$APPDIR/llarp-control.png" "$APPDIR/usr/share/icons/hicolor/256x256/apps/"
ln -s llarp-control.png "$APPDIR/.DirIcon"

OUT=$OUTDIR/LLARP_Control-$VERSION-x86_64.AppImage
ARCH=x86_64 "$TOOL" --no-appstream "$APPDIR" "$OUT" >"$WORK/appimagetool.log" 2>&1 \
    || { cat "$WORK/appimagetool.log" >&2; exit 1; }
echo "==> wrote $OUT ($(du -h "$OUT" | cut -f1))"
