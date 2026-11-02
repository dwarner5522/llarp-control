#!/usr/bin/env bash
# Build llarp-control-bundle.tar.gz: llarpd source (with submodules), llarpctl and
# a one-shot installer for a VPS. Your llarp checkout is not modified.
#
#   ./make-bundle.sh [path/to/llarp/repo] [output.tar.gz]
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "${1:-$HERE/../llarp}" && pwd)
OUT=$(realpath -m "${2:-$HERE/../llarp-control-bundle.tar.gz}")
NAME=llarp-control-bundle

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
STAGE=$WORK/$NAME
mkdir -p "$STAGE"

TAG=$(git -C "$REPO" rev-parse --short=9 HEAD)
mkdir -p "$STAGE/llarp"
# fast path: a clean checkout whose submodules are all at their recorded commits is used as is
# (tracked files only), so nothing has to be downloaded again
if [ -z "$(git -C "$REPO" status --porcelain --untracked-files=no --ignore-submodules=none)" ] \
   && ! git -C "$REPO" submodule status --recursive 2>/dev/null | grep -q '^[-+U]'; then
    echo "==> copying $REPO (clean, submodules checked out)"
    git -C "$REPO" ls-files -z --recurse-submodules | tar -C "$REPO" --null -T - -cf - | tar -C "$STAGE/llarp" -xf -
else
    echo "==> cloning $REPO (with submodules)"
    git clone -q "$REPO" "$WORK/clone"
    git -C "$WORK/clone" checkout -q "$(git -C "$REPO" rev-parse HEAD)"
    git -C "$WORK/clone" submodule update -q --init --recursive
    if [ -n "$(git -C "$REPO" status --porcelain --untracked-files=no)" ]; then
        echo "warning: $REPO has uncommitted changes; the bundle uses the committed version $TAG" >&2
    fi
    tar -C "$WORK/clone" --exclude=.git --exclude='./build*' -cf - . | tar -C "$STAGE/llarp" -xf -
fi
echo "$TAG" > "$STAGE/VERSION"

echo "==> adding llarpctl"
# from the committed version, not the working tree: on a Windows checkout the working tree can
# have CRLF line endings, which would break every script on the VPS
if [ -n "$(git -C "$HERE" status --porcelain --untracked-files=no -- llarp_core.py llarpctl llarp_gui.py install.sh bundle)" ]; then
    echo "warning: uncommitted changes in llarp-control; the bundle uses the committed version" >&2
fi
CTL_REV=$(git -C "$HERE" describe --tags --always --dirty 2>/dev/null || echo unknown)
mkdir -p "$STAGE/llarp-control" "$WORK/ctl"
git -C "$HERE" archive HEAD llarp_core.py llarpctl llarp_gui.py install.sh bundle | tar -C "$WORK/ctl" -xf -
cp "$WORK/ctl/llarp_core.py" "$WORK/ctl/llarpctl" "$WORK/ctl/llarp_gui.py" "$WORK/ctl/install.sh" "$STAGE/llarp-control/"
cp "$WORK/ctl/bundle/install.sh" "$WORK/ctl/bundle/README.txt" "$STAGE/"
echo "$CTL_REV" > "$STAGE/llarp-control/VERSION"
chmod +x "$STAGE/install.sh" "$STAGE/llarp-control/install.sh" "$STAGE/llarp-control/llarpctl"
if grep -lq $'\r' "$STAGE/install.sh" "$STAGE/llarp-control/"*; then
    echo "error: CRLF line endings in the bundle" >&2
    exit 1
fi

tar -C "$WORK" -czf "$OUT" "$NAME"
echo "==> wrote $OUT ($(du -h "$OUT" | cut -f1), llarpd $TAG, llarp-control $CTL_REV)"
