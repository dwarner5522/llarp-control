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

echo "==> cloning $REPO (with submodules)"
git clone -q "$REPO" "$WORK/clone"
git -C "$WORK/clone" checkout -q "$(git -C "$REPO" rev-parse HEAD)"
git -C "$WORK/clone" submodule update -q --init --recursive
TAG=$(git -C "$REPO" rev-parse --short=9 HEAD)
if [ -n "$(git -C "$REPO" status --porcelain --untracked-files=no)" ]; then
    echo "warning: $REPO has uncommitted changes; the bundle uses the committed version $TAG" >&2
fi
mkdir -p "$STAGE/llarp"
tar -C "$WORK/clone" --exclude=.git --exclude='./build*' -cf - . | tar -C "$STAGE/llarp" -xf -
echo "$TAG" > "$STAGE/VERSION"

echo "==> adding llarpctl"
mkdir -p "$STAGE/llarp-control"
cp "$HERE/llarp_core.py" "$HERE/llarpctl" "$HERE/llarp_gui.py" "$HERE/install.sh" "$STAGE/llarp-control/"
cp "$HERE/bundle/install.sh" "$HERE/bundle/README.txt" "$STAGE/"
chmod +x "$STAGE/install.sh" "$STAGE/llarp-control/install.sh" "$STAGE/llarp-control/llarpctl"

tar -C "$WORK" -czf "$OUT" "$NAME"
echo "==> wrote $OUT ($(du -h "$OUT" | cut -f1), llarpd $TAG)"
