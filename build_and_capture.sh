#!/bin/bash
# build_and_capture.sh — build the loader and extract the current machine's key from a hosted LABS plugin.
#

set -e
cd "$(dirname "$0")"

echo "== building loader =="
xcrun clang -arch x86_64 -g -O0 tools/labs_host.m -o tools/labs_host \
  -framework Foundation -framework CoreFoundation -framework AudioToolbox
echo "   ok"

PLIST="/Library/Audio/Plug-Ins/Components/LABS.component/Contents/Info.plist"
VER=$(defaults read "$PLIST" CFBundleShortVersionString 2>/dev/null || echo "?")

# Blowfish-constructor file offset (x86_64 slice)per LABS build
# For any other build, re-derive it with find_ctor.py and pass it as $2 below.
case "$VER" in
  3.7.29*) OFF=0xF37640 ;;
  1.5.1*)  OFF=0x7AF4D0 ;;
  *)       OFF="" ;;
esac

echo "== installed LABS version: $VER  ->  ctor offset: ${OFF:-UNKNOWN} =="
if [ -z "$OFF" ]; then
  cat <<EOF
Unknown LABS version. Re-derive the constructor offset:
    python3 -m pip install --user capstone macholib
    # thin the x86_64 slice, then:
    python3 find_ctor.py . /path/to/LABS   # prints 'ctor entry = 0x....'
Then run:
    lldb --batch -o "command script import ./capture_key.py" \\
                 -o "capture_run ./tools/labs_host 0xYOUROFFSET"
EOF
  exit 1
fi

echo "== capturing key (lldb) =="
lldb --batch \
  -o "command script import ./capture_key.py" \
  -o "capture_run ./tools/labs_host $OFF" \
  2>&1 | grep -E 'per-machine|fixed preset|hex=|err=|success=' | sort -u
echo
