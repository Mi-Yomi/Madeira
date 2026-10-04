#!/bin/bash
# Rebuild the unmodified part of wineserver from the checked-out Wine pin.
# build.sh passes the archive member names supplied by its iOS replacements;
# those originals must not be compiled (some depend on unavailable macOS APIs).
# Unlike the historical CI helper, every required compile/object is mandatory.
set -euo pipefail

BUILD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$BUILD_DIR/../.." && pwd)"
WINE_SRC="$REPO_ROOT/wine"
OBJ_DIR="$BUILD_DIR/obj/base"
BASE_LIB="$BUILD_DIR/libwineserver_base.a"
AR="${AR:-ar}"
# Apple ar may list its symbol-table member; it is regenerated on repack.
archive_members() {
    "$AR" t "$1" | sed -e '/^__\.SYMDEF$/d' -e '/^__\.SYMDEF SORTED$/d' \
        -e '/^__\.SYMDEF_64$/d' -e '/^__\.SYMDEF_64 SORTED$/d'
}

for name in "$@"; do
    case "$name" in
        ''|*/*|*..*|*[!a-zA-Z0-9_.-]*|[!a-zA-Z0-9_]*|*.o.o)
            echo "Invalid replacement member: $name" >&2; exit 1;;
        *.o) ;;
        *) echo "Expected an .o replacement member: $name" >&2; exit 1;;
    esac
done
[ -f "$WINE_SRC/build-macos/include/config.h" ] || {
    echo "Missing Wine generated config.h; prepare wine/build-macos first" >&2; exit 1;
}
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
mkdir -p "$OBJ_DIR"
# Never include a stale object left by a failed or different source checkout.
rm -f "$OBJ_DIR"/*.o "$OBJ_DIR"/*.err

CC_FLAGS=(
    -arch arm64 -isysroot "$SDK" -miphoneos-version-min=17.0 -O2
    -I"$WINE_SRC/include" -I"$WINE_SRC/include/wine"
    -I"$WINE_SRC/build-macos/include"
    -I"$BUILD_DIR" -I"$WINE_SRC/server"
    -I"$REPO_ROOT/build/ntdll-unix/shims"
    -I"$BUILD_DIR/../madsync" -DHAVE_LINUX_NTSYNC_H=1
    -include "$BUILD_DIR/config_ios.h" -include stdarg.h
    -include "$BUILD_DIR/unicode_fix.h"
    -include "$BUILD_DIR/wineserver_ios_kill.h"
    -DBINDIR=\"/usr/local/bin\" -DDATADIR=\"/usr/local/share\"
    -D__WINESRC__ -DWINE_IOS=1 -Dmain=wineserver_main
    -Wno-implicit-function-declaration
)

OBJECTS=()
for src in "$WINE_SRC"/server/*.c; do
    [ -f "$src" ] || { echo "No Wine server sources found" >&2; exit 1; }
    name="${src##*/}"
    name="${name%.c}"
    replaced=false
    for member in "$@"; do
        if [ "$member" = "$name.o" ]; then replaced=true; break; fi
    done
    if [ "$replaced" = true ]; then continue; fi
    echo "  base/$name..."
    if ! xcrun -sdk iphoneos clang "${CC_FLAGS[@]}" -c "$src" -o "$OBJ_DIR/$name.o" 2>"$OBJ_DIR/$name.err"; then
        cat "$OBJ_DIR/$name.err" >&2
        echo "Failed Wine base compile: $src" >&2
        exit 1
    fi
    [ -s "$OBJ_DIR/$name.o" ] || { echo "Missing Wine base object: $name.o" >&2; exit 1; }
    OBJECTS+=("$OBJ_DIR/$name.o")
done
[ "${#OBJECTS[@]}" -gt 0 ] || { echo "No unmodified Wine server objects built" >&2; exit 1; }

# Preserve the previous complete base if compilation or archiving fails.
rm -f "$BASE_LIB.tmp"
"$AR" rcs "$BASE_LIB.tmp" "${OBJECTS[@]}"
archive_members "$BASE_LIB.tmp" | LC_ALL=C sort > "$OBJ_DIR/actual-members.txt"
printf '%s\n' "${OBJECTS[@]##*/}" | LC_ALL=C sort > "$OBJ_DIR/expected-members.txt"
diff -u "$OBJ_DIR/expected-members.txt" "$OBJ_DIR/actual-members.txt"
mv "$BASE_LIB.tmp" "$BASE_LIB"
echo "Wine base archive: ${#OBJECTS[@]} objects from the current source tree"
