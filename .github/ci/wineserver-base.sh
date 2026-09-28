#!/bin/bash
# build/wineserver/build.sh only swaps patched objects into an existing
# libwineserver.a, which is not in the repository. Build that base archive
# from every wine/server/*.c with the same flags.
set -u
R="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="$R/build/wineserver"
WINE_SRC="$R/wine"
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
OBJ="$BUILD_DIR/obj/base"
mkdir -p "$OBJ"

CC_FLAGS=(
    -arch arm64 -isysroot "$SDK" -miphoneos-version-min=17.0 -O2
    -I"$WINE_SRC/include" -I"$WINE_SRC/include/wine"
    -I"$WINE_SRC/build-macos/include"
    -I"$BUILD_DIR" -I"$WINE_SRC/server"
    -I"$R/build/ntdll-unix/shims"
    -I"$BUILD_DIR/../madsync" -DHAVE_LINUX_NTSYNC_H=1
    -include "$BUILD_DIR/config_ios.h"
    -include stdarg.h
    -include "$BUILD_DIR/unicode_fix.h"
    -include "$BUILD_DIR/wineserver_ios_kill.h"
    -DBINDIR=\"/usr/local/bin\" -DDATADIR=\"/usr/local/share\"
    -D__WINESRC__ -DWINE_IOS=1
    -Dmain=wineserver_main
    -Wno-implicit-function-declaration -Wno-int-conversion
)

fail=""
for src in "$WINE_SRC"/server/*.c; do
    n=$(basename "$src" .c)
    if ! xcrun -sdk iphoneos clang "${CC_FLAGS[@]}" -c "$src" -o "$OBJ/$n.o" 2>"$OBJ/$n.err"; then
        fail="$fail $n"; echo "== $n FAILED"; head -20 "$OBJ/$n.err"
    fi
done
echo "base failures:${fail:- none}"
rm -f "$BUILD_DIR/obj/libwineserver.a"
ar rcs "$BUILD_DIR/obj/libwineserver.a" "$OBJ"/*.o
echo "base archive: $(ar t "$BUILD_DIR/obj/libwineserver.a" | wc -l) objects"
