#!/bin/bash
set -euo pipefail

BUILD_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$BUILD_DIR/../.." && pwd)"
WINE_SRC="$REPO_ROOT/wine"
APP_LIB="$REPO_ROOT/app/Madeira/libwineserver.a"
SHIMS_DIR="$REPO_ROOT/build/ntdll-unix/shims"
OBJ_DIR="$BUILD_DIR/obj"
WORK_LIB="$OBJ_DIR/libwineserver.next.a"
AR="${AR:-ar}"
NM="${NM:-nm}"
# Apple ar may list its symbol-table member; it is regenerated on repack.
archive_members() {
    "$AR" t "$1" | sed -e '/^__\.SYMDEF$/d' -e '/^__\.SYMDEF SORTED$/d' \
        -e '/^__\.SYMDEF_64$/d' -e '/^__\.SYMDEF_64 SORTED$/d'
}
MODE="${1:-all}"
case "$MODE" in
    all|request|main|mach|unicode) ;;
    *) echo "Usage: $0 [all|request|main|mach|unicode]" >&2; exit 1;;
esac

# Resolve tools before expensive compilation; never rely on a versioned local
# Homebrew installation. CI can provide llvm-mingw's llvm-objcopy through PATH.
if [ -z "${OBJCOPY:-}" ]; then
    if command -v llvm-objcopy >/dev/null 2>&1; then
        OBJCOPY=$(command -v llvm-objcopy)
    else
        OBJCOPY=/opt/homebrew/opt/llvm/bin/llvm-objcopy
    fi
fi
[ -x "$OBJCOPY" ] || { echo "llvm-objcopy not found; set OBJCOPY or PATH" >&2; exit 1; }
[ -f "$WINE_SRC/build-macos/include/config.h" ] || {
    echo "Missing Wine generated config.h; prepare wine/build-macos first" >&2; exit 1;
}
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
mkdir -p "$OBJ_DIR"

CC_FLAGS=(
    -arch arm64 -isysroot "$SDK" -miphoneos-version-min=17.0 -O2
    -I"$WINE_SRC/include" -I"$WINE_SRC/include/wine"
    -I"$WINE_SRC/build-macos/include"
    -I"$BUILD_DIR" -I"$WINE_SRC/server"
    -I"$SHIMS_DIR"
    -I"$BUILD_DIR/../madsync" -DHAVE_LINUX_NTSYNC_H=1
    -include "$BUILD_DIR/config_ios.h"
    -include stdarg.h
    -include "$BUILD_DIR/unicode_fix.h"
    -include "$BUILD_DIR/wineserver_ios_kill.h"
    -DBINDIR=\"/usr/local/bin\" -DDATADIR=\"/usr/local/share\"
    -D__WINESRC__ -DWINE_IOS=1
    -Dmain=wineserver_main
    # Symbol collisions with win32u are NOT handled via -D macros — that
    # rewrites macro args (e.g. DECL_HANDLER(name)) and breaks struct
    # name concatenation. Renames done post-compile via objcopy below,
    # applied to EVERY .o in libwineserver.a so cross-file refs (e.g.
    # clipboard.c calling send_notify_message defined in queue.c) stay
    # internal to the archive after the renames.
    -Wno-implicit-function-declaration
)

compile_one() {
    local src=$1
    local name=$2
    echo -n "  $name... "
    rm -f "$OBJ_DIR/$name.o"
    if xcrun -sdk iphoneos clang "${CC_FLAGS[@]}" -c "$src" -o "$OBJ_DIR/$name.o" 2>"$OBJ_DIR/err-$name.txt"; then
        [ -s "$OBJ_DIR/$name.o" ] || { echo "Missing object: $name.o" >&2; return 1; }
        echo "OK"
    else
        echo "FAILED (see $OBJ_DIR/err-$name.txt)"
        cat "$OBJ_DIR/err-$name.txt"
        return 1
    fi
}

# Patched files: name:source_file:replaces_in_archive
PATCHED_FILES=(
    "wine_log_ios:wine_log_ios.c:wine_log_ios.o"
    "request_ios:request_ios.c:request.o"
    "main_ios:main_ios.c:main.o"
    "mach_ios:mach_ios.c:mach.o"
    "unicode_ios:unicode_ios.c:unicode.o"
    "fd_ios:fd_ios.c:fd.o"
    # This is the single source of truth for compilation and archive insertion.
    "object:$WINE_SRC/server/object.c:object.o"
    # ml805: event/handle carry the [evt-hist] instrumentation.
    "event:$WINE_SRC/server/event.c:event.o"
    # Fastsync's semaphore half (madeira_semaphore_cell_index and friends in
    # server/semaphore.c) is referenced by inproc_sync.c and thread.c, so it is
    # compiled from the submodule and swapped in as well.
    "semaphore:$WINE_SRC/server/semaphore.c:semaphore.o"
    "handle:$WINE_SRC/server/handle.c:handle.o"
    # ml575: async.c carries the free_async_queue UAF fix.
    "async:$WINE_SRC/server/async.c:async.o"
    "process_ios:$WINE_SRC/server/process.c:process.o"
    # Files needing rebuild only because the -Dws_* renames must apply
    # to both definers and callers — fixes 10 symbol collisions with win32u.
    "window:$BUILD_DIR/window_ios.c:window.o"
    "user:$WINE_SRC/server/user.c:user.o"
    "mapping:$BUILD_DIR/mapping_ios.c:mapping.o"
    "class:$WINE_SRC/server/class.c:class.o"
    "region:$WINE_SRC/server/region.c:region.o"
    "queue:$BUILD_DIR/queue_ios.c:queue.o"
    # S2: virtual-desktop input fix (WSF_VISIBLE + input_desktop + cursor.clip
    # in create_desktop) lives in the submodule's winstation.c
    "winstation:$WINE_SRC/server/winstation.c:winstation.o"
    # task#32 Steam: stop_thread Mach-based context capture (iOS signal
    # suspend is dead) lives in the submodule's thread.c
    "thread:$WINE_SRC/server/thread.c:thread.o"
    # ml1058: in-process synchronisation. The archive's copy was compiled with no
    # ntsync header, i.e. as the all-stubs variant; build the real one against the
    # userspace driver in build/madsync.
    "inproc_sync:$WINE_SRC/server/inproc_sync.c:inproc_sync.o"
    # ml474 (#79): sock.c now builds from the submodule. Before this entry
    # the archive carried a hand-inserted Jul-10 sock.o (probed, source
    # lost) that every rebuild silently preserved — the #79 TCP-table
    # forensics were reading three-week-old mystery code. The submodule
    # copy adds the [srv-conn]/[tcp-state]/[tcp-enum] probes.
    "sock:$WINE_SRC/server/sock.c:sock.o"
    # ml2101: the opt-in HID controller (MADEIRA_PAD_MODE = hid) and Wine's
    # hidparse.sys parser it builds its preparsed data with. New objects.
    "hidpad_ios:hidpad_ios.c:hidpad_ios.o"
    "hidparse_ios:$REPO_ROOT/build/hidpad/hidparse_ios.c:hidparse_ios.o"
)

# A full build always rebuilds the current Wine sources. Never seed it from
# an old app archive. Partial rebuilds require an earlier complete local build.
if [ "$MODE" = all ]; then
    EXCLUDED=()
    for entry in "${PATCHED_FILES[@]}"; do
        EXCLUDED+=("${entry##*:}")
    done
    bash "$BUILD_DIR/build-base.sh" "${EXCLUDED[@]}"
    cp "$BUILD_DIR/libwineserver_base.a" "$WORK_LIB"
else
    [ -s "$OBJ_DIR/libwineserver.a" ] || {
        echo "No complete local wineserver archive; run $0 all first" >&2; exit 1;
    }
    cp "$OBJ_DIR/libwineserver.a" "$WORK_LIB"
fi

echo "=== Building kill wrapper (without kill macro) ==="
echo -n "  wineserver_ios_kill... "
# Compile WITHOUT -include wineserver_ios_kill.h to avoid recursive macro
KILL_FLAGS=(-arch arm64 -isysroot "$SDK" -miphoneos-version-min=17.0 -O2
    -I"$BUILD_DIR" -DWINE_IOS=1 -Wno-implicit-function-declaration)
rm -f "$OBJ_DIR/wineserver_ios_kill.o"
if xcrun -sdk iphoneos clang "${KILL_FLAGS[@]}" -c "$BUILD_DIR/wineserver_ios_kill.c" -o "$OBJ_DIR/wineserver_ios_kill.o" 2>"$OBJ_DIR/err-kill.txt"; then
    [ -s "$OBJ_DIR/wineserver_ios_kill.o" ] || { echo "Missing kill wrapper object" >&2; exit 1; }
    echo "OK"
else
    echo "FAILED"; cat "$OBJ_DIR/err-kill.txt"; exit 1
fi

echo "=== Building patched wineserver files ($MODE) ==="
REPLACEMENTS=("wineserver_ios_kill.o:wineserver_ios_kill.o")
for entry in "${PATCHED_FILES[@]}"; do
    IFS=: read -r name src old_obj <<< "$entry"
    if [ "$MODE" != all ] && [ "$name" != "${MODE}_ios" ] && [ "$name" != "$MODE" ]; then
        continue
    fi
    if [[ "$src" != /* ]]; then src="$BUILD_DIR/$src"; fi
    compile_one "$src" "$name"
    REPLACEMENTS+=("$name.o:$old_obj")
done

# Apply only objects compiled successfully in this invocation. A missing member
# is allowed for a new overlay, but any archiver failure is fatal.
echo "=== Updating libwineserver.a ==="
for entry in "${REPLACEMENTS[@]}"; do
    new_obj="${entry%%:*}"
    old_obj="${entry##*:}"
    [ -s "$OBJ_DIR/$new_obj" ] || { echo "Missing replacement: $new_obj" >&2; exit 1; }
    archive_members "$WORK_LIB" > "$OBJ_DIR/members.txt"
    if grep -Fxq "$old_obj" "$OBJ_DIR/members.txt"; then "$AR" d "$WORK_LIB" "$old_obj"; fi
    if [ "$old_obj" != "$new_obj" ] && grep -Fxq "$new_obj" "$OBJ_DIR/members.txt"; then
        "$AR" d "$WORK_LIB" "$new_obj"
    fi
    "$AR" r "$WORK_LIB" "$OBJ_DIR/$new_obj"
done

echo ""
echo "=== Renaming colliding symbols in every .o (objcopy sweep) ==="
# Renames internal-to-archive: extract every .o, rename the 10 symbols
# we know collide with win32u-unix, repackage. Affects definitions AND
# references uniformly, so cross-file calls inside wineserver still
# resolve. Externals (win32u, etc.) only see the ws_-prefixed names.
COLLISIONS=(
    alloc_user_handle free_user_handle get_virtual_screen_rect
    destroy_thread_windows get_window_thread is_desktop_class
    is_message_class is_window_visible mirror_region send_notify_message
    # shared_session: BOTH wineserver and win32u-unix declare it as a
    # common global. Single-process iOS link merges them — last writer
    # wins. win32u's shared_session_init() overwrites with the client-side
    # NtMapViewOfSection result (read-only), making wineserver's writes
    # silently fail since they're going through the client's RO view.
    # Rename wineserver-side to ws_shared_session so each side has its
    # own pointer to its own mapping of the same backing file.
    shared_session
    # user_shared_data: the same defect as shared_session, one layer over.
    # wineserver defines it as a common global and ntdll-unix defines it as
    # initialized data; the single-process link merges them. wineserver's
    # create_user_data_mapping() sets it to a writable alias, then the guest's
    # ntdll init runs virtual_ios.c's `user_shared_data = NULL;
    # NtAllocateVirtualMemory(..., PAGE_READONLY)` over the SAME variable, so
    # the server's pointer starts aiming at the guest's read-only page in the
    # FEX guest band. Unlike shared_session this does not fail silently: the
    # server's next store faults on a PROT_READ page and the main loop wedges
    # forever, which is why the shared clock could never be published and why
    # every process hung in server_init_process() the moment a client
    # connected -- guest ntdll init is exactly when the pointer was stolen.
    user_shared_data
)
RENAME_ARGS=()
for s in "${COLLISIONS[@]}"; do
    RENAME_ARGS+=(--redefine-sym "_${s}=_ws_${s}")
done
"$NM" -g "$WORK_LIB" > "$OBJ_DIR/symbols-before.txt"
awk '{ print $NF }' "$OBJ_DIR/symbols-before.txt" | LC_ALL=C sort -u > "$OBJ_DIR/names-before.txt"
TMP_RENAME_DIR="$OBJ_DIR/rename"
rm -rf "$TMP_RENAME_DIR" && mkdir -p "$TMP_RENAME_DIR"
# A duplicate member name would be lost by ar x. Reject it before extraction.
archive_members "$WORK_LIB" | LC_ALL=C sort > "$OBJ_DIR/expected-members.txt"
if [ -n "$(uniq -d "$OBJ_DIR/expected-members.txt")" ]; then
    echo "Duplicate wineserver archive members" >&2; exit 1
fi
(cd "$TMP_RENAME_DIR" && "$AR" x "$WORK_LIB")
RENAMED=()
for f in "$TMP_RENAME_DIR"/*.o; do
    [ -s "$f" ] || { echo "Missing extracted wineserver object: $f" >&2; exit 1; }
    "$OBJCOPY" "${RENAME_ARGS[@]}" "$f"
    RENAMED+=("$f")
done
# Repack into a new archive, leaving the last successful library untouched.
rm -f "$WORK_LIB"
"$AR" rcs "$WORK_LIB" "${RENAMED[@]}"
archive_members "$WORK_LIB" | LC_ALL=C sort > "$OBJ_DIR/actual-members.txt"
diff -u "$OBJ_DIR/expected-members.txt" "$OBJ_DIR/actual-members.txt"
"$NM" -g "$WORK_LIB" > "$OBJ_DIR/symbols-after.txt"
awk '{ print $NF }' "$OBJ_DIR/symbols-after.txt" | LC_ALL=C sort -u > "$OBJ_DIR/names-after.txt"
for s in "${COLLISIONS[@]}"; do
    if grep -Fxq "_$s" "$OBJ_DIR/names-after.txt"; then
        echo "Unrenamed wineserver symbol: _$s" >&2; exit 1
    fi
    if grep -Fxq "_$s" "$OBJ_DIR/names-before.txt" && ! grep -Fxq "_ws_$s" "$OBJ_DIR/names-after.txt"; then
        echo "Missing renamed wineserver symbol: _ws_$s" >&2; exit 1
    fi
done
# Every current overlay must survive the archive surgery, even for a partial build.
for entry in "${PATCHED_FILES[@]}"; do
    grep -Fxq "${entry%%:*}.o" "$OBJ_DIR/actual-members.txt" || {
        echo "Missing patched archive member: ${entry%%:*}.o" >&2; exit 1;
    }
done
grep -Fxq wineserver_ios_kill.o "$OBJ_DIR/actual-members.txt"
mv "$WORK_LIB" "$OBJ_DIR/libwineserver.a"
rm -rf "$TMP_RENAME_DIR"
echo "  symbol rename + repack OK"

echo "Copying to app..."
cp "$OBJ_DIR/libwineserver.a" "$APP_LIB.tmp"
mv "$APP_LIB.tmp" "$APP_LIB"
echo "Done! libwineserver.a: $(wc -c < "$APP_LIB" | tr -d ' ') bytes"
