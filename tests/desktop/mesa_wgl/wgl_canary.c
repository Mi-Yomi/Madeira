/* SPDX-License-Identifier: MIT
 * Madeira's staged Windows GDI/WGL canary. No OpenGL import at process startup.
 * Build: x86_64-w64-mingw32-clang -std=c11 -Wall -Wextra -Werror -O2
 *        wgl_canary.c -o wgl-canary.exe -lgdi32 -luser32
 * Run: wgl-canary.exe --stage gdi|legacy|core43|modern [--hold-ms 3000]
 * Double-click/no arguments, or --interactive: local report and visible softpipe frames.
 * Exit zero proves only the named stages printed here, never Blender support.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <GL/gl.h>
#include <GL/glext.h>
#include <GL/wglext.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <io.h>
#include <fcntl.h>

#include "wgl_canary_pixels.h"

static HMODULE gl_module;
static int source_built_reference;
static int core_unavailable;
static int strict_modern;
static int interactive;
static WCHAR interactive_report[32768];
static HWND hidden_console;
static UINT console_show_command;
static PROC (WINAPI *get_gl_proc)(LPCSTR);
static HGLRC (WINAPI *create_context)(HDC);
static BOOL (WINAPI *make_current)(HDC, HGLRC);
static BOOL (WINAPI *delete_context)(HGLRC);
static const GLubyte *(APIENTRY *get_string)(GLenum);
static void (APIENTRY *get_integer)(GLenum, GLint *);
static void (APIENTRY *clear_color)(GLfloat, GLfloat, GLfloat, GLfloat);
static void (APIENTRY *clear)(GLbitfield);
static void (APIENTRY *viewport)(GLint, GLint, GLsizei, GLsizei);
static void (APIENTRY *read_pixels)(GLint, GLint, GLsizei, GLsizei, GLenum, GLenum, void *);
static void (APIENTRY *read_buffer)(GLenum);
static void (APIENTRY *finish)(void);
static GLenum (APIENTRY *get_error)(void);
static void (APIENTRY *draw_arrays)(GLenum, GLint, GLsizei);

static void begin(const char *stage)
{
    printf("BEGIN stage=%s\n", stage);
    SetLastError(0);
}

static int fail(const char *stage)
{
    printf("FAIL stage=%s win32_error=%lu\n", stage, (unsigned long)GetLastError());
    return 0;
}

static void pass(const char *stage)
{
    printf("PASS stage=%s\n", stage);
}

/* WGL implementations can return these invalid pseudo-pointers. */
static int valid_proc(PROC p)
{
    uintptr_t n = (uintptr_t)p;
    return n > 3 && n != UINTPTR_MAX;
}

static PROC extension(const char *name)
{
    PROC p = get_gl_proc(name);
    if (!valid_proc(p)) {
        printf("MISSING extension=%s\n", name);
        return NULL;
    }
    return p;
}

#define LOAD_EXPORT(target, name) do { \
    FARPROC found = GetProcAddress(gl_module, name); \
    if (!found) { printf("MISSING export=%s\n", name); return fail("gl-exports"); } \
    _Static_assert(sizeof(target) == sizeof(found), "function pointer width"); \
    memcpy(&(target), &found, sizeof(target)); \
} while (0)

#define LOAD_EXTENSION(type, target, name) \
    type target; do { \
        PROC found = extension(name); \
        if (!found) return fail("core-functions"); \
        _Static_assert(sizeof(target) == sizeof(found), "function pointer width"); \
        memcpy(&(target), &found, sizeof(target)); \
    } while (0)

static LRESULT CALLBACK window_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static void pump_for(DWORD milliseconds)
{
    DWORD start = GetTickCount();
    do {
        MSG msg;
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if (!milliseconds) break;
        Sleep(10);
    } while (GetTickCount() - start < milliseconds);
}

/* User-invoked diagnostics only: create a new report beside this EXE, never
 * overwrite an existing file, collect other logs, or send anything anywhere. */
static int open_interactive_report(void)
{
    WCHAR *slash;
    DWORD n = GetModuleFileNameW(NULL, interactive_report, 32768);
    HANDLE file = INVALID_HANDLE_VALUE;
    int fd;
    if (!n || n >= 32768 || !(slash = wcsrchr(interactive_report, L'\\'))) return 0;
    size_t remaining = 32768 - (size_t)(slash + 1 - interactive_report);
    if (remaining < 100) return 0;
    for (unsigned i = 0; i < 32; ++i) {
        swprintf(slash + 1, remaining, L"canary-result-%lu-%lu-%u.txt",
                 (unsigned long)GetCurrentProcessId(), (unsigned long)GetTickCount(), i);
        file = CreateFileW(interactive_report, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                           CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file != INVALID_HANDLE_VALUE) break;
        if (GetLastError() != ERROR_FILE_EXISTS && GetLastError() != ERROR_ALREADY_EXISTS) return 0;
    }
    if (file == INVALID_HANDLE_VALUE) return 0;
    fd = _open_osfhandle((intptr_t)file, _O_WRONLY | _O_TEXT);
    if (fd < 0) { CloseHandle(file); return 0; }
    if (_dup2(fd, _fileno(stdout)) || _dup2(fd, _fileno(stderr))) { _close(fd); return 0; }
    _close(fd);
    setvbuf(stdout, NULL, _IONBF, 0);
    return 1;
}

static void hide_owned_console(void)
{
    DWORD processes[2];
    HWND console = GetConsoleWindow();
    WINDOWPLACEMENT placement = {0};
    placement.length = sizeof(placement);
    /* Never hide an inherited/shared parent console. Restore only a visible
     * console for which this process is the sole attached client. */
    if (console && GetConsoleProcessList(processes, 2) == 1 &&
        processes[0] == GetCurrentProcessId() && IsWindowVisible(console) &&
        GetWindowPlacement(console, &placement)) {
        console_show_command = placement.showCmd;
        ShowWindow(console, SW_HIDE);
        hidden_console = console;
    }
}

static void restore_owned_console(void)
{
    if (hidden_console && IsWindow(hidden_console))
        ShowWindow(hidden_console, (int)console_show_command);
    hidden_console = NULL;
}

static int hold_interactive_frame(HDC dc, const WCHAR *title, const char *expected)
{
    if (!interactive) return 1;
    HWND hwnd = WindowFromDC(dc);
    printf("VISUAL_EXPECT %s; held=7000ms; visibility=UNVERIFIED\n", expected);
    if (!hwnd || !SetWindowTextW(hwnd, title) || !GdiFlush()) return fail("interactive-frame");
    pump_for(7000);
    return IsWindow(hwnd) ? 1 : fail("interactive-window-closed");
}

static int show_interactive_gdi(HDC dc)
{
    BITMAPINFO info = {0};
    RECT rect;
    /* Two top-down rows, red/green above blue/white. */
    const DWORD pixels[4] = {0x00ff0000, 0x0000ff00, 0x000000ff, 0x00ffffff};
    if (!interactive) return 1;
    info.bmiHeader.biSize = sizeof(info.bmiHeader);
    info.bmiHeader.biWidth = 2;
    info.bmiHeader.biHeight = -2;
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    if (!GetClientRect(WindowFromDC(dc), &rect) ||
        StretchDIBits(dc, 0, 0, rect.right, rect.bottom, 0, 0, 2, 2, pixels, &info,
                      DIB_RGB_COLORS, SRCCOPY) != 2) return fail("interactive-gdi-pattern");
    return hold_interactive_frame(dc, L"GDI: red/green above blue/white (7 sec)",
                                  "frame=GDI quadrants=red,green,blue,white");
}

/* Strict mode checks the cleanup of prerequisite GDI probes too. */
static int strict_gdi_cleanup(HDC memory, HBITMAP bitmap, HGDIOBJ previous)
{
    int ok = 1;
    if (previous && previous != HGDI_ERROR) {
        HGDIOBJ restored = SelectObject(memory, previous);
        if (!restored || restored == HGDI_ERROR) ok = 0;
    }
    if (bitmap && !DeleteObject(bitmap)) ok = 0;
    if (memory && !DeleteDC(memory)) ok = 0;
    if (!ok) fail("modern-gdi-cleanup");
    return ok;
}

/* Match Mesa's positive padded bitmap width and negative top-down height.
 * The visible source width is intentionally different from its row stride.
 */
static int check_gdi(HDC window_dc)
{
    BITMAPV5HEADER src = {0};
    BITMAPINFO dst = {0};
    uint32_t source[CANARY_STRIDE_PIXELS * CANARY_HEIGHT];
    HDC memory_dc = NULL;
    HBITMAP bitmap = NULL;
    HGDIOBJ previous = NULL;
    void *pixels = NULL;
    int ok = 0;

    begin("gdi-memory");
    canary_fill(source);
    src.bV5Size = sizeof(src);
    src.bV5Width = CANARY_STRIDE_PIXELS;
    src.bV5Height = -CANARY_HEIGHT;
    src.bV5Planes = 1;
    src.bV5BitCount = 32;
    src.bV5Compression = BI_RGB;
    dst.bmiHeader.biSize = sizeof(dst.bmiHeader);
    dst.bmiHeader.biWidth = CANARY_WIDTH;
    dst.bmiHeader.biHeight = -CANARY_HEIGHT;
    dst.bmiHeader.biPlanes = 1;
    dst.bmiHeader.biBitCount = 32;
    dst.bmiHeader.biCompression = BI_RGB;
    memory_dc = CreateCompatibleDC(window_dc);
    if (!memory_dc) goto out;
    bitmap = CreateDIBSection(memory_dc, &dst, DIB_RGB_COLORS, &pixels, NULL, 0);
    if (!bitmap || !pixels) goto out;
    previous = SelectObject(memory_dc, bitmap);
    if (!previous || previous == HGDI_ERROR) goto out;
    memset(pixels, 0x5a, CANARY_WIDTH * CANARY_HEIGHT * sizeof(uint32_t));
    if (StretchDIBits(memory_dc, 0, 0, CANARY_WIDTH, CANARY_HEIGHT,
                      0, 0, CANARY_WIDTH, CANARY_HEIGHT,
                      source, (const BITMAPINFO *)&src, DIB_RGB_COLORS, SRCCOPY) != CANARY_HEIGHT)
        goto out;
    if (!GdiFlush() || !canary_check(pixels, CANARY_WIDTH)) goto out;
    pass("gdi-memory");

    begin("gdi-window");
    if (StretchDIBits(window_dc, 0, 0, CANARY_WIDTH, CANARY_HEIGHT,
                      0, 0, CANARY_WIDTH, CANARY_HEIGHT,
                      source, (const BITMAPINFO *)&src, DIB_RGB_COLORS, SRCCOPY) != CANARY_HEIGHT)
        goto out;
    if (!GdiFlush()) goto out;
    memset(pixels, 0x5a, CANARY_WIDTH * CANARY_HEIGHT * sizeof(uint32_t));
    if (!BitBlt(memory_dc, 0, 0, CANARY_WIDTH, CANARY_HEIGHT, window_dc, 0, 0, SRCCOPY))
        goto out;
    if (!GdiFlush() || !canary_check(pixels, CANARY_WIDTH)) goto out;
    pass("gdi-window");
    puts("LIMIT gdi-window=backing-surface-readback; compositor-display-unverified");
    ok = 1;
out:
    if (!ok) fail("gdi");
    if (strict_modern) {
        if (!strict_gdi_cleanup(memory_dc, bitmap, previous)) ok = 0;
    } else {
        if (previous && previous != HGDI_ERROR) SelectObject(memory_dc, previous);
        if (bitmap) DeleteObject(bitmap);
        if (memory_dc) DeleteDC(memory_dc);
    }
    return ok;
}


/* The reference process may load only the two just-built application-local DLLs.
 * This is module identity, not a renderer capability or execution claim.
 */
static int module_identity(HMODULE module, const WCHAR *basename, const char *label)
{
    WCHAR actual[32768], expected[32768], *slash;
    char utf8[131072];
    DWORD n = GetModuleFileNameW(module, actual, 32768);
    if (!n || n >= 32768) return fail("module-path");
    n = GetModuleFileNameW(NULL, expected, 32768);
    if (!n || n >= 32768) return fail("executable-path");
    slash = wcsrchr(expected, L'\\');
    if (!slash || (size_t)(slash - expected + 1) + wcslen(basename) >= 32768)
        return fail("module-path");
    wcscpy(slash + 1, basename);
    if (source_built_reference && _wcsicmp(actual, expected)) return fail("module-not-app-local");
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, actual, -1,
                            utf8, sizeof(utf8), NULL, NULL)) return fail("module-path");
    printf("MODULE %s=%s\n", label, utf8);
    return 1;
}

static int check_window_pixel(HDC dc, const char *stage, unsigned r, unsigned g, unsigned b)
{
    BITMAPINFO info = {0};
    RECT client;
    HDC memory = NULL;
    HBITMAP bitmap = NULL;
    HGDIOBJ previous = NULL;
    uint32_t *pixel = NULL;
    unsigned actual_r = 0, actual_g = 0, actual_b = 0;
    int ok = 0;
    begin(stage);
    if (!GetClientRect(WindowFromDC(dc), &client) || client.bottom < 5) goto out;
    memory = CreateCompatibleDC(dc);
    if (!memory) goto out;
    info.bmiHeader.biSize = sizeof(info.bmiHeader);
    info.bmiHeader.biWidth = 1;
    info.bmiHeader.biHeight = -1;
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;
    bitmap = CreateDIBSection(memory, &info, DIB_RGB_COLORS, (void **)&pixel, NULL, 0);
    if (!bitmap || !pixel) goto out;
    previous = SelectObject(memory, bitmap);
    if (!previous || previous == HGDI_ERROR) goto out;
    *pixel = 0x005a5a5a;
    if (!GdiFlush() || !BitBlt(memory, 0, 0, 1, 1, dc, 4, client.bottom - 5, SRCCOPY) || !GdiFlush())
        goto out;
    actual_r = (*pixel >> 16) & 255;
    actual_g = (*pixel >> 8) & 255;
    actual_b = *pixel & 255;
    printf("WINDOW_PIXEL stage=%s rgb=%u,%u,%u\n", stage, actual_r, actual_g, actual_b);
    ok = canary_close(actual_r, r) && canary_close(actual_g, g) && canary_close(actual_b, b);
    if (ok) pass(stage);
out:
    if (!ok) fail(stage);
    if (strict_modern) {
        if (!strict_gdi_cleanup(memory, bitmap, previous)) ok = 0;
    } else {
        if (previous && previous != HGDI_ERROR) SelectObject(memory, previous);
        if (bitmap) DeleteObject(bitmap);
        if (memory) DeleteDC(memory);
    }
    return ok;
}

static int load_gl(void)
{
    WCHAR module_path[32768], *slash;
    const char *forwarded[] = {"wglChoosePixelFormat", "wglDescribePixelFormat",
        "wglGetPixelFormat", "wglSetPixelFormat", "wglSwapBuffers"};
    begin("gl-load");
    if (source_built_reference) {
        DWORD n = GetModuleFileNameW(NULL, module_path, 32768);
        if (!n || n >= 32768) return fail("executable-path");
        slash = wcsrchr(module_path, L'\\');
        if (!slash || (size_t)(slash - module_path) + 14 >= 32768) return fail("module-path");
        wcscpy(slash + 1, L"opengl32.dll");
        gl_module = LoadLibraryExW(module_path, NULL,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    } else gl_module = LoadLibraryW(L"opengl32.dll");
    if (!gl_module) return fail("gl-load");
    if (!module_identity(gl_module, L"opengl32.dll", "opengl32")) return 0;
    if (source_built_reference) {
        HMODULE gallium = GetModuleHandleW(L"libgallium_wgl.dll");
        if (!gallium || !module_identity(gallium, L"libgallium_wgl.dll", "gallium"))
            return fail("gallium-identity");
    }
    for (unsigned i = 0; i < sizeof(forwarded) / sizeof(forwarded[0]); ++i)
        if (!GetProcAddress(gl_module, forwarded[i])) {
            printf("MISSING export=%s\n", forwarded[i]);
            return fail("gdi-wgl-forwarders");
        }
    LOAD_EXPORT(get_gl_proc, "wglGetProcAddress");
    LOAD_EXPORT(create_context, "wglCreateContext");
    LOAD_EXPORT(make_current, "wglMakeCurrent");
    LOAD_EXPORT(delete_context, "wglDeleteContext");
    LOAD_EXPORT(get_string, "glGetString");
    LOAD_EXPORT(get_integer, "glGetIntegerv");
    LOAD_EXPORT(clear_color, "glClearColor");
    LOAD_EXPORT(clear, "glClear");
    LOAD_EXPORT(viewport, "glViewport");
    LOAD_EXPORT(read_pixels, "glReadPixels");
    LOAD_EXPORT(read_buffer, "glReadBuffer");
    LOAD_EXPORT(finish, "glFinish");
    LOAD_EXPORT(get_error, "glGetError");
    LOAD_EXPORT(draw_arrays, "glDrawArrays");
    pass("gl-load");
    return 1;
}

static int check_pixel(const char *stage, unsigned r, unsigned g, unsigned b)
{
    unsigned char rgba[4] = {0};
    GLenum error;
    finish();
    read_buffer(GL_BACK);
    read_pixels(4, 4, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, rgba);
    error = get_error();
    printf("PIXEL stage=%s rgba=%u,%u,%u,%u gl_error=0x%x\n",
           stage, rgba[0], rgba[1], rgba[2], rgba[3], error);
    if (error != GL_NO_ERROR || !canary_close(rgba[0], r) ||
        !canary_close(rgba[1], g) || !canary_close(rgba[2], b)) return fail(stage);
    pass(stage);
    return 1;
}

static int check_shader(void)
{
    LOAD_EXTENSION(PFNGLCREATESHADERPROC, create_shader, "glCreateShader");
    LOAD_EXTENSION(PFNGLSHADERSOURCEPROC, shader_source, "glShaderSource");
    LOAD_EXTENSION(PFNGLCOMPILESHADERPROC, compile_shader, "glCompileShader");
    LOAD_EXTENSION(PFNGLGETSHADERIVPROC, shader_iv, "glGetShaderiv");
    LOAD_EXTENSION(PFNGLGETSHADERINFOLOGPROC, shader_log, "glGetShaderInfoLog");
    LOAD_EXTENSION(PFNGLDELETESHADERPROC, delete_shader, "glDeleteShader");
    LOAD_EXTENSION(PFNGLCREATEPROGRAMPROC, create_program, "glCreateProgram");
    LOAD_EXTENSION(PFNGLATTACHSHADERPROC, attach_shader, "glAttachShader");
    LOAD_EXTENSION(PFNGLLINKPROGRAMPROC, link_program, "glLinkProgram");
    LOAD_EXTENSION(PFNGLGETPROGRAMIVPROC, program_iv, "glGetProgramiv");
    LOAD_EXTENSION(PFNGLGETPROGRAMINFOLOGPROC, program_log, "glGetProgramInfoLog");
    LOAD_EXTENSION(PFNGLUSEPROGRAMPROC, use_program, "glUseProgram");
    LOAD_EXTENSION(PFNGLDELETEPROGRAMPROC, delete_program, "glDeleteProgram");
    LOAD_EXTENSION(PFNGLGENVERTEXARRAYSPROC, gen_arrays, "glGenVertexArrays");
    LOAD_EXTENSION(PFNGLBINDVERTEXARRAYPROC, bind_array, "glBindVertexArray");
    LOAD_EXTENSION(PFNGLDELETEVERTEXARRAYSPROC, delete_arrays, "glDeleteVertexArrays");
    const char *sources[] = {
        "#version 430 core\nvoid main(){vec2 p[3]=vec2[3](vec2(-1,-1),vec2(3,-1),vec2(-1,3));gl_Position=vec4(p[gl_VertexID],0,1);}",
        "#version 430 core\nlayout(location=0) out vec4 c;void main(){c=vec4(1,0,0,1);}"
    };
    const GLenum types[] = {GL_VERTEX_SHADER, GL_FRAGMENT_SHADER};
    GLuint shaders[2] = {0}, program = 0, array = 0;
    GLint status = 0;
    char log[2048];
    int ok = 0;

    begin("core-shader");
    for (unsigned i = 0; i < 2; ++i) {
        shaders[i] = create_shader(types[i]);
        if (!shaders[i]) goto out;
        shader_source(shaders[i], 1, &sources[i], NULL);
        compile_shader(shaders[i]);
        shader_iv(shaders[i], GL_COMPILE_STATUS, &status);
        if (!status) {
            shader_log(shaders[i], sizeof(log), NULL, log);
            printf("SHADER_LOG %s\n", log);
            goto out;
        }
    }
    program = create_program();
    if (!program) goto out;
    attach_shader(program, shaders[0]);
    attach_shader(program, shaders[1]);
    link_program(program);
    program_iv(program, GL_LINK_STATUS, &status);
    if (!status) {
        program_log(program, sizeof(log), NULL, log);
        printf("PROGRAM_LOG %s\n", log);
        goto out;
    }
    use_program(program);
    gen_arrays(1, &array);
    bind_array(array);
    viewport(0, 0, 32, 32);
    clear_color(0, 0, 1, 1);
    clear(GL_COLOR_BUFFER_BIT);
    draw_arrays(GL_TRIANGLES, 0, 3);
    ok = check_pixel("core-shader-readback", 255, 0, 0);
out:
    use_program(0);
    if (array) delete_arrays(1, &array);
    if (program) delete_program(program);
    for (unsigned i = 0; i < 2; ++i) if (shaders[i]) delete_shader(shaders[i]);
    if (strict_modern && get_error() != GL_NO_ERROR) { fail("modern-core-shader-cleanup"); ok = 0; }
    if (!ok) fail("core-shader");
    return ok;
}

/* The original three modes retain their original behavior. */
#include "wgl_canary_modern.h"

static int check_wgl(HDC dc, int modern)
{
    PIXELFORMATDESCRIPTOR wanted = {0}, actual = {0};
    HGLRC legacy = NULL, core = NULL;
    int format, ok = 0;
    const GLubyte *renderer, *version;

    if (!load_gl()) return 0;
    begin("pixel-format");
    wanted.nSize = sizeof(wanted);
    wanted.nVersion = 1;
    wanted.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
    wanted.iPixelType = PFD_TYPE_RGBA;
    wanted.cColorBits = 24;
    format = ChoosePixelFormat(dc, &wanted); /* Exercise Wine's real GDI forwarder. */
    if (!format || !DescribePixelFormat(dc, format, sizeof(actual), &actual)) goto out;
    printf("FORMAT index=%d flags=0x%lx color=%u depth=%u stencil=%u\n", format,
           (unsigned long)actual.dwFlags, actual.cColorBits, actual.cDepthBits, actual.cStencilBits);
    if ((actual.dwFlags & wanted.dwFlags) != wanted.dwFlags || actual.iPixelType != PFD_TYPE_RGBA)
        goto out;
    if (!SetPixelFormat(dc, format, &actual) || GetPixelFormat(dc) != format) goto out;
    pass("pixel-format");

    begin("legacy-context");
    legacy = create_context(dc);
    if (!legacy || !make_current(dc, legacy)) goto out;
    if (get_gl_proc("madeira_nonexistent_gl_canary_20261005") != NULL) {
        puts("FAIL stage=unknown-extension-must-return-null");
        goto out;
    }
    renderer = get_string(GL_RENDERER);
    version = get_string(GL_VERSION);
    if (!renderer || !version) goto out;
    printf("GL renderer=%s version=%s\n", renderer, version);
    if (source_built_reference) {
        GLint major = 0, minor = 0, profile = 0;
        get_integer(GL_MAJOR_VERSION, &major);
        get_integer(GL_MINOR_VERSION, &minor);
        if (major > 3 || (major == 3 && minor >= 2)) get_integer(GL_CONTEXT_PROFILE_MASK, &profile);
        printf("LEGACY version=%d.%d profile=0x%x\n", major, minor, profile);
        if (get_error() || major < 3 ||
            (strict_modern ? strncmp((const char *)renderer, "llvmpipe (", 10) :
                             strcmp((const char *)renderer, "softpipe")) ||
            !strstr((const char *)version, "Mesa 26.2.4")) {
            fail(strict_modern ? "llvmpipe-identity" : "softpipe-identity"); goto out;
        }
    }
    pass("legacy-context");
    viewport(0, 0, 32, 32);
    clear_color(0.25f, 0.5f, 0.75f, 1.0f);
    clear(GL_COLOR_BUFFER_BIT);
    if (!check_pixel("legacy-clear-readback", 64, 128, 191)) goto out;
    begin("legacy-swap");
    if (!SwapBuffers(dc)) goto out;
    pass("legacy-swap");
    if (!check_window_pixel(dc, "legacy-window-readback", 64, 128, 191)) goto out;
    if (!hold_interactive_frame(dc, L"Mesa frame 1: blue (7 sec)", "frame=GL1 rgb=64,128,191")) goto out;
    clear_color(0.75f, 0.25f, 0.5f, 1.0f);
    clear(GL_COLOR_BUFFER_BIT);
    if (!check_pixel("legacy-second-readback", 191, 64, 128)) goto out;
    begin("legacy-second-swap");
    if (!SwapBuffers(dc)) goto out;
    pass("legacy-second-swap");
    if (!check_window_pixel(dc, "legacy-second-window-readback", 191, 64, 128)) goto out;
    if (!hold_interactive_frame(dc, L"Mesa frame 2: purple (7 sec)", "frame=GL2 rgb=191,64,128")) goto out;
    puts("LIMIT swap=window-backing-pixel-readback; compositor-display-unverified");
    if (!modern) { ok = 1; goto out; }

    begin("core43-context");
    {
        PROC found = extension("wglCreateContextAttribsARB");
        PFNWGLCREATECONTEXTATTRIBSARBPROC create_attribs;
        GLint major = 0, minor = 0, profile = 0;
        const int attributes[] = {WGL_CONTEXT_MAJOR_VERSION_ARB, 4,
            WGL_CONTEXT_MINOR_VERSION_ARB, 3,
            WGL_CONTEXT_PROFILE_MASK_ARB, WGL_CONTEXT_CORE_PROFILE_BIT_ARB, 0};
        if (!found) {
            puts("UNAVAILABLE core43=missing-create-context-attribs");
            core_unavailable = 1;
            goto out;
        }
        memcpy(&create_attribs, &found, sizeof(create_attribs));
        core = create_attribs(dc, NULL, attributes);
        if (!core) {
            DWORD error = GetLastError();
            if (error != ERROR_INVALID_VERSION_ARB && error != ERROR_INVALID_PROFILE_ARB) {
                fail("core43-create");
                goto out;
            }
            printf("UNAVAILABLE core43=context-rejected win32_error=%lu\n", (unsigned long)error);
            core_unavailable = 1;
            goto out;
        }
        if (!make_current(dc, core)) goto out;
        get_integer(GL_MAJOR_VERSION, &major);
        get_integer(GL_MINOR_VERSION, &minor);
        get_integer(GL_CONTEXT_PROFILE_MASK, &profile);
        printf("CORE version=%d.%d profile=0x%x\n", major, minor, profile);
        if (get_error() || major < 4 || (major == 4 && minor < 3) ||
            !(profile & GL_CONTEXT_CORE_PROFILE_BIT) ||
            (strict_modern && profile != GL_CONTEXT_CORE_PROFILE_BIT)) goto out;
    }
    pass("core43-context");
    if (!check_shader()) goto out;
    begin("core-swap");
    if (!SwapBuffers(dc)) goto out;
    pass("core-swap");
    if (!check_window_pixel(dc, "core-window-readback", 255, 0, 0)) goto out;
    puts("LIMIT swap=API-success; compositor-display-unverified");
    if (strict_modern) {
        if (!check_modern(dc)) goto out;
        HMODULE gallium = GetModuleHandleW(L"libgallium_wgl.dll");
        if (!gallium || !module_identity(gl_module, L"opengl32.dll", "opengl32-after") ||
            !module_identity(gallium, L"libgallium_wgl.dll", "gallium-after")) goto out;
        pass("modern-module-recheck");
    }
    ok = 1;
out:
    if (!ok && !core_unavailable) fail("wgl");
    if (make_current && !make_current(NULL, NULL)) { fail("detach"); ok = 0; core_unavailable = 0; }
    if (core && !delete_context(core)) { fail("delete-core"); ok = 0; core_unavailable = 0; }
    if (legacy && !delete_context(legacy)) { fail("delete-legacy"); ok = 0; core_unavailable = 0; }
    return ok;
}

int main(int argc, char **argv)
{
    const char *stage = "gdi";
    DWORD hold_ms = 0;
    WNDCLASSW cls = {0};
    HWND window = NULL;
    HDC dc = NULL;
    int result = 1, registered = 0;
    interactive = argc == 1 || (argc == 2 && !strcmp(argv[1], "--interactive"));
    if (interactive) {
        if (!open_interactive_report()) {
            MessageBoxW(NULL, L"Cannot create a new local report beside this EXE. Extract the whole ZIP into a writable folder and try again.",
                        L"Madeira softpipe canary", MB_OK | MB_ICONERROR);
            return 1;
        }
        stage = "legacy";
        source_built_reference = 1;
        hide_owned_console();
        if (!SetEnvironmentVariableA("GALLIUM_DRIVER", "softpipe") || _putenv_s("GALLIUM_DRIVER", "softpipe")) {
            fail("interactive-renderer-environment"); goto out;
        }
        puts("INTERACTIVE local canary report only; no upload; compositor visibility requires your observation");
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    for (int i = interactive ? argc : 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--source-built-reference")) source_built_reference = 1;
        else if (!strcmp(argv[i], "--stage") && i + 1 < argc) stage = argv[++i];
        else if (!strcmp(argv[i], "--hold-ms") && i + 1 < argc) {
            char *end;
            unsigned long n = strtoul(argv[++i], &end, 10);
            if (!*argv[i] || *end || n > 30000) return 2;
            hold_ms = (DWORD)n;
        } else return 2;
    }
    if (strcmp(stage, "gdi") && strcmp(stage, "legacy") && strcmp(stage, "core43") && strcmp(stage, "modern")) return 2;
    strict_modern = !strcmp(stage, "modern");
    if (strict_modern && (!source_built_reference || hold_ms)) return 2;
    printf("CANARY stage=%s pointer_bits=%u\n", stage, (unsigned)(8 * sizeof(void *)));
    begin("window");
    cls.style = CS_OWNDC;
    cls.lpfnWndProc = window_proc;
    cls.hInstance = GetModuleHandleW(NULL);
    cls.lpszClassName = L"MadeiraWglCanary";
    if (!RegisterClassW(&cls)) { fail("window-class"); goto out; }
    registered = 1;
    window = CreateWindowW(cls.lpszClassName, L"Madeira WGL canary", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                          CW_USEDEFAULT, CW_USEDEFAULT, interactive ? 400 : 240, interactive ? 300 : 180,
                          NULL, NULL, cls.hInstance, NULL);
    if (!window) { fail("window-create"); goto out; }
    if (interactive) SetForegroundWindow(window);
    dc = GetDC(window);
    if (!dc || WindowFromDC(dc) != window) { fail("window-dc"); goto out; }
    RECT client;
    if (!GetClientRect(window, &client) || client.right < 32 || client.bottom < 32) {
        fail("window-client"); goto out;
    }
    pass("window");
    pump_for(0);
    if (!check_gdi(dc)) goto out;
    if (!show_interactive_gdi(dc)) goto out;
    if (strcmp(stage, "gdi") && !check_wgl(dc, strict_modern || !strcmp(stage, "core43"))) {
        if (core_unavailable && !strict_modern) result = 77;
        if (strict_modern) fail("modern-required");
        goto out;
    }
    if (!strict_modern) printf("PASS requested-stage=%s\n", stage);
    result = 0;
out:
    pump_for(hold_ms);
    if (strict_modern) {
        if (dc && !ReleaseDC(window, dc)) { fail("release-dc"); result = 1; }
        if (window && !DestroyWindow(window)) { fail("destroy-window"); result = 1; }
        if (gl_module && !FreeLibrary(gl_module)) { fail("free-gl-module"); result = 1; }
        if (registered && !UnregisterClassW(cls.lpszClassName, cls.hInstance)) { fail("unregister-class"); result = 1; }
        if (!result) { pass("modern-platform-cleanup"); printf("PASS requested-stage=%s\n", stage); }
    } else {
        if (dc) ReleaseDC(window, dc);
        if (window) DestroyWindow(window);
        if (gl_module) FreeLibrary(gl_module);
        if (registered) UnregisterClassW(cls.lpszClassName, cls.hInstance);
    }
    if (interactive) {
        WCHAR summary[34000];
        restore_owned_console();
        printf("INTERACTIVE_RESULT exit=%d compositor_display_proven=false\n", result);
        fflush(stdout);
        swprintf(summary, 34000,
                 L"%ls\n\nDid you see all three pictures: GDI quadrants, blue, then purple? This program cannot verify what appeared on the iPhone.\n\nLocal report (not sent anywhere):\n%ls",
                 result ? L"A canary check failed. Review the local report." :
                          L"Backing-pixel and app-local Mesa checks passed. Visible output still needs your confirmation.",
                 interactive_report);
        MessageBoxW(NULL, summary, L"Madeira softpipe canary result", MB_OK | (result ? MB_ICONERROR : MB_ICONINFORMATION));
    }
    return result;
}
