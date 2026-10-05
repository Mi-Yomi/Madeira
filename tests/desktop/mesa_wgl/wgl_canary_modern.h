/* SPDX-License-Identifier: MIT
 * Strict modern stage only. Included after the original core43 canary.
 * Fixed workloads: 2 single-invocation dispatches, 2 storage draws,
 * one two-command/two-instance indexed indirect draw, 8 clip-control draws.
 * The accepting runner must enforce a 45-second process-tree timeout.
 */
#ifndef WGL_CANARY_MODERN_H
#define WGL_CANARY_MODERN_H
#include "wgl_canary_modern_values.h"
typedef void (APIENTRY *MEnumProc)(GLenum);
typedef void (APIENTRY *MGenProc)(GLsizei, GLuint *);
typedef void (APIENTRY *MDeleteProc)(GLsizei, const GLuint *);
typedef void (APIENTRY *MBindProc)(GLenum, GLuint);
typedef GLboolean (APIENTRY *MIsProc)(GLuint);
#define MODERN_FUNCTIONS(X) \
 X(PFNGLGETSTRINGIPROC, GetStringi) \
 X(PFNGLGETINTEGER64VPROC, GetInteger64v) \
 X(PFNGLGETINTEGERI_VPROC, GetIntegeri_v) \
 X(PFNGLCREATESHADERPROC, CreateShader) \
 X(PFNGLSHADERSOURCEPROC, ShaderSource) \
 X(PFNGLCOMPILESHADERPROC, CompileShader) \
 X(PFNGLGETSHADERIVPROC, GetShaderiv) \
 X(PFNGLGETSHADERINFOLOGPROC, GetShaderInfoLog) \
 X(PFNGLDELETESHADERPROC, DeleteShader) \
 X(PFNGLISSHADERPROC, IsShader) \
 X(PFNGLCREATEPROGRAMPROC, CreateProgram) \
 X(PFNGLATTACHSHADERPROC, AttachShader) \
 X(PFNGLDETACHSHADERPROC, DetachShader) \
 X(PFNGLLINKPROGRAMPROC, LinkProgram) \
 X(PFNGLGETPROGRAMIVPROC, GetProgramiv) \
 X(PFNGLGETPROGRAMINFOLOGPROC, GetProgramInfoLog) \
 X(PFNGLUSEPROGRAMPROC, UseProgram) \
 X(PFNGLDELETEPROGRAMPROC, DeleteProgram) \
 X(PFNGLISPROGRAMPROC, IsProgram) \
 X(PFNGLGETUNIFORMLOCATIONPROC, GetUniformLocation) \
 X(PFNGLUNIFORM1UIPROC, Uniform1ui) \
 X(PFNGLUNIFORM1FPROC, Uniform1f) \
 X(PFNGLGETPROGRAMINTERFACEIVPROC, GetProgramInterfaceiv) \
 X(PFNGLGETPROGRAMRESOURCEINDEXPROC, GetProgramResourceIndex) \
 X(PFNGLGETPROGRAMRESOURCEIVPROC, GetProgramResourceiv) \
 X(PFNGLGENBUFFERSPROC, GenBuffers) \
 X(PFNGLBINDBUFFERPROC, BindBuffer) \
 X(PFNGLBUFFERDATAPROC, BufferData) \
 X(PFNGLBINDBUFFERBASEPROC, BindBufferBase) \
 X(PFNGLMAPBUFFERRANGEPROC, MapBufferRange) \
 X(PFNGLUNMAPBUFFERPROC, UnmapBuffer) \
 X(PFNGLDELETEBUFFERSPROC, DeleteBuffers) \
 X(PFNGLISBUFFERPROC, IsBuffer) \
 X(PFNGLDISPATCHCOMPUTEPROC, DispatchCompute) \
 X(PFNGLMEMORYBARRIERPROC, MemoryBarrier) \
 X(PFNGLGENVERTEXARRAYSPROC, GenVertexArrays) \
 X(PFNGLBINDVERTEXARRAYPROC, BindVertexArray) \
 X(PFNGLDELETEVERTEXARRAYSPROC, DeleteVertexArrays) \
 X(PFNGLISVERTEXARRAYPROC, IsVertexArray) \
 X(PFNGLVERTEXATTRIBIPOINTERPROC, VertexAttribIPointer) \
 X(PFNGLVERTEXATTRIBDIVISORPROC, VertexAttribDivisor) \
 X(PFNGLENABLEVERTEXATTRIBARRAYPROC, EnableVertexAttribArray) \
 X(PFNGLDISABLEVERTEXATTRIBARRAYPROC, DisableVertexAttribArray) \
 X(PFNGLMULTIDRAWELEMENTSINDIRECTPROC, MultiDrawElementsIndirect) \
 X(PFNGLGENFRAMEBUFFERSPROC, GenFramebuffers) \
 X(PFNGLBINDFRAMEBUFFERPROC, BindFramebuffer) \
 X(PFNGLFRAMEBUFFERTEXTURE2DPROC, FramebufferTexture2D) \
 X(PFNGLCHECKFRAMEBUFFERSTATUSPROC, CheckFramebufferStatus) \
 X(PFNGLDELETEFRAMEBUFFERSPROC, DeleteFramebuffers) \
 X(PFNGLISFRAMEBUFFERPROC, IsFramebuffer) \
 X(MGenProc, GenTextures) \
 X(MBindProc, BindTexture) \
 X(PFNGLTEXSTORAGE2DPROC, TexStorage2D) \
 X(MDeleteProc, DeleteTextures) \
 X(MIsProc, IsTexture) \
 X(PFNGLDRAWBUFFERSPROC, DrawBuffers) \
 X(PFNGLCLEARBUFFERUIVPROC, ClearBufferuiv) \
 X(PFNGLCLEARBUFFERFVPROC, ClearBufferfv) \
 X(PFNGLBLITFRAMEBUFFERPROC, BlitFramebuffer) \
 X(PFNGLCLIPCONTROLPROC, ClipControl) \
 X(MEnumProc, Disable) \
 X(MEnumProc, Enable) \
 X(MEnumProc, DepthFunc)
struct modern_api {
#define MODERN_FIELD(type, name) type name;
 MODERN_FUNCTIONS(MODERN_FIELD)
#undef MODERN_FIELD
};
static struct modern_api m;
static int modern_error(const char *stage)
{
    GLenum error = get_error();
    if (error) { printf("MODERN_ERROR stage=%s gl_error=0x%x\n", stage, error); return fail(stage); }
    return 1;
}
static int modern_load(void)
{
#define MODERN_LOAD(type, name) do { \
    PROC found = (PROC)GetProcAddress(gl_module, "gl" #name); \
    if (!valid_proc(found)) found = extension("gl" #name); \
    if (!valid_proc(found)) return fail("modern-functions"); \
    _Static_assert(sizeof(type) == sizeof(found), "procedure width"); \
    memcpy(&m.name, &found, sizeof(found)); \
} while (0);
    MODERN_FUNCTIONS(MODERN_LOAD)
#undef MODERN_LOAD
    return modern_error("modern-functions");
}
static int modern_identity(void)
{
    GLint count = 0, draw_parameters = 0, clip_control = 0;
    const char *renderer = (const char *)get_string(GL_RENDERER);
    const char *version = (const char *)get_string(GL_VERSION);
    const char *glsl = (const char *)get_string(GL_SHADING_LANGUAGE_VERSION);
    if (!renderer || !version || !glsl) return fail("modern-identity");
    printf("MODERN_IDENTITY renderer=%s version=%s glsl=%s\n", renderer, version, glsl);
    if (source_built_reference && (strncmp(renderer, "llvmpipe (", 10) || !strstr(version, "Mesa 26.2.4")))
        return fail("modern-identity");
    get_integer(GL_NUM_EXTENSIONS, &count);
    if (count < 0 || count > 4096) return fail("modern-extension-count");
    for (GLint i = 0; i < count; ++i) {
        const char *name = (const char *)m.GetStringi(GL_EXTENSIONS, (GLuint)i);
        if (!name) return fail("modern-extension-query");
        if (!strcmp(name, "GL_ARB_shader_draw_parameters")) ++draw_parameters;
        if (!strcmp(name, "GL_ARB_clip_control")) ++clip_control;
    }
    printf("MODERN_EXTENSIONS enumerated=%d draw_parameters=%d clip_control=%d\n", count, draw_parameters, clip_control);
    if (draw_parameters != 1 || clip_control != 1) return fail("modern-extensions");
    const GLenum keys[] = {GL_MAX_VERTEX_SHADER_STORAGE_BLOCKS, GL_MAX_FRAGMENT_SHADER_STORAGE_BLOCKS,
        GL_MAX_COMPUTE_SHADER_STORAGE_BLOCKS, GL_MAX_SHADER_STORAGE_BUFFER_BINDINGS,
        GL_MAX_COMBINED_SHADER_STORAGE_BLOCKS, GL_MAX_COMPUTE_WORK_GROUP_INVOCATIONS,
        GL_MAX_DRAW_BUFFERS, GL_MAX_COLOR_ATTACHMENTS};
    const char *names[] = {"vertex_blocks", "fragment_blocks", "compute_blocks", "bindings",
                          "combined_blocks", "compute_invocations", "draw_buffers", "color_attachments"};
    const GLint floors[] = {12, 12, 12, 12, 24, 1, 2, 2};
    for (unsigned i = 0; i < sizeof(keys)/sizeof(keys[0]); ++i) {
        GLint value = 0;
        get_integer(keys[i], &value);
        printf("MODERN_LIMIT %s=%d\n", names[i], value);
        if (value < floors[i]) return fail("modern-limits");
    }
    GLint64 size = 0;
    m.GetInteger64v(GL_MAX_SHADER_STORAGE_BLOCK_SIZE, &size);
    printf("MODERN_LIMIT block_bytes=%lld\n", (long long)size);
    if (size < 16) return fail("modern-limits");
    for (unsigned i = 0; i < 3; ++i) {
        GLint groups = 0, threads = 0;
        m.GetIntegeri_v(GL_MAX_COMPUTE_WORK_GROUP_COUNT, i, &groups);
        m.GetIntegeri_v(GL_MAX_COMPUTE_WORK_GROUP_SIZE, i, &threads);
        printf("MODERN_WORKGROUP axis=%u count=%d size=%d\n", i, groups, threads);
        if (groups < 1 || threads < 1) return fail("modern-limits");
    }
    if (!modern_error("modern-limits")) return 0;
    pass("modern-identity-limits");
    return 1;
}
/* Encode logs so even newlines/control bytes cannot become proof records. */
static int modern_log(GLuint object, int program, const char *name, unsigned stage, GLint status)
{
    char log[2048] = {0};
    GLint needed = 0;
    GLsizei length = 0;
    if (program) {
        m.GetProgramiv(object, GL_INFO_LOG_LENGTH, &needed);
        m.GetProgramInfoLog(object, sizeof(log), &length, log);
    } else {
        m.GetShaderiv(object, GL_INFO_LOG_LENGTH, &needed);
        m.GetShaderInfoLog(object, sizeof(log), &length, log);
    }
    if (length < 0 || length >= (GLsizei)sizeof(log) || needed > (GLint)sizeof(log))
        return fail("modern-log-bound");
    printf("MODERN_LOG program=%s kind=%s stage=%u status=%d bytes=%d hex=", name,
           program ? "link" : "compile", stage, status, length);
    for (GLsizei i = 0; i < length; ++i) printf("%02x", (unsigned char)log[i]);
    puts("");
    return modern_error("modern-shader-log");
}
static GLuint modern_program(const char *name, const char *vs, const char *fs, const char *cs)
{
    const char *sources[3] = {vs, fs, cs};
    const GLenum types[3] = {GL_VERTEX_SHADER, GL_FRAGMENT_SHADER, GL_COMPUTE_SHADER};
    GLuint shaders[3] = {0}, program = 0;
    GLint status = 0;
    int ok = 0, attached[3] = {0};
    for (unsigned i = 0; i < 3; ++i) if (sources[i]) {
        shaders[i] = m.CreateShader(types[i]);
        if (!shaders[i]) goto out;
        m.ShaderSource(shaders[i], 1, &sources[i], NULL);
        m.CompileShader(shaders[i]);
        m.GetShaderiv(shaders[i], GL_COMPILE_STATUS, &status);
        if (!modern_log(shaders[i], 0, name, i, status) || !status) goto out;
    }
    program = m.CreateProgram();
    if (!program) goto out;
    for (unsigned i = 0; i < 3; ++i) if (shaders[i]) {
        m.AttachShader(program, shaders[i]); attached[i] = 1;
    }
    m.LinkProgram(program);
    m.GetProgramiv(program, GL_LINK_STATUS, &status);
    ok = modern_log(program, 1, name, 3, status) && status;
out:
    for (unsigned i = 0; i < 3; ++i) if (shaders[i]) {
        if (attached[i]) m.DetachShader(program, shaders[i]);
        m.DeleteShader(shaders[i]);
        if (m.IsShader(shaders[i])) ok = 0;
    }
    if (!modern_error("modern-shader-cleanup")) ok = 0;
    if (!ok) {
        if (program) {
            m.DeleteProgram(program);
            if (m.IsProgram(program)) fail("modern-program-cleanup");
        }
        fail("modern-compile-link");
        return 0;
    }
    return program;
}
static int modern_source(char *dst, size_t capacity, int readonly, const char *body)
{
    size_t used = 0;
    int n = snprintf(dst, capacity, "#version 430 core\n");
    if (n < 0 || (size_t)n >= capacity) return 0;
    used = (size_t)n;
    for (unsigned i = 0; i < 12; ++i) {
        n = snprintf(dst + used, capacity - used,
            "layout(std430,binding=%u) %sbuffer B%u { uint v[4]; } b%u;\n", i,
            readonly ? "readonly " : "", i, i);
        if (n < 0 || (size_t)n >= capacity - used) return 0;
        used += (size_t)n;
    }
    n = snprintf(dst + used, capacity - used, "%s", body);
    return n >= 0 && (size_t)n < capacity - used;
}
static int modern_blocks(GLuint program, const char *name, int compute)
{
    GLint count = 0;
    const GLenum properties[] = {GL_BUFFER_BINDING, GL_BUFFER_DATA_SIZE,
        GL_REFERENCED_BY_VERTEX_SHADER, GL_REFERENCED_BY_FRAGMENT_SHADER, GL_REFERENCED_BY_COMPUTE_SHADER};
    m.GetProgramInterfaceiv(program, GL_SHADER_STORAGE_BLOCK, GL_ACTIVE_RESOURCES, &count);
    printf("MODERN_BLOCK_COUNT program=%s count=%d\n", name, count);
    if (count != 12) return fail("modern-active-blocks");
    for (unsigned i = 0; i < 12; ++i) {
        char block[16];
        GLint values[5] = {-1, -1, -1, -1, -1};
        GLsizei written = 0;
        snprintf(block, sizeof(block), "B%u", i);
        GLuint index = m.GetProgramResourceIndex(program, GL_SHADER_STORAGE_BLOCK, block);
        if (index == GL_INVALID_INDEX) return fail("modern-block-index");
        m.GetProgramResourceiv(program, GL_SHADER_STORAGE_BLOCK, index, 5, properties, 5, &written, values);
        printf("MODERN_BLOCK program=%s block=%u binding=%d bytes=%d vertex=%d fragment=%d compute=%d\n",
               name, i, values[0], values[1], values[2], values[3], values[4]);
        if (written != 5 || values[0] != (GLint)i || values[1] != 16 ||
            values[2] != !compute || values[3] != !compute || values[4] != compute)
            return fail("modern-block-references");
    }
    return modern_error("modern-block-references");
}
static int modern_uint_pixel(const char *phase, unsigned trial, unsigned sample, GLint x, GLint y, const uint32_t expected[4])
{
    GLuint actual[4] = {0};
    read_buffer(GL_COLOR_ATTACHMENT0);
    read_pixels(x, y, 1, 1, GL_RGBA_INTEGER, GL_UNSIGNED_INT, actual);
    printf("MODERN_UINT phase=%s trial=%u sample=%u xy=%d,%d values=%08x,%08x,%08x,%08x\n",
           phase, trial, sample, x, y, actual[0], actual[1], actual[2], actual[3]);
    if (memcmp(actual, expected, sizeof(actual))) return fail("modern-uint-pixel");
    return modern_error("modern-uint-pixel");
}
static int modern_rgba_pixel(const char *phase, unsigned trial, unsigned sample, GLint x, GLint y, const unsigned char expected[4])
{
    unsigned char actual[4] = {0};
    read_buffer(GL_COLOR_ATTACHMENT1);
    read_pixels(x, y, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, actual);
    printf("MODERN_PIXEL phase=%s trial=%u sample=%u xy=%d,%d rgba=%u,%u,%u,%u\n",
           phase, trial, sample, x, y, actual[0], actual[1], actual[2], actual[3]);
    if (memcmp(actual, expected, sizeof(actual))) return fail("modern-rgba-pixel");
    return modern_error("modern-rgba-pixel");
}
static void modern_clear(void)
{
    const GLuint zero[4] = {0};
    const GLfloat black[4] = {0,0,0,1}, depth = 1;
    m.ClearBufferuiv(GL_COLOR, 0, zero);
    m.ClearBufferfv(GL_COLOR, 1, black);
    m.ClearBufferfv(GL_DEPTH, 0, &depth);
}
static int modern_present(HDC dc, GLuint fbo, unsigned trial, const unsigned char expected[4])
{
    char stage[64];
    m.BindFramebuffer(GL_DRAW_FRAMEBUFFER, 0);
    const GLenum back = GL_BACK;
    m.DrawBuffers(1, &back);
    read_buffer(GL_COLOR_ATTACHMENT1);
    m.BlitFramebuffer(0, 0, 32, 32, 0, 0, 32, 32, GL_COLOR_BUFFER_BIT, GL_NEAREST);
    if (!modern_error("modern-present-blit") || !SwapBuffers(dc)) return fail("modern-present-swap");
    snprintf(stage, sizeof(stage), "modern-storage-window-%u", trial);
    if (!check_window_pixel(dc, stage, expected[0], expected[1], expected[2])) return 0;
    m.BindFramebuffer(GL_FRAMEBUFFER, fbo);
    const GLenum attachments[2] = {GL_COLOR_ATTACHMENT0, GL_COLOR_ATTACHMENT1};
    m.DrawBuffers(2, attachments);
    return modern_error("modern-present-restore");
}
static int check_modern(HDC dc)
{
    /* Separate uint results preserve every checksum bit. Normalized attachment1
     * proves presentation without illegal integer-to-default framebuffer blits. */
    GLuint buffers[12] = {0}, extra[3] = {0}, textures[3] = {0}, array = 0, fbo = 0;
    GLuint programs[4] = {0};
    char cs[8192], vs[8192], fs[8192];
    uint32_t words[12][4], expected[4];
    unsigned char color[4];
    DWORD started = GetTickCount();
    int ok = 0, cleanup_ok = 1;
    begin("modern-capabilities");
    if (!modern_load() || !modern_identity()) return 0;
    if (!modern_source(cs, sizeof(cs), 0,
        "layout(local_size_x=1,local_size_y=1,local_size_z=1) in;\nuniform uint seed;\n"
        "uint word(uint b,uint j){uint x=(seed^(0x9e3779b9u*(b+1u)))+0x85ebca6bu*(j+1u);x^=x>>16;x*=0x7feb352du;x^=x>>15;return x;}\n"
        "void main(){for(uint j=0u;j<4u;++j){"
        "b0.v[j]=word(0u,j);b1.v[j]=word(1u,j);b2.v[j]=word(2u,j);b3.v[j]=word(3u,j);"
        "b4.v[j]=word(4u,j);b5.v[j]=word(5u,j);b6.v[j]=word(6u,j);b7.v[j]=word(7u,j);"
        "b8.v[j]=word(8u,j);b9.v[j]=word(9u,j);b10.v[j]=word(10u,j);b11.v[j]=word(11u,j);}}")) goto out;
    /* Every weighted term contributes to its own observed 32-bit stage checksum;
     * there is no subtraction/cancellation of repeated expressions. */
    /* Explicit strings keep shader arithmetic reviewable against the C oracle. */
    const char *sum0 = "(0x31415927u+b0.v[0]*3u+b1.v[0]*5u+b2.v[0]*7u+b3.v[0]*9u+b4.v[0]*11u+b5.v[0]*13u+b6.v[0]*15u+b7.v[0]*17u+b8.v[0]*19u+b9.v[0]*21u+b10.v[0]*23u+b11.v[0]*25u)";
    const char *sum1 = "(0x31415927u*2u+b0.v[1]*5u+b1.v[1]*7u+b2.v[1]*9u+b3.v[1]*11u+b4.v[1]*13u+b5.v[1]*15u+b6.v[1]*17u+b7.v[1]*19u+b8.v[1]*21u+b9.v[1]*23u+b10.v[1]*25u+b11.v[1]*27u)";
    const char *sum2 = "(0x31415927u*3u+b0.v[2]*7u+b1.v[2]*9u+b2.v[2]*11u+b3.v[2]*13u+b4.v[2]*15u+b5.v[2]*17u+b6.v[2]*19u+b7.v[2]*21u+b8.v[2]*23u+b9.v[2]*25u+b10.v[2]*27u+b11.v[2]*29u)";
    const char *sum3 = "(0x31415927u*4u+b0.v[3]*9u+b1.v[3]*11u+b2.v[3]*13u+b3.v[3]*15u+b4.v[3]*17u+b5.v[3]*19u+b6.v[3]*21u+b7.v[3]*23u+b8.v[3]*25u+b9.v[3]*27u+b10.v[3]*29u+b11.v[3]*31u)";
    const char *encode = "vec4 encode(uvec4 q){return vec4(float((q.x^(q.y>>8))&255u),float((q.y^(q.z>>16))&255u),float((q.z^(q.w>>24))&255u),255.0)/255.0;}\n";
    char body[4096];
    int n = snprintf(body, sizeof(body),
        "flat out uvec2 vertex_sum;void main(){vec2 p[3]=vec2[3](vec2(-1,-1),vec2(3,-1),vec2(-1,3));"
        "gl_Position=vec4(p[gl_VertexID],0,1);vertex_sum=uvec2(%s,%s);}", sum0, sum1);
    if (n < 0 || (size_t)n >= sizeof(body) || !modern_source(vs, sizeof(vs), 1, body)) goto out;
    n = snprintf(body, sizeof(body),
        "flat in uvec2 vertex_sum;layout(location=0) out uvec4 result;layout(location=1) out vec4 color;\n%s"
        "void main(){result=uvec4(vertex_sum,%s,%s);color=encode(result);}", encode, sum2, sum3);
    if (n < 0 || (size_t)n >= sizeof(body) || !modern_source(fs, sizeof(fs), 1, body)) goto out;
    programs[0] = modern_program("compute", NULL, NULL, cs);
    programs[1] = modern_program("storage", vs, fs, NULL);
    if (!programs[0] || !programs[1] || !modern_blocks(programs[0], "compute", 1) ||
        !modern_blocks(programs[1], "storage", 0)) goto out;
    const char *indirect_vs = "#version 430 core\n#extension GL_ARB_shader_draw_parameters : require\n"
        "layout(location=0) in uint instance_value;flat out uvec4 parameters;"
        "void main(){int local=gl_VertexID-gl_BaseVertexARB-3*gl_DrawIDARB;"
        "vec2 p=local==0?vec2(0,0):local==1?vec2(1,0):local==2?vec2(0,1):vec2(8,8);"
        "gl_Position=vec4(vec2(-.9)+vec2(float(gl_DrawIDARB),float(gl_InstanceID))+.8*p,0,1);"
        "parameters=uvec4(gl_BaseVertexARB,gl_BaseInstanceARB,gl_DrawIDARB,instance_value);}";
    n = snprintf(fs, sizeof(fs), "#version 430 core\nflat in uvec4 parameters;layout(location=0) out uvec4 result;"
        "layout(location=1) out vec4 color;\n%svoid main(){result=parameters;color=encode(result);}", encode);
    if (n < 0 || (size_t)n >= sizeof(fs)) goto out;
    programs[2] = modern_program("indirect", indirect_vs, fs, NULL);
    programs[3] = modern_program("clip",
        "#version 430 core\nuniform float clip_z;void main(){vec2 p[3]=vec2[3](vec2(-1,-1),vec2(0,-1),vec2(-1,0));gl_Position=vec4(p[gl_VertexID],clip_z,1);}",
        "#version 430 core\nlayout(location=0) out uvec4 result;layout(location=1) out vec4 color;void main(){result=uvec4(1,2,3,4);color=vec4(1);}", NULL);
    if (!programs[2] || !programs[3]) goto out;
    m.GenBuffers(12, buffers);
    m.GenBuffers(3, extra);
    m.GenVertexArrays(1, &array); m.BindVertexArray(array);
    m.GenFramebuffers(1, &fbo); m.BindFramebuffer(GL_FRAMEBUFFER, fbo);
    m.GenTextures(3, textures);
    const GLenum formats[3] = {GL_RGBA32UI, GL_RGBA8, GL_DEPTH_COMPONENT32F};
    const GLenum attachments[3] = {GL_COLOR_ATTACHMENT0, GL_COLOR_ATTACHMENT1, GL_DEPTH_ATTACHMENT};
    for (unsigned i = 0; i < 3; ++i) {
        if (!textures[i]) goto out;
        m.BindTexture(GL_TEXTURE_2D, textures[i]);
        m.TexStorage2D(GL_TEXTURE_2D, 1, formats[i], 32, 32);
        m.FramebufferTexture2D(GL_FRAMEBUFFER, attachments[i], GL_TEXTURE_2D, textures[i], 0);
    }
    m.DrawBuffers(2, attachments);
    if (!array || !fbo || m.CheckFramebufferStatus(GL_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE) goto out;
    m.Disable(GL_DITHER); m.Disable(GL_BLEND); m.Disable(GL_CULL_FACE);
    m.Disable(GL_MULTISAMPLE); m.Disable(GL_FRAMEBUFFER_SRGB); m.Disable(GL_SCISSOR_TEST);
    m.Disable(GL_DEPTH_TEST);
    m.ClipControl(GL_LOWER_LEFT, GL_NEGATIVE_ONE_TO_ONE);
    viewport(0,0,32,32);
    if (!modern_error("modern-objects")) goto out;
    const uint32_t seeds[2] = {MODERN_SEED_A, MODERN_SEED_B};
    GLint seed_location = m.GetUniformLocation(programs[0], "seed");
    if (seed_location < 0) goto out;
    for (unsigned trial = 0; trial < 2; ++trial) {
        for (unsigned i = 0; i < 12; ++i) {
            const uint32_t sentinel[4] = {0xdeadbeefu,0xdeadbeefu,0xdeadbeefu,0xdeadbeefu};
            if (!buffers[i]) goto out;
            m.BindBuffer(GL_SHADER_STORAGE_BUFFER, buffers[i]);
            m.BufferData(GL_SHADER_STORAGE_BUFFER, sizeof(sentinel), sentinel, GL_DYNAMIC_COPY);
            m.BindBufferBase(GL_SHADER_STORAGE_BUFFER, i, buffers[i]);
        }
        m.UseProgram(programs[0]); m.Uniform1ui(seed_location, seeds[trial]);
        m.DispatchCompute(1,1,1);
        m.MemoryBarrier(GL_SHADER_STORAGE_BARRIER_BIT | GL_BUFFER_UPDATE_BARRIER_BIT);
        for (unsigned i = 0; i < 12; ++i) {
            m.BindBuffer(GL_SHADER_STORAGE_BUFFER, buffers[i]);
            void *mapped = m.MapBufferRange(GL_SHADER_STORAGE_BUFFER, 0, sizeof(words[i]), GL_MAP_READ_BIT);
            if (!mapped) goto out;
            memcpy(words[i], mapped, sizeof(words[i]));
            if (!m.UnmapBuffer(GL_SHADER_STORAGE_BUFFER)) goto out;
            printf("MODERN_SSBO trial=%u seed=%08x block=%u words=%08x,%08x,%08x,%08x\n",
                trial, seeds[trial], i, words[i][0],words[i][1],words[i][2],words[i][3]);
            for (unsigned j = 0; j < 4; ++j) if (words[i][j] != modern_word(seeds[trial], i, j)) goto out;
        }
        if (!modern_error("modern-compute-readback")) goto out;
        modern_checksums(words, expected); modern_color(expected, color);
        m.UseProgram(programs[1]); modern_clear(); draw_arrays(GL_TRIANGLES,0,3);
        if (!modern_uint_pixel("storage", trial, 0, 4,4, expected) ||
            !modern_rgba_pixel("storage", trial, 0, 4,4, color) ||
            !modern_present(dc, fbo, trial, color)) goto out;
    }
    pass("modern-storage");
    /* firstIndex counts uint indices, not bytes. baseVertex is signed in the
     * 20-byte DrawElementsIndirectCommand; baseInstance never offsets InstanceID. */
    struct indirect_command { uint32_t count, instances, first_index; int32_t base_vertex; uint32_t base_instance; };
    _Static_assert(sizeof(struct indirect_command) == 20, "indirect command size");
    const struct indirect_command commands[2] = {{3,2,2,5,7},{3,2,6,9,11}};
    const uint32_t indices[9] = {99,99,0,1,2,99,3,4,5};
    uint32_t instances[13];
    for (unsigned i = 0; i < 13; ++i) instances[i] = modern_instance_value(i);
    for (unsigned i = 0; i < 3; ++i) if (!extra[i]) goto out;
    m.BindBuffer(GL_ELEMENT_ARRAY_BUFFER, extra[0]);
    m.BufferData(GL_ELEMENT_ARRAY_BUFFER, sizeof(indices), indices, GL_STATIC_DRAW);
    m.BindBuffer(GL_DRAW_INDIRECT_BUFFER, extra[1]);
    m.BufferData(GL_DRAW_INDIRECT_BUFFER, sizeof(commands), commands, GL_STATIC_DRAW);
    m.BindBuffer(GL_ARRAY_BUFFER, extra[2]);
    m.BufferData(GL_ARRAY_BUFFER, sizeof(instances), instances, GL_STATIC_DRAW);
    m.VertexAttribIPointer(0,1,GL_UNSIGNED_INT,sizeof(uint32_t),(void *)0);
    m.VertexAttribDivisor(0,1); m.EnableVertexAttribArray(0);
    m.UseProgram(programs[2]); modern_clear();
    m.MultiDrawElementsIndirect(GL_TRIANGLES,GL_UNSIGNED_INT,(void *)0,2,sizeof(commands[0]));
    for (unsigned draw = 0; draw < 2; ++draw) for (unsigned instance = 0; instance < 2; ++instance) {
        expected[0] = (uint32_t)commands[draw].base_vertex;
        expected[1] = commands[draw].base_instance; expected[2] = draw;
        expected[3] = modern_instance_value(commands[draw].base_instance + instance);
        modern_color(expected,color);
        GLint x = 4 + 16*(GLint)draw, y = 4 + 16*(GLint)instance;
        if (!modern_uint_pixel("indirect",draw,instance,x,y,expected) ||
            !modern_rgba_pixel("indirect",draw,instance,x,y,color)) goto out;
    }
    m.DisableVertexAttribArray(0);
    pass("modern-indirect");
    m.UseProgram(programs[3]); m.Enable(GL_DEPTH_TEST); m.DepthFunc(GL_ALWAYS);
    GLint z_location = m.GetUniformLocation(programs[3],"clip_z");
    if (z_location < 0) goto out;
    for (unsigned origin = 0; origin < 2; ++origin)
        for (unsigned depth = 0; depth < 2; ++depth)
            for (unsigned positive = 0; positive < 2; ++positive) {
                unsigned trial = origin*4 + depth*2 + positive;
                GLenum origin_value = origin ? GL_UPPER_LEFT : GL_LOWER_LEFT;
                GLenum depth_value = depth ? GL_ZERO_TO_ONE : GL_NEGATIVE_ONE_TO_ONE;
                GLint actual_origin = 0, actual_depth = 0;
                m.ClipControl(origin_value,depth_value);
                get_integer(GL_CLIP_ORIGIN,&actual_origin); get_integer(GL_CLIP_DEPTH_MODE,&actual_depth);
                printf("MODERN_CLIP trial=%u origin=0x%x depth=0x%x z=%s\n",trial,actual_origin,actual_depth,positive?"0.5":"-0.5");
                if (actual_origin != (GLint)origin_value || actual_depth != (GLint)depth_value) goto out;
                modern_clear(); m.Uniform1f(z_location,positive ? .5f : -.5f); draw_arrays(GL_TRIANGLES,0,3);
                for (unsigned sample = 0; sample < 2; ++sample) {
                    int visible = sample == origin && (!depth || positive);
                    const uint32_t drawn[4] = {1,2,3,4}, empty[4] = {0};
                    const unsigned char white[4] = {255,255,255,255}, black[4] = {0,0,0,255};
                    GLint y = sample ? 27 : 4;
                    GLfloat observed = -1, wanted = visible ? (depth ? .5f : (positive ? .75f : .25f)) : 1.0f;
                    if (!modern_uint_pixel("clip",trial,sample,4,y,visible?drawn:empty) ||
                        !modern_rgba_pixel("clip",trial,sample,4,y,visible?white:black)) goto out;
                    read_pixels(4,y,1,1,GL_DEPTH_COMPONENT,GL_FLOAT,&observed);
                    printf("MODERN_DEPTH trial=%u sample=%u value=%.9g\n",trial,sample,(double)observed);
                    /* Negated bounded comparison also rejects NaN. */
                    if (!(observed >= wanted-.000001f && observed <= wanted+.000001f) ||
                        !modern_error("modern-clip-depth")) goto out;
                }
            }
    pass("modern-clip");
    ok = modern_error("modern-render-complete");
out:
    m.UseProgram(0); m.BindFramebuffer(GL_FRAMEBUFFER,0); m.BindTexture(GL_TEXTURE_2D,0);
    m.BindVertexArray(0); m.BindBuffer(GL_ARRAY_BUFFER,0); m.BindBuffer(GL_DRAW_INDIRECT_BUFFER,0);
    for (unsigned i = 0; i < 12; ++i) m.BindBufferBase(GL_SHADER_STORAGE_BUFFER,i,0);
    m.BindBuffer(GL_SHADER_STORAGE_BUFFER,0);
    m.Disable(GL_DEPTH_TEST); m.ClipControl(GL_LOWER_LEFT,GL_NEGATIVE_ONE_TO_ONE);
    if (array) { m.DeleteVertexArrays(1,&array); if (m.IsVertexArray(array)) cleanup_ok = 0; }
    m.DeleteBuffers(12,buffers); m.DeleteBuffers(3,extra);
    for (unsigned i = 0; i < 12; ++i) if (buffers[i] && m.IsBuffer(buffers[i])) cleanup_ok = 0;
    for (unsigned i = 0; i < 3; ++i) if (extra[i] && m.IsBuffer(extra[i])) cleanup_ok = 0;
    if (fbo) { m.DeleteFramebuffers(1,&fbo); if (m.IsFramebuffer(fbo)) cleanup_ok = 0; }
    m.DeleteTextures(3,textures);
    for (unsigned i = 0; i < 3; ++i) if (textures[i] && m.IsTexture(textures[i])) cleanup_ok = 0;
    for (unsigned i = 0; i < 4; ++i) if (programs[i]) {
        m.DeleteProgram(programs[i]); if (m.IsProgram(programs[i])) cleanup_ok = 0;
    }
    if (!modern_error("modern-cleanup")) cleanup_ok = 0;
    printf("MODERN_ELAPSED milliseconds=%lu\n", (unsigned long)(GetTickCount()-started));
    if (!cleanup_ok) { fail("modern-cleanup"); ok = 0; }
    if (GetTickCount()-started >= 45000) { fail("modern-deadline"); ok = 0; }
    if (ok) { pass("modern-cleanup"); pass("modern-capabilities"); }
    else fail("modern-capabilities");
    return ok;
}
#undef MODERN_FUNCTIONS
#endif
