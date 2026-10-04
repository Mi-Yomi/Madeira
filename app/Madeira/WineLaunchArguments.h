/* Windows-style argument decoding for Wine's argv entry point.
 *
 * MADEIRA_ARGS contains arguments only (not argv[0]). Keep this dependency-free
 * so the exact production parser can be exercised without an Apple SDK.
 * Rules: https://learn.microsoft.com/en-us/cpp/c-language/parsing-c-command-line-arguments
 * This is not a shell: single quotes, carets and metacharacters are literal.
 */
#ifndef MADEIRA_WINE_LAUNCH_ARGUMENTS_H
#define MADEIRA_WINE_LAUNCH_ARGUMENTS_H

#include <stddef.h>
#include <string.h>

/* These match LibraryEntry.validate(): 64 arguments, less than 4 KB of UTF-8. */
#define MADEIRA_LAUNCH_ARGS_BYTES 4096
#define MADEIRA_LAUNCH_ARGS_COUNT 64

/* argv needs MADEIRA_LAUNCH_ARGS_COUNT + 1 slots, including the NULL sentinel.
 * Returns the argument count, or -1 for a command outside the supported bounds.
 * On failure argv[0] is NULL; never launch a silently truncated command.
 * input and storage must not overlap. UTF-8 bytes are copied without recoding.
 */
static int madeira_parse_launch_arguments(const char *input,
                                         char storage[MADEIRA_LAUNCH_ARGS_BYTES],
                                         char *argv[MADEIRA_LAUNCH_ARGS_COUNT + 1])
{
    const char *read = input ? input : "";
    char *write = storage;
    int argc = 0;

    argv[0] = NULL;
    if (strlen(read) >= MADEIRA_LAUNCH_ARGS_BYTES) return -1;
    while (*read)
    {
        int quoted = 0;
        while (*read == ' ' || *read == '\t') read++;
        if (!*read) break;
        if (argc == MADEIRA_LAUNCH_ARGS_COUNT) { argv[0] = NULL; return -1; }
        argv[argc++] = write;
        while (*read && (quoted || (*read != ' ' && *read != '\t')))
        {
            size_t slashes = 0;
            while (*read == '\\') { slashes++; read++; }
            if (*read == '"')
            {
                size_t pairs = slashes / 2;
                while (pairs--) *write++ = '\\';
                if (slashes & 1) { *write++ = '"'; read++; }
                else if (quoted && read[1] == '"') { *write++ = '"'; read += 2; }
                else { quoted = !quoted; read++; }
            }
            else
            {
                while (slashes--) *write++ = '\\';
                if (*read && (quoted || (*read != ' ' && *read != '\t')))
                    *write++ = *read++;
            }
        }
        *write++ = '\0';
    }
    argv[argc] = NULL;
    return argc;
}


/* A working folder is an absolute C: directory inside drive_c, never a device,
 * UNC or drive-relative path. Normalize separators and reject ambiguous dot /
 * Win32-trimmed components instead of accidentally writing in another folder.
 * UTF-8 bytes are preserved. Output excludes a trailing slash except C:\. */
static int madeira_normalize_working_directory(const char *input, char output[1024])
{
    size_t length = input ? strlen(input) : 0, write = 3, read = 3;
    output[0] = 0;
    if (length < 3 || length >= 1024 || (input[0] != 'C' && input[0] != 'c') ||
        input[1] != ':' || (input[2] != '\\' && input[2] != '/')) return -1;
    memcpy(output, "C:\\", 3);
    while (read < length)
    {
        while (input[read] == '\\' || input[read] == '/') read++;
        if (!input[read]) break;
        size_t start = read;
        while (input[read] && input[read] != '\\' && input[read] != '/')
        {
            unsigned char c = (unsigned char)input[read++];
            if (c < 32 || strchr(":*?\"<>|", c)) { output[0] = 0; return -1; }
        }
        size_t count = read - start;
        if (input[read - 1] == '.' || input[read - 1] == ' ')
        { output[0] = 0; return -1; }
        if (write > 3) output[write++] = '\\';
        memcpy(output + write, input + start, count);
        write += count;
    }
    output[write] = 0;
    return 0;
}

#endif
