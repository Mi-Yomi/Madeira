/* Compile the actual normal-init and metadata wrapper from signal_arm64_ios.c. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef MINCORE_INCORE
#define MINCORE_INCORE 1
#endif
#include "ios_jit_dump.h"

void *ios_jit_rw_base_global;
size_t ios_jit_pool_size_global;
static const size_t vm_page_size = 16384;
static unsigned int log_calls;
static size_t log_length;
static char last_log[257];
static ssize_t metadata_write( int fd, const void *bytes, size_t size )
{
    assert( fd == STDERR_FILENO && size <= 256 && size > 0 );
    assert( ((const char *)bytes)[size - 1] == '\n' );
    ++log_calls;
    log_length = size;
    memcpy( last_log, bytes, size );
    last_log[size] = 0;
    errno = EIO; /* Even a failing metadata write must not clobber fault errno. */
    return -1;
}
#define write metadata_write
#include "jit-dump-wrapper.inc"
#undef write

int main(void)
{
    char digits[256] = {0}, expected[256], long_reason[1024];
    size_t len = 0;
    errno = EDOM;
    ios_dump_jit_pool( "uninitialized" );
    assert( !log_calls && errno == EDOM );
    setenv( "MADEIRA_JIT_DUMP", "0", 1 );
    ios_init_jit_dump_policy();
    ios_dump_jit_pool( "disabled" );
    assert( !log_calls && !ios_jit_dump_policy.limit && errno == EDOM );
    setenv( "MADEIRA_JIT_DUMP", "1", 1 );
    setenv( "MADEIRA_JIT_DUMP_MAX_MB", "0", 1 );
    ios_init_jit_dump_policy();
    ios_dump_jit_pool( "invalid cap" );
    assert( !log_calls && !ios_jit_dump_policy.limit && errno == EDOM );
    setenv( "MADEIRA_JIT_DUMP_MAX_MB", "16", 1 );
    setenv( "MADEIRA_DOCS_DIR", "/verified-test-only", 1 );
    pthread_once( &ios_jit_dump_once, ios_init_jit_dump_policy );
    assert( ios_jit_dump_policy.limit == 16 * IOS_JIT_DUMP_CHUNK );
    assert( !strcmp( ios_jit_dump_policy.path, "/verified-test-only/fex-jit-dump.bin" ) );
    setenv( "MADEIRA_JIT_DUMP", "0", 1 );
    pthread_once( &ios_jit_dump_once, ios_init_jit_dump_policy );
    assert( ios_jit_dump_policy.limit == 16 * IOS_JIT_DUMP_CHUNK );
    /* Invalid pool exercises logging with zero filesystem I/O. */
    ios_dump_jit_pool( "mach UNHANDLED" );
    ios_dump_jit_pool( "ILL diag" );
    assert( log_calls == 1 && errno == EDOM );
    assert( !strcmp( last_log, "[jit-dump] mach UNHANDLED: invalid-pool written=0 logical=0 pool=0 queries=0 writes=0 errno=0\n" ) );
    ios_jit_dump_number( digits, &len, SIZE_MAX );
    snprintf( expected, sizeof(expected), "%zu", SIZE_MAX );
    assert( !strcmp( digits, expected ) );
    memset( long_reason, 'x', sizeof(long_reason) - 1 );
    long_reason[sizeof(long_reason) - 1] = 0;
    __atomic_store_n( &ios_jit_dump_state, IOS_JIT_DUMP_READY, __ATOMIC_RELEASE );
    ios_dump_jit_pool( long_reason );
    assert( log_calls == 2 && log_length == 256 && errno == EDOM );
    puts( "PASS: production env/init-once, metadata-only bounded logger, errno and shared wrapper guard" );
    return 0;
}
