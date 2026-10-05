/* Execute the production helper with bounded/failing I/O and competing callers. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* Darwin's residency bits, supplied explicitly to the portable test. */
#ifndef MINCORE_INCORE
#define MINCORE_INCORE 1
#endif
#ifndef MINCORE_PAGED_OUT
#define MINCORE_PAGED_OUT 0x20
#endif
#ifndef MINCORE_MODIFIED_OTHER
#define MINCORE_MODIFIED_OTHER 0x10
#endif

static int mock_open( const char *, int, mode_t );
static int mock_mincore( void *, size_t, void * );
static ssize_t mock_pwrite( int, const void *, size_t, off_t );
static int mock_ftruncate( int, off_t );
static int mock_close( int );
#define open mock_open
#define mincore mock_mincore
#define pwrite mock_pwrite
#define ftruncate mock_ftruncate
#define close mock_close
#include "ios_jit_dump.h"
#undef open
#undef mincore
#undef pwrite
#undef ftruncate
#undef close

struct faults
{
    unsigned int opens, queries, writes, truncates, closes;
    int fake_io, open_error, query_error_at, write_error_at, write_error;
    int zero_at, eintr_always, short_max, truncate_error, close_error, reenter;
    unsigned int residency;
    int hole_page;
    size_t max_extent, max_write, truncated_length;
};
static struct faults faults;
static struct ios_jit_dump_policy policy;
static unsigned int state;
static unsigned char *pool;
static size_t pool_size, page_size;
static char directory[512];
static unsigned int checks;

static void nested_capture(void)
{
    struct ios_jit_dump_result r = ios_jit_dump_capture( &policy, &state, pool, pool_size );
    assert( !r.attempted );
}
static int mock_open( const char *path, int flags, mode_t mode )
{
    ++faults.opens;
    assert( mode == 0600 );
    assert( (flags & (O_EXCL | O_CLOEXEC | O_NOFOLLOW)) == (O_EXCL | O_CLOEXEC | O_NOFOLLOW) );
    assert( !(flags & O_TRUNC) );
    if (faults.open_error) { errno = faults.open_error; return -1; }
    return faults.fake_io ? 123 : open( path, flags, mode );
}
static int mock_mincore( void *addr, size_t len, void *output )
{
    unsigned char *vec = output;
    size_t pages = len / page_size + !!(len % page_size), i;
    ++faults.queries;
    assert( len <= IOS_JIT_DUMP_CHUNK && pages <= 256 );
    assert( (uintptr_t)addr % page_size == 0 );
    if (faults.reenter) nested_capture();
    if (faults.query_error_at == (int)faults.queries) { errno = ENOMEM; return -1; }
    for (i = 0; i < pages; ++i)
        vec[i] = (int)(((unsigned char *)addr - pool) / page_size + i) == faults.hole_page
                 ? 0 : faults.residency;
    return 0;
}
static ssize_t mock_pwrite( int fd, const void *bytes, size_t len, off_t off )
{
    ++faults.writes;
    assert( len <= page_size && len > 0 );
    assert( off >= 0 && (size_t)off + len <= policy.limit );
    assert( bytes == pool + off );
    if (len > faults.max_write) faults.max_write = len;
    if (faults.reenter) nested_capture();
    if (faults.eintr_always || faults.write_error_at == (int)faults.writes)
    { errno = faults.eintr_always ? EINTR : faults.write_error; return -1; }
    if (faults.zero_at == (int)faults.writes) return 0;
    if (faults.short_max && len > (size_t)faults.short_max) len = faults.short_max;
    if ((size_t)off + len > faults.max_extent) faults.max_extent = off + len;
    return faults.fake_io ? (ssize_t)len : pwrite( fd, bytes, len, off );
}
static int mock_ftruncate( int fd, off_t len )
{
    ++faults.truncates;
    assert( len >= 0 && (size_t)len <= policy.limit );
    faults.truncated_length = len;
    if (faults.truncate_error) { errno = EIO; return -1; }
    return faults.fake_io ? 0 : ftruncate( fd, len );
}
static int mock_close( int fd )
{
    int result;
    ++faults.closes;
    result = faults.fake_io ? 0 : close( fd );
    if (faults.close_error) { errno = EINTR; return -1; }
    return result;
}
static void reset( const char *enabled, const char *limit )
{
    unlink( policy.path );
    memset( &faults, 0, sizeof(faults) );
    faults.residency = MINCORE_INCORE;
    faults.hole_page = -1;
    ios_jit_dump_prepare( &policy, enabled, limit, directory, page_size );
    __atomic_store_n( &state, IOS_JIT_DUMP_READY, __ATOMIC_RELEASE );
}
static struct ios_jit_dump_result capture( size_t size )
{
    struct ios_jit_dump_result result;
    errno = EDOM;
    result = ios_jit_dump_capture( &policy, &state, pool, size );
    assert( errno == EDOM );
    assert( result.query_calls == faults.queries && result.write_calls == faults.writes );
    assert( result.written_bytes <= policy.limit );
    assert( faults.writes <= policy.limit / page_size + IOS_JIT_DUMP_RETRY_BUDGET );
    if (result.attempted && faults.opens && !faults.open_error)
        assert( faults.closes == 1 && faults.truncates == 1 );
    ++checks;
    return result;
}
static void check_file( size_t length )
{
    unsigned char buffer[8192];
    struct stat st;
    int fd = open( policy.path, O_RDONLY );
    assert( fd >= 0 && fstat( fd, &st ) == 0 );
    assert( st.st_size == (off_t)length && (st.st_mode & 0777) == 0600 );
    while (length)
    {
        size_t n = length < sizeof(buffer) ? length : sizeof(buffer);
        assert( read( fd, buffer, n ) == (ssize_t)n );
        length -= n;
    }
    close( fd );
}
static void *concurrent_capture( void *unused )
{
    struct ios_jit_dump_result r;
    (void)unused;
    r = ios_jit_dump_capture( &policy, &state, pool, page_size );
    return (void *)(uintptr_t)r.attempted;
}

int main( int argc, char **argv )
{
    const char *off_values[] = {NULL, "", "0", "off", "no", "yes", "garbage", "10", "1 "};
    const char *bad_caps[] = {"0", "-1", "1025", "999999999999999999999", "16MB", " 16", "1.0"};
    struct ios_jit_dump_result r;
    size_t i;
    long host_page_size = sysconf( _SC_PAGESIZE );
    assert( argc == 2 );
    /* Real mprotect calls must use the host's VM granularity (16 KiB on
     * arm64 macOS), not the 4 KiB case used by the mock-only bounds tests. */
    assert( host_page_size >= 4096 && host_page_size <= 65536 );
    page_size = (size_t)host_page_size;
    assert( !(page_size & (page_size - 1)) );
    assert( snprintf( directory, sizeof(directory), "%s", argv[1] ) < (int)sizeof(directory) );
    pool_size = 4 * IOS_JIT_DUMP_CHUNK;
    assert( posix_memalign( (void **)&pool, 65536, pool_size ) == 0 );
    memset( pool, 0xa5, pool_size );

    for (i = 0; i < sizeof(off_values) / sizeof(*off_values); ++i)
    {
        reset( off_values[i], NULL );
        r = capture( pool_size );
        assert( !r.attempted && !faults.opens && !faults.queries && !faults.writes );
    }
    reset( "1", NULL );
    assert( policy.limit == 16 * IOS_JIT_DUMP_CHUNK );
    for (i = 0; i < sizeof(bad_caps) / sizeof(*bad_caps); ++i)
    {
        reset( "1", bad_caps[i] );
        assert( !policy.limit );
        assert( !capture( pool_size ).attempted );
    }
    reset( "1", "1024" );
    assert( policy.limit == (size_t)1024 * IOS_JIT_DUMP_CHUNK );
    reset( "1", "0001" );
    assert( policy.limit == IOS_JIT_DUMP_CHUNK );
    {
        char long_path[600];
        memset( long_path, 'x', sizeof(long_path) - 1 );
        long_path[sizeof(long_path) - 1] = 0;
        ios_jit_dump_prepare( &policy, "1", NULL, long_path, page_size );
        assert( !policy.limit );
        ios_jit_dump_prepare( &policy, "1", NULL, NULL, page_size );
        assert( !strcmp( policy.path, "/tmp/fex-jit-dump.bin" ) );
        policy.path[0] = 0; /* never remove anything outside this test directory */
    }
    for (i = 0; i < 4; ++i)
    {
        const size_t bad_pages[] = {0, 1024, 5000, 131072};
        ios_jit_dump_prepare( &policy, "1", NULL, directory, bad_pages[i] );
        assert( !policy.limit );
    }
    reset( "1", "1" );
    __atomic_store_n( &state, 0, __ATOMIC_RELEASE );
    assert( !capture( pool_size ).attempted && !faults.opens );
    reset( "1", "1" );
    r = ios_jit_dump_capture( &policy, &state, pool + 1, 10 );
    assert( !strcmp( r.status, "invalid-pool" ) && !faults.opens );
    reset( "1", "1" );
    r = ios_jit_dump_capture( &policy, &state, NULL, 0 );
    assert( !strcmp( r.status, "invalid-pool" ) && !faults.opens );
    reset( "1", "1" );
    r = ios_jit_dump_capture( &policy, &state, pool, SIZE_MAX );
    assert( !strcmp( r.status, "invalid-pool" ) && !faults.opens );

    /* Real bytes, partial final page, and one shared attempt across call sites. */
    reset( "1", "1" );
    r = capture( page_size + 123 );
    assert( !strcmp( r.status, "complete" ) && r.written_bytes == page_size + 123 );
    check_file( page_size + 123 );
    nested_capture();
    assert( faults.opens == 1 );
    {
        unsigned char got[3];
        int fd = open( policy.path, O_RDONLY );
        assert( pread( fd, got, 3, page_size - 1 ) == 3 );
        assert( got[0] == 0xa5 && got[1] == 0xa5 && got[2] == 0xa5 );
        close( fd );
    }

    /* Sparse hole must never read even a PROT_NONE pool page. */
    reset( "1", "1" );
    faults.hole_page = 1;
    assert( mprotect( pool + page_size, page_size, PROT_NONE ) == 0 );
    r = capture( 3 * page_size );
    assert( r.written_bytes == 2 * page_size && r.logical_bytes == 3 * page_size );
    assert( mprotect( pool + page_size, page_size, PROT_READ | PROT_WRITE ) == 0 );
    {
        unsigned char byte = 1;
        int fd = open( policy.path, O_RDONLY );
        assert( pread( fd, &byte, 1, page_size ) == 1 && byte == 0 );
        close( fd );
    }
    reset( "1", "1" );
    faults.residency = MINCORE_PAGED_OUT;
    assert( capture( page_size ).written_bytes == page_size );
    reset( "1", "1" );
    faults.residency = MINCORE_MODIFIED_OTHER;
    r = capture( page_size );
    assert( !r.written_bytes && !faults.writes && r.logical_bytes == page_size );
    reset( "1", "1" );
    faults.residency = 0;
    r = capture( 2 * page_size + 19 );
    assert( !r.written_bytes && !faults.writes );
    check_file( 2 * page_size + 19 );

    reset( "1", "1" );
    r = capture( pool_size );
    assert( !strcmp( r.status, "capped" ) && r.logical_bytes == IOS_JIT_DUMP_CHUNK );
    assert( r.written_bytes == IOS_JIT_DUMP_CHUNK && faults.writes == IOS_JIT_DUMP_CHUNK / page_size );
    check_file( IOS_JIT_DUMP_CHUNK );
    reset( "1", "1" );
    faults.short_max = (int)(page_size / 4);
    r = capture( 2 * page_size + 3 );
    assert( !strcmp( r.status, "complete" ) && r.written_bytes == 2 * page_size + 3 );
    check_file( 2 * page_size + 3 );
    reset( "1", "1" );
    faults.write_error_at = 1;
    faults.write_error = EINTR;
    r = capture( page_size );
    assert( !strcmp( r.status, "complete" ) && r.write_calls == 2 );
    reset( "1", "1" );
    faults.eintr_always = 1;
    r = capture( page_size );
    assert( !strcmp( r.status, "write-budget" ) && r.write_calls == 9 && !r.written_bytes );
    check_file( 0 );
    reset( "1", "1" );
    faults.short_max = 1;
    r = capture( page_size );
    assert( !strcmp( r.status, "write-budget" ) && r.write_calls == 9 && r.written_bytes == 9 );
    check_file( 9 );
    reset( "1", "1" );
    faults.zero_at = 1;
    r = capture( page_size );
    assert( !strcmp( r.status, "write-failed" ) && r.error == EIO && r.write_calls == 1 );
    reset( "1", "1" );
    faults.write_error_at = 2;
    faults.write_error = ENOSPC;
    r = capture( 2 * page_size );
    assert( r.error == ENOSPC && r.written_bytes == page_size && r.logical_bytes == page_size );
    check_file( page_size );
    reset( "1", "2" );
    faults.query_error_at = 2;
    r = capture( pool_size );
    assert( !strcmp( r.status, "residency-failed" ) && r.logical_bytes == IOS_JIT_DUMP_CHUNK );
    assert( r.written_bytes == IOS_JIT_DUMP_CHUNK && r.query_calls == 2 );
    check_file( IOS_JIT_DUMP_CHUNK );
    reset( "1", "1" );
    faults.query_error_at = 1;
    r = capture( page_size );
    assert( r.error == ENOMEM && !faults.writes && !r.logical_bytes );
    reset( "1", "1" );
    faults.truncate_error = 1;
    r = capture( page_size );
    assert( !strcmp( r.status, "truncate-failed" ) && r.error == EIO );
    reset( "1", "1" );
    faults.close_error = 1;
    r = capture( page_size );
    assert( !strcmp( r.status, "close-failed" ) && r.error == EINTR && faults.closes == 1 );
    reset( "1", "1" );
    faults.open_error = EACCES;
    r = capture( page_size );
    assert( r.error == EACCES && !faults.queries && !faults.closes );
    nested_capture();
    assert( faults.opens == 1 );

    /* Existing dumps and symlinks cannot be overwritten, even across restarts. */
    reset( "1", "1" );
    {
        int fd = open( policy.path, O_WRONLY | O_CREAT | O_EXCL, 0600 );
        assert( fd >= 0 && write( fd, "keep", 4 ) == 4 );
        close( fd );
        r = ios_jit_dump_capture( &policy, &state, pool, page_size );
        assert( r.error == EEXIST && !faults.writes && !faults.closes );
        check_file( 4 );
    }
    reset( "1", "1" );
    assert( symlink( "/nonexistent-test-target", policy.path ) == 0 );
    r = ios_jit_dump_capture( &policy, &state, pool, page_size );
    assert( r.error == EEXIST && !faults.writes );

    reset( "1", "1" );
    faults.reenter = 1;
    assert( capture( 2 * page_size ).written_bytes == 2 * page_size );
    assert( faults.opens == 1 );
    reset( "1", "1" );
    {
        pthread_t threads[16];
        unsigned int winners = 0;
        for (i = 0; i < 16; ++i) assert( !pthread_create( &threads[i], NULL, concurrent_capture, NULL ) );
        for (i = 0; i < 16; ++i)
        {
            void *value;
            assert( !pthread_join( threads[i], &value ) );
            winners += (unsigned int)(uintptr_t)value;
        }
        assert( winners == 1 && faults.opens == 1 && faults.closes == 1 );
    }

    /* Upper bounds using a PROT_NONE mapping: mock writes do not touch it. */
    free( pool );
    pool_size = (size_t)1024 * IOS_JIT_DUMP_CHUNK;
    pool = mmap( NULL, pool_size + 65536, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
    assert( pool != MAP_FAILED );
    {
        unsigned char *mapping = pool;
        pool = (unsigned char *)(((uintptr_t)pool + 65535) & ~(uintptr_t)65535);
        for (page_size = 4096; page_size <= 65536; page_size *= 4)
        {
            reset( "1", NULL );
            faults.fake_io = 1;
            r = capture( pool_size );
            assert( r.written_bytes == 16 * IOS_JIT_DUMP_CHUNK && r.query_calls == 16 );
            printf( "enabled default: page=%zu bytes=%zu queries=%u writes=%u (+8 retry budget)\n",
                    page_size, r.written_bytes, r.query_calls, r.write_calls );
            reset( "1", "1024" );
            faults.fake_io = 1;
            r = capture( pool_size );
            assert( r.written_bytes == pool_size && r.query_calls == 1024 );
            printf( "explicit maximum: page=%zu bytes=%zu queries=%u writes=%u (+8 retry budget)\n",
                    page_size, r.written_bytes, r.query_calls, r.write_calls );
        }
        munmap( mapping, pool_size + 65536 );
    }
    unlink( policy.path );
    printf( "PASS: %u captures, policy validation, sparse contents, failure bounds, reentry and 16 competing threads\n", checks );
    return 0;
}
