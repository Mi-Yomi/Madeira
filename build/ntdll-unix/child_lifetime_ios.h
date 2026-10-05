/* Process-lifetime bookkeeping shared by the iOS spawn and exit paths.
 * Tokens identify a reservation, not a reusable array index or pthread. */
#ifndef MADEIRA_CHILD_LIFETIME_IOS_H
#define MADEIRA_CHILD_LIFETIME_IOS_H

#include <stdint.h>
#include <setjmp.h>

/* Called on the child's entry thread once its PEB is known. */
void madeira_child_lifetime_bind( void *peb );
/* Detach the PEB before teardown can reuse it and pin the token until
 * finish_exit. Entry-thread cleanup cannot release a pinned reservation. */
uint64_t madeira_child_lifetime_begin_exit( void *peb );
/* Called by the owner finalizer after cleanup completes or that cleanup
 * frame permanently unwinds/terminates. Aborted resource cleanup is not
 * retried and must not be reported as completed. */
void madeira_child_lifetime_finish_exit( uint64_t token );
/* Boot/spawn failure or entry-thread fallback. Preserves pending teardown. */
void madeira_child_lifetime_release( uint64_t token );

/* Only the thread performing process teardown owns this scope. pthread_exit
 * runs its registered cleanup handler. The iOS exit shim redirects its own
 * longjmp here first, so it cannot jump over a live pthread cleanup record. */
struct madeira_child_exit_scope
{
    jmp_buf jump;
    struct madeira_child_exit_scope *previous;
    uint64_t token;
    volatile int status;
};
void madeira_child_exit_scope_prepare( struct madeira_child_exit_scope *scope, uint64_t token );
/* Publish only after setjmp has initialized scope->jump. */
void madeira_child_exit_scope_enter( struct madeira_child_exit_scope *scope );
void madeira_child_exit_scope_cleanup( void *scope );
void madeira_child_lifetime_redirect_exit( int status );

#endif
