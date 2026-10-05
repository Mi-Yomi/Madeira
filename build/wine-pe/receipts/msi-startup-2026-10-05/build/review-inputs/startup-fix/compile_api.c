#include <windows.h>
#define ERR(...) ((void)0)
#include "proposal_helpers.inc"
DWORD audit_connect(HANDLE pipe, HANDLE process) { return custom_connect_server(pipe, process); }
BOOL audit_io(HANDLE pipe, void *buffer, DWORD count, DWORD *size, BOOL write)
{ return custom_pipe_io(pipe, buffer, count, size, write); }
