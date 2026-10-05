# MSI custom-action startup modifications

Date: 2026-10-05

Modified Wine file: `dlls/msi/custom.c`, from Wine fork revision
`4f5b19718f4de88ecc5cb0dc08b119497a67ba8f`, after the retained prior MSI patches.
Original copyright and LGPL notices in that file are preserved. These
modifications are distributed under the original LGPL-2.1-or-later terms.

The patch uses overlapped server-pipe operations, waits for either a server
connection or child exit, completes/cancels pending I/O before releasing its
caller-owned storage, and clears a failed startup's cached server handle.
Successful custom-action return values and the outer Continue/Async policy
are preserved. No installer timeout is introduced.

The added helpers are `custom_pipe_result`, `custom_connect_server`, and
`custom_pipe_io`. Existing changes are confined to `custom_start_server`,
`custom_stop_server`, and `custom_client_thread`.

Incremental baseline SHA-256:
`9c6db8469d1db7d1fff83af45e4f4851238e3b09fc06055996cfbb956fd6af50`

Patch SHA-256:
`a3c010ea77cf18c3b37ad2bc249692758839d9f83fbe7b081b08312dc8e36bae`

Final custom.c SHA-256:
`0feda873cdce7625044f153c10ad05fa3d49939bde94f4fe28fce75b0735669f`

The complete patch and exact final source are supplied in
`patches/msi-startup-wait.patch` and `source/custom.c`. `SOURCE-REBUILD.md`
describes the corresponding source and build inputs. This receipt does not
make an overall distribution or relinking compliance determination.
