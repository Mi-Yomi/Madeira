# Local Wine MSI modifications, 2026-10-05

This candidate is derived from Wine commit
4f5b19718f4de88ecc5cb0dc08b119497a67ba8f. Exactly one source file is modified:
`dlls/msi/custom.c`, by the retained `patches/msi-combined.patch`.

Patch SHA-256: 3efc2fb4733e67f8951284d5f0384a4df4a39f284a5f30fc395840bbbc1ea4a8

Original custom.c SHA-256:
201da579180bccd76abbf0feb291686faa29c7940357e55a08838bde5b501c25

Modified custom.c SHA-256:
31c63ede3acf225cfe4d9d772a00b752e82410ebcb060f58f0bfbc9f9e2ea0c5

The local patch propagates DLL custom-action loading/entrypoint/caught-exception
failure, checks custom-action server startup and ownership, and prevents client
thread creation when server initialization fails. Existing successful-action
return codes and outer Continue/Async policy are preserved. Original Wine and
bundled dependency notices are unchanged and included beside this record.

The independently reviewed patch and complete corresponding pinned source are
necessary reproduction inputs. This note is a change record, not a claim that
all redistribution/relinking duties or runtime compatibility are established.
