# MSI custom-action server startup wait review

Reviewed 2026-10-05 UTC against the pinned local sources in `reference/sources.json`.

**Result: no blocking issue found in the final isolated proposal.**

The final comment-only revision has no behavioral drift: replacing its leading comment with the previously reviewed comment reproduces the previous SHA256 for the source, patch, and helper include exactly.

## Findings

- `proposed-custom.c:624`: the private manual-reset connection event and process-first wait handle immediate/pending connection, `ERROR_PIPE_CONNECTED`, child death, simultaneous signals, and wait failures. The post-connection process check also rejects an already-dead child on immediate-success paths.
- `proposed-custom.c:595`: the completion finisher resolves the initial review's lifetime gap. It probes terminal status after the blocking result call, preserves a failed wait's original error, requests cancellation when that failed wait leaves I/O pending, and retains the caller's storage until terminal completion. A TRUE result with pending status is also drained. Immediate `ERROR_PIPE_CONNECTED` and other synchronous connect errors correctly bypass this finisher because they create no outstanding operation.
- `proposed-custom.c:692`: all three later operations on the overlapped pipe use the blocking wrapper, including shutdown at line 812 and the action exchange at lines 850 and 858. The action exchange is serialized by `custom_action_cs`. Package references and normal action cleanup protect ordinary destruction/stop ownership; existing cleanup-error behavior is unchanged.
- No source/helper or production edits were made during the independent review. This report is the only review-authored file.

## Verification

- All eight reference files match the Git blob hashes in `reference/sources.json`.
- `proposal.patch` exactly matches the six-hunk baseline-to-proposal diff; the helper include exactly matches its insertion in the proposed source.
- Independently reran all 33 deterministic API-model cases successfully with `ASAN_OPTIONS=detect_leaks=0 ./test_wait` (exit 0). Cases include failed completion waits while still pending, cancellation/completion races, TRUE-but-pending results, immediate paths, error preservation, read/write failures, and short transfers.
- Reviewed clean aarch64, arm64ec, and i686 helper compilation records and verified their output artifact hashes against `compile-results.json`.

## Final SHA256

| File | SHA256 |
| --- | --- |
| `proposed-custom.c` | `0feda873cdce7625044f153c10ad05fa3d49939bde94f4fe28fce75b0735669f` |
| `proposal.patch` | `a3c010ea77cf18c3b37ad2bc249692758839d9f83fbe7b081b08312dc8e36bae` |
| `proposal_helpers.inc` | `b982c9579fb3b0f79d5765b0367ea36a88eba9920e2f3614113011350819da09` |

## Limits

These are source review, deterministic API-model tests, and helper ABI compilation. They do not establish full MSI-module compilation, integration behavior, real Wine/iOS named-pipe cancellation, process signaling, or WoW64 marshaling. LeakSanitizer cannot run under this executor's ptrace environment, so leak detection was disabled for the independent run; ASan/UBSan model execution passed.

The remedy targets a child that exits before connecting. A living child that never connects, later stalled action I/O, and shutdown (`proposed-custom.c:808`) remain unbounded. If cancellation refuses and the I/O never reaches a terminal state, the finisher must retain live storage indefinitely. The proposal deliberately does not impose an installer timeout or claim bounded recovery from that condition.
