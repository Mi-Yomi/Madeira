# Local MSI client failure changes, 2026-10-05

This incremental, unpublished source candidate modifies only
`dlls/msi/custom.c:custom_client_thread`. It is based on the sealed source hash
31c63ede3acf225cfe4d9d772a00b752e82410ebcb060f58f0bfbc9f9e2ea0c5,
which combines Wine fork commit 4f5b19718f4de88ecc5cb0dc08b119497a67ba8f
with the two prior MSI fixes documented in `Prior-MSI-MODIFICATIONS.md`.

Candidate source SHA-256:
9c6db8469d1db7d1fff83af45e4f4851238e3b09fc06055996cfbb956fd6af50

The change captures pipe/handle/wait/query failures before diagnostic or cleanup
calls, turns missing errors and short transfers into deterministic failure,
balances COM initialization, and preserves existing action results and outer
Continue/Async policy. No other production function changes.

Original Wine copyright and LGPL-2.1-or-later notices remain intact. These local
modifications and new tests are provided under LGPL-2.1-or-later, the same license
as the source they test. No authorship, upstream acceptance, shipment, or legal
compliance claim is inferred from this preparation. Any later distribution needs
the original pinned corresponding source, both earlier changes and this patch,
rebuild instructions, and the existing notices.
