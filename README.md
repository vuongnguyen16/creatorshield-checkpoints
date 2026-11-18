# CreatorShield public checkpoints

Signed chain-head bulletins for the CreatorShield development project. No work titles, file names, owners, file contents or private keys are published.

M5 acceptance was amended on 2026-11-17 to allow three real checkpoints on the same day. The first three cover heads #5, #6 and #7. Heads #6 and #7 are clearly labelled synthetic acceptance deposits in the private application. This does not demonstrate three days of operation. A separate daily job remains scheduled.

Every JSON file carries the canonical bulletin, SHA-256 hash, Ed25519 signature and domain creatorshield/checkpoint/v1. Public verification keys are in public-keys.json; pin or obtain the trust root independently when assessing authenticity. Historical files must never be replaced.

Git author and committer timestamps are self-reported. They are not an independent timestamp authority. An anonymous HTTPS retrieval demonstrates that the bytes are publicly available by the retrieval time; retain external observations if stronger time evidence is needed. Repository administrators can rewrite history, so retain independent copies of published hashes and artifacts.

## Key rotation (2026-11-18)

The first six bulletins (2026-11-17 heads #5 to #7 and the 2026-11-18 on-demand bulletin for head #7) are signed with `key-supabase-dev-2026-11`. That key was retired on 2026-11-18. Its existing signatures stay valid, but it no longer signs new bulletins. Starting with the 2026-11-18 daily bulletin for head #9, bulletins are signed with the dedicated checkpoint key `key-checkpoint-2026-11`. Both public keys are in `public-keys.json`; select one by the `keyId` inside each bulletin.
