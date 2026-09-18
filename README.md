# blocfone® marketplace program

Source of the **blocfone® marketplace** Solana program, published for
transparency and reproducible verification.

| | |
|---|---|
| **Program ID (mainnet)** | `6aYP8MQt44Zn91McAT7BU4gfoFoGxZ8H1jdNJuFVnS9R` |
| Program name | `blocfone_market` |
| Framework | Anchor 1.1.x |
| Security contact | hello@blocfone.io (see `security.txt` embedded in the program, and https://blocfone.com/privacy-cookie-policy/) |

## What it does

The on-chain marketplace: providers, signed offer batches, and orders. It opens
an order against a Merkle-proven offer, requires the matching USDC escrow
deposit (in the same transaction, or, since 2026-09-18, already claimed by the
escrow program for that order: `open_claimed_order`, which also stamps the
signature of the buyer's transfer on the order), stamps the provider split, and drives the
order lifecycle (provisioning, active, settled, refunded, paid out) with a
program-owned settlement vault. It sits beside the escrow program and never
holds funds itself except through the settlement vault.

## Reproducible / verified build

✅ **Verified on mainnet (2026-09-18, the simple-send build).** The deployed
program matches this source: OtterSec reports `is_verified: true`, on-chain
executable hash
`a341f80a920b27e7f7d353aa7c762d9b55e2d57183fa579bc9048590808cabc0`, source
commit `683c89866ce2aeec2bef43c2cdab467e79fe89a2`, built with base image
`solanafoundation/solana-verifiable-build:4.1.1`. Status:
https://verify.osec.io/status/6aYP8MQt44Zn91McAT7BU4gfoFoGxZ8H1jdNJuFVnS9R

`VERIFIED-HASH` in this repo holds that hash, and this repo's CI fails if its
own build ever differs from it. The previous verified build (2026-09-11) had
the hash `69ea40e299a440285e11fd6cb0d8e9acddf1a7d5dc33ce032f2479c923363f14`
at commit `f0abae6`.

Reproduce the build yourself (requires Docker):

```bash
cargo install solana-verify --locked
solana-verify build --base-image solanafoundation/solana-verifiable-build:4.1.1 --library-name blocfone_market
solana-verify get-executable-hash target/deploy/blocfone_market.so
```

The on-chain verification was registered with:

```bash
solana-verify verify-from-repo \
  --program-id 6aYP8MQt44Zn91McAT7BU4gfoFoGxZ8H1jdNJuFVnS9R \
  --library-name blocfone_market \
  --base-image solanafoundation/solana-verifiable-build:4.1.1 \
  https://github.com/ParisMind/blocfone-market-program
```

## Reporting a security issue

Email hello@blocfone.io. Please give us a reasonable opportunity to investigate
and resolve before public disclosure. Full policy:
https://blocfone.com/privacy-cookie-policy/

## Licence

See [`LICENSE`](LICENSE). Source-available, all rights reserved: the code is
published for transparency and reproducible verification, not for reuse. It
implements inventions covered by U.S. Patent No. 10,915,873 and European Patent
No. EP 3 542 333; no patent rights are granted or waived.
