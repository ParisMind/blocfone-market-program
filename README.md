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
deposit to ride the same transaction, stamps the provider split, and drives the
order lifecycle (provisioning, active, settled, refunded, paid out) with a
program-owned settlement vault. It sits beside the escrow program and never
holds funds itself except through the settlement vault.

## Reproducible / verified build

Requires Docker.

```bash
cargo install solana-verify --locked
solana-verify build --library-name blocfone_market
solana-verify get-executable-hash target/deploy/blocfone_market.so
```

To verify the on-chain program against this source (after the program is
deployed from a build of this repo):

```bash
solana-verify verify-from-repo -um \
  --program-id 6aYP8MQt44Zn91McAT7BU4gfoFoGxZ8H1jdNJuFVnS9R \
  https://github.com/ParisMind/blocfone-market-program
```

## Reporting a security issue

Email hello@blocfone.io. Please give us a reasonable opportunity to investigate
and resolve before public disclosure. Full policy:
https://blocfone.com/privacy-cookie-policy/

## Licence

A licence will be added to this repository. Until then, all rights reserved; the
source is published for transparency and verification.
