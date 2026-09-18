// blocfone® market — the mode-1 marketplace program (P1-01…P1-04).
//
// Sits BESIDE the deployed rent-vault escrow, never inside it (ADR-009): the
// escrow keeps holding the money; this program holds the marketplace facts —
// who the providers are (P1-01, this file's scope), which offer batches they
// anchored (P1-02), and each order's lifecycle (P1-03/04).
//
// P1-01 — the Provider account and its two instructions.
//   • register_provider : one PDA per authority, seeds ["provider", authority].
//     Duplicate registration is structurally impossible — `init` on an existing
//     PDA fails at the runtime, no flag needed.
//   • update_provider   : payout wallet / status changes, authority-only via
//     `has_one`. The payout wallet is what `settle` (P1-04) will pay, so the
//     binding between authority and payout wallet is the security-critical
//     fact this account exists to state (ADR-006).
//
// P1-02 — the OfferBatch account (ADR-002: only the Merkle root goes on-chain,
// offer terms never do).
//   • publish_offer_batch : anchors a catalogue snapshot's Merkle root with a
//     slot validity window. Only a registered, ACTIVE provider — registration
//     is proven by the Provider PDA existing at its seeds, so an unregistered
//     authority fails account validation, not a require!.
//     Batches are seeded by a per-provider counter (`provider.batch_count`),
//     not by root: rotation (P1-09) may legitimately re-anchor an identical
//     root after an expiry, and the counter gives a stable enumeration order.
//   • expire_batch : authority-only, Active → Expired. One-way — a superseded
//     batch never comes back; the rotation publishes a new one instead.
//     `open_order` (P1-03) is the consumer of state + window.
//
// P1-04 — the order lifecycle (+ ADR-014 split stamping).
//   • set_provider_share : the ADR-014 split parameter, in basis points, set
//     ONLY by the trusted administrator (the upgrade authority — never the
//     provider's own key). Registration defaults to 0 bps: fail-safe, and
//     PikaSIM's correct permanent value.
//   • open_order stamps the CONCRETE split (bps + provider amount) onto the
//     Order at purchase — a later rate change never touches an existing
//     order. Floor-to-provider rounding at USDC's 6 decimals.
//   • start_provisioning / attest_provisioned / settle / refund : the walk
//     Funded → Provisioning → Active → Settled, and the Refunded exit from
//     any pre-settled state. Oracle-gated (config.oracle); every transition
//     emits an event the off-chain ledger consumes. attest_provisioned also
//     requires the PROVIDER's signature over the delivery commitment (ADR-020).
//     settle and refund RETAIN the Order: the contract is stored on chain for
//     the life of the deal plus its retention window rather than deleted at
//     the moment it completes (ADR-018 / PC-7), and settled_at is stamped so
//     that window is computable here. close_order releases the account and
//     its rent afterwards, gated by the ClosurePolicy PDA, paid_out, and the
//     elapsed window. The money itself moves in the escrow program
//     (release/refund) and, for the platform's own split, in payout.
//
// P1-03 — the Order account and open_order (ADR-013).
//   • init_config / update_config : the cluster-specific facts (escrow program
//     id, USDC mint) live in a config PDA set by the UPGRADE AUTHORITY — never
//     baked-in constants (house rule: on-chain addresses are required config
//     on every cluster). The gate reads the real authority from ProgramData,
//     the same pattern as the escrow's withdraw_rent_vault.
//   • open_order : verifies the offer's Merkle proof against the batch root,
//     checks the batch window, then — the ADR-013 seam — reads the
//     Instructions sysvar and refuses unless THIS transaction also carries the
//     escrow-program deposit matching (buyer, order_id, price, USDC mint).
//     The escrow is never CPI'd; the deposit instruction stays byte-identical
//     to what production wallets sign today. Order lands as Funded.
//
// SIMPLE SEND (2026-09-15, owner plan v4) — open_claimed_order.
//   The buyer's own transaction is now a plain USDC transfer into a vault the
//   escrow program announced (`open_escrow`, status Pending). Blocfone's
//   oracle then sends ONE transaction: escrow `claim` (Pending → Funded) and
//   this program's `open_claimed_order`. The ADR-013 seam changes shape:
//   instead of scanning the Instructions sysvar for a same-transaction
//   deposit, open_claimed_order READS THE ESCROW ACCOUNT and refuses unless
//   it is a Funded escrow of the configured program for (buyer, order_id)
//   with amount == price, the configured mint, the settlement vault as
//   beneficiary, the oracle as authority and a real deadline. Order and
//   deposit are bound by derived address (escrow PDA = f(buyer, order_id)),
//   by the memo / reference key in the buyer's transfer, and by the deposit
//   signature stamped on the Order itself (deposit_signature, appended last)
//   and in the OrderOpened event. Owner decision 2026-09-15: every order
//   opened before the field existed is a test order, so growing the record
//   is accepted; those accounts are no longer readable by this build.
//   `open_order` (the sysvar-paired ritual) is kept untouched as the rollback
//   path: the orders service picks the ritual, a program redeploy does not.
//
// Stake is declared now (claim element: provider skin-in-the-game) but stays 0
// until P2-05 — the slash-policy ADR gates any instruction that moves it.

use anchor_lang::prelude::*;
use anchor_spl::associated_token::get_associated_token_address;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};
use solana_instructions_sysvar as ix_sysvar;

/// The runtime's ed25519 verification precompile (ADR-017). Signatures it
/// checks are validated by the RUNTIME before any program executes; a program
/// proves authorship by reading what the precompile was asked to verify.
const ED25519_PROGRAM_ID: Pubkey = pubkey!("Ed25519SigVerify111111111111111111111111111");

/// Security refresh 2026-08-21 (H1). An ed25519 precompile record carries
/// three INSTRUCTION-INDEX fields beside its offsets: [sig_off, sig_ix,
/// pk_off, pk_ix, msg_off, msg_len, msg_ix]. The runtime verifies the key and
/// message it finds in the instruction each index names (0xFFFF = this
/// instruction's own data). The parsers below read the key and message from
/// the precompile's OWN data — so they must insist the runtime did too, or a
/// transaction author could have the runtime verify one (key, message) while
/// the program reads another. web3's `Ed25519Program.createInstructionWithPublicKey`
/// sets all three to 0xFFFF; anything else is refused.
fn ed25519_record_is_self_contained(d: &[u8], base: usize) -> bool {
    let rd = |o: usize| -> u16 { u16::from_le_bytes([d[o], d[o + 1]]) };
    d.len() >= base + 14 && rd(base + 2) == u16::MAX && rd(base + 6) == u16::MAX && rd(base + 12) == u16::MAX
}

#[cfg(test)]
mod ed25519_record_tests {
    use super::*;

    fn record(sig_ix: u16, pk_ix: u16, msg_ix: u16) -> Vec<u8> {
        let mut d = vec![1u8, 0u8];
        for v in [16u16, sig_ix, 80, pk_ix, 112, 84, msg_ix] {
            d.extend_from_slice(&v.to_le_bytes());
        }
        d
    }

    #[test]
    fn accepts_only_self_referencing_records() {
        assert!(ed25519_record_is_self_contained(&record(u16::MAX, u16::MAX, u16::MAX), 2));
        assert!(!ed25519_record_is_self_contained(&record(0, u16::MAX, u16::MAX), 2));
        assert!(!ed25519_record_is_self_contained(&record(u16::MAX, 3, u16::MAX), 2));
        assert!(!ed25519_record_is_self_contained(&record(u16::MAX, u16::MAX, 1), 2));
        // a record that runs past the data is not self-contained either
        assert!(!ed25519_record_is_self_contained(&record(u16::MAX, u16::MAX, u16::MAX)[..10], 2));
    }
}
use solana_sha256_hasher::hashv;

declare_id!("6aYP8MQt44Zn91McAT7BU4gfoFoGxZ8H1jdNJuFVnS9R");

// On-chain security.txt (2026-09-10) — embedded in the program binary so a
// wallet or explorer that flags an unrecognised program can find who to
// contact. Behind `no-entrypoint` so the CPI/lib build (which has no program
// binary) does not carry it. Takes effect only on the next deploy of a build
// that includes it; the marketplace program is byte-neutral to this until then.
#[cfg(not(feature = "no-entrypoint"))]
use solana_security_txt::security_txt;

#[cfg(not(feature = "no-entrypoint"))]
security_txt! {
    name: "blocfone® marketplace program",
    project_url: "https://blocfone.com",
    contacts: "email:hello@blocfone.io",
    policy: "https://blocfone.com/privacy-cookie-policy/",
    preferred_languages: "en"
}

#[program]
pub mod blocfone_market {
    use super::*;

    /// Register the signing authority as a provider. One provider per
    /// authority; the PDA seed makes a second registration fail before this
    /// handler ever runs.
    pub fn register_provider(ctx: Context<RegisterProvider>, payout_wallet: Pubkey) -> Result<()> {
        // A default (all-zero) payout wallet would make every future settle
        // burn USDC into an address nobody holds. Refuse it at the door.
        require!(payout_wallet != Pubkey::default(), MarketError::InvalidPayoutWallet);

        let provider = &mut ctx.accounts.provider;
        provider.authority = ctx.accounts.authority.key();
        provider.payout_wallet = payout_wallet;
        provider.stake = 0; // parked until the P2-05 slash-policy ADR
        provider.status = ProviderStatus::Active;
        provider.registered_at = Clock::get()?.unix_timestamp;
        provider.batch_count = 0;
        // ADR-017: no signing key at registration — it is set by
        // `set_provider_signing_key`, and publishing is refused until it is.
        provider.signing_pubkey = Pubkey::default();
        // ADR-014: 0 bps until the trusted administrator sets the rate —
        // fail-safe, and PikaSIM's correct permanent value.
        provider.provider_share_bps = 0;
        provider.bump = ctx.bumps.provider;
        Ok(())
    }

    /// ADR-014: set a provider's revenue share. TRUSTED ADMINISTRATOR ONLY
    /// (the accounts struct gates on the program upgrade authority — the
    /// provider's own key cannot call this). Never retroactive: orders stamp
    /// their split at purchase.
    pub fn set_provider_share(ctx: Context<SetProviderShare>, share_bps: u16) -> Result<()> {
        require!(share_bps <= 10_000, MarketError::InvalidShareBps);
        let provider = &mut ctx.accounts.provider;
        let old = provider.provider_share_bps;
        provider.provider_share_bps = share_bps;
        emit!(ProviderShareChanged {
            provider: provider.key(),
            old_bps: old,
            new_bps: share_bps,
        });
        Ok(())
    }

    /// Change the payout wallet and/or status. Only the registered authority —
    /// enforced by `has_one`, so a foreign signer fails in account validation,
    /// never reaching this body.
    pub fn update_provider(
        ctx: Context<UpdateProvider>,
        new_payout_wallet: Option<Pubkey>,
        new_status: Option<ProviderStatus>,
    ) -> Result<()> {
        let provider = &mut ctx.accounts.provider;
        if let Some(wallet) = new_payout_wallet {
            require!(wallet != Pubkey::default(), MarketError::InvalidPayoutWallet);
            provider.payout_wallet = wallet;
        }
        if let Some(status) = new_status {
            provider.status = status;
        }
        Ok(())
    }

    /// Anchor one catalogue snapshot: its Merkle root plus the slot window in
    /// which orders may open against it. The provider must exist (PDA at its
    /// seeds) and be Active; the batch account is seeded by the provider's
    /// running counter, which this instruction advances.
    /// Register or ROTATE a provider's batch-signing key (ADR-017).
    ///
    /// Rotation is the single mechanism behind the custody story: a batch
    /// signed under delegated custody stays signed under the key in force at
    /// the time, and moving to provider-held custody is one call here. The
    /// account is realloc'd because Provider accounts registered before
    /// ADR-017 predate the `signing_pubkey` field.
    pub fn set_provider_signing_key(
        ctx: Context<SetProviderSigningKey>,
        signing_pubkey: Pubkey,
    ) -> Result<()> {
        let info = ctx.accounts.provider.to_account_info();
        let needed = 8 + Provider::INIT_SPACE;

        // The account must BE a Provider — check the discriminator before we
        // touch anything, so a mistyped address can never be grown and
        // rewritten as one.
        {
            let data = info.try_borrow_data()?;
            require!(data.len() >= 8, MarketError::ProviderNotActive);
            require!(data[..8] == Provider::DISCRIMINATOR[..], MarketError::ProviderNotActive);
        }

        // GROW BEFORE DESERIALIZING. Accounts registered before ADR-017 are
        // 32 bytes short of the current layout, and Anchor cannot deserialize
        // a struct out of a buffer smaller than it — so this migration cannot
        // be expressed with `Account<Provider>` at all. Zero-init means the
        // appended field reads as "no key registered", which is exactly the
        // state a pre-ADR-017 provider should be in.
        if info.data_len() < needed {
            let rent = Rent::get()?.minimum_balance(needed);
            if rent > info.lamports() {
                let top_up = rent - info.lamports();
                anchor_lang::system_program::transfer(
                    CpiContext::new(
                        ctx.accounts.system_program.key(),
                        anchor_lang::system_program::Transfer {
                            from: ctx.accounts.authority.to_account_info(),
                            to: info.clone(),
                        },
                    ),
                    top_up,
                )?;
            }
            info.resize(needed)?; // grows zero-filled — the appended key reads as "unset"
        }

        let mut provider: Provider = {
            let data = info.try_borrow_data()?;
            Provider::try_deserialize(&mut &data[..])?
        };
        require_keys_eq!(
            provider.authority,
            ctx.accounts.authority.key(),
            MarketError::AuthorityMismatch
        );
        require!(provider.status == ProviderStatus::Active, MarketError::ProviderNotActive);
        provider.signing_pubkey = signing_pubkey;
        // Rewrite the canonical bump too: it repairs any account whose bump
        // was displaced by an earlier layout, and costs nothing when correct.
        provider.bump = ctx.bumps.provider;
        {
            let mut data = info.try_borrow_mut_data()?;
            provider.try_serialize(&mut &mut data[..])?;
        }
        Ok(())
    }

    pub fn publish_offer_batch(
        ctx: Context<PublishOfferBatch>,
        merkle_root: [u8; 32],
        valid_from_slot: u64,
        valid_until_slot: u64,
        offer_count: u32,
        nonce: [u8; 16],
    ) -> Result<()> {
        let provider = &mut ctx.accounts.provider;
        require!(provider.status == ProviderStatus::Active, MarketError::ProviderNotActive);

        // ADR-017 / PC-2: the PROVIDER must have authored this batch, and the
        // chain — not blocfone's assertion — is what establishes it. Refuse
        // outright if no signing key is registered: an unsigned batch must be
        // impossible, not merely discouraged.
        require!(provider.signing_pubkey != Pubkey::default(), MarketError::NoSigningKey);
        verify_provider_batch_signature(
            &ctx.accounts.instructions.to_account_info(),
            &provider.signing_pubkey,
            &ctx.accounts.authority.key(),
            &merkle_root,
            valid_from_slot,
            valid_until_slot,
            offer_count,
            &nonce,
        )?;
        // An all-zero root is the Merkle equivalent of the all-zero payout
        // wallet: structurally a root, semantically nothing. Same for an empty
        // batch — anchoring zero offers is always a pipeline bug upstream.
        require!(merkle_root != [0u8; 32], MarketError::InvalidMerkleRoot);
        require!(offer_count > 0, MarketError::EmptyBatch);
        // The window must be an actual window, and one that can still be used:
        // a batch that expires at or before the current slot is dead on
        // arrival — publishing it can only be an anchoring-service bug.
        require!(valid_until_slot > valid_from_slot, MarketError::InvalidValidityWindow);
        require!(valid_until_slot > Clock::get()?.slot, MarketError::InvalidValidityWindow);

        let batch = &mut ctx.accounts.batch;
        batch.provider = provider.key();
        batch.merkle_root = merkle_root;
        batch.valid_from_slot = valid_from_slot;
        batch.valid_until_slot = valid_until_slot;
        batch.offer_count = offer_count;
        batch.state = BatchState::Active;
        batch.seq = provider.batch_count;
        batch.published_at = Clock::get()?.unix_timestamp;
        batch.bump = ctx.bumps.batch;

        provider.batch_count = provider
            .batch_count
            .checked_add(1)
            .ok_or(MarketError::CounterOverflow)?;
        Ok(())
    }

    /// Retire a batch: Active → Expired, one-way. Called by the anchoring
    /// service on catalogue rotation (P1-09). Orders against an Expired batch
    /// are refused by `open_order` (P1-03) regardless of the slot window.
    pub fn expire_batch(ctx: Context<ExpireBatch>) -> Result<()> {
        let batch = &mut ctx.accounts.batch;
        require!(batch.state == BatchState::Active, MarketError::BatchNotActive);
        batch.state = BatchState::Expired;
        Ok(())
    }

    /// One-time write of the cluster-specific facts. Upgrade-authority gated
    /// (the accounts struct proves the signer against ProgramData).
    pub fn init_config(
        ctx: Context<InitConfig>,
        escrow_program: Pubkey,
        usdc_mint: Pubkey,
        oracle: Pubkey,
        rent_collector: Pubkey,
    ) -> Result<()> {
        require!(escrow_program != Pubkey::default(), MarketError::InvalidConfig);
        require!(usdc_mint != Pubkey::default(), MarketError::InvalidConfig);
        require!(oracle != Pubkey::default(), MarketError::InvalidConfig);
        require!(rent_collector != Pubkey::default(), MarketError::InvalidConfig);
        let config = &mut ctx.accounts.config;
        config.escrow_program = escrow_program;
        config.usdc_mint = usdc_mint;
        config.oracle = oracle;
        config.rent_collector = rent_collector;
        config.bump = ctx.bumps.config;
        Ok(())
    }

    /// Correct the config. Same gate as init — a wrong value must never
    /// require a redeploy to fix.
    pub fn update_config(
        ctx: Context<UpdateConfig>,
        escrow_program: Pubkey,
        usdc_mint: Pubkey,
        oracle: Pubkey,
        rent_collector: Pubkey,
    ) -> Result<()> {
        require!(escrow_program != Pubkey::default(), MarketError::InvalidConfig);
        require!(usdc_mint != Pubkey::default(), MarketError::InvalidConfig);
        require!(oracle != Pubkey::default(), MarketError::InvalidConfig);
        require!(rent_collector != Pubkey::default(), MarketError::InvalidConfig);
        let config = &mut ctx.accounts.config;
        config.escrow_program = escrow_program;
        config.usdc_mint = usdc_mint;
        config.oracle = oracle;
        config.rent_collector = rent_collector;
        Ok(())
    }

    /// Open an order against an anchored offer. The three gates, in order:
    ///  1. the batch is Active and the current slot is inside its window;
    ///  2. the Merkle proof connects offer_hash to the batch root;
    ///  3. (ADR-013) this very transaction carries the escrow deposit for
    ///     (buyer, order_id) with amount == price and the configured mint —
    ///     found by scanning the Instructions sysvar, no CPI.
    /// All three pass → the Order lands already Funded: the deposit is in the
    /// same atomic transaction, so "order exists" implies "money in vault".
    pub fn open_order(
        ctx: Context<OpenOrder>,
        order_id: u64,
        offer_hash: [u8; 32],
        price: u64,
        trace_id: [u8; 16],
        proof: Vec<[u8; 32]>,
        duration_days: u16,
        provider_price: u64,
    ) -> Result<()> {
        let batch = &ctx.accounts.batch;
        let config = &ctx.accounts.config;
        let buyer = ctx.accounts.buyer.key();
        let clock = Clock::get()?;

        // Gate 0 (security refresh 2026-08-21, C2) — only the configured
        // ORACLE opens orders, as the payer it already is in the production
        // deposit ritual (the sponsor countersigns before the wallet sees the
        // transaction). Without this pin the price and duration below are
        // whatever the transaction's author typed: the Merkle proof binds the
        // OFFER, not its price. A handler require!, not a constraint
        // expression, so the account order and layout stay byte-identical.
        require!(
            ctx.accounts.payer.key() == config.oracle,
            MarketError::Unauthorized
        );
        // (L2) A suspended provider's unexpired batches are not orderable.
        require!(
            ctx.accounts.provider.status == ProviderStatus::Active,
            MarketError::ProviderNotActive
        );

        // Gate 1 — the batch is usable now.
        require!(batch.state == BatchState::Active, MarketError::BatchNotActive);
        require!(
            clock.slot >= batch.valid_from_slot && clock.slot <= batch.valid_until_slot,
            MarketError::BatchWindowClosed
        );

        // Gate 2 — the offer is genuinely in the batch.
        require!(offer_hash != [0u8; 32], MarketError::InvalidOfferHash);
        require!(price > 0, MarketError::InvalidPrice);
        // ADR-018: the plan duration is a contract term, stamped so the
        // retention window is computable on-chain without trusting a later
        // caller. 1..=366 covers every product incl. custom 365-day plans.
        require!(
            duration_days >= 1 && duration_days <= 366,
            MarketError::InvalidDuration
        );
        require!(proof.len() <= 32, MarketError::ProofTooLong);
        require!(
            verify_merkle_proof(&batch.merkle_root, &offer_hash, &proof),
            MarketError::InvalidMerkleProof
        );

        // Gate 3 — the paired deposit is in this transaction (ADR-013), and
        // (2026-08-21, C1) it is for the vault, under the oracle, with a real
        // window.
        let expected_escrow = Pubkey::find_program_address(
            &[b"escrow", buyer.as_ref(), &order_id.to_le_bytes()],
            &config.escrow_program,
        )
        .0;
        verify_paired_deposit(
            &ctx.accounts.instructions.to_account_info(),
            config,
            &buyer,
            order_id,
            price,
            &expected_escrow,
            clock.unix_timestamp,
        )?;

        // ADR-014: stamp the CONCRETE split now. Floor to the provider at
        // USDC's 6 decimals; treasury takes the sub-unit remainder. A later
        // rate change never touches this order.
        let bps = ctx.accounts.provider.provider_share_bps;
        // Defence in depth (2026-08-11): set_provider_share already refuses
        // anything above 10_000, but an account can be damaged by other means —
        // one was, by a field-layout change, and every order opened afterwards
        // stamped a share LARGER THAN THE PRICE. Nothing downstream could then
        // settle. Refuse at the stamp instead of discovering it at settlement,
        // when the buyer's money is already in escrow.
        require!(bps <= 10_000, MarketError::InvalidShareBps);
        // ADR-014 as amended 2026-08-18: the stamp is the PROVIDER PRICE (an
        // amount) when the platform states one — retail = provider price +
        // platform fee, and the fee ratio varies plan by plan, so an amount is
        // the faithful stamp. TRUST: only a transaction the configured ORACLE
        // co-signs (as payer) may state a provider price; a buyer-only open
        // (provider_price = 0, or a non-oracle payer) falls back to the
        // provider's bps — so no buyer can lower a provider's cut, and no
        // provider can raise it past the price.
        // (2026-08-21) Gate 0 made the payer the oracle unconditionally, so a
        // stated provider price is always the platform's statement — no silent
        // fallback to bps for a non-oracle payer any more (L1).
        let provider_share_amount = if provider_price > 0 {
            require!(provider_price <= price, MarketError::InvalidShareBps);
            provider_price
        } else {
            ((price as u128) * (bps as u128) / 10_000u128) as u64
        };

        let order = &mut ctx.accounts.order;
        order.buyer = buyer;
        order.batch = batch.key();
        order.provider = ctx.accounts.provider.key();
        order.offer_hash = offer_hash;
        order.price = price;
        order.order_id = order_id;
        order.escrow = expected_escrow;
        order.provider_share_bps = bps;
        order.provider_share_amount = provider_share_amount;
        order.state = OrderState::Funded;
        order.opened_at = clock.unix_timestamp;
        order.trace_id = trace_id;
        order.bump = ctx.bumps.order;
        order.duration_days = duration_days;
        order.settled_at = 0; // stamped by the terminal instruction (ADR-018)
        order.delivery_commitment = [0u8; 32]; // stamped at attestation (ADR-020)
        order.paid_out = false;
        order.deposit_signature = [0u8; 64]; // the deposit is this very transaction
        Ok(())
    }

    /// Simple send (2026-09-15): open an order over an escrow that is ALREADY
    /// Funded — claimed by the oracle from the buyer's plain transfer, in this
    /// same transaction or an earlier one. Gates 0–2 are open_order's; gate 3
    /// reads the escrow account instead of the Instructions sysvar. The buyer
    /// does not sign: their consent is the transfer (and the consent message,
    /// ADR-016); the Order PDA is still seeded by their key.
    pub fn open_claimed_order(
        ctx: Context<OpenClaimedOrder>,
        order_id: u64,
        offer_hash: [u8; 32],
        price: u64,
        trace_id: [u8; 16],
        proof: Vec<[u8; 32]>,
        duration_days: u16,
        provider_price: u64,
        deposit_signature: [u8; 64],
    ) -> Result<()> {
        let batch = &ctx.accounts.batch;
        let config = &ctx.accounts.config;
        let buyer = ctx.accounts.buyer.key();
        let clock = Clock::get()?;

        // Gate 0 — only the configured oracle opens orders (C2), exactly as
        // in open_order. Here it is also the escrow's claimant.
        require!(ctx.accounts.payer.key() == config.oracle, MarketError::Unauthorized);
        require!(
            ctx.accounts.provider.status == ProviderStatus::Active,
            MarketError::ProviderNotActive
        );

        // Gate 1 — the batch is usable now.
        require!(batch.state == BatchState::Active, MarketError::BatchNotActive);
        require!(
            clock.slot >= batch.valid_from_slot && clock.slot <= batch.valid_until_slot,
            MarketError::BatchWindowClosed
        );

        // Gate 2 — the offer is genuinely in the batch.
        require!(offer_hash != [0u8; 32], MarketError::InvalidOfferHash);
        require!(price > 0, MarketError::InvalidPrice);
        require!(
            duration_days >= 1 && duration_days <= 366,
            MarketError::InvalidDuration
        );
        require!(proof.len() <= 32, MarketError::ProofTooLong);
        require!(
            verify_merkle_proof(&batch.merkle_root, &offer_hash, &proof),
            MarketError::InvalidMerkleProof
        );

        // Gate 3' — the escrow account IS the deposit. Derived address first
        // (a different escrow, however well-formed, is not this order's), then
        // owner, then the state itself.
        let expected_escrow = Pubkey::find_program_address(
            &[b"escrow", buyer.as_ref(), &order_id.to_le_bytes()],
            &config.escrow_program,
        )
        .0;
        let escrow_ai = ctx.accounts.escrow.to_account_info();
        require!(escrow_ai.key() == expected_escrow, MarketError::DepositEscrowMismatch);
        require!(*escrow_ai.owner == config.escrow_program, MarketError::MissingEscrowDeposit);
        let escrow = {
            let data = escrow_ai.try_borrow_data()?;
            parse_escrow(&data).ok_or(MarketError::DepositMalformed)?
        };
        verify_claimed_escrow(&escrow, config, &buyer, order_id, price, clock.unix_timestamp)?;

        // ADR-014 stamp — identical to open_order.
        let bps = ctx.accounts.provider.provider_share_bps;
        require!(bps <= 10_000, MarketError::InvalidShareBps);
        let provider_share_amount = if provider_price > 0 {
            require!(provider_price <= price, MarketError::InvalidShareBps);
            provider_price
        } else {
            ((price as u128) * (bps as u128) / 10_000u128) as u64
        };

        let order = &mut ctx.accounts.order;
        order.buyer = buyer;
        order.batch = batch.key();
        order.provider = ctx.accounts.provider.key();
        order.offer_hash = offer_hash;
        order.price = price;
        order.order_id = order_id;
        order.escrow = expected_escrow;
        order.provider_share_bps = bps;
        order.provider_share_amount = provider_share_amount;
        order.state = OrderState::Funded;
        order.opened_at = clock.unix_timestamp;
        order.trace_id = trace_id;
        order.bump = ctx.bumps.order;
        order.duration_days = duration_days;
        order.settled_at = 0;
        order.delivery_commitment = [0u8; 32];
        order.paid_out = false;
        order.deposit_signature = deposit_signature;

        emit!(OrderOpened {
            order_id,
            order: order.key(),
            buyer,
            escrow: expected_escrow,
            price,
            deposit_signature,
        });
        Ok(())
    }

    /// The saga has reserved supply and placed the provider order:
    /// Funded → Provisioning. Oracle only.
    pub fn start_provisioning(ctx: Context<OracleTransition>) -> Result<()> {
        let order = &mut ctx.accounts.order;
        require!(order.state == OrderState::Funded, MarketError::InvalidTransition);
        order.state = OrderState::Provisioning;
        emit!(OrderProvisioning { order_id: order.order_id, order: order.key() });
        Ok(())
    }

    /// Delivery is confirmed (the eSIM/number provisioned and handed over):
    /// Provisioning → Active. The oracle drives the move, but ADR-020 makes
    /// it unable to fabricate one: the PROVIDER's registered signing key —
    /// the same key that certified the offer batch — must have signed
    /// "BLOCFONE-DELIVERY-v1" ‖ order ‖ commitment in this very transaction,
    /// and the commitment (sealed MSISDN for numbered orders, sealed ICCID
    /// otherwise; ADR-011 construction) lands on the RETAINED Order account
    /// (ADR-018), so the durable record says WHAT was delivered — provable
    /// under lawful disclosure, readable by no one.
    pub fn attest_provisioned(
        ctx: Context<AttestProvisioned>,
        delivery_commitment: [u8; 32],
    ) -> Result<()> {
        let order = &mut ctx.accounts.order;
        require!(order.state == OrderState::Provisioning, MarketError::InvalidTransition);
        require!(delivery_commitment != [0u8; 32], MarketError::InvalidCommitment);
        let provider = &ctx.accounts.provider;
        require!(provider.signing_pubkey != Pubkey::default(), MarketError::NoSigningKey);
        verify_provider_delivery_signature(
            &ctx.accounts.instructions.to_account_info(),
            &provider.signing_pubkey,
            &order.key(),
            &delivery_commitment,
        )?;
        order.state = OrderState::Active;
        order.delivery_commitment = delivery_commitment;
        emit!(OrderActive { order_id: order.order_id, order: order.key(), delivery_commitment });
        Ok(())
    }

    /// The purchase's happy ending: Active → Settled — and the Order account
    /// STAYS (ADR-018 / PC-7): the contract is stored on-chain for the whole
    /// life of the deal plus the retention window, not deleted at the moment
    /// it completes. `settled_at` is stamped so the retention window is
    /// computable on-chain. The emitted event carries the stamped split —
    /// the ledger's input, and (Phase 2) the vault's payout facts.
    pub fn settle(ctx: Context<OracleTransition>) -> Result<()> {
        let order = &mut ctx.accounts.order;
        require!(order.state == OrderState::Active, MarketError::InvalidTransition);
        // A stamped split that exceeds the price is corrupt data, and this used
        // to PANIC on the subtraction below — which strands the money, because
        // a panicking instruction can never complete and the order can never
        // leave Active. Found by the P1-20 acceptance run (2026-08-11) after a
        // Provider account carried a share of 49810 bps.
        //
        // Refusing is deliberate rather than saturating: silently settling with
        // treasury_amount = 0 would hand a provider more than the buyer paid.
        // A clear error leaves the order recoverable and a human deciding.
        require!(
            order.provider_share_amount <= order.price,
            MarketError::InvalidShareBps
        );
        order.state = OrderState::Settled;
        order.settled_at = Clock::get()?.unix_timestamp;
        emit!(OrderSettled {
            order_id: order.order_id,
            order: order.key(),
            buyer: order.buyer,
            provider: order.provider,
            escrow: order.escrow,
            price: order.price,
            provider_share_bps: order.provider_share_bps,
            provider_share_amount: order.provider_share_amount,
            treasury_amount: order.price - order.provider_share_amount,
        });
        Ok(())
    }

    /// The failure exit: any pre-settled state → Refunded — and the account
    /// STAYS, exactly like settle (ADR-018 §1): a refunded order is the
    /// record of a deal that failed to perform, which is precisely what a
    /// dispute needs. The escrow program's own refund returns the buyer's
    /// USDC; this records why, durably.
    pub fn refund(ctx: Context<OracleTransition>) -> Result<()> {
        let order = &mut ctx.accounts.order;
        require!(
            matches!(
                order.state,
                OrderState::Funded | OrderState::Provisioning | OrderState::Active
            ),
            MarketError::InvalidTransition
        );
        order.state = OrderState::Refunded;
        order.settled_at = Clock::get()?.unix_timestamp;
        emit!(OrderRefunded {
            order_id: order.order_id,
            order: order.key(),
            buyer: order.buyer,
            escrow: order.escrow,
            price: order.price,
        });
        Ok(())
    }

    /// ADR-014 §4 (built 2026-08-18): the SETTLEMENT VAULT pays stamps, not
    /// formulas. The escrow releases into the vault's USDC account (the vault
    /// PDA is the deposits' beneficiary — no key of blocfone's can spend from
    /// it); this instruction then pays the Order's STAMPED provider amount to
    /// the provider's registered payout wallet and the remainder (the platform
    /// fee) to treasury. Permissionless: anyone — the provider included — may
    /// trigger it; there is exactly one thing it can do.
    ///
    /// Requires the Order to be Settled (money in the vault) and not yet paid
    /// out; marks it paid so the stamps pay once and only once.
    pub fn payout(ctx: Context<Payout>) -> Result<()> {
        // ── the destination pins (see the Payout context doc) ────────────────
        let cfg = &ctx.accounts.config;
        let prov = &ctx.accounts.provider;
        require!(ctx.accounts.order.provider == prov.key(), MarketError::ProviderMismatch);
        require!(ctx.accounts.vault_token.owner == ctx.accounts.vault_authority.key(), MarketError::WrongTokenOwner);
        require!(ctx.accounts.vault_token.mint == cfg.usdc_mint, MarketError::WrongMint);
        require!(ctx.accounts.provider_token.owner == prov.payout_wallet, MarketError::WrongTokenOwner);
        require!(ctx.accounts.provider_token.mint == cfg.usdc_mint, MarketError::WrongMint);
        require!(ctx.accounts.treasury_token.owner == cfg.rent_collector, MarketError::WrongTokenOwner);
        require!(ctx.accounts.treasury_token.mint == cfg.usdc_mint, MarketError::WrongMint);
        // (2026-08-21, L3) the destinations are the owners' ASSOCIATED token
        // accounts, not merely accounts they own — a permissionless caller
        // could otherwise route the money into a token account the owner
        // never watches. Money would still be theirs; it must also be FOUND.
        require!(
            ctx.accounts.provider_token.key() == get_associated_token_address(&prov.payout_wallet, &cfg.usdc_mint),
            MarketError::NotAssociatedTokenAccount
        );
        require!(
            ctx.accounts.treasury_token.key() == get_associated_token_address(&cfg.rent_collector, &cfg.usdc_mint),
            MarketError::NotAssociatedTokenAccount
        );

        let order = &mut ctx.accounts.order;
        require!(order.state == OrderState::Settled, MarketError::InvalidTransition);
        require!(!order.paid_out, MarketError::AlreadyPaidOut);
        require!(order.provider_share_amount <= order.price, MarketError::InvalidShareBps);
        let provider_amount = order.provider_share_amount;
        let treasury_amount = order.price - provider_amount;

        let bump = ctx.bumps.vault_authority;
        let seeds: &[&[u8]] = &[b"settlement_vault", &[bump]];
        let signer = &[seeds];
        if provider_amount > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.key(),
                    Transfer {
                        from: ctx.accounts.vault_token.to_account_info(),
                        to: ctx.accounts.provider_token.to_account_info(),
                        authority: ctx.accounts.vault_authority.to_account_info(),
                    },
                    signer,
                ),
                provider_amount,
            )?;
        }
        if treasury_amount > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.key(),
                    Transfer {
                        from: ctx.accounts.vault_token.to_account_info(),
                        to: ctx.accounts.treasury_token.to_account_info(),
                        authority: ctx.accounts.vault_authority.to_account_info(),
                    },
                    signer,
                ),
                treasury_amount,
            )?;
        }
        let order = &mut ctx.accounts.order;
        order.paid_out = true;
        emit!(OrderPaidOut {
            order_id: order.order_id,
            order: order.key(),
            provider: order.provider,
            provider_wallet: ctx.accounts.provider.payout_wallet,
            provider_amount,
            treasury_amount,
        });
        Ok(())
    }

    /// ADR-018 §3: closure policy, upgrade-authority gated. Its OWN tiny PDA
    /// rather than a MarketConfig field, so the existing config account's
    /// layout never changes. Absent account = closure OFF — fail closed in
    /// the only irreversible direction.
    pub fn set_closure_policy(ctx: Context<SetClosurePolicy>, enabled: bool) -> Result<()> {
        let policy = &mut ctx.accounts.policy;
        policy.enabled = enabled;
        policy.bump = ctx.bumps.policy;
        Ok(())
    }

    /// ADR-018 §2 (window amended to 90 days by the owner, 2026-08-17):
    /// return a terminal Order's rent to config.rent_collector — but never
    /// before `settled_at + plan duration + 90 days`, and never while the
    /// closure policy is off. The window is enforced HERE, on-chain: nobody,
    /// blocfone included, can shred the record early. The retention promise
    /// is a program rule, not our word.
    pub fn close_order(ctx: Context<CloseOrder>) -> Result<()> {
        require!(ctx.accounts.policy.enabled, MarketError::ClosureDisabled);
        let order = &ctx.accounts.order;
        require!(
            matches!(order.state, OrderState::Settled | OrderState::Refunded),
            MarketError::InvalidTransition
        );
        // (2026-08-21, M3) a Settled order must have been PAID OUT before its
        // record goes — `payout` is the vault's only outflow and needs the
        // unpaid Settled Order, so closing first would strand the USDC.
        require!(
            order.state == OrderState::Refunded || order.paid_out,
            MarketError::NotPaidOut
        );
        let now = Clock::get()?.unix_timestamp;
        require!(
            retention_elapsed(now, order.settled_at, order.duration_days),
            MarketError::RetentionNotElapsed
        );
        emit!(OrderClosed { order_id: order.order_id, order: order.key() });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ADR-018 retention
// ---------------------------------------------------------------------------

/// 90 days (owner, 2026-08-17 — raised from ADR-018's original 60): time
/// for a buyer to see the charge on a statement and raise it, after the
/// plan itself has run its course. This is the FLOOR the program enforces;
/// the off-chain sweeper's own schedule (ORDER_CLOSE_AFTER_DAYS, default
/// 7 years) sits above it and can only ever be later, never earlier.
pub const RETENTION_WINDOW_SECONDS: i64 = 90 * 86_400;

/// May a terminal order's on-chain record be closed yet? Pure on purpose —
/// the unit tests below pin the boundary exactly, because this one
/// comparison IS the retention promise.
fn retention_elapsed(now: i64, settled_at: i64, duration_days: u16) -> bool {
    now >= settled_at + (duration_days as i64) * 86_400 + RETENTION_WINDOW_SECONDS
}

#[cfg(test)]
mod retention_tests {
    use super::*;
    const DAY: i64 = 86_400;

    #[test]
    fn refuses_through_the_whole_window() {
        let settled = 1_700_000_000;
        // a 7-day plan: refused at settle, at expiry, and one second short
        assert!(!retention_elapsed(settled, settled, 7));
        assert!(!retention_elapsed(settled + 7 * DAY, settled, 7));
        assert!(!retention_elapsed(settled + 7 * DAY + 90 * DAY - 1, settled, 7));
    }

    #[test]
    fn opens_exactly_at_the_boundary() {
        let settled = 1_700_000_000;
        assert!(retention_elapsed(settled + 7 * DAY + 90 * DAY, settled, 7));
        // zero-duration (a refunded never-delivered order): 90 days flat
        assert!(!retention_elapsed(settled + 90 * DAY - 1, settled, 0));
        assert!(retention_elapsed(settled + 90 * DAY, settled, 0));
    }

    #[test]
    fn longest_plan_still_computes() {
        let settled = 1_700_000_000;
        assert!(!retention_elapsed(settled + 365 * DAY + 90 * DAY - 1, settled, 365));
        assert!(retention_elapsed(settled + 365 * DAY + 90 * DAY, settled, 365));
    }
}

// ---------------------------------------------------------------------------
// ADR-013 helpers
// ---------------------------------------------------------------------------

/// Sorted-pair, domain-separated SHA-256 Merkle verification. 0x00 prefixes
/// the leaf hash, 0x01 prefixes every interior node — without the domains, a
/// proof for an interior node could masquerade as a leaf (second-preimage).
/// Sorted pairs make proofs position-free: no index to carry or get wrong.
/// ⚠️ This IS the canonical tree shape — the anchoring service (P1-08/09)
/// must build byte-identically, and its package tests assert against vectors
/// generated from this definition.
fn verify_merkle_proof(root: &[u8; 32], offer_hash: &[u8; 32], proof: &[[u8; 32]]) -> bool {
    let mut node = hashv(&[&[0u8], offer_hash.as_ref()]).to_bytes();
    for sibling in proof {
        let (lo, hi) = if node <= *sibling { (node, *sibling) } else { (*sibling, node) };
        node = hashv(&[&[1u8], lo.as_ref(), hi.as_ref()]).to_bytes();
    }
    node == *root
}

/// ADR-017 / PC-2 receive leg — prove the PROVIDER authored this batch.
///
/// Solana cannot verify ed25519 inside a program affordably, so the runtime
/// provides a precompile: a transaction carries an
/// `Ed25519SigVerify111111111111111111111111111` instruction which the
/// RUNTIME checks before any program runs. Our job is therefore not to verify
/// the signature but to prove that the runtime already did, over exactly the
/// key and bytes we require — otherwise a caller could attach a valid
/// signature over something else entirely.
///
/// Precompile data layout (Solana docs):
///   [0]     u8   number of signatures
///   [1]     u8   padding
///   then, per signature, a 14-byte offsets record:
///     signature_offset u16, signature_ix_index u16,
///     public_key_offset u16, public_key_ix_index u16,
///     message_data_offset u16, message_data_size u16, message_ix_index u16
///   with the referenced bytes living at those offsets (index 0xFFFF means
///   "this same instruction", which is how we build it).
///
/// The message we require is the fixed 123-byte layout that
/// @blocfone/provider-signing produces — rebuilt here from the instruction's
/// own arguments, so a signature can only ever authorise the exact batch
/// being published.
fn verify_provider_batch_signature(
    instructions_sysvar: &AccountInfo,
    signing_pubkey: &Pubkey,
    authority: &Pubkey,
    merkle_root: &[u8; 32],
    valid_from_slot: u64,
    valid_until_slot: u64,
    offer_count: u32,
    nonce: &[u8; 16],
) -> Result<()> {
    // Rebuild the exact bytes the provider signed: TAG | authority | root |
    // from | until | count | nonce  = 23 + 32 + 32 + 8 + 8 + 4 + 16 = 123.
    let mut expected = [0u8; 123];
    expected[..23].copy_from_slice(b"BLOCFONE-OFFER-BATCH-v1");
    expected[23..55].copy_from_slice(authority.as_ref());
    expected[55..87].copy_from_slice(merkle_root);
    expected[87..95].copy_from_slice(&valid_from_slot.to_le_bytes());
    expected[95..103].copy_from_slice(&valid_until_slot.to_le_bytes());
    expected[103..107].copy_from_slice(&offer_count.to_le_bytes());
    expected[107..123].copy_from_slice(nonce);

    let mut index = 0usize;
    loop {
        let ix = match ix_sysvar::load_instruction_at_checked(index, instructions_sysvar) {
            Ok(ix) => ix,
            Err(_) => break, // ran past the end of the transaction
        };
        index += 1;
        if ix.program_id != ED25519_PROGRAM_ID {
            continue;
        }
        // A precompile instruction the runtime accepted. Read its offsets and
        // compare what it actually verified with what we require.
        let d = &ix.data;
        if d.len() < 2 {
            return Err(error!(MarketError::BatchSignatureMissing));
        }
        let count = d[0] as usize;
        for i in 0..count {
            let base = 2 + i * 14;
            if d.len() < base + 14 {
                return Err(error!(MarketError::BatchSignatureMissing));
            }
            let rd = |o: usize| -> usize { u16::from_le_bytes([d[o], d[o + 1]]) as usize };
            // (2026-08-21, H1) the runtime must have verified THIS
            // instruction's own key and message, not another instruction's.
            if !ed25519_record_is_self_contained(d, base) {
                return Err(error!(MarketError::SignatureRecordNotSelfContained));
            }
            let pk_off = rd(base + 4);
            let msg_off = rd(base + 8);
            let msg_len = rd(base + 10);
            if d.len() < pk_off + 32 || d.len() < msg_off + msg_len {
                return Err(error!(MarketError::BatchSignatureMissing));
            }
            // The key the runtime verified against MUST be the provider's
            // registered signing key — not merely some valid signature.
            if &d[pk_off..pk_off + 32] != signing_pubkey.as_ref() {
                return Err(error!(MarketError::BatchSignatureWrongKey));
            }
            if msg_len != expected.len() || &d[msg_off..msg_off + msg_len] != &expected[..] {
                return Err(error!(MarketError::BatchSignatureMismatch));
            }
            return Ok(()); // the runtime verified this provider over these terms
        }
    }
    Err(error!(MarketError::BatchSignatureMissing))
}

/// The exact bytes a provider signs to attest a delivery (ADR-020):
/// TAG | order pda | delivery commitment = 20 + 32 + 32 = 84. Pure, so the
/// unit test below pins the layout the JS signer must reproduce.
fn delivery_message(order: &Pubkey, commitment: &[u8; 32]) -> [u8; 84] {
    let mut m = [0u8; 84];
    m[..20].copy_from_slice(b"BLOCFONE-DELIVERY-v1");
    m[20..52].copy_from_slice(order.as_ref());
    m[52..84].copy_from_slice(commitment);
    m
}

/// ADR-020: the delivery twin of verify_provider_batch_signature — the SAME
/// introspection discipline, deliberately duplicated rather than refactored
/// so the audited batch path stays byte-identical. The runtime's ed25519
/// precompile must have verified the provider's REGISTERED key over the
/// delivery message in this very transaction.
fn verify_provider_delivery_signature(
    instructions_sysvar: &AccountInfo,
    signing_pubkey: &Pubkey,
    order: &Pubkey,
    commitment: &[u8; 32],
) -> Result<()> {
    let expected = delivery_message(order, commitment);

    let mut index = 0usize;
    loop {
        let ix = match ix_sysvar::load_instruction_at_checked(index, instructions_sysvar) {
            Ok(ix) => ix,
            Err(_) => break, // ran past the end of the transaction
        };
        index += 1;
        if ix.program_id != ED25519_PROGRAM_ID {
            continue;
        }
        let d = &ix.data;
        if d.len() < 2 {
            return Err(error!(MarketError::DeliverySignatureMissing));
        }
        let count = d[0] as usize;
        for i in 0..count {
            let base = 2 + i * 14;
            if d.len() < base + 14 {
                return Err(error!(MarketError::DeliverySignatureMissing));
            }
            let rd = |o: usize| -> usize { u16::from_le_bytes([d[o], d[o + 1]]) as usize };
            // (2026-08-21, H1) same self-containment rule as the batch parser.
            if !ed25519_record_is_self_contained(d, base) {
                return Err(error!(MarketError::SignatureRecordNotSelfContained));
            }
            let pk_off = rd(base + 4);
            let msg_off = rd(base + 8);
            let msg_len = rd(base + 10);
            if d.len() < pk_off + 32 || d.len() < msg_off + msg_len {
                return Err(error!(MarketError::DeliverySignatureMissing));
            }
            // The key the runtime verified against MUST be the provider's
            // registered signing key — not merely some valid signature.
            if &d[pk_off..pk_off + 32] != signing_pubkey.as_ref() {
                return Err(error!(MarketError::DeliverySignatureWrongKey));
            }
            if msg_len != expected.len() || &d[msg_off..msg_off + msg_len] != &expected[..] {
                return Err(error!(MarketError::DeliverySignatureMissing));
            }
            return Ok(()); // the runtime verified this provider over this delivery
        }
    }
    Err(error!(MarketError::DeliverySignatureMissing))
}

#[cfg(test)]
mod delivery_message_tests {
    use super::*;

    #[test]
    fn layout_is_tag_order_commitment() {
        let order = Pubkey::new_unique();
        let commitment = [7u8; 32];
        let m = delivery_message(&order, &commitment);
        assert_eq!(&m[..20], b"BLOCFONE-DELIVERY-v1");
        assert_eq!(&m[20..52], order.as_ref());
        assert_eq!(&m[52..84], &commitment);
    }
}

/// Scan the transaction's instructions for the escrow deposit that pairs with
/// this Order. A candidate is (escrow program, `initialize` discriminator,
/// same order_id); once found, every remaining fact must match exactly —
/// a near-miss is an error, never "keep looking", so a malformed pairing
/// cannot be shadowed by a second candidate.
///
/// Deployed `initialize` layout (rent-vault build, verified against source):
///   data:     discriminator(8) ++ order_id u64 ++ amount u64 ++ deadline i64
///   accounts: 0 subscriber, 1 beneficiary, 2 authority, 3 mint, 4 rent_vault,
///             5 escrow, 6 vault, 7 subscriber_token, 8 token, 9 system
/// Security refresh 2026-08-21 (C1): the deposit must be FOR US and UNDER OUR
/// CONTROL, not merely present. The escrow program stores beneficiary and
/// authority verbatim from its caller and lets the authority refund at any
/// time, so a deposit that names the buyer as its own beneficiary/authority
/// would leave "order exists" true and "money reachable by blocfone" false.
/// Hence three more pins: beneficiary == the settlement vault PDA, authority
/// == config.oracle, and a deadline at least DEPOSIT_DEADLINE_FLOOR_SECS out
/// (the saga assumes a 24 h window; the escrow caps at 25 h).
pub const DEPOSIT_DEADLINE_FLOOR_SECS: i64 = 20 * 3_600;

/// Pure on purpose — unit-tested below.
fn deposit_deadline_ok(deadline: i64, now: i64) -> bool {
    deadline >= now.saturating_add(DEPOSIT_DEADLINE_FLOOR_SECS)
}

fn verify_paired_deposit(
    instructions_sysvar: &AccountInfo,
    config: &MarketConfig,
    buyer: &Pubkey,
    order_id: u64,
    price: u64,
    expected_escrow: &Pubkey,
    now: i64,
) -> Result<()> {
    let disc: [u8; 8] = hashv(&[b"global:initialize"]).to_bytes()[..8]
        .try_into()
        .unwrap();
    let settlement_vault = Pubkey::find_program_address(&[b"settlement_vault"], &crate::ID).0;

    let mut index = 0usize;
    loop {
        let ix = match ix_sysvar::load_instruction_at_checked(index, instructions_sysvar) {
            Ok(ix) => ix,
            Err(_) => break, // ran past the end of the transaction
        };
        index += 1;

        if ix.program_id != config.escrow_program || ix.data.len() < 32 || ix.data[..8] != disc {
            continue;
        }
        let ix_order_id = u64::from_le_bytes(ix.data[8..16].try_into().unwrap());
        if ix_order_id != order_id {
            continue;
        }

        // The candidate. From here every mismatch is terminal.
        let amount = u64::from_le_bytes(ix.data[16..24].try_into().unwrap());
        let deadline = i64::from_le_bytes(ix.data[24..32].try_into().unwrap());
        require!(amount == price, MarketError::DepositAmountMismatch);
        require!(ix.accounts.len() >= 10, MarketError::DepositMalformed);
        require!(ix.accounts[0].pubkey == *buyer, MarketError::DepositBuyerMismatch);
        require!(ix.accounts[1].pubkey == settlement_vault, MarketError::DepositBeneficiaryMismatch);
        require!(ix.accounts[2].pubkey == config.oracle, MarketError::DepositAuthorityMismatch);
        require!(ix.accounts[3].pubkey == config.usdc_mint, MarketError::DepositMintMismatch);
        require!(ix.accounts[5].pubkey == *expected_escrow, MarketError::DepositEscrowMismatch);
        require!(deposit_deadline_ok(deadline, now), MarketError::DepositDeadlineTooSoon);
        return Ok(());
    }
    err!(MarketError::MissingEscrowDeposit)
}

#[cfg(test)]
mod deposit_pin_tests {
    use super::*;

    #[test]
    fn deadline_floor_is_exact() {
        let now = 1_700_000_000;
        assert!(!deposit_deadline_ok(now + DEPOSIT_DEADLINE_FLOOR_SECS - 1, now));
        assert!(deposit_deadline_ok(now + DEPOSIT_DEADLINE_FLOOR_SECS, now));
        // the production service sets now + 86_400; the escrow MIN (600) is refused
        assert!(deposit_deadline_ok(now + 86_400, now));
        assert!(!deposit_deadline_ok(now + 600, now));
        assert!(!deposit_deadline_ok(i64::MIN, now));
    }
}

// ---------------------------------------------------------------------------
// Simple send (2026-09-15): reading the escrow account instead of the sysvar
// ---------------------------------------------------------------------------

/// The escrow program's `Escrow` account, as this program needs to read it.
/// Layout (blocfone-escrow, rent-vault build — frozen, and asserted by the
/// escrow's own tests): 8-byte Anchor discriminator sha256("account:Escrow")
/// then borsh: subscriber, beneficiary, authority, mint (32 each), amount u64,
/// order_id u64, deadline i64, status u8, bump u8 — 162 bytes in all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowView {
    pub subscriber: Pubkey,
    pub beneficiary: Pubkey,
    pub authority: Pubkey,
    pub mint: Pubkey,
    pub amount: u64,
    pub order_id: u64,
    pub deadline: i64,
    pub status: u8,
}

/// The escrow program's EscrowStatus::Funded (variant index 0). Pending, the
/// simple-send announcement state, is 3 — an announced-but-unpaid escrow
/// must never open an order.
pub const ESCROW_STATUS_FUNDED: u8 = 0;
pub const ESCROW_ACCOUNT_LEN: usize = 8 + 32 * 4 + 8 + 8 + 8 + 1 + 1;

fn parse_escrow(data: &[u8]) -> Option<EscrowView> {
    if data.len() < ESCROW_ACCOUNT_LEN {
        return None;
    }
    let disc: [u8; 8] = hashv(&[b"account:Escrow"]).to_bytes()[..8].try_into().ok()?;
    if data[..8] != disc {
        return None;
    }
    let pk = |o: usize| Pubkey::new_from_array(data[o..o + 32].try_into().unwrap());
    let u64at = |o: usize| u64::from_le_bytes(data[o..o + 8].try_into().unwrap());
    Some(EscrowView {
        subscriber: pk(8),
        beneficiary: pk(40),
        authority: pk(72),
        mint: pk(104),
        amount: u64at(136),
        order_id: u64at(144),
        deadline: i64::from_le_bytes(data[152..160].try_into().unwrap()),
        status: data[160],
    })
}

/// The same pins verify_paired_deposit applies to a deposit instruction,
/// applied to the escrow STATE — plus the one the sysvar path could not
/// check: the escrow is Funded, i.e. the money is in the vault right now.
fn verify_claimed_escrow(
    e: &EscrowView,
    config: &MarketConfig,
    buyer: &Pubkey,
    order_id: u64,
    price: u64,
    now: i64,
) -> Result<()> {
    let settlement_vault = Pubkey::find_program_address(&[b"settlement_vault"], &crate::ID).0;
    require!(e.status == ESCROW_STATUS_FUNDED, MarketError::EscrowNotFunded);
    require!(e.subscriber == *buyer, MarketError::DepositBuyerMismatch);
    require!(e.order_id == order_id, MarketError::DepositEscrowMismatch);
    require!(e.amount == price, MarketError::DepositAmountMismatch);
    require!(e.mint == config.usdc_mint, MarketError::DepositMintMismatch);
    require!(e.beneficiary == settlement_vault, MarketError::DepositBeneficiaryMismatch);
    require!(e.authority == config.oracle, MarketError::DepositAuthorityMismatch);
    require!(deposit_deadline_ok(e.deadline, now), MarketError::DepositDeadlineTooSoon);
    Ok(())
}

#[cfg(test)]
mod escrow_view_tests {
    use super::*;

    fn escrow_bytes(status: u8) -> (Vec<u8>, EscrowView) {
        let v = EscrowView {
            subscriber: Pubkey::new_unique(), beneficiary: Pubkey::new_unique(),
            authority: Pubkey::new_unique(), mint: Pubkey::new_unique(),
            amount: 1_600_000, order_id: 700_001, deadline: 1_700_086_400, status,
        };
        let mut d = Vec::new();
        d.extend_from_slice(&hashv(&[b"account:Escrow"]).to_bytes()[..8]);
        for pk in [&v.subscriber, &v.beneficiary, &v.authority, &v.mint] {
            d.extend_from_slice(pk.as_ref());
        }
        d.extend_from_slice(&v.amount.to_le_bytes());
        d.extend_from_slice(&v.order_id.to_le_bytes());
        d.extend_from_slice(&v.deadline.to_le_bytes());
        d.push(v.status);
        d.push(254); // bump
        (d, v)
    }

    #[test]
    fn parses_the_frozen_layout_exactly() {
        let (d, v) = escrow_bytes(0);
        assert_eq!(d.len(), ESCROW_ACCOUNT_LEN);
        assert_eq!(parse_escrow(&d), Some(v));
    }

    #[test]
    fn refuses_short_data_and_foreign_discriminators() {
        let (d, _) = escrow_bytes(0);
        assert_eq!(parse_escrow(&d[..d.len() - 1]), None);
        let mut wrong = d.clone();
        wrong[0] ^= 1;
        assert_eq!(parse_escrow(&wrong), None);
    }

    #[test]
    fn pins_every_field_and_the_funded_state() {
        let (_, v) = escrow_bytes(0);
        let config = MarketConfig {
            escrow_program: Pubkey::new_unique(), usdc_mint: v.mint, oracle: v.authority,
            rent_collector: Pubkey::new_unique(), bump: 1,
        };
        let vault = Pubkey::find_program_address(&[b"settlement_vault"], &crate::ID).0;
        let good = EscrowView { beneficiary: vault, ..v };
        let now = good.deadline - DEPOSIT_DEADLINE_FLOOR_SECS;
        let check = |e: &EscrowView| verify_claimed_escrow(e, &config, &good.subscriber, good.order_id, good.amount, now);
        assert!(check(&good).is_ok());
        assert!(check(&EscrowView { status: 3, ..good.clone() }).is_err(), "Pending must not open");
        assert!(check(&EscrowView { status: 1, ..good.clone() }).is_err(), "Released must not open");
        assert!(check(&EscrowView { amount: good.amount - 1, ..good.clone() }).is_err());
        assert!(check(&EscrowView { order_id: 1, ..good.clone() }).is_err());
        assert!(check(&EscrowView { subscriber: Pubkey::new_unique(), ..good.clone() }).is_err());
        assert!(check(&EscrowView { mint: Pubkey::new_unique(), ..good.clone() }).is_err());
        assert!(check(&EscrowView { beneficiary: Pubkey::new_unique(), ..good.clone() }).is_err());
        assert!(check(&EscrowView { authority: Pubkey::new_unique(), ..good.clone() }).is_err());
        assert!(check(&EscrowView { deadline: good.deadline - 1, ..good.clone() }).is_err());
    }
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct RegisterProvider<'info> {
    /// The provider record. `init` + fixed seeds = the duplicate-registration
    /// guard: the second attempt finds the account already owned and aborts.
    #[account(
        init,
        payer = authority,
        space = 8 + Provider::INIT_SPACE,
        seeds = [b"provider", authority.key().as_ref()],
        bump
    )]
    pub provider: Account<'info, Provider>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateProvider<'info> {
    #[account(
        mut,
        seeds = [b"provider", authority.key().as_ref()],
        bump = provider.bump,
        has_one = authority @ MarketError::AuthorityMismatch
    )]
    pub provider: Account<'info, Provider>,

    pub authority: Signer<'info>,
}

/// ADR-017 — set/rotate the batch-signing key. Authority-gated exactly as
/// the provider's other mutations are, and realloc'd to the current layout so
/// pre-ADR-017 accounts migrate on first use rather than needing a sweep.
#[derive(Accounts)]
pub struct SetProviderSigningKey<'info> {
    /// CHECK: deliberately unchecked — a pre-ADR-017 account is too short for
    /// `Account<Provider>` to load, which is the very thing this instruction
    /// exists to fix. The PDA seeds prove which account it is, the
    /// discriminator is checked in the handler before any write, and the
    /// stored authority is compared against the signer after deserialization.
    #[account(mut, seeds = [b"provider", authority.key().as_ref()], bump)]
    pub provider: UncheckedAccount<'info>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct PublishOfferBatch<'info> {
    /// CHECK: the Instructions sysvar — address-pinned; read by
    /// `verify_provider_batch_signature` to prove the runtime verified the
    /// provider's ed25519 signature over these exact batch terms (ADR-017).
    #[account(address = ix_sysvar::ID @ MarketError::BatchSignatureMissing)]
    pub instructions: UncheckedAccount<'info>,

    /// Publisher must BE a registered provider: deriving this PDA from the
    /// signing authority is the registration check — an unregistered
    /// authority has no account here and fails validation.
    #[account(
        mut,
        seeds = [b"provider", authority.key().as_ref()],
        bump = provider.bump,
        has_one = authority @ MarketError::AuthorityMismatch
    )]
    pub provider: Account<'info, Provider>,

    /// Seeded by the provider's running batch counter — every publish gets a
    /// fresh, enumerable address; identical roots may recur across batches.
    #[account(
        init,
        payer = authority,
        space = 8 + OfferBatch::INIT_SPACE,
        seeds = [
            b"offer_batch",
            provider.key().as_ref(),
            provider.batch_count.to_le_bytes().as_ref()
        ],
        bump
    )]
    pub batch: Account<'info, OfferBatch>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitConfig<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = 8 + MarketConfig::INIT_SPACE,
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, MarketConfig>,

    /// This program — used only to locate its ProgramData account.
    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @ MarketError::Unauthorized)]
    pub program: Program<'info, crate::program::BlocfoneMarket>,

    /// The upgrade-authority record. THIS is the actual gate — it tracks
    /// whatever the upgrade authority is (including a future multisig) with
    /// no constant to keep in sync.
    #[account(constraint = program_data.upgrade_authority_address == Some(authority.key()) @ MarketError::Unauthorized)]
    pub program_data: Account<'info, ProgramData>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    pub authority: Signer<'info>,

    #[account(mut, seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, MarketConfig>,

    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @ MarketError::Unauthorized)]
    pub program: Program<'info, crate::program::BlocfoneMarket>,

    #[account(constraint = program_data.upgrade_authority_address == Some(authority.key()) @ MarketError::Unauthorized)]
    pub program_data: Account<'info, ProgramData>,
}

#[derive(Accounts)]
#[instruction(order_id: u64)]
pub struct OpenOrder<'info> {
    /// The customer. Signs (consent to the purchase) but never pays rent or
    /// fees — social-login wallets hold zero SOL by design.
    pub buyer: Signer<'info>,

    /// Rent payer for the Order account: the fee sponsor in production, the
    /// test wallet on localnet. Distinct from the buyer on purpose.
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, MarketConfig>,

    pub batch: Account<'info, OfferBatch>,

    /// The batch's provider — the source of the ADR-014 split rate stamped
    /// onto the order.
    #[account(constraint = batch.provider == provider.key() @ MarketError::BatchProviderMismatch)]
    pub provider: Account<'info, Provider>,

    #[account(
        init,
        payer = payer,
        space = 8 + Order::INIT_SPACE,
        seeds = [b"order", buyer.key().as_ref(), &order_id.to_le_bytes()],
        bump
    )]
    pub order: Account<'info, Order>,

    /// CHECK: the Instructions sysvar — address-pinned; read by
    /// verify_paired_deposit to prove the escrow deposit rides this tx.
    #[account(address = ix_sysvar::ID @ MarketError::DepositMalformed)]
    pub instructions: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

/// Simple send (2026-09-15). Same shape as OpenOrder except: the buyer is
/// not a signer, and the escrow ACCOUNT replaces the Instructions sysvar.
#[derive(Accounts)]
#[instruction(order_id: u64)]
pub struct OpenClaimedOrder<'info> {
    /// CHECK: the customer's key — seeds the Order PDA and must equal the
    /// escrow's subscriber (checked in the handler). Not a signer: the buyer's
    /// act was the transfer into the vault.
    pub buyer: UncheckedAccount<'info>,

    /// The oracle: fee payer, Order rent payer, and the escrow's claimant.
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, MarketConfig>,

    pub batch: Account<'info, OfferBatch>,

    #[account(constraint = batch.provider == provider.key() @ MarketError::BatchProviderMismatch)]
    pub provider: Account<'info, Provider>,

    #[account(
        init,
        payer = payer,
        space = 8 + Order::INIT_SPACE,
        seeds = [b"order", buyer.key().as_ref(), &order_id.to_le_bytes()],
        bump
    )]
    pub order: Account<'info, Order>,

    /// CHECK: the escrow program's Escrow account for (buyer, order_id) —
    /// address, owner and every field verified in the handler (no CPI, no
    /// crate dependency on the escrow: the layout is frozen and parsed here).
    pub escrow: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

/// ADR-014: the trusted administrator (upgrade authority) sets a provider's
/// share. The provider account is passed directly — its own authority has NO
/// say here; the gate is ProgramData, same as the config instructions.
#[derive(Accounts)]
pub struct SetProviderShare<'info> {
    pub authority: Signer<'info>,

    #[account(mut)]
    pub provider: Account<'info, Provider>,

    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @ MarketError::Unauthorized)]
    pub program: Program<'info, crate::program::BlocfoneMarket>,

    #[account(constraint = program_data.upgrade_authority_address == Some(authority.key()) @ MarketError::Unauthorized)]
    pub program_data: Account<'info, ProgramData>,
}

/// A state-only lifecycle move (start_provisioning, settle, refund).
/// Only the configured oracle signs.
#[derive(Accounts)]
pub struct OracleTransition<'info> {
    #[account(address = config.oracle @ MarketError::Unauthorized)]
    pub oracle: Signer<'info>,

    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, MarketConfig>,

    #[account(mut)]
    pub order: Account<'info, Order>,
}

/// ADR-020: the delivery attestation. The oracle drives, the ORDER'S OWN
/// provider must have signed the delivery message in this transaction —
/// the provider account is pinned to order.provider, so the oracle cannot
/// substitute a friendlier signer.
#[derive(Accounts)]
pub struct AttestProvisioned<'info> {
    #[account(address = config.oracle @ MarketError::Unauthorized)]
    pub oracle: Signer<'info>,

    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, MarketConfig>,

    #[account(mut)]
    pub order: Account<'info, Order>,

    #[account(address = order.provider @ MarketError::ProviderMismatch)]
    pub provider: Account<'info, Provider>,

    /// CHECK: the instructions sysvar, pinned by address; introspected for
    /// the ed25519 precompile verification of the provider's signature.
    #[account(address = ix_sysvar::ID)]
    pub instructions: UncheckedAccount<'info>,
}

/// ADR-014 §4: the vault payout. Every destination is PINNED — in the
/// HANDLER, as require!s over fully-loaded accounts (constraint expressions
/// that reference sibling accounts across the SPL type boundary faulted in
/// generated loading code, 2026-08-18): the caller supplies accounts but
/// cannot choose where money goes:
///   provider        = order.provider (the Provider PDA)
///   provider_token  = a USDC account OWNED BY provider.payout_wallet
///   treasury_token  = a USDC account OWNED BY config.rent_collector (treasury)
///   vault_token     = the vault authority's USDC account, the ONLY source
/// The vault authority is a data-less PDA; the token program checks its
/// signature via seeds, so no key of blocfone's can move vault funds.
#[derive(Accounts)]
pub struct Payout<'info> {
    /// Anyone. Permissionless by design (ADR-014 §4).
    pub caller: Signer<'info>,

    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, MarketConfig>,

    #[account(mut)]
    pub order: Account<'info, Order>,

    pub provider: Account<'info, Provider>,

    /// CHECK: data-less PDA, the vault's token authority; validated by seeds.
    #[account(seeds = [b"settlement_vault"], bump)]
    pub vault_authority: UncheckedAccount<'info>,

    #[account(mut)]
    pub vault_token: Account<'info, TokenAccount>,

    #[account(mut)]
    pub provider_token: Account<'info, TokenAccount>,

    #[account(mut)]
    pub treasury_token: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}

/// ADR-018 §2/§3: the ONLY instruction that ever closes an Order — and only
/// after the on-chain retention window, and only while the closure policy
/// says so. The policy PDA must EXIST (absent = closure off, fail closed).
#[derive(Accounts)]
pub struct CloseOrder<'info> {
    #[account(address = config.oracle @ MarketError::Unauthorized)]
    pub oracle: Signer<'info>,

    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, MarketConfig>,

    #[account(seeds = [b"closure_policy"], bump = policy.bump)]
    pub policy: Account<'info, ClosurePolicy>,

    #[account(mut, close = rent_collector)]
    pub order: Account<'info, Order>,

    /// CHECK: receives the closed Order's rent; pinned to the configured
    /// collector, so it can never be redirected by the caller.
    #[account(mut, address = config.rent_collector @ MarketError::Unauthorized)]
    pub rent_collector: UncheckedAccount<'info>,
}

/// Upgrade-authority gated, same proof-of-authority as UpdateConfig.
#[derive(Accounts)]
pub struct SetClosurePolicy<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init_if_needed,
        payer = authority,
        space = 8 + ClosurePolicy::INIT_SPACE,
        seeds = [b"closure_policy"],
        bump
    )]
    pub policy: Account<'info, ClosurePolicy>,

    /// (2026-08-21, M2) linked to THIS program's ProgramData exactly as
    /// InitConfig/UpdateConfig are — without the link, any upgradeable
    /// program's ProgramData (and its authority) satisfied the gate.
    #[account(
        address = crate::ID,
        constraint = program.programdata_address()? == Some(program_data.key()) @ MarketError::Unauthorized
    )]
    pub program: Program<'info, crate::program::BlocfoneMarket>,

    #[account(constraint = program_data.upgrade_authority_address == Some(authority.key()) @ MarketError::Unauthorized)]
    pub program_data: Account<'info, ProgramData>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ExpireBatch<'info> {
    #[account(
        seeds = [b"provider", authority.key().as_ref()],
        bump = provider.bump,
        has_one = authority @ MarketError::AuthorityMismatch
    )]
    pub provider: Account<'info, Provider>,

    /// The batch must belong to the signing authority's provider — `has_one`
    /// stops provider A expiring provider B's batches.
    #[account(
        mut,
        has_one = provider @ MarketError::BatchProviderMismatch
    )]
    pub batch: Account<'info, OfferBatch>,

    pub authority: Signer<'info>,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// One registered supply provider (mirrors the `providers` row —
/// DATA_MODEL_PROVENANCE authority 3).
#[account]
#[derive(InitSpace)]
pub struct Provider {
    /// Who may update this record and (later) publish batches against it.
    pub authority: Pubkey,
    /// Where `settle` releases escrowed USDC (ADR-006). For PikaSIM this is
    /// the blocfone-operated fiat-bridge wallet — the recorded claim gap.
    pub payout_wallet: Pubkey,
    /// Provider stake in USDC base units. Always 0 until P2-05.
    pub stake: u64,
    pub status: ProviderStatus,
    pub registered_at: i64,
    /// Running batch counter — the seed of the NEXT OfferBatch, advanced on
    /// every publish. Doubles as "how many batches ever published".
    pub batch_count: u64,
    /// ADR-014: this provider's revenue share of each order, in basis points
    /// (8500 = 85%). Registration starts it at 0 (PikaSIM's permanent
    /// value); only the trusted administrator moves it; orders stamp it at
    /// purchase, so changes are never retroactive.
    pub provider_share_bps: u16,
    pub bump: u8,
    /// ADR-017: the provider's OFFER-SIGNING identity — the ed25519 key whose
    /// signature over a batch's Merkle root the chain verifies in
    /// `publish_offer_batch`. Distinct from `authority`, which signs the
    /// Solana TRANSACTION: blocfone relays and pays, so the transaction signer
    /// is ours while the BATCH signature is the provider's. All-zero means "no
    /// signing key registered yet", and publishing is refused.
    ///
    /// LAST FIELD, DELIBERATELY: accounts registered before ADR-017 are simply
    /// 32 bytes shorter, so growing one cannot shift a single existing field.
    /// (Placing it mid-struct silently moved `bump` and broke every seeds
    /// constraint — caught on devnet, 2026-08-11.)
    pub signing_pubkey: Pubkey,
}

/// One anchored catalogue snapshot (mirrors the `offer_batches` row). The
/// offers themselves live off-chain (ADR-002); this account holds only the
/// Merkle root that `open_order` (P1-03) verifies proofs against, and the
/// validity window that bounds when it may be used.
#[account]
#[derive(InitSpace)]
pub struct OfferBatch {
    /// The Provider PDA this batch belongs to.
    pub provider: Pubkey,
    /// Merkle root over the batch's canonical offer hashes.
    pub merkle_root: [u8; 32],
    /// First slot at which orders may open against this batch…
    pub valid_from_slot: u64,
    /// …and the last. `open_order` refuses outside [from, until].
    pub valid_until_slot: u64,
    /// Leaves under the root — lets P1-03 sanity-bound proof indices.
    pub offer_count: u32,
    pub state: BatchState,
    /// This batch's position in the provider's publish sequence (its seed).
    pub seq: u64,
    pub published_at: i64,
    pub bump: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, InitSpace)]
pub enum ProviderStatus {
    Active,
    Suspended,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, InitSpace)]
pub enum BatchState {
    Active,
    Expired,
}

/// Cluster-specific facts, set by the upgrade authority — never baked in.
#[account]
#[derive(InitSpace)]
pub struct MarketConfig {
    /// The deployed escrow program whose deposit must pair with every order.
    pub escrow_program: Pubkey,
    /// The only mint a paired deposit may carry (USDC on this cluster).
    pub usdc_mint: Pubkey,
    /// Who may drive order lifecycles (the settlement service's key).
    pub oracle: Pubkey,
    /// Where closed Orders' rent returns (close-on-settle).
    pub rent_collector: Pubkey,
    pub bump: u8,
}

/// One purchase (mirrors the mode-1 columns on the `orders` row). Created
/// already Funded — ADR-013 guarantees the deposit rides the same
/// transaction. Later lifecycle (P1-04): Provisioning → Active → Settled,
/// or Refunded.
#[account]
#[derive(InitSpace)]
pub struct Order {
    pub buyer: Pubkey,
    /// The anchored batch the offer was proven against.
    pub batch: Pubkey,
    /// The batch's provider — settlement's payee (ADR-014).
    pub provider: Pubkey,
    /// Canonical hash of the off-chain offer terms (ADR-002).
    pub offer_hash: [u8; 32],
    /// USDC base units; equals the paired deposit's amount by construction.
    pub price: u64,
    /// Shared key with the escrow: escrow PDA = f(buyer, order_id).
    pub order_id: u64,
    /// The paired escrow PDA, derived and stored for the audit walk.
    pub escrow: Pubkey,
    /// ADR-014 stamp: the split rate at purchase, and the provider's
    /// concrete amount (floor). Treasury's share = price − amount.
    pub provider_share_bps: u16,
    pub provider_share_amount: u64,
    pub state: OrderState,
    pub opened_at: i64,
    /// Off-chain trace ID (F-05 convention: derivable from / stored beside
    /// the Order PDA).
    pub trace_id: [u8; 16],
    pub bump: u8,
    // ADR-018 (appended last so every pre-existing field keeps its offset):
    /// The plan's duration — a contract term, and the retention window's
    /// on-chain input.
    pub duration_days: u16,
    /// When the order went terminal (Settled or Refunded); 0 while live.
    pub settled_at: i64,
    /// ADR-020: WHAT was delivered, sealed — the provider-signed commitment
    /// (MSISDN for numbered orders, ICCID otherwise; sha256(value‖salt)).
    /// Zero until attestation.
    pub delivery_commitment: [u8; 32],
    /// ADR-014 §4: the vault has paid this order's stamps. Once, only.
    pub paid_out: bool,
    /// Simple send (2026-09-15, owner decision): the buyer's deposit
    /// transaction signature — the order↔payment link, on the record itself
    /// for the whole retention window. Appended last (every earlier field
    /// keeps its offset); orders opened before this field exists are test
    /// orders and are not read by this build. Zeros on the legacy
    /// `open_order` path, whose deposit IS the order's own transaction.
    pub deposit_signature: [u8; 64],
}

/// ADR-018 §3: whether close_order may run at all. Its own PDA so the
/// MarketConfig layout never changes; ABSENT = closure OFF.
#[account]
#[derive(InitSpace)]
pub struct ClosurePolicy {
    pub enabled: bool,
    pub bump: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, InitSpace)]
pub enum OrderState {
    Funded,
    Provisioning,
    Active,
    Settled,
    Refunded,
    Disputed,
}

// ---------------------------------------------------------------------------
// Events — the off-chain ledger's inputs (P1-19 consumes these; the P1-04
// test double proves they balance).
// ---------------------------------------------------------------------------

#[event]
pub struct ProviderShareChanged {
    pub provider: Pubkey,
    pub old_bps: u16,
    pub new_bps: u16,
}

/// Simple send (2026-09-15): the Order's opening, with the buyer's deposit
/// transaction signature (also stamped on the Order). Only open_claimed_order
/// emits it.
#[event]
pub struct OrderOpened {
    pub order_id: u64,
    pub order: Pubkey,
    pub buyer: Pubkey,
    pub escrow: Pubkey,
    pub price: u64,
    pub deposit_signature: [u8; 64],
}

#[event]
pub struct OrderProvisioning {
    pub order_id: u64,
    pub order: Pubkey,
}

#[event]
pub struct OrderActive {
    pub order_id: u64,
    pub order: Pubkey,
    /// ADR-020: the provider-signed sealed record of WHAT was delivered.
    pub delivery_commitment: [u8; 32],
}

#[event]
pub struct OrderSettled {
    pub order_id: u64,
    pub order: Pubkey,
    pub buyer: Pubkey,
    pub provider: Pubkey,
    pub escrow: Pubkey,
    pub price: u64,
    pub provider_share_bps: u16,
    pub provider_share_amount: u64,
    pub treasury_amount: u64,
}

#[event]
pub struct OrderClosed {
    pub order_id: u64,
    pub order: Pubkey,
}

/// ADR-014 §4: the vault paid the stamps — the ledger's payout input, and
/// the public record that THIS provider wallet received THIS amount.
#[event]
pub struct OrderPaidOut {
    pub order_id: u64,
    pub order: Pubkey,
    pub provider: Pubkey,
    pub provider_wallet: Pubkey,
    pub provider_amount: u64,
    pub treasury_amount: u64,
}

#[event]
pub struct OrderRefunded {
    pub order_id: u64,
    pub order: Pubkey,
    pub buyer: Pubkey,
    pub escrow: Pubkey,
    pub price: u64,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[error_code]
pub enum MarketError {
    #[msg("Payout wallet must be a real address")]
    InvalidPayoutWallet,
    #[msg("Signer is not this provider's authority")]
    AuthorityMismatch,
    #[msg("Provider is not active")]
    ProviderNotActive,
    #[msg("Merkle root must not be all zeros")]
    InvalidMerkleRoot,
    #[msg("A batch must anchor at least one offer")]
    EmptyBatch,
    #[msg("Batch validity window is empty or already over")]
    InvalidValidityWindow,
    #[msg("Batch does not belong to this provider")]
    BatchProviderMismatch,
    #[msg("Batch is not active")]
    BatchNotActive,
    #[msg("Counter overflow")]
    CounterOverflow,
    #[msg("Signer is not the program upgrade authority")]
    Unauthorized,
    #[msg("Config addresses must be real")]
    InvalidConfig,
    #[msg("Current slot is outside the batch validity window")]
    BatchWindowClosed,
    #[msg("Offer hash must not be all zeros")]
    InvalidOfferHash,
    #[msg("Price must be positive")]
    InvalidPrice,
    #[msg("Merkle proof exceeds maximum depth")]
    ProofTooLong,
    #[msg("Plan duration must be 1-366 days")]
    InvalidDuration,
    #[msg("Delivery commitment must not be all zeros")]
    InvalidCommitment,
    #[msg("No ed25519 verification of the provider's delivery signature found in this transaction")]
    DeliverySignatureMissing,
    #[msg("The delivery signature was made by a key other than the provider's registered signing key")]
    DeliverySignatureWrongKey,
    #[msg("The provider account is not this order's provider")]
    ProviderMismatch,
    #[msg("This order's stamps have already been paid out")]
    AlreadyPaidOut,
    #[msg("Token account owner is not the required party")]
    WrongTokenOwner,
    #[msg("Token account mint is not the configured USDC")]
    WrongMint,
    #[msg("Order closure is disabled by policy")]
    ClosureDisabled,
    #[msg("The on-chain retention window has not elapsed")]
    RetentionNotElapsed,
    #[msg("Merkle proof does not connect the offer to the batch root")]
    InvalidMerkleProof,
    #[msg("No escrow deposit for this order in the transaction")]
    MissingEscrowDeposit,
    #[msg("Paired deposit amount does not equal the order price")]
    DepositAmountMismatch,
    #[msg("Paired deposit is not in the configured mint")]
    DepositMintMismatch,
    #[msg("Paired deposit subscriber is not the buyer")]
    DepositBuyerMismatch,
    #[msg("Paired deposit escrow address mismatch")]
    DepositEscrowMismatch,
    #[msg("Paired deposit instruction is malformed")]
    DepositMalformed,
    #[msg("Provider has no registered batch-signing key")]
    NoSigningKey,
    #[msg("This transaction carries no ed25519 verification of the provider's batch signature")]
    BatchSignatureMissing,
    #[msg("The verified ed25519 signature does not match this provider's registered signing key")]
    BatchSignatureWrongKey,
    #[msg("The verified ed25519 signature covers different batch terms than this instruction publishes")]
    BatchSignatureMismatch,
    #[msg("Share must be between 0 and 10000 basis points")]
    InvalidShareBps,
    #[msg("Order state does not allow this transition")]
    InvalidTransition,
    // ── security refresh 2026-08-21 (appended; earlier codes unchanged) ──
    #[msg("The paired deposit's beneficiary is not the settlement vault")]
    DepositBeneficiaryMismatch,
    #[msg("The paired deposit's authority is not the configured oracle")]
    DepositAuthorityMismatch,
    #[msg("The paired deposit's deadline is too soon — at least DEPOSIT_DEADLINE_FLOOR_SECS ahead is required")]
    DepositDeadlineTooSoon,
    #[msg("The ed25519 record must verify this instruction's own key and message (all instruction indices 0xFFFF)")]
    SignatureRecordNotSelfContained,
    #[msg("A settled order must be paid out before its record may be closed")]
    NotPaidOut,
    #[msg("Payout destination must be the owner's associated token account")]
    NotAssociatedTokenAccount,
    // ── simple send 2026-09-15 (appended; earlier codes unchanged) ──
    #[msg("The escrow for this order is not Funded — announced but unpaid, or already settled")]
    EscrowNotFunded,
}

#[cfg(test)]
mod order_layout_tests {
    use super::*;
    use anchor_lang::AnchorSerialize;

    #[test]
    fn paid_out_is_the_last_byte_and_false_when_fresh() {
        let o = Order {
            buyer: Pubkey::new_unique(), batch: Pubkey::new_unique(), provider: Pubkey::new_unique(),
            offer_hash: [9u8; 32], price: 1_600_000, order_id: 42, escrow: Pubkey::new_unique(),
            provider_share_bps: 0, provider_share_amount: 1_350_000, state: OrderState::Settled,
            opened_at: 1, trace_id: [7u8; 16], bump: 255, duration_days: 7, settled_at: 2,
            delivery_commitment: [0xd6u8; 32], paid_out: false, deposit_signature: [0xabu8; 64],
        };
        let mut bytes = Vec::new();
        o.serialize(&mut bytes).unwrap();
        // 255 through paid_out (the pre-simple-send record), then the 64-byte
        // deposit signature appended last.
        assert_eq!(bytes.len(), 319, "Order borsh length");
        assert_eq!(Order::INIT_SPACE, 319, "Order INIT_SPACE");
        assert_eq!(bytes[254], 0, "paid_out keeps its offset, false");
        assert!(bytes[255..].iter().all(|b| *b == 0xab), "deposit_signature is the last 64 bytes");
        let back = Order::try_from_slice(&bytes).unwrap();
        assert!(!back.paid_out);
        assert_eq!(back.deposit_signature, [0xabu8; 64]);
        assert!(back.state == OrderState::Settled);
    }
}
