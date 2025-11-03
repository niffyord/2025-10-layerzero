# LayerZero Starknet Threat Model

## Overview and Scope
This document captures a first-pass threat model for the LayerZero V2 Starknet implementation contained in this repository. The analysis focuses on the components that are in the formal audit scope:

- `layerzero/src/endpoint/**` — EndpointV2 core router and helper components.
- `layerzero/src/message_lib/uln_302/**` — UltraLightNode message library responsible for verification and fee accounting.
- `layerzero/src/workers/dvn/**` — Decentralized Verifier Network worker contract and fee logic.
- `libs/multisig/src/**` — Shared multisig primitive relied on by DVN administration.
- `libs/enumerable_set/src/**` — Library that powers role/account set bookkeeping across the protocol.

The threat model also considers how these scoped contracts integrate with other LayerZero modules (treasury, executors, OApps, mocks) because misbehavior at their interfaces can affect security-critical invariants even if the supporting components are not formally in scope.

## Security Objectives
The primary security objectives, extracted from the documentation and code comments, are:

1. **Immutability of core routing logic.** EndpointV2 and UltraLightNode contracts must not be upgradable, preventing unilateral tampering with message validation rules.
2. **Censorship resistance.** Endpoint owners must be unable to block, reorder, or permanently delay valid user messages under correct configuration.
3. **Integrity of message delivery.** Only packets that were emitted on a source chain and validated by the configured DVNs should be executed on the destination.
4. **Config isolation.** Only OApp delegates may configure their per-application settings; global administrators must not be able to hijack application-level state.
5. **Economic correctness.** Fees collected from users must be routed to the correct workers and treasury accounts, with no loss or theft of funds.
6. **Role accountability.** DVN multisigs and administrators should not be able to escalate privileges or bypass signature thresholds without explicit consensus.

## System Architecture Summary
LayerZero Starknet retains the canonical four-step flow from the EVM implementation:

1. **Send (Source chain).** An OApp calls `EndpointV2.send` with payload, path, and fee instructions. Endpoint forwards fee receipts to the configured `MessageLib` (typically ULN302), which computes worker payments and emits a `PacketSent` event that off-chain relayers observe.
2. **Verify (Destination chain).** DVN members observe packets and submit validation signatures to ULN302 via `verify`. ULN tracks confirmations per packet and enforces security parameters (e.g., quorum).
3. **Commit.** Once verification thresholds are met, a permissionless actor calls ULN302 to commit the payload hash to EndpointV2, binding the packet to the destination state.
4. **Execute.** Executors (or any actor) call `EndpointV2.lz_receive` to deliver the message to the destination OApp. Optional compose flows can enqueue sub-messages routed through the composer component.

Trust boundaries exist between contracts owned by LayerZero (Endpoint, Treasury), per-application delegates (OApps), and independent workers (DVNs, Executors). Off-chain agents (DVN signers, Executors) bridge cross-chain data and must coordinate with on-chain contracts while respecting signature and fee rules.

## Assets and Trust Boundaries

| Asset / Boundary | Description | Threats |
| --- | --- | --- |
| **Endpoint Storage** | Nonces, payload hashes, per-OApp configuration, fee balances. | Unauthorized mutation, replay attacks, DoS through nonce desynchronization. |
| **ULN Verification Records** | Per-packet confirmation counts and commit statuses. | Forged confirmations, premature commitments, stale replay. |
| **DVN Admin Keys** | Multisig-managed keys controlling worker configuration. | Key compromise, signature malleability, privilege escalation. |
| **Treasury and Worker Fee Balances** | ERC20 allowances held on behalf of workers and treasury. | Theft via incorrect accounting, blocked refunds, draining allowances. |
| **OApp Delegated Configurations** | Per application send/receive library config and timeouts. | Hijacking by unauthorized roles, misconfiguration leading to DoS. |
| **Role Enumerations** | Sets of authorized signers stored via enumerable set library. | Set corruption, inconsistent iteration allowing bypass of threshold checks. |
| **Event Feeds** | Off-chain data (PacketSent, DvnFeesPaid) consumed by relayers. | Event suppression, conflicting events causing confusion or replay. |

Boundary transitions include calls from OApps into Endpoint, from ULN into Endpoint, from DVNs into ULN, and from off-chain executors into Endpoint. Each boundary must ensure authenticity, authorization, and replay protection.

## Attacker Profiles and Assumptions

- **Malicious External User:** Can deploy arbitrary OApps, craft calls with any calldata, and manipulate ERC20 allowances. Goal: steal funds, execute unauthorized packets, or DoS the protocol.
- **Compromised OApp Delegate:** Holds delegate role for a particular OApp. Goal: escalate privileges, manipulate cross-chain messages of other OApps.
- **Compromised DVN Signer:** Holds one or more DVN signing keys but not the full multisig threshold. Goal: forge verification data or subvert admin actions.
- **Compromised DVN Admin Multisig:** Full control of DVN admin multisig. Goal: drain fees, disable verification, or change security parameters. Assumed to require multiple colluding parties but still in threat space.
- **Endpoint Owner Misuse:** LayerZero-controlled owner key accidentally or maliciously invoked. System objective is to limit damage (e.g., owner cannot censor messages).
- **Off-chain Relayer / Executor:** Observes events and triggers commitments/executions. Could attempt to grief by withholding participation or flooding transactions.

Assumptions used by the protocol:

- Starknet L1 provides integrity of contract code and storage, and transactions eventually finalize.
- ERC20 tokens used for fees conform to expected allowance semantics.
- Off-chain DVN members correctly sign packets they believe valid; signature thresholds are set to withstand a minority of faulty signers.
- Alexandria and starknet core libraries work correctly (explicitly out-of-scope but relied upon).

## Detailed Threat Analysis

### EndpointV2 Components

1. **Messaging Channel (nonce tracking).**
   - *Threats:* Replay or skip misuse leading to message loss; unauthorized increment of inbound nonce enabling packet skipping; stale nonce causing DoS.
   - *Mitigations to verify:* Nonce increments gated to authorized caller (Endpoint or message lib); skip/burn/nillify restricted to OApp delegate and require current payload hash.

2. **Message Lib Manager.**
   - *Threats:* Unauthorized library reassignment leading to downgrade attack; inconsistent send vs receive libraries causing funds to be locked; default library hijack by owner.
   - *Mitigations:* Delegated configuration per OApp with `onlyDelegate`/`onlyEndpointOwner` guards; storage separation for send/receive libs. Need to confirm owner cannot override delegate-specific settings unexpectedly.

3. **Messaging Composer.**
   - *Threats:* Compose replay or spoofing, leading to unauthorized downstream calls; message hash collision enabling unauthorized `lz_compose` execution.
   - *Mitigations:* Hash binding to GUID/index; composer enforces sequential receipt and uses stored hash for replay protection.

4. **Fee Handling.**
   - *Threats:* Underflow/overflow in fee accounting due to ERC20 behavior; refunds not executed allowing fund loss; malicious OApp providing insufficient allowance leading to partial payments.
   - *Mitigations:* Endpoint calculates allowances before forwarding; ensures leftover funds returned to payer. Confirm safe math or invariants in Cairo code.

5. **Access Control (Ownable, Delegates).**
   - *Threats:* Delegate creation without proper authorization; inability to revoke delegates leading to stuck configs.
   - *Mitigations:* Ownable component ensures only owner can assign default libs; per-OApp delegate tracked; rate-limiter optionally prevents abuse.

### UltraLightNode 302 Message Library

1. **Verification Pipeline.**
   - *Threats:* Acceptance of forged DVN signatures; counting same signer multiple times; missing replay protection.
   - *Mitigations:* Use of `EnumerableSet` for signer tracking; verification struct ensures `submitted` flag prevents replay; signature validation through DVN interface. Need to audit signature parsing and ensure domain separation (chain IDs, channel IDs).

2. **Fee Receipts.**
   - *Threats:* Incorrect fee distribution allowing DVN/executor underpayment; malicious DVN to set zero fee causing workers to stop; integer truncation in fee splits.
   - *Mitigations:* Fee library provides deterministic quoting; receipts returned to Endpoint for transfer.

3. **Config Storage.**
   - *Threats:* Config upgrade by unauthorized party; stale config causing security downgrade.
   - *Mitigations:* Config setters restricted to ULN owner/admin; storage layout uses prefixed names to avoid collisions during upgrades.

4. **Commit Interface.**
   - *Threats:* Commit called before threshold; missing check of ULN state when Endpoint fetches payload hash; commit reentrancy.
   - *Mitigations:* Commit ensures required confirmations; Endpoint reads payload hash only once per commit; reentrancy guard present on Endpoint.

### DVN Worker Contracts

1. **Multisig Governance.**
   - *Threats:* Signature replay for admin actions; ability for admin to escalate privileges without threshold; message forging.
   - *Mitigations:* Uses libs/multisig to enforce nonce-based replay protection and threshold verification; actions encoded with domain-specific data.

2. **Fee Library.**
   - *Threats:* Undercharging enabling DoS by requiring DVN to subsidize; misconfiguration allowing price feed injection.
   - *Mitigations:* Only DVN admin sets fee parameters; input validation required.

3. **Upgradeability.**
   - *Threats:* Storage collision on upgrade leading to privilege reset or funds loss; malicious upgrade to bypass checks.
   - *Mitigations:* Explicit storage naming; upgrade gated by multisig; Endpoint interacts with DVN via stable interface.

### Shared Libraries

1. **`libs/multisig`.**
   - *Threats:* Incorrect signature verification; ability to reuse signature across domains; lack of nonce separation allowing cross-call replay.
   - *Mitigations:* Domain separators should include contract address and action type; ensure hashed message includes nonce and expiry.

2. **`libs/enumerable_set`.**
   - *Threats:* Set operations failing to remove entries leading to stale authorizations; iteration order assumptions exploited.
   - *Mitigations:* Contract uses `contains` before removal; rely on library correctness.

## Threat Matrix (STRIDE Perspective)

| Component | Spoofing | Tampering | Repudiation | Information Disclosure | Denial of Service | Elevation of Privilege |
| --- | --- | --- | --- | --- | --- | --- |
| Endpoint send/receive | Malicious OApp spoofing another path via forged `path` | Payload hash overwrite | Lack of event logs for certain operations | Config leakage minimal, but OApp settings on-chain public | Flood send to exhaust storage or gas | Delegate misconfig to override libs |
| ULN verify/commit | Fake DVN signatures | Modify verification struct | DVN signers deny signing | Config reveals security params (public) | Commit withheld to stall | ULN owner using admin to reduce threshold |
| DVN admin | Spoofed multisig call without quorum | Modify fee config | Signers deny action | Admin calldata includes parameters publicly known | Spam actions to block queue | Upgrade contract to bypass checks |
| Multisig lib | Forged signature due to missing domain | Alter internal storage | Dispute over which actions executed | Logs show actions | Gas grief | Accept arbitrary signer |

## Recommended Focus Areas

1. **Signature Validation and Domain Separation.** Ensure all signature verifications (DVN admin actions, ULN verification) include chain-specific domains, nonces, and class hashes to avoid replay across contracts or chains.
2. **Nonce and Payload Hash Management.** Examine `MessagingChannel` and `ULN` handling of inbound/outbound nonces to ensure no gaps allow replay or message loss, especially around skip/burn/nillify flows.
3. **Fee Accounting Accuracy.** Audit ERC20 allowance usage, refunds, and fee receipt handling to prevent fund loss or stuck balances.
4. **Upgrade Safety for Workers.** Confirm storage naming conventions prevent slot clashes. Validate upgrade functions cannot be invoked by untrusted actors.
5. **Permission Boundaries.** Review how Endpoint owner vs delegate permissions are enforced to ensure censorship resistance objective is met.
6. **Composable Flows.** Inspect composer hash binding and authorization to prevent unauthorized `lz_compose` execution or value transfer.
7. **Enumerable Set Reliance.** Validate library cannot be manipulated to cause incorrect membership results, as multiple modules depend on accurate signer tracking.

## Residual Risks and Open Questions

- Reliance on out-of-scope Alexandria/Bytes libraries introduces upstream risk; confirm versions used do not contain undisclosed vulnerabilities beyond known keccak issue.
- Event-based off-chain relays remain a point of censorship if executors/dvns refuse to participate; consider incentives and redundancy.
- Treasury fee logic and LZ token integration (currently disabled) should be re-reviewed when enabled, as it introduces new trust boundaries.

## References
- `README.md` and `layerzero/README.md` for architecture and invariants.
- Scoped contract directories for detailed implementation.

