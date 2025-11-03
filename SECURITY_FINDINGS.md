# Security Findings

## 1. Native/ZRO Fee Allowance Check Causes Denial of Service

**Location**: `layerzero/src/endpoint/endpoint_v2.cairo`, function `_assert_messaging_fee` (lines 582-607).

**Description**: The fee validation logic requires the payer's token balance to be greater than or equal to their current allowance (`supplied_*_balance >= supplied_*_fee_allowance`). This is stricter than necessary: an allowance merely authorizes the endpoint to pull up to that amount, but the payer may keep a standing allowance that exceeds their live balance. As long as the balance covers the actual fee (`required_*_fee`), the transfer should proceed. The current check reverts whenever the allowance remains high while the balance drops below that allowance, even if the balance is still sufficient for the fee.

**Impact**: Any sender (or OApp acting on behalf of a user) that previously approved a large allowance will be unable to send messages once their balance falls below that historical allowance, despite still holding enough tokens to cover the real fee. Attackers (or even honest configuration changes in the ULN that raise expected allowances) can therefore force a denial of service until the user manually resets their allowance to match the balance. The issue impacts both the native fee path and the optional ZRO token fee path because the same predicate is applied to `supplied_native_balance` and `supplied_zro_balance`.

**Recommendation**: Update `_assert_messaging_fee` to compare balances against the required fee (e.g., `supplied_native_balance >= required_native_fee`) instead of against the allowance. The allowance comparison should remain solely between `supplied_*_fee_allowance` and `required_*_fee`.

## 2. Delegates Can Permanently Block Future Messages by Skipping Before Verification

**Location**: `layerzero/src/endpoint/messaging_channel/messaging_channel.cairo`, functions `skip` (lines 126-141) and `inbound_nonce` (lines 81-95); `layerzero/src/endpoint/endpoint_v2.cairo`, function `_committable` (lines 551-560) used by `commit` (lines 240-278).

**Description**: The `skip` helper only asserts that the provided nonce equals the current inbound nonce plus one before writing that value into `lazy_inbound_nonce`. The inbound nonce calculation simply returns the last lazy checkpoint unless a payload hash has been stored for consecutive nonces. As a result, an authorized OApp delegate can call `skip` for the next expected nonce even before the corresponding payload hash has been committed. Once `lazy_inbound_nonce` is advanced to that nonce, `_committable` rejects future commit attempts for the same message because the nonce is no longer greater than the lazy checkpoint and no payload hash exists yet. The legitimate packet can never be committed, leaving the channel permanently desynchronized for that path.

**Impact**: Any compromised or malicious delegate (or OApp contract itself) can irreversibly brick an inbound messaging path by front-running the ULN commit with a `skip` call. This violates the protocol’s censorship-resistance objective by allowing an authorized-but-untrusted role to permanently suppress otherwise valid packets without providing the stored payload hash.

**Recommendation**: Require `skip` to observe a stored payload hash before advancing the lazy nonce—e.g., assert that `_has_payload_hash(receiver, src_eid, sender, nonce)` is true (and optionally clear it) or restrict skipping to nonces strictly below the most recently committed value. Alternatively, move the lazy nonce update logic into `commit`/`clear` so that a skip cannot occur before verification.

## 3. DVN Signature Digest Lacks Domain Separation Across Deployments

**Location**: `layerzero/src/workers/dvn/dvn.cairo`, function `hash_call_data` (lines 283-298) invoked by both `execute` (lines 167-207) and `quorum_change_admin` (lines 211-249).

**Description**: The multisig digest for DVN administrative actions hashes only the tuple `(vid, call_data.to, expiration, selector, calldata)`. It omits any binding to the DVN contract’s own address, class hash, or chain-specific domain. If two DVN instances share the same verifier ID and signer set—a realistic configuration for multi-chain deployments—any signatures collected for one instance can be replayed on the other so long as the target call data matches. Because `_verify_n_signatures` does not distinguish which DVN generated the digest, the receiving contract cannot tell whether the signatures were intended for a different deployment.

**Impact**: Cross-environment replay becomes possible whenever multiple DVNs reuse the same multisig quorum. An attacker who obtains legitimate signatures for DVN A (e.g., to call `execute` or `quorum_change_admin`) can relay the identical calldata to DVN B and satisfy its signature check, even if B’s administrators never authorized that action. This breaks the intended security boundary between DVN deployments and can be used to escalate privileges or mutate configuration on the unintended instance.

**Recommendation**: Incorporate an unambiguous domain separator into the digest—such as hashing the DVN contract address, Starknet chain ID, and a fixed type string alongside the existing fields—before verifying signatures. All off-chain signers must update to sign the new domain-aware hash.

## 4. Compose Replay Possible When Message Hash Equals Sentinel Value

**Location**: `layerzero/src/endpoint/messaging_composer/messaging_composer.cairo`, constant `RECEIVED_MESSAGE_HASH` (lines 52-55) and `lz_compose` (lines 123-166).

**Description**: Delivered compose entries are marked with the sentinel `RECEIVED_MESSAGE_HASH = 0x1`. Because this sentinel is a legitimate Keccak-256 output, an attacker who can find a compose payload whose hash equals `0x1` will satisfy the queue check and, after the first delivery, leave the entry indistinguishable from the “already delivered” marker. Subsequent `lz_compose` calls with the same payload will continue to pass the equality check (`expected_hash == actual_hash`) and succeed indefinitely because the stored value remains `0x1`.

**Impact**: Although preimage-searching for a specific Keccak-256 value is computationally expensive, the design provides no cryptographic guarantee against it. A determined attacker (or future quantum adversary) could construct such a payload to trigger unlimited, unauthorized compose executions—including repeated token transfers if `value > 0`—even after the queue should be closed.

**Recommendation**: Replace the hash-based sentinel with explicit state, such as a parallel boolean flag or a sentinel value outside the Keccak image (e.g., store `Option<Bytes32>` and use `None` for “delivered”). This ensures that the stored marker cannot collide with a valid message hash.
