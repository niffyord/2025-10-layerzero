# Security Findings

## 1. Native/ZRO Fee Allowance Check Causes Denial of Service

**Location**: `layerzero/src/endpoint/endpoint_v2.cairo`, function `_assert_messaging_fee` (lines 582-607).

**Description**: The fee validation logic requires the payer's token balance to be greater than or equal to their current allowance (`supplied_*_balance >= supplied_*_fee_allowance`). This is stricter than necessary: an allowance merely authorizes the endpoint to pull up to that amount, but the payer may keep a standing allowance that exceeds their live balance. As long as the balance covers the actual fee (`required_*_fee`), the transfer should proceed. The current check reverts whenever the allowance remains high while the balance drops below that allowance, even if the balance is still sufficient for the fee.

**Impact**: Any sender (or OApp acting on behalf of a user) that previously approved a large allowance will be unable to send messages once their balance falls below that historical allowance, despite still holding enough tokens to cover the real fee. Attackers (or even honest configuration changes in the ULN that raise expected allowances) can therefore force a denial of service until the user manually resets their allowance to match the balance. The issue impacts both the native fee path and the optional ZRO token fee path because the same predicate is applied to `supplied_native_balance` and `supplied_zro_balance`.

**Recommendation**: Update `_assert_messaging_fee` to compare balances against the required fee (e.g., `supplied_native_balance >= required_native_fee`) instead of against the allowance. The allowance comparison should remain solely between `supplied_*_fee_allowance` and `required_*_fee`.
