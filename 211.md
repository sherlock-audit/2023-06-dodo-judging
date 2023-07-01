lemonmon

high

# A user can get more dTokens than they should get via `D3VaultFunding.userDeposit()`, due to accounting issues in `D3VaultLiquidation.liquidate()`

## Summary

The vault token balance (`assetInfo[debt].balance`) is not updated during liquidation (`D3VaultLiquidation.liquidate()`).

Thus, a user who calls `D3VaultFunding.userDeposit()` can get more dTokens than they should get.

## Vulnerability Detail

When `D3VaultLiquidation.liquidate()` is called, the debt is transferred to the vault:

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultLiquidation.sol#L55

But `assetInfo[debt].balance` is not updated, even though the debt tokens were received.

This leads to the issue that if a user deposits this debt token right after the liquidation, they will receive more dTokens in return than they should, because `D3VaultFunding.userDeposit()` is using the wrongly tracked value of `assetInfo[debt].balance`:

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L32-L34

As a result, the protocol will mint more dTokens for the user than they should receive:

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L39-L41

## Impact

A user can call `D3VaultFunding.userDeposit()` right after a token got liquidated by `D3VaultLiquidation.liquidate()`, resulting in that the user will receive more dToken than they should receive, due to accounting issues in `D3VaultLiquidation.liquidate()`.

All LP holders will suffer from inflated dTokens.

## Code Snippet

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultLiquidation.sol#L55

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L32-L34

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L39-L41

## Tool used

Manual Review

## Recommendation

After `D3VaultLiquidation.liquidate()` is transferring the debt tokens to the vault, update the `assetInfo[debt].balance` of the vault.

If the repaid debt in `D3VaultLiquidation.liquidate()` was meant to be sent to the pool, like in the function `D3VaultLiquidation.liquidateByDODO()`, the `ID3MM(pool).updateReserveByVault(debt)` should be called at the end of `D3VaultLiquidation.liquidate()`. Otherwise a very similar problem can occur since the `state.balances[debtToken]` is not being updated. `state.balances[debtToken]` is used in a similar way in the D3Trading.sol contract to determine the actual balance received.