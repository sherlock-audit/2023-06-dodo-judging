BugHunter101

medium

# `D3VaultFunding.userWithdraw()` doen not have mindTokenAmount

## Summary

`D3VaultFunding.userWithdraw()` doen not have mindTokenAmount, and use `_getExchangeRate` directly.This is vulnerable to a sandwich attack.

## Vulnerability Detail

As we can see, `D3VaultFunding.userWithdraw()` doen not have mindTokenAmount, and use `_getExchangeRate` directly.
```solidity
function userWithdraw(address to, address user, address token, uint256 dTokenAmount) external nonReentrant allowedToken(token) returns(uint256 amount) {
        accrueInterest(token);
        AssetInfo storage info = assetInfo[token];
        require(dTokenAmount <= IDToken(info.dToken).balanceOf(msg.sender), Errors.DTOKEN_BALANCE_NOT_ENOUGH);

        amount = dTokenAmount.mul(_getExchangeRate(token));//@audit does not check amount value
        IDToken(info.dToken).burn(msg.sender, dTokenAmount);
        IERC20(token).safeTransfer(to, amount);
        info.balance = info.balance - amount;

        // used for calculate user withdraw amount
        // this function could be called from d3Proxy, so we need "user" param
        // In the meantime, some users may hope to use this function directly,
        // to prevent these users fill "user" param with wrong addresses,
        // we use "msg.sender" param to check.
        emit UserWithdraw(msg.sender, user, token, amount);
    }
```

 And the `_getExchangeRate()` result is about `cash `, `info.totalBorrows`, `info.totalReserves`,`info.withdrawnReserves`,`dTokenSupply`,This is vulnerable to a sandwich attack leading to huge slippage
```solidity
function _getExchangeRate(address token) internal view returns (uint256) {
        AssetInfo storage info = assetInfo[token];
        uint256 cash = getCash(token);
        uint256 dTokenSupply = IERC20(info.dToken).totalSupply();
        if (dTokenSupply == 0) { return 1e18; }
        return (cash + info.totalBorrows - (info.totalReserves - info.withdrawnReserves)).div(dTokenSupply);
    } 
```

## Impact

This is vulnerable to a sandwich attack.

## Code Snippet

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L56

## Tool used

Manual Review

## Recommendation

Add `mindTokenAmount` parameter for `userWithdraw()` function and check if `amount < mindTokenAmount`