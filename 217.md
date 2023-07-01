HALITUS

high

# When a D3MM pool repays all of the borrowed funds to vault using `D3Funding.sol repayAll`, an attacker can steal double the amount of those funds from vault

## Summary

When a D3MM pool repays all of the borrowed funds to vault using [D3Funding.sol repayAll](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Pool/D3Funding.sol#L40-L46), an attacker can steal double the amount of those funds from vault. This is because the balance of vault is not updated correctly in [D3VaultFunding.sol _poolRepayAll](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L117-L133).

`amount` should be added in `info.balance` instead of being subtracted.

```solidity
    function _poolRepayAll(address pool, address token) internal {
        .
        .
        info.totalBorrows = info.totalBorrows - amount;
        info.balance = info.balance - amount; // amount should be added here
        .
        .
    }
```

## Vulnerability Detail
A `D3MM pool` can repay all of the borrowed funds from vault using the function [D3Funding.sol repayAll](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Pool/D3Funding.sol#L40-L46) which further calls [D3VaultFunding.sol poolRepayAll](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L113) and eventually [D3VaultFunding.sol _poolRepayAll](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L117-L133).

```solidity
    function repayAll(address token) external onlyOwner nonReentrant poolOngoing {
        ID3Vault(state._D3_VAULT_).poolRepayAll(token);
        _updateReserve(token);
        require(checkSafe(), Errors.NOT_SAFE);
    }
```

The vault keeps a record of borrowed funds and its current token balance.

`_poolRepayAll()` is supposed to:
1. Decrease the borrowed funds by the repaid amount
2. Increase the token balance by the same amount #vulnerability
3. Transfer the borrowed funds from pool to vault

However, `_poolRepayAll()` is decreasing the token balance instead.

```solidity
    function _poolRepayAll(address pool, address token) internal {
        .
        .
        .
        .

        info.totalBorrows = info.totalBorrows - amount;
        info.balance = info.balance - amount; // amount should be added here

        IERC20(token).safeTransferFrom(pool, address(this), amount);

        emit PoolRepay(pool, token, amount, interests);
    }
```
Let's say a vault has 100,000 USDC
A pool borrows 20,000 USDC from vault

When the pool calls `poolRepayAll()`, the asset info in vault will change as follows:

1. `totalBorrows => 20,000 - 20,000 => 0` // info.totalBorrows - amount
2. `balance => 100,000 - 20,000 => 80,000` // info.balance - amount
3. `tokens owned by vault => 100,000 + 20,000 => 120,000 USDC` // 20,000 USDC is transferred from pool to vault (repayment)
4. The difference of recorded balance (80,000) and actual balance (120,000) is `40,000 USDC` 

**An attacker waits for the `poolRepayAll()` function call by a pool.**

When `poolRepayAll()` is executed, the attacker calls [D3VaultFunding.sol userDeposit()](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L29), which deposits 40,000 USDC in vault on behalf of the attacker.

After this, the attacker withdraws the deposited amount using [D3VaultFunding.sol userWithdraw()](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L51) and thus gains 40,000 USDC.

```solidity
    function userDeposit(address user, address token) external nonReentrant allowedToken(token) {
        .
        .
        .
        AssetInfo storage info = assetInfo[token];
        uint256 realBalance = IERC20(token).balanceOf(address(this)); // check tokens owned by vault
        uint256 amount = realBalance - info.balance; // amount = 120000-80000
        .
        .
        .
        IDToken(info.dToken).mint(user, dTokenAmount);
        info.balance = realBalance;

        emit UserDeposit(user, token, amount);
    }
```

## Impact

Loss of funds from vault. 
The loss will be equal to 2x amount of borrowed tokens that a D3MM pool repays using [D3VaultFunding.sol poolRepayAll]()

## Code Snippet

[D3VaultFunding.sol _poolRepayAll()](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L129)

```solidity
    function _poolRepayAll(address pool, address token) internal {
        .
        .
        info.totalBorrows = info.totalBorrows - amount;
        info.balance = info.balance - amount; // vulnerability: amount should be added here

        IERC20(token).safeTransferFrom(pool, address(this), amount);

        emit PoolRepay(pool, token, amount, interests);
    }
```

## Tool used

Manual Review

## Recommendation
In [D3VaultFunding.sol _poolRepayAll](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L129), do the following changes:

Current code:
`info.balance = info.balance - amount;`

New (replace '-' with '+'):
`info.balance = info.balance + amount;`