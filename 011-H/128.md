Oxhunter526

high

# Title: Insufficient Liquidity Handling in `D3VaultFunding` Contract

## Summary
The `D3VaultFunding` contract lacks explicit handling or prevention mechanisms for situations where the liquidity in the vault becomes insufficient to meet borrowing or repayment demands. This oversight poses security risks and financial vulnerabilities.
## Vulnerability Detail
The contract does not have safeguards in place to manage liquidity adequately. Multiple borrowing requests can lead to insufficient liquidity in the vault. This can result in partial or failed borrowings, inconsistent state, and potential systemic risks.
## Impact
1. Insufficient liquidity may lead to partial or failed borrowing operations, affecting the protocol's functioning and potentially causing financial losses for market-making pools or users.
2. Inconsistent state within the protocol can result from incomplete or failed transactions, leading to data inconsistencies and incorrect accounting of funds.
3. The lack of liquidity management mechanisms increases systemic risks, compromising the stability and reliability of the protocol.
## Code Snippet
The `poolBorrow` function allows market-making pools to borrow funds from the vault. While the function includes checks for borrowing quotas and token balances, it does not have explicit checks or mechanisms to prevent borrowing amounts from exceeding the available liquidity in the vault.
Insufficient liquidity can occur when multiple borrowing requests are made, surpassing the available funds in the vault.
[Link](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L70-L92)
```solidity
    function poolBorrow(address token, uint256 amount) external nonReentrant allowedToken(token) onlyPool {
        uint256 quota = ID3PoolQuota(_POOL_QUOTA_).getPoolQuota(msg.sender, token);
        accrueInterest(token);

        AssetInfo storage info = assetInfo[token];
        BorrowRecord storage record = info.borrowRecord[msg.sender];
        uint256 oldInterestIndex = record.interestIndex;
        uint256 currentInterestIndex = info.borrowIndex;
        if (oldInterestIndex == 0) oldInterestIndex = 1e18;
        uint256 usedQuota = record.amount.div(oldInterestIndex).mul(currentInterestIndex);
        require(amount + usedQuota <= quota, Errors.EXCEED_QUOTA);
        require(amount <= info.balance, Errors.AMOUNT_EXCEED_VAULT_BALANCE);

        uint256 interests = usedQuota - record.amount;

        record.amount = usedQuota + amount;
        record.interestIndex = currentInterestIndex;
        info.totalBorrows = info.totalBorrows + amount;
        info.balance = info.balance - amount; 
        IERC20(token).safeTransfer(msg.sender, amount);

        emit PoolBorrow(msg.sender, token, amount, interests);
    }
```
The `poolRepay` and `poolRepayAll` functions handle the repayment of borrowed funds. These functions do not explicitly check or enforce the availability of sufficient liquidity in the vault to handle all repayment demands.
If the liquidity in the vault is insufficient to fulfill all repayment requests, it can lead to incomplete or failed repayment transactions.
[Link](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L94-L133)
```solidity
 function poolRepay(address token, uint256 amount) external nonReentrant allowedToken(token) onlyPool {
        accrueInterest(token);

        AssetInfo storage info = assetInfo[token];
        BorrowRecord storage record = info.borrowRecord[msg.sender];
        uint256 borrows = record.amount.div(record.interestIndex == 0 ? 1e18 : record.interestIndex).mul(info.borrowIndex);
        require(amount <= borrows, Errors.AMOUNT_EXCEED);

        uint256 interests = borrows - record.amount;

        record.amount = borrows - amount;
        record.interestIndex = info.borrowIndex;
        info.totalBorrows = info.totalBorrows - amount;
        info.balance = info.balance + amount;
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        emit PoolRepay(msg.sender, token, amount, interests);
    }

    function poolRepayAll(address token) external nonReentrant allowedToken(token) onlyPool {
        _poolRepayAll(msg.sender, token);
    }

    function _poolRepayAll(address pool, address token) internal {
        accrueInterest(token);

        AssetInfo storage info = assetInfo[token];
        BorrowRecord storage record = info.borrowRecord[pool];
        uint256 amount = record.amount.div(record.interestIndex == 0 ? 1e18 : record.interestIndex).mul(info.borrowIndex);

        uint256 interests = amount;

        record.amount = 0;
        record.interestIndex = info.borrowIndex;
        info.totalBorrows = info.totalBorrows - amount;
        info.balance = info.balance - amount;
        IERC20(token).safeTransferFrom(pool, address(this), amount);

        emit PoolRepay(pool, token, amount, interests);
    }
```
The contract lacks explicit mechanisms for monitoring and managing liquidity within the vault.
There are no safeguards or circuit breakers to prevent over-borrowing or to handle situations where liquidity falls below acceptable levels.
The absence of these liquidity management mechanisms can contribute to situations where the available liquidity becomes insufficient to meet borrowing or repayment demands.
## Tool used

Manual Review

## Recommendation
1. Implement explicit liquidity management mechanisms to prevent or handle situations of insufficient liquidity.
2. Monitor liquidity levels and set borrowing limits based on available liquidity to ensure the contract can meet borrowing demands.
3. Consider implementing circuit breakers or safeguards to prevent over-borrowing and protect against liquidity shortfalls.