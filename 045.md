PRAISE

medium

# possible precision loss in D3VaultLiquidation.finishLiquidation() function when calculating realDebt because of division before multiplication

## Summary
finishLiquidation() divides before multiplying when calculating realDebt.

## Vulnerability Detail
```solidity 
uint256 realDebt = borrows.div(record.interestIndex == 0 ? 1e18 : record.interestIndex).mul(info.borrowIndex);
```

There will be precision loss when calculating the realDebt because solidity truncates values when dividing and dividing before multiplying causes precision loss.

Values that suffered from precision loss will be updated here
```solidity
 info.totalBorrows = info.totalBorrows - realDebt;
```
## Impact
Values that suffered from precision loss will be updated here
```solidity
 info.totalBorrows = info.totalBorrows - realDebt;
```
## Code Snippet
https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultLiquidation.sol#L144

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultLiquidation.sol#L147
## Tool used

Manual Review

## Recommendation
don't divide before multiplying 