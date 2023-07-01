twcctop

high

# Pool Repayment Allowed During Liquidation Process


## Summary
During the DODO team liquidation process, the pool is able to repay even when it is in a state of liquidation. The `D3VaultFunding#poolRepay` function does not include a check to verify if the pool is currently in liquidation. This poses a risk because there are two steps involved in the liquidation process, and if the pool repays during the gap between the `startLiquidation` and `finishLiquidation` steps, it will still be liquidated.

## Vulnerability Detail
The vulnerability lies in the `D3VaultFunding#poolRepay` function. This function allows the pool to repay a specified amount of tokens. However, it lacks a validation step to ensure that the pool is not in the process of liquidation.

## Impact
The impact of this vulnerability is that a pool can repay tokens even when it is undergoing liquidation. This behavior is not intended and can lead to undesired consequences. If the pool repays during the liquidation process, it will still be liquidated, which can have adverse effects on the system's stability and integrity.

## Code Snippet
https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultLiquidation.sol#L117-L152 
https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultLiquidation.sol#L65-L85
https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L94

```solidity
function poolRepay(address token, uint256 amount) external nonReentrant allowedToken(token) onlyPool {
  // Repayment logic
  ...
}

function startLiquidation(address pool) external onlyLiquidator nonReentrant { 
...
}
function finishLiquidation(address pool) external onlyLiquidator nonReentrant { 
...
}
```

## Tool used
Manual Review

## Recommendation
To address this vulnerability, it is recommended to add a check in the `D3VaultFunding#poolRepay` function to verify if the pool is currently in the process of liquidation. If the pool is in liquidation, the function should reject the repayment request. This will ensure that pools can only repay when they are not undergoing liquidation, preventing undesired liquidation scenarios.