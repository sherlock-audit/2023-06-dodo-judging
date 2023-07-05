Oxhunter526

high

# Title: Missing Pre-Liquidation Verifications in `startLiquidation` Function

## Summary
The `startLiquidation` function in the contract does not include all the necessary checks that are present in the `liquidate` function. This omission raises security concerns as it allows the initiation of the liquidation process without verifying bad debt after interest accrual and without ensuring the positive net worth of collateral tokens and the negative net worth of debt tokens.
## Vulnerability Detail
The `startLiquidation` function initiates the liquidation process without conducting all the relevant validations, including checks for bad debt, positive net worth collateral tokens, and negative net worth debt tokens. This omission can potentially lead to unwarranted or premature liquidation actions and may result in imbalanced or unfair outcomes.
## Impact
1. False Liquidation: Initiating the liquidation process without validating bad debt may lead to false liquidations, causing unnecessary disruptions and potential losses for the pool.
2. Unbalanced Liquidation: By ignoring checks for positive net worth collateral tokens and negative net worth debt tokens, the function may allow liquidation to proceed even when the pool does not meet the necessary criteria. This can result in imbalanced liquidation actions and unfair distribution of assets.
## Code Snippet
[Link](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultLiquidation.sol#L30-L85)
## Proof of Concept (PoC):
In this Proof of Concept, we will demonstrate the security concern related to the incomplete validation checks in the startLiquidation function. The PoC assumes a scenario where the function is vulnerable to premature or unjustified liquidation initiation.
1. Preconditions
- The contract is deployed and the `startLiquidation` function is accessible.
- The pool selected for liquidation is not currently in a liquidation state.
2. Steps to Exploit the Vulnerability:
a. Manipulating the Pool State:
- As an attacker, gain control over the targeted pool's state, such as modifying its debt or collateral values.
- Ensure that the pool does not meet the necessary criteria for liquidation, such as having negative net worth debt tokens.
b. Calling the `startLiquidation` Function:
- Initiate the `startLiquidation` function by providing the address of the manipulated pool.
- Observe that the function proceeds with the liquidation process without detecting the manipulated state.
3. Impacts
- The premature or unjustified liquidation may result in the inappropriate redistribution of assets, leading to financial losses for the pool participants.
- The lack of comprehensive validation increases the risk of false liquidations and imbalanced asset distributions.
## Tool used

Manual Review

## Recommendation
To address this security concern, it is recommended to enhance the `startLiquidation` function with comprehensive validations that mirror the checks performed in the `liquidate` function. This includes validating bad debt after interest accrual and ensuring the positive net worth of collateral tokens and the negative net worth of debt tokens. By incorporating these checks, the function will be better equipped to prevent false or unbalanced liquidations and maintain the integrity of the system.
