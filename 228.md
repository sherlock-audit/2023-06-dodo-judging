BugBusters

high

# Potential FlashLoan attack in _getExchangeRate function

## Summary
The _getExchangeRate function  may be vulnerable to flash loan attacks due to its reliance on the totalSupply value obtained from an external contract.

## Vulnerability Detail
Flash loans enable borrowers to manipulate large amounts of funds within a single transaction. In the context of the _getExchangeRate function, if an attacker can manipulate the totalSupply value of the token in question, it can lead to incorrect exchange rate calculations and potentially disrupt the intended functionality of the smart contract.

## Impact
If an attacker successfully manipulates the totalSupply value through a flash loan attack, it can result in inaccurate exchange rate calculations. This can have various consequences, such as incorrect interest calculations, liquidity imbalances, or mispricings, which may adversely impact the stability and reliability of the smart contract.

## Code Snippet
https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L230-L236

## Tool used

Manual Review

## Recommendation
