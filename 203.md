0x52

medium

# Protocol is completely incompatible with USDT due to lack of 0 approval

## Summary

USDT will revert if the current allowance is greater than 0 and an non-zero approval is made. There are multiple instances throughout the contracts where this causes issues. In some places this can create scenarios where it becomes impossible to liquidate and/or borrow it.

## Vulnerability Detail

See summary.

## Impact

USDT may become impossible to liquidate or borrow 

## Code Snippet

[D3Funding.sol#L20-L23](https://github.com/sherlock-audit/2023-06-dodo/blob/a8d30e611acc9762029f8756d6a5b81825faf348/new-dodo-v3/contracts/DODOV3MM/D3Pool/D3Funding.sol#L20-L23)

[D3Funding.sol#L50-L53](https://github.com/sherlock-audit/2023-06-dodo/blob/a8d30e611acc9762029f8756d6a5b81825faf348/new-dodo-v3/contracts/DODOV3MM/D3Pool/D3Funding.sol#L50-L53)

[D3Funding.sol#L64-L67](https://github.com/sherlock-audit/2023-06-dodo/blob/a8d30e611acc9762029f8756d6a5b81825faf348/new-dodo-v3/contracts/DODOV3MM/D3Pool/D3Funding.sol#L64-L67)

[D3MMLiquidationRouter.sol#L24](https://github.com/sherlock-audit/2023-06-dodo/blob/a8d30e611acc9762029f8756d6a5b81825faf348/new-dodo-v3/contracts/DODOV3MM/periphery/D3MMLiquidationRouter.sol#L24)

## Tool used

Manual Review

## Recommendation

Utilize the OZ safeERC20 library and safeApprove