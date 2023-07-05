PRAISE

high

# D3Proxy.withdrawWETH() can be used to steal WETH balance of D3Proxy.sol

## Summary
D3Proxy.withdrawWETH() is external and therefore callable by anyone
## Vulnerability Detail
D3Proxy.withdrawWETH() does a transfer to `to` address with the ETH balance of D3Proxy.sol
```solidity
 function withdrawWETH(address to, uint256 minAmount) external payable {
        uint256 withdrawAmount = IWETH(_WETH_).balanceOf(address(this));
        require(withdrawAmount >= minAmount, "D3PROXY_WETH_NOT_ENOUGH");

        _withdrawWETH(to, withdrawAmount);
    }

```

## Impact
The WETH balance of D3Proxy.sol can be emptied by anyone via D3Proxy.withdrawWETH() even though the funds doesn't belong to them.


## Code Snippet
https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/periphery/D3Proxy.sol#L198

## Tool used

Manual Review

## Recommendation
create a check to ensure only depositors of WETH in D3Proxy.sol can withdraw the right amount of WETH they deposited.




