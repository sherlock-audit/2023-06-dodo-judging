tsvetanovv

high

# A malicious user can front-run  `refundETH()`

## Summary
A malicious user can front-run  `refundETH()` in `D3Proxy.sol`

## Vulnerability Detail
```solidity
/// @dev when fromToken = ETH and call buyTokens, call this function to refund user's eth
function refundETH() external payable { 
        if (address(this).balance > 0) {
            _safeTransferETH(msg.sender, address(this).balance);
        }
    }
```

The above function refund Ether to the user who invokes this function.
A malicious user can watch the menpool and fron-run honest user and steal his ETH.

The implementation of the `refundETH()` and `withdrawWETH` functions itself is not good. Any user can wait for some balance to appear in the contract and immediately steal it.

## Impact

Users can lose funds

## Code Snippet

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/periphery/D3Proxy.sol#L188-L203

## Tool used

Manual Review

## Recommendation

Add some kind of access control or track if a user needs some ETH refund