tsvetanovv

high

# No access control in `D3Callee()`

## Summary

The `D3Callee()` function doesn't have access control and a malicious user can exploit this

## Vulnerability Detail
In  `D3MMLiquidationRouter.sol` we have external function `D3Callee()`:
```solidity
function D3Callee(LiquidationOrder calldata order, address router, bytes calldata routeData) external {
        IERC20(order.fromToken).approve(_DODO_APPROVE_, type(uint256).max);
        (bool success, bytes memory data) = router.call(routeData);
        if (!success) {
            assembly {
                revert(add(data, 32), mload(data))
            }
        }
        IERC20(order.toToken).transfer(msg.sender, IERC20(order.toToken).balanceOf(address(this)));
    }
```

First, this function approves an unlimited amount of the `fromToken` to be spent by the `_DODO_APPROVE_` address without any checks.
After this malicious `router` address can be passed as an argument, with a contract that they control. Finally, the tokens are sent to `msg.sender`.

## Impact

Loss of funds

## Code Snippet

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/periphery/D3MMLiquidationRouter.sol#L23-L32

## Tool used

Manual Review

## Recommendation

Add access control in `D3Callee()`