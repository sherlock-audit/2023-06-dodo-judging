MohammedRizwan

high

# Wrong use of access control modifier on D3Funding.makerWithdraw() function

## Summary
Wrong use of access control modifier on D3Funding.makerWithdraw() function

## Vulnerability Detail
## Impact

In D3Funding.sol contract,

```Solidity
File: contracts/DODOV3MM/D3Pool/D3Funding.sol

73    function makerWithdraw(address to, address token, uint256 amount) external onlyOwner nonReentrant poolOngoing {
74        IERC20(token).safeTransfer(to, amount);
75
76        _updateReserve(token);
77        require(checkSafe(), Errors.NOT_SAFE);
78        require(checkBorrowSafe(), Errors.NOT_BORROW_SAFE);
79
80        emit MakerWithdraw(to, token, amount);
81    }
```

As seen above at L-73, makerWithdraw() function has used onlyOwner modifier which is wrong use of access control as per NatSpec comment. The comment says "....only maker could withdraw."

```Solidity

57    /// @notice maker deposit, anyone could deposit but only maker could withdraw
58    function makerDeposit(address token) external nonReentrant poolOngoing {
```
at L-57, the function NatSpec comments says, only maker could withdraw which means that the onlyOwner modifier used on makerWithdraw() is incorrect and funds withdrawal is in wrong hands.

Therefore, considering the NatSpec comment, makerWithdraw() must only be accessed by onlyMaker modifer.

For further information, corelate and understand the contracts with Type.sol, 
https://github.com/sherlock-audit/2023-06-dodo/blob/a8d30e611acc9762029f8756d6a5b81825faf348/new-dodo-v3/contracts/DODOV3MM/lib/Types.sol#L11

The major issue here is the access control is given in wrong hands. if onlyOwner is given access to makerWithdraw() in current implementation is wrong and does not comply the NatSpec comments.

## Code Snippet

Comment mentioning onlyMaker can withdraw:
https://github.com/sherlock-audit/2023-06-dodo/blob/a8d30e611acc9762029f8756d6a5b81825faf348/new-dodo-v3/contracts/DODOV3MM/D3Pool/D3Funding.sol#L57

https://github.com/sherlock-audit/2023-06-dodo/blob/a8d30e611acc9762029f8756d6a5b81825faf348/new-dodo-v3/contracts/DODOV3MM/D3Pool/D3Funding.sol#L73

Type.sol
https://github.com/sherlock-audit/2023-06-dodo/blob/a8d30e611acc9762029f8756d6a5b81825faf348/new-dodo-v3/contracts/DODOV3MM/lib/Types.sol#L11

## Tool used
Manual Review

## Recommendation
Use onlyMaker modifier on makerWithdraw() instead of onlyOwner.

```Solidity

+   modifier onlyMaker() {
+        require(msg.sender == state._MAKER_, "not maker");
+        _;
+    }

// some code


-    function makerWithdraw(address to, address token, uint256 amount) external onlyOwner nonReentrant poolOngoing {
+    function makerWithdraw(address to, address token, uint256 amount) external onlyMaker nonReentrant poolOngoing {

        IERC20(token).safeTransfer(to, amount);

        _updateReserve(token);
        require(checkSafe(), Errors.NOT_SAFE);
        require(checkBorrowSafe(), Errors.NOT_BORROW_SAFE);

        emit MakerWithdraw(to, token, amount);
    }
```