0xdice91

high

# Users deposit can be stolen through `frontrunning` in `D3VaultFunding.userDeposit`

## Summary
When a user deposits by calling `D3VaultFunding.userDeposit` instead of D3Proxy.sol `userDeposit` function, he transfers token to the vault before the call. The transfer can be `backrunned` by a malicious actor to `steal` the user's deposit.
## Vulnerability Detail
In `D3VaultFunding.userDeposit` tokens are transferred to the contract before the call but a malicious actor watching the mempool can frontrun the users `userDeposit` call, to call `userdeposit`.
Since the amount to be minted is only calculated through the difference between the `real balance` and the `info.balance` of the token in the contract, `dtoken` is minted to the `malicious actor`.
```solidity

    /// @notice user should transfer token to vault before call this function
    function userDeposit(address user, address token) external nonReentrant allowedToken(token) {
        accrueInterest(token);

        AssetInfo storage info = assetInfo[token];
        uint256 realBalance = IERC20(token).balanceOf(address(this));
        uint256 amount = realBalance  - info.balance;
        require(ID3UserQuota(_USER_QUOTA_).checkQuota(user, token, amount), Errors.EXCEED_QUOTA);
        uint256 exchangeRate = _getExchangeRate(token);
        uint256 totalDToken = IDToken(info.dToken).totalSupply();
        require(totalDToken.mul(exchangeRate) + amount <= info.maxDepositAmount, Errors.EXCEED_MAX_DEPOSIT_AMOUNT);
        uint256 dTokenAmount = amount.div(exchangeRate);

        IDToken(info.dToken).mint(user, dTokenAmount);
        info.balance = realBalance;

        emit UserDeposit(user, token, amount);
    }

   ```
 
## Impact
Users who deposit through `D3VaultFunding.userDeposit` stand a risk of losing their funds to malicious actors
## Code Snippet
https://github.com/sherlock-audit/2023-06-dodo/blob/a8d30e611acc9762029f8756d6a5b81825faf348/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L29
## Tool used
Manual Review

## Recommendation
Proper checks should be implemented to ensure that users are only able to deposit through D3Proxy.sol `userDeposit` function.

```solidity
function userDeposit(address user, address token, uint256 amount) external payable {
        if (token == _ETH_ADDRESS_) {
            require(msg.value == amount, "D3PROXY_PAYMENT_NOT_MATCH");
            _deposit(msg.sender, _D3_VAULT_, _WETH_, amount);
            ID3Vault(_D3_VAULT_).userDeposit(user, _WETH_);
        } else {
            _deposit(msg.sender, _D3_VAULT_, token, amount);
            ID3Vault(_D3_VAULT_).userDeposit(user, token);
        }
    }
```
