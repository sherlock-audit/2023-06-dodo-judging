# Issue H-1: Anyone can sell other users' tokens as `fromToken`, and get the `toToken`'s themselves due to `decodeData.payer` is never checked. 

Source: https://github.com/sherlock-audit/2023-06-dodo-judging/issues/106 

## Found by 
dirk\_y, osmanozdemir1, qckhp
## Summary
Anyone can sell other users' tokens as `fromToken`, and get the `toToken`'s themselves due to `decodeData.payer` is never checked.

## Vulnerability Detail
Let's examine the token-selling process and the transaction flow.

The user will initiate the transaction with the `sellTokens()` method in the `D3Proxy.sol` contract, and provide multiple inputs like `pool`, `fromToken`, `toToken`, `fromAmount`, `data` etc.

[https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/periphery/D3Proxy.sol#L80-L101](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/periphery/D3Proxy.sol#L80-L101)

```solidity
// File: D3Proxy.sol
    function sellTokens(
        address pool,
        address to,
        address fromToken,
        address toToken,
        uint256 fromAmount,
        uint256 minReceiveAmount,
        bytes calldata data,
        uint256 deadLine
    ) public payable judgeExpired(deadLine) returns (uint256 receiveToAmount) {
        if (fromToken == _ETH_ADDRESS_) {
            require(msg.value == fromAmount, "D3PROXY_VALUE_INVALID");
            receiveToAmount = ID3MM(pool).sellToken(to, _WETH_, toToken, fromAmount, minReceiveAmount, data);
        } else if (toToken == _ETH_ADDRESS_) {
            receiveToAmount =
                ID3MM(pool).sellToken(address(this), fromToken, _WETH_, fromAmount, minReceiveAmount, data);
            _withdrawWETH(to, receiveToAmount);
            // multicall withdraw weth to user
        } else {
            receiveToAmount = ID3MM(pool).sellToken(to, fromToken, toToken, fromAmount, minReceiveAmount, data);
        }
    }
```

After some checks, this method in the `D3Proxy.sol` will make a call to the `sellToken()` function in the pool contract (inherits *D3Trading.sol*). After this call, things that will happen in the pool contract are:

1. Transferring the `toToken`'s to the "to" address (with `_transferOut`)
    
2. Making a callback to `D3Proxy` contract to deposit `fromToken`'s to the pool. (with `IDODOSwapCallback(msg.sender).d3MMSwapCallBack`)
    
3. Checking the pool balance and making sure that the `fromToken`'s are actually deposited to the pool. (with this line: `IERC20(fromToken).balanceOf(address(this)) - state.balances[fromToken] >= fromAmount`)
    

You can see the code here:  
[https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Pool/D3Trading.sol#L108-L118](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Pool/D3Trading.sol#L108-L118)

```solidity
// File: D3Trading.sol
// Method: sellToken()
108.-->  _transferOut(to, toToken, receiveToAmount);
109.
110.     // external call & swap callback
111.-->  IDODOSwapCallback(msg.sender).d3MMSwapCallBack(fromToken, fromAmount, data);
112.     // transfer mtFee to maintainer
113.     _transferOut(state._MAINTAINER_, toToken, mtFee);
114.
115.     require(
116.-->      IERC20(fromToken).balanceOf(address(this)) - state.balances[fromToken] >= fromAmount,
117.         Errors.FROMAMOUNT_NOT_ENOUGH
118.     );
```

The source of the vulnerability is the `d3MMSwapCallBack()` function in the `D3Proxy`. It is called by the pool contract with the `fromToken`, `fromAmount` and `data` inputs to make a `fromToken` deposit to the pool.

The issue is that the deposit is made from `decodeData.payer` and **it is never checked if that payer is actually the seller**. Here is the line that causes this vulnerability:  
[https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/periphery/D3Proxy.sol#L142](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/periphery/D3Proxy.sol#L142)

```solidity
//File: D3Proxy.sol 
    /// @notice This callback is used to deposit token into D3MM
    /// @param token The address of token
    /// @param value The amount of token need to deposit to D3MM
    /// @param _data Any data to be passed through to the callback
    function d3MMSwapCallBack(address token, uint256 value, bytes calldata _data) external override {
        require(ID3Vault(_D3_VAULT_).allPoolAddrMap(msg.sender), "D3PROXY_CALLBACK_INVALID");
        SwapCallbackData memory decodeData;
        decodeData = abi.decode(_data, (SwapCallbackData));
-->     _deposit(decodeData.payer, msg.sender, token, value);
    }
```

An attacker can create a `SwapCallbackData` struct with any regular user's address, encode it and pass it through the `sellTokens()` function, and get the `toToken`'s.

You can say that `_deposit()` will need the payer's approval but the attackers will know that too. A regular user might have already approved the pool & proxy for the max amount. Attackers can easily check any token's allowances and exploit already approved tokens. Or they can simply watch the mempool and front-run any normal seller right after they approve but before they call the `sellTokens()`.

## Impact
An attacker can sell any user's tokens and steal their funds.

## Code Snippet
https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/periphery/D3Proxy.sol#L80-L101

```solidity
The `sellTokens()` function in the `D3Proxy.sol`:
// File: D3Proxy.sol
    function sellTokens(
        address pool,
        address to,
        address fromToken,
        address toToken,
        uint256 fromAmount,
        uint256 minReceiveAmount,
        bytes calldata data,
        uint256 deadLine
    ) public payable judgeExpired(deadLine) returns (uint256 receiveToAmount) {
        if (fromToken == _ETH_ADDRESS_) {
            require(msg.value == fromAmount, "D3PROXY_VALUE_INVALID");
            receiveToAmount = ID3MM(pool).sellToken(to, _WETH_, toToken, fromAmount, minReceiveAmount, data);
        } else if (toToken == _ETH_ADDRESS_) {
            receiveToAmount =
                ID3MM(pool).sellToken(address(this), fromToken, _WETH_, fromAmount, minReceiveAmount, data);
            _withdrawWETH(to, receiveToAmount);
            // multicall withdraw weth to user
        } else {
            receiveToAmount = ID3MM(pool).sellToken(to, fromToken, toToken, fromAmount, minReceiveAmount, data);
        }
    }
```

The `sellToken()` function in the `D3Trading.sol`:
https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Pool/D3Trading.sol#L90-L126

```solidity
// File: D3Trading.sol
// Method: sellToken()
108.-->  _transferOut(to, toToken, receiveToAmount);
109.
110.     // external call & swap callback
111.-->  IDODOSwapCallback(msg.sender).d3MMSwapCallBack(fromToken, fromAmount, data);
112.     // transfer mtFee to maintainer
113.     _transferOut(state._MAINTAINER_, toToken, mtFee);
114.
115.     require(
116.-->      IERC20(fromToken).balanceOf(address(this)) - state.balances[fromToken] >= fromAmount,
117.         Errors.FROMAMOUNT_NOT_ENOUGH
118.     );
```

The `d3MMSwapCallBack()` function in the `D3Proxy.sol`:
https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/periphery/D3Proxy.sol#L134-L143

```solidity
//File: D3Proxy.sol 
    /// @notice This callback is used to deposit token into D3MM
    /// @param token The address of token
    /// @param value The amount of token need to deposit to D3MM
    /// @param _data Any data to be passed through to the callback
    function d3MMSwapCallBack(address token, uint256 value, bytes calldata _data) external override {
        require(ID3Vault(_D3_VAULT_).allPoolAddrMap(msg.sender), "D3PROXY_CALLBACK_INVALID");
        SwapCallbackData memory decodeData;
        decodeData = abi.decode(_data, (SwapCallbackData));
-->     _deposit(decodeData.payer, msg.sender, token, value);
    }
```


## Tool used

Manual Review

## Recommendation
I would recommend to check if the `decodeData.payer == msg.sender` in the beginning of the `sellTokens()` function in `D3Proxy` contract. Because msg.sender will be the pool's address if you want to check it in the `d3MMSwapCallBack()` function, and this check will not be valid to see if the payer is actually the seller. 

Another option might be creating a local variable called "seller" and saving the msg.sender value when they first started the transaction. After that make `decodeData.payer == seller` check in the `d3MMSwapCallBack()`.



## Discussion

**Attens1423**

fix pr: https://github.com/DODOEX/new-dodo-v3/pull/41/commits/292141d1bb3be71cde6b154f7619c52d628ca18c

# Issue H-2: Wrong pool potentially being removed by the function `D3Vault.removeD3Pool` 

Source: https://github.com/sherlock-audit/2023-06-dodo-judging/issues/184 

## Found by 
ADM, BugBusters, Sulpiride, lemonmon
## Summary

When calling the function `D3Vault.removeD3Pool` it can happen that the wrong pool is being removed.

## Vulnerability Detail

If the `creator` has multiple pools stored inside `creatorPoolMap[creator]`, the `D3Vault.removeD3Pool` function will always remove the last pool from `creatorPoolMap[creator]`. The `pool` param from `D3Vault.removeD3Pool()` is being ignored, thus potentially removing the wrong pool.

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultStorage.sol#L35

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3Vault.sol#L36

When the `pool` to remove is found inside the `poolList` (line 45 D3Vault.sol), the code wants to set the last element of the `poolList` to the current index `i` of the `pool` that should be removed (line 46 D3Vault.sol):

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3Vault.sol#L45-L46

But instead of assigning it via `=`, the comparison operator `==` is used, which doesn't change the elements inside the `poolList` array. Then the unchanged `poolList` is assigned to the `creatorPoolMap[creator]`:

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3Vault.sol#L47

This means that the array of pools in `creatorPoolMap[creator]` is still the same as before without any changes.

Then the last element of the pools array in `creatorPoolMap[creator]` is being removed:

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3Vault.sol#L48

Thus potentially the wrong pool was removed.

## Impact

The wrong pool can get removed when calling `D3Vault.removeD3Pool()`.

If the wrong pool gets removed, the actual `pool` that was supposed to be removed cannot be removed anymore, because `allPoolAddrMap[pool]` is set to false (line 40 D3Vault), making line 37 in D3Vault.sol always revert when trying to remove the pool.

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3Vault.sol#L37

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3Vault.sol#L40

Additionally if the wrong pool gets removed, the `allPoolAddrMap[pool]` is set to false for the `pool` that should have been removed (line 40 D3Vault), which means that the `pool` can be added again as a duplicate, because line 14 and line 22 in D3Vault doesn't revert anymore.

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3Vault.sol#L40

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3Vault.sol#L14

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3Vault.sol#L22

## Code Snippet

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultStorage.sol#L35

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3Vault.sol#L36

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3Vault.sol#L45-L48

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3Vault.sol#L37

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3Vault.sol#L40

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3Vault.sol#L14

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3Vault.sol#L22

## Tool used

Manual Review

## Recommendation

The correct operator `=` should be used in D3Vault.sol line 46.

```solidity
// D3Vault
// removeD3Pool
46                poolList[i] = poolList[poolList.length - 1];
```



## Discussion

**traceurl**

Fixed in this PR: https://github.com/DODOEX/new-dodo-v3/pull/27

# Issue H-3: A user can get more dTokens than they should get via `D3VaultFunding.userDeposit()`, due to accounting issues in `D3VaultLiquidation.liquidate()` 

Source: https://github.com/sherlock-audit/2023-06-dodo-judging/issues/211 

## Found by 
0xkaden, dirk\_y, lemonmon, seeques
## Summary

The vault token balance (`assetInfo[debt].balance`) is not updated during liquidation (`D3VaultLiquidation.liquidate()`).

Thus, a user who calls `D3VaultFunding.userDeposit()` can get more dTokens than they should get.

## Vulnerability Detail

When `D3VaultLiquidation.liquidate()` is called, the debt is transferred to the vault:

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultLiquidation.sol#L55

But `assetInfo[debt].balance` is not updated, even though the debt tokens were received.

This leads to the issue that if a user deposits this debt token right after the liquidation, they will receive more dTokens in return than they should, because `D3VaultFunding.userDeposit()` is using the wrongly tracked value of `assetInfo[debt].balance`:

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L32-L34

As a result, the protocol will mint more dTokens for the user than they should receive:

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L39-L41

## Impact

A user can call `D3VaultFunding.userDeposit()` right after a token got liquidated by `D3VaultLiquidation.liquidate()`, resulting in that the user will receive more dToken than they should receive, due to accounting issues in `D3VaultLiquidation.liquidate()`.

All LP holders will suffer from inflated dTokens.

## Code Snippet

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultLiquidation.sol#L55

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L32-L34

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L39-L41

## Tool used

Manual Review

## Recommendation

After `D3VaultLiquidation.liquidate()` is transferring the debt tokens to the vault, update the `assetInfo[debt].balance` of the vault.

If the repaid debt in `D3VaultLiquidation.liquidate()` was meant to be sent to the pool, like in the function `D3VaultLiquidation.liquidateByDODO()`, the `ID3MM(pool).updateReserveByVault(debt)` should be called at the end of `D3VaultLiquidation.liquidate()`. Otherwise a very similar problem can occur since the `state.balances[debtToken]` is not being updated. `state.balances[debtToken]` is used in a similar way in the D3Trading.sol contract to determine the actual balance received.

# Issue H-4: When a D3MM pool repays all of the borrowed funds to vault using `D3Funding.sol repayAll`, an attacker can steal double the amount of those funds from vault 

Source: https://github.com/sherlock-audit/2023-06-dodo-judging/issues/217 

## Found by 
0x4db5362c, 0xG0P1, 0xkaden, HALITUS, Proxy, Sulpiride, dirk\_y, osmanozdemir1, seeques, skyge
## Summary

When a D3MM pool repays all of the borrowed funds to vault using [D3Funding.sol repayAll](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Pool/D3Funding.sol#L40-L46), an attacker can steal double the amount of those funds from vault. This is because the balance of vault is not updated correctly in [D3VaultFunding.sol _poolRepayAll](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L117-L133).

`amount` should be added in `info.balance` instead of being subtracted.

```solidity
    function _poolRepayAll(address pool, address token) internal {
        .
        .
        info.totalBorrows = info.totalBorrows - amount;
        info.balance = info.balance - amount; // amount should be added here
        .
        .
    }
```

## Vulnerability Detail
A `D3MM pool` can repay all of the borrowed funds from vault using the function [D3Funding.sol repayAll](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Pool/D3Funding.sol#L40-L46) which further calls [D3VaultFunding.sol poolRepayAll](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L113) and eventually [D3VaultFunding.sol _poolRepayAll](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L117-L133).

```solidity
    function repayAll(address token) external onlyOwner nonReentrant poolOngoing {
        ID3Vault(state._D3_VAULT_).poolRepayAll(token);
        _updateReserve(token);
        require(checkSafe(), Errors.NOT_SAFE);
    }
```

The vault keeps a record of borrowed funds and its current token balance.

`_poolRepayAll()` is supposed to:
1. Decrease the borrowed funds by the repaid amount
2. Increase the token balance by the same amount #vulnerability
3. Transfer the borrowed funds from pool to vault

However, `_poolRepayAll()` is decreasing the token balance instead.

```solidity
    function _poolRepayAll(address pool, address token) internal {
        .
        .
        .
        .

        info.totalBorrows = info.totalBorrows - amount;
        info.balance = info.balance - amount; // amount should be added here

        IERC20(token).safeTransferFrom(pool, address(this), amount);

        emit PoolRepay(pool, token, amount, interests);
    }
```
Let's say a vault has 100,000 USDC
A pool borrows 20,000 USDC from vault

When the pool calls `poolRepayAll()`, the asset info in vault will change as follows:

1. `totalBorrows => 20,000 - 20,000 => 0` // info.totalBorrows - amount
2. `balance => 100,000 - 20,000 => 80,000` // info.balance - amount
3. `tokens owned by vault => 100,000 + 20,000 => 120,000 USDC` // 20,000 USDC is transferred from pool to vault (repayment)
4. The difference of recorded balance (80,000) and actual balance (120,000) is `40,000 USDC` 

**An attacker waits for the `poolRepayAll()` function call by a pool.**

When `poolRepayAll()` is executed, the attacker calls [D3VaultFunding.sol userDeposit()](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L29), which deposits 40,000 USDC in vault on behalf of the attacker.

After this, the attacker withdraws the deposited amount using [D3VaultFunding.sol userWithdraw()](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L51) and thus gains 40,000 USDC.

```solidity
    function userDeposit(address user, address token) external nonReentrant allowedToken(token) {
        .
        .
        .
        AssetInfo storage info = assetInfo[token];
        uint256 realBalance = IERC20(token).balanceOf(address(this)); // check tokens owned by vault
        uint256 amount = realBalance - info.balance; // amount = 120000-80000
        .
        .
        .
        IDToken(info.dToken).mint(user, dTokenAmount);
        info.balance = realBalance;

        emit UserDeposit(user, token, amount);
    }
```

## Impact

Loss of funds from vault. 
The loss will be equal to 2x amount of borrowed tokens that a D3MM pool repays using [D3VaultFunding.sol poolRepayAll]()

## Code Snippet

[D3VaultFunding.sol _poolRepayAll()](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L129)

```solidity
    function _poolRepayAll(address pool, address token) internal {
        .
        .
        info.totalBorrows = info.totalBorrows - amount;
        info.balance = info.balance - amount; // vulnerability: amount should be added here

        IERC20(token).safeTransferFrom(pool, address(this), amount);

        emit PoolRepay(pool, token, amount, interests);
    }
```

## Tool used

Manual Review

## Recommendation
In [D3VaultFunding.sol _poolRepayAll](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L129), do the following changes:

Current code:
`info.balance = info.balance - amount;`

New (replace '-' with '+'):
`info.balance = info.balance + amount;`



## Discussion

**traceurl**

Fixed in this PR: https://github.com/DODOEX/new-dodo-v3/pull/26

# Issue H-5: Potential FlashLoan attack in _getExchangeRate function 

Source: https://github.com/sherlock-audit/2023-06-dodo-judging/issues/228 

## Found by 
0xkaden, BugBusters, dirk\_y, kutugu
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



## Discussion

**traceurl**

Fixed in this PR https://github.com/DODOEX/new-dodo-v3/pull/43

# Issue M-1: possible precision loss in D3VaultLiquidation.finishLiquidation() function when calculating realDebt because of division before multiplication 

Source: https://github.com/sherlock-audit/2023-06-dodo-judging/issues/45 

## Found by 
0xdice91, BugBusters, BugHunter101, Kalyan-Singh, MohammedRizwan, Oxhunter526, PRAISE, Sulpiride, amaechieth, kutugu
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

# Issue M-2: D3Oracle.getPrice() and D3Oracle.getOriginalPrice() doesn't check If Arbitrum sequencer is down for Chainlink feeds 

Source: https://github.com/sherlock-audit/2023-06-dodo-judging/issues/62 

## Found by 
0xHati, 0xNoodleDon, 0xdice91, Avci, MohammedRizwan, PNS, PRAISE, bitsurfer, jprod15, kutugu, qckhp, seeques, shogoki, shtesesamoubiq, skyge, tsvetanovv
## Summary
When utilizing Chainlink in L2 chains like Arbitrum, it's important to ensure that the prices provided are not falsely perceived as fresh, even when the sequencer is down. This vulnerability could potentially be exploited by malicious actors to gain an unfair advantage.

## Vulnerability Detail
There is no check in D3Oracle.getPrice()
```solidity
 function getPrice(address token) public view override returns (uint256) {
        require(priceSources[token].isWhitelisted, "INVALID_TOKEN");
        AggregatorV3Interface priceFeed = AggregatorV3Interface(priceSources[token].oracle);
        (uint80 roundID, int256 price,, uint256 updatedAt, uint80 answeredInRound) = priceFeed.latestRoundData();
        require(price > 0, "Chainlink: Incorrect Price");
        require(block.timestamp - updatedAt < priceSources[token].heartBeat, "Chainlink: Stale Price");
        require(answeredInRound >= roundID, "Chainlink: Stale Price");
        return uint256(price) * 10 ** (36 - priceSources[token].priceDecimal - priceSources[token].tokenDecimal);
    }
```

no check in D3Oracle.getOriginalPrice() too
```solidity
 function getOriginalPrice(address token) public view override returns (uint256, uint8) {
        require(priceSources[token].isWhitelisted, "INVALID_TOKEN");
        AggregatorV3Interface priceFeed = AggregatorV3Interface(priceSources[token].oracle);
        (uint80 roundID, int256 price,, uint256 updatedAt, uint80 answeredInRound) = priceFeed.latestRoundData();
        require(price > 0, "Chainlink: Incorrect Price");
        require(block.timestamp - updatedAt < priceSources[token].heartBeat, "Chainlink: Stale Price");
        require(answeredInRound >= roundID, "Chainlink: Stale Price");
        uint8 priceDecimal = priceSources[token].priceDecimal;
        return (uint256(price), priceDecimal);
    }
```

## Impact
could potentially be exploited by malicious actors to gain an unfair advantage.

## Code Snippet
https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/periphery/D3Oracle.sol#L48

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/periphery/D3Oracle.sol#L58
## Tool used

Manual Review

## Recommendation
code example of Chainlink:
https://docs.chain.link/data-feeds/l2-sequencer-feeds#example-code

# Issue M-3: `D3VaultFunding.userWithdraw()` doen not have mindTokenAmount 

Source: https://github.com/sherlock-audit/2023-06-dodo-judging/issues/85 

## Found by 
0xDjango, Avci, BugHunter101, Oxhunter526, dirk\_y
## Summary

`D3VaultFunding.userWithdraw()` doen not have mindTokenAmount, and use `_getExchangeRate` directly.This is vulnerable to a sandwich attack.

## Vulnerability Detail

As we can see, `D3VaultFunding.userWithdraw()` doen not have mindTokenAmount, and use `_getExchangeRate` directly.
```solidity
function userWithdraw(address to, address user, address token, uint256 dTokenAmount) external nonReentrant allowedToken(token) returns(uint256 amount) {
        accrueInterest(token);
        AssetInfo storage info = assetInfo[token];
        require(dTokenAmount <= IDToken(info.dToken).balanceOf(msg.sender), Errors.DTOKEN_BALANCE_NOT_ENOUGH);

        amount = dTokenAmount.mul(_getExchangeRate(token));//@audit does not check amount value
        IDToken(info.dToken).burn(msg.sender, dTokenAmount);
        IERC20(token).safeTransfer(to, amount);
        info.balance = info.balance - amount;

        // used for calculate user withdraw amount
        // this function could be called from d3Proxy, so we need "user" param
        // In the meantime, some users may hope to use this function directly,
        // to prevent these users fill "user" param with wrong addresses,
        // we use "msg.sender" param to check.
        emit UserWithdraw(msg.sender, user, token, amount);
    }
```

 And the `_getExchangeRate()` result is about `cash `, `info.totalBorrows`, `info.totalReserves`,`info.withdrawnReserves`,`dTokenSupply`,This is vulnerable to a sandwich attack leading to huge slippage
```solidity
function _getExchangeRate(address token) internal view returns (uint256) {
        AssetInfo storage info = assetInfo[token];
        uint256 cash = getCash(token);
        uint256 dTokenSupply = IERC20(info.dToken).totalSupply();
        if (dTokenSupply == 0) { return 1e18; }
        return (cash + info.totalBorrows - (info.totalReserves - info.withdrawnReserves)).div(dTokenSupply);
    } 
```

## Impact

This is vulnerable to a sandwich attack.

## Code Snippet

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L56

## Tool used

Manual Review

## Recommendation

Add `mindTokenAmount` parameter for `userWithdraw()` function and check if `amount < mindTokenAmount`



## Discussion

**Attens1423**

We will add slippage protection in D3Proxy

# Issue M-4: D3Oracle will return the wrong price if the Chainlink aggregator returns price outside min/max range 

Source: https://github.com/sherlock-audit/2023-06-dodo-judging/issues/129 

## Found by 
0xdice91, BugHunter101, MohammedRizwan, PRAISE, Proxy, dirk\_y, kutugu
## Summary

Chainlink oracles have a min and max price that they return. If the price goes below the minimum price the oracle will not return the correct price but only the min price. Same goes for the other extremity.

## Vulnerability Detail

Both [`getPrice()`](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/periphery/D3Oracle.sol#L48-L56) and [`getOriginalPrice()`](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/periphery/D3Oracle.sol#L58-L67) only check `price > 0` not are they within the correct range

```solidity
(uint80 roundID, int256 price,, uint256 updatedAt, uint80 answeredInRound) = priceFeed.latestRoundData();
require(price > 0, "Chainlink: Incorrect Price");
require(block.timestamp - updatedAt < priceSources[token].heartBeat, "Chainlink: Stale Price");
require(answeredInRound >= roundID, "Chainlink: Stale Price");
```

## Impact

The wrong price may be returned in the event of a market crash.
The functions with the issue are used in [`D3VaultFunding.sol`](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol), [`D3VaultLiquidation.sol`](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultLiquidation.sol) and [`D3UserQuota.sol`](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/periphery/D3UserQuota.sol)

## Code Snippet

- D3Oracle.sol functions:
  - [`getPrice()`](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/periphery/D3Oracle.sol#L48-L56)
  - [`getOriginalPrice()`](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/periphery/D3Oracle.sol#L58-L67)

## Tool used

Manual Review

## Recommendation

[Check the latest answer against reasonable limits](https://docs.chain.link/data-feeds#check-the-latest-answer-against-reasonable-limits) and/or revert in case you get a bad price

```solidity
 require(price >= minAnswer && price <= maxAnswer, "invalid price");
```



## Discussion

**Attens1423**

How can we get minPrice and maxPrice from oracle contract? Could you give us a more detailed procession?

**0xffff11**

https://docs.chain.link/data-feeds#check-the-latest-answer-against-reasonable-limits @Attens1423 


**Attens1423**

We understand this doc. If you could offer a code example, including how to get minPrice and maxPrice from code, we would appreciate it

# Issue M-5: Pool Repayment Allowed During Liquidation Process 

Source: https://github.com/sherlock-audit/2023-06-dodo-judging/issues/131 

## Found by 
dirk\_y, twcctop

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

# Issue M-6: Wrong assignment of `cumulativeBid` for RangeOrder state in getRangeOrderState function 

Source: https://github.com/sherlock-audit/2023-06-dodo-judging/issues/178 

## Found by 
bitsurfer
## Summary

Wrong assignment of `cumulativeBid` for RangeOrder state

## Vulnerability Detail

In `D3Trading`, the `getRangeOrderState` function is returning RangeOrder (get swap status for internal swap) which is assinging wrong toTokenMMInfo.cumulativeBid which suppose to be `cumulativeBid` not `cumulativeAsk`

The error lies in the assignment of `roState.toTokenMMInfo.cumulativeBid`. Instead of assigning `tokenCumMap[toToken].cumulativeAsk`, it should be assigning `tokenCumMap[toToken].cumulativeBid`.

```js
File: D3Trading.sol
86:         roState.toTokenMMInfo.cumulativeBid =
87:             allFlag >> (toTokenIndex) & 1 == 0 ? 0 : tokenCumMap[toToken].cumulativeAsk;
```

This wrong assignment value definitely will mess up accounting balance, resulting unknown state will occure, which is not expected by the protocol

For one case, this `getRangeOrderState` is being used in `querySellTokens` & `queryBuyTokens` which may later called from `sellToken` and `buyToken`. The issue is when calling `_contructTokenState` which can be reverted from `PMMRangeOrder` when buy or sell token

```js
File: PMMRangeOrder.sol
100:         // B
101:         tokenState.B = askOrNot ? tokenState.B0 - tokenMMInfo.cumulativeAsk : tokenState.B0 - tokenMMInfo.cumulativeBid;
```

When the `tokenMMInfo.cumulativeBid` (which was wrongly assign from `cumulativeAsk`) is bigger than `tokenState.B0`, this will revert

## Impact

This wrong assignment value definitely will mess up accounting balance, resulting unknown state will occure, which is not expected by the protocol. For example reverting state showing a case above.

## Code Snippet

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Pool/D3Trading.sol#L86-L87

## Tool used

Manual Review

## Recommendation

Fix the error to

```diff
File: D3Trading.sol
86:         roState.toTokenMMInfo.cumulativeBid =
--:             allFlag >> (toTokenIndex) & 1 == 0 ? 0 : tokenCumMap[toToken].cumulativeAsk;
++:             allFlag >> (toTokenIndex) & 1 == 0 ? 0 : tokenCumMap[toToken].cumulativeBid;
```



## Discussion

**Attens1423**

fix pr:https://github.com/DODOEX/new-dodo-v3/pull/40

# Issue M-7: D3VaultFunding#checkBadDebtAfterAccrue is inaccurate and can lead to further damage to both LP's and MM 

Source: https://github.com/sherlock-audit/2023-06-dodo-judging/issues/192 

## Found by 
0x52
## Summary

D3VaultFunding#checkBadDebtAfterAccrue makes the incorrect assumption that a collateral ratio of less than 1e18 means that the pool has bad debt. Due to how collateral and debt weight affect the collateral ratio calculation a pool can have a collateral ratio less than 1e18 will still maintaining debt that is profitable to liquidate. The result of this is that the after this threshold has been passed, a pool can no longer be liquidate by anyone which can lead to continued losses that harm both the LPs and the MM being liquidated.

## Vulnerability Detail

[D3VaultFunding.sol#L382-L386](https://github.com/sherlock-audit/2023-06-dodo/blob/a8d30e611acc9762029f8756d6a5b81825faf348/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L382-L386)

            if (balance >= borrows) {
                collateral += min(balance - borrows, info.maxCollateralAmount).mul(info.collateralWeight).mul(price);
            } else {
                debt += (borrows - balance).mul(info.debtWeight).mul(price);
            }

When calculating the collateral and debt values, the value of the collateral is adjusted by the collateralWeight and debtWeight respectively. This can lead to a position in which the collateral ratio is less than 1e18, which incorrectly signals the pool has bad debt via the checkBadDebtAfterAccrue check. 

Example:

    Assume a pool has the following balances and debts:
    
    Token A - 100 borrows 125 balance
    Token B - 100 borrows 80 balance
    
    Price A = 1
    collateralWeightA = 0.8
    
    Price B = 1
    debtWeightB = 1.2
    
    collateral = 25 * 1 * 0.8 = 20
    debt = 20 * 1 * 1.2 = 24
    
    collateralRatio = 20/24 = 0.83

The problem here is that there is no bad debt at all and it is still profitable to liquidate this pool, even with a discount:

    ExcessCollateral = 125 - 100 = 25
    
    25 * 1 * 0.95 [DISCOUNT] = 23.75
    
    ExcessDebt = 100 - 80 = 20
    
    20 * 1 = 20

The issue with this is that once this check has been triggered, no other market participants besides DODO can liquidate this position. This creates a significant inefficiency in the market that can easily to real bad debt being created for the pool. This bad debt is harmful to both the pool MM, who could have been liquidated with remaining collateral, and also the vault LPs who directly pay for the bad debt.

## Impact

Unnecessary loss of funds to LPs and MMs

## Code Snippet

[D3VaultFunding.sol#L308-L310](https://github.com/sherlock-audit/2023-06-dodo/blob/a8d30e611acc9762029f8756d6a5b81825faf348/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultFunding.sol#L308-L310)

## Tool used

Manual Review

## Recommendation

The methodology of the bad debt check should be changed to remove collateral and debt weights to accurately indicate the presence of bad debt.



## Discussion

**Attens1423**

The market maker actually controls two contracts with two separate accounts. The owner account of D3Maker is responsible for price feeding, while the owner account of D3MM is responsible for depositing and withdrawing funds. The use of modifiers here meets the design requirements：
https://github.com/sherlock-audit/2023-06-dodo/blob/a8d30e611acc9762029f8756d6a5b81825faf348/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3VaultLiquidation.sol#L142C1-L148C31
```solidity
uint256 realDebt = borrows.div(record.interestIndex == 0 ? 1e18 : record.interestIndex).mul(info.borrowIndex);
// if balance > realDebt, transferFrom realDebt instead of debt
IERC20(token).transferFrom(pool, address(this), realDebt); 
```

**hrishibhat**

@IAm0x52 

**Attens1423**

We have discovered some hidden issues in the dodo liquidation process, and we agree to modify the check of bad debts.

# Issue M-8: D3UserQuote#getUserQuote queries incorrect token for exchangeRate leading to inaccurate quota calculations 

Source: https://github.com/sherlock-audit/2023-06-dodo-judging/issues/193 

## Found by 
0x4db5362c, 0x52, 0xrobsol, dirk\_y, kutugu, stuart\_the\_minion
## Summary

A small typo in the valuation loop of D3UserQuote#getUserQuote uses the wrong variable leading to and incorrect quota being returned. The purpose of a quota is to mitigate risk of positions being too large. This incorrect assumption can dramatically underestimate the quota leading to oversized (and overrisk) positions.

## Vulnerability Detail

[D3UserQuota.sol#L75-L84](https://github.com/sherlock-audit/2023-06-dodo/blob/a8d30e611acc9762029f8756d6a5b81825faf348/new-dodo-v3/contracts/DODOV3MM/D3Vault/periphery/D3UserQuota.sol#L75-L84)

        for (uint256 i = 0; i < tokenList.length; i++) {
            address _token = tokenList[i];
            (address assetDToken,,,,,,,,,,) = d3Vault.getAssetInfo(_token);
            uint256 tokenBalance = IERC20(assetDToken).balanceOf(user);
            if (tokenBalance > 0) {
                tokenBalance = tokenBalance.mul(d3Vault.getExchangeRate(token)); <- @audit-issue queries token instead of _token
                (uint256 tokenPrice, uint8 priceDecimal) = ID3Oracle(d3Vault._ORACLE_()).getOriginalPrice(_token);
                usedQuota = usedQuota + tokenBalance * tokenPrice / 10 ** (priceDecimal+tokenDecimals);
            }
        }

D3UserQuota.sol#L80 incorrectly uses token rather than _token as it should. This returns the wrong exchange rate which can dramatically alter the perceived token balance as well as the calculated quota.

## Impact

Quota is calculated incorrectly leading to overly risky positions, which in turn can cause loss to the system

## Code Snippet

[D3UserQuota.sol#L69-L97](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/periphery/D3UserQuota.sol#L69-L97)

## Tool used

Manual Review

## Recommendation

Change variable from token to _token:

    -           tokenBalance = tokenBalance.mul(d3Vault.getExchangeRate(token));
    +           tokenBalance = tokenBalance.mul(d3Vault.getExchangeRate(_token));



## Discussion

**traceurl**

We redesigned D3UserQuota.

In the old version:
1. used quota is calculated based on the USD value of the deposited token
2. global quota is shared by all tokens

In this new version:
1. used quota is the amount of the deposited token, so price change won't affect quota
2. each token has its own global quota

# Issue M-9: Protocol is completely incompatible with USDT due to lack of 0 approval 

Source: https://github.com/sherlock-audit/2023-06-dodo-judging/issues/203 

## Found by 
0x4db5362c, 0x52, Avci, BugHunter101, Chandr, HALITUS, MohammedRizwan, PRAISE, Proxy, Sulpiride, Vagner, amaechieth, jprod15, kutugu, seerether, shealtielanz, shogoki, skyge, tsvetanovv
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

