osmanozdemir1

high

# Anyone can sell other users' tokens as `fromToken`, and get the `toToken`'s themselves due to `decodeData.payer` is never checked.

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
