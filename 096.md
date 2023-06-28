0xG0P1

high

# The `multicall` function within the `D3Proxy.sol` contract is not functioning as intended.

## Summary
The `multicall` function within the `D3Proxy.sol` contract enables users to expend the contract's balance. However, the `msg.value` is not being updated within the for loop, resulting in a loss of funds.
## Vulnerability Detail
The `multicall` function in the `D3Proxy.sol` contract is a `payable` function that allows users to send ETH and execute multiple functions within the contract. However, there is a vulnerability whereby an attacker can exploit the `multicall` function to repeatedly call the `sellTokens` function in the `D3Proxy` contract. The attacker only needs to provide ETH once, and for subsequent calls, the contract's balance is utilized due to the lack of change in the `msg.value`. This vulnerability allows the attacker to manipulate the contract's balance to their advantage.

Consider the following scenario:

1. An external owned account (EOA) initiates a direct call to the `buyTokens` function within the `D3Proxy` contract, providing 10 ETH as the input. The trade is executed successfully, requiring 5 ETH to be sent to the `D3MMPool` in order to obtain the specified amount of `toToken`. The remaining 5 ETH is sent to the `D3Proxy` contract, and the `EOA` is expected to claim a refund. At this point, the `D3Proxy` contract holds a balance of 5 ETH.

2. An attacker or a random user calls the `sellTokens` function twice using the `multicall` functionality, supplying 5 ETH.

3. During the first iteration (i = 0) of the `multicall` loop, the `msg.value` parameter is set to 5 ETH, resulting in a trade where the user receives `toToken` worth 5 ETH. However, when the second iteration (i = 1) is executed, the `msg.value` remains unchanged at 5 ETH. Consequently, the contract's balance is depleted to facilitate the trade, allowing the attacker to obtain `toToken` worth 10 ETH by providing only 5 ETH. This action causes other EOAs to experience financial losses.

In summary, due to the failure to properly adjust the `msg.value` within the `multicall` function, the attacker can exploit this inconsistency to manipulate the contract's balance, unfairly acquiring a higher value of toTokens compared to the amount of ETH originally provided. As a result, other legitimate EOAs involved in the process suffer significant financial losses.

## Impact
This vulnerability has two impacts: 
1. EOAs may lose funds.
2. The `multicall` function fails to update `msg.value`, rendering it unable to process multiple payable functions as expected.
## Code Snippet
https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/periphery/D3Proxy.sol#L56-L69

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/periphery/D3Proxy.sol#L91
https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/periphery/D3Proxy.sol#L151
## Tool used

Manual Review

## Recommendation
To address the vulnerability, it is recommended to implement caching of `msg.value` in the `multicall` function. This ensures that `msg.value` is updated in every iteration.