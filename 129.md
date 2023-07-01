Proxy

medium

# D3Oracle will return the wrong price if the Chainlink aggregator returns price outside min/max range

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
