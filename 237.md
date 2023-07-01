0xrobsol

medium

# Potential Underflow in getPrice function due to inadequate checking of token price decimal

## Summary
In the getPrice function of the D3UserQuota contract, there is a potential risk of an underflow condition, where the expression 36 - priceSources[token].priceDecimal - priceSources[token].tokenDecimal could result in a negative value if priceSources[token].priceDecimal is greater than 36.

## Vulnerability Detail
This contract uses Chainlink oracle for price feeds. The getPrice function aims to return the token price with respect to USD. While doing so, it scales the price by a factor of 10 ** (36 - priceSources[token].priceDecimal - priceSources[token].tokenDecimal). If priceSources[token].priceDecimal is > 36, it could cause this expression to underflow, resulting in an incorrect price calculation.

## Impact
This vulnerability could lead to an inaccurate token price being returned by the getPrice function. If left unchecked, it could have implications on other functions that rely on the getPrice function for token pricing, potentially impacting contract operations related to token pricing.

## Code Snippet
https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/periphery/D3Oracle.sol#L55

## Tool used

Manual Review

## Recommendation
To mitigate this potential issue, the getPrice function should include a require statement that checks if priceSources[token].priceDecimal is less than 36:

`require(priceSources[token].priceDecimal < 36, "Token price decimal cannot be greater than or equal to 36");
    return uint256(price) * 10 ** (36 - priceSources[token].priceDecimal - priceSources[token].tokenDecimal);`