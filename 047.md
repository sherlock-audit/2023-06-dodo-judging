PRAISE

high

# `payFromAmount` and `vusdAmount` in D3Trading.buyToken() are calculated with both 10**18 and 10**36. This will cause them to be bigger than they should be or lesser.

## Summary
Both `10**18` and `10**36` are used to calculate `payFromAmount` and `vusdAmount` in D3Trading.buyToken().
## Vulnerability Detail
DODOMath._GeneralIntegrate() is the root cause of this issue.
```solidity
 function _GeneralIntegrate(
        uint256 V0,
        uint256 V1, //@audit-info this is baseBalance when this function is called within PMMPricing._BuyBaseToken()
        uint256 V2, //@audit-info  this is B2 when this function is called within PMMPricing._BuyBaseToken()
        uint256 i,
        uint256 k
    ) internal pure returns (uint256) {
        require(V0 > 0, "TARGET_IS_ZERO");
        uint256 fairAmount = i * (V1 - V2); // i*delta 
        if (k == 0) {
            return fairAmount / DecimalMath.ONE;
        }
        uint256 V0V0V1V2 = DecimalMath.divFloor(V0 * V0 / V1, V2);
        uint256 penalty = DecimalMath.mulFloor(k, V0V0V1V2); // k(V0^2/V1/V2)
        return (DecimalMath.ONE - k + penalty) * fairAmount / DecimalMath.ONE2;//@audit the issue is this line. 
    }
```
The issue is in the last line of the above snippet i.e the return statement. DecimalMath.ONE and DecimalMath.ONE2 are used in the calculation that is returned here
```solidity
return (DecimalMath.ONE - k + penalty) * fairAmount / DecimalMath.ONE2;//@audit the issue is this line. 
```

DecimalMath.ONE is  10 ** 18  [see here](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/lib/DecimalMath.sol#L15)

` uint256 internal constant ONE = 10 ** 18;`

 and  DecimalMath.ONE2 is 10 ** 36  [see here](https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/lib/DecimalMath.sol#L16)

` uint256 internal constant ONE2 = 10 ** 36;`

So precision loss is bound to happen which could either inflate the product of the returned calculation more than should be  or deflate it more than should be




Now DODOMath._GeneralIntegrate() is called by PMMPricing._BuyBaseToken(),

PMMPricing._BuyBaseToken() is called by PMMPricing._queryBuyBaseToken(),

PMMPricing._queryBuyBaseToken() is called by PMMRangeOrder.queryBuyTokens(),

PMMRangeOrder.queryBuyTokens() is called by D3Trading.buyToken() here 
```solidity
(uint256 payFromAmount, uint256 receiveToAmount, uint256 vusdAmount, uint256 swapFee, uint256 mtFee) =//@audit-info payFromAmount and vusdAmount is calculated with 2 different decimals.
            queryBuyTokens(fromToken, toToken, quoteAmount);
```
 to query amount (i.e both `payFromAmount` and `vusdAmount` )


in  PMMRangeOrder.queryBuyTokens() `payFromAmount` and `vusdAmount` are gotten via a call to PMMPricing._queryBuyBaseToken()
here 
```solidity
  payVUSD = PMMPricing._queryBuyBaseToken(toTokenState, toTokenAmount);//@audit payVusd  is vusdAmount
```

and here
```solidity
   payFromToken = PMMPricing._queryBuyBaseToken(fromTokenState, payVUSD); //@audit payFromToken is payFromAmount
```
## Impact
Some form of  precision loss is bound to happen which could either inflate the product of the returned calculation more than should be  or deflate it more than should be

## Code Snippet
https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/lib/DODOMath.sol#L42

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/lib/PMMPricing.sol#L44

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/lib/PMMPricing.sol#L24

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/lib/PMMRangeOrder.sol#L59

https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/lib/PMMRangeOrder.sol#L65


## Tool used

Manual Review

## Recommendation
use either only DecimalMath.ONE or  DecimalMath.ONE2 avoid using conflicting decimals