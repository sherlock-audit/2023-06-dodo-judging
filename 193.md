0x52

medium

# D3UserQuote#getUserQuote queries incorrect token for exchangeRate leading to inaccurate quota calculations

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