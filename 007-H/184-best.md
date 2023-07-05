lemonmon

high

# Wrong pool potentially being removed by the function `D3Vault.removeD3Pool`

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