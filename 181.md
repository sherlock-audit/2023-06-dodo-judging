josephdara

medium

# No access control with public visibility for  ``` function createDToken```

## Summary
In the ```D3Vault.sol``` there are 3 functions used for creation and setting of tokens in the vault, 
- ``` function addNewToken```
- ```  function createDToken```
- ```function setToken```
The first function ``` addNewToken``` is an external function with the onlyOwner modifier used to create a d3token and add it to the tokens array. It calls ```createDToken``` to create a new D3Tokeninstance
The second function ```createDToken``` is a public function with no access control modifier, it is used to generate a new instance of a D3Token and initialize it but does not add it to the list.
The third function ``` setToken``` is used to modify info of contracts already on the list of tokens.

Going by the design pattern, ```  function createDToken``` is supposed to be private or it should have an onlyOwner modifier.
It should be private because it is only called once - inside ```addNewToken``` throughout the codebase. And also tokens created with ```createDToken``` can  never be added to the vault because ```setToken``` requires the token to be added already.
## Vulnerability Detail
private function made public with no modifier 
## Impact
https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3Vault.sol#L153-L158
https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3Vault.sol#L128-L136
https://github.com/sherlock-audit/2023-06-dodo/blob/main/new-dodo-v3/contracts/DODOV3MM/D3Vault/D3Vault.sol#L159-L167
## Code Snippet

## Tool used

Manual Review

## Recommendation
Make the function private
```solidity
    function createDToken(address token) private returns (address) {
        address d3Token = ICloneFactory(_CLONE_FACTORY_).clone(_D3TOKEN_LOGIC_);
        IDToken(d3Token).init(token, address(this));
        return d3Token;
    }
```