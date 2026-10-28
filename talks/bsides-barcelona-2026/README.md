# Talk

|Title| Hunting Blockchain Dead-Drop Resolvers in Enterprise Traffic|
|---|---|
|Conference|BSides Barcelona 2026|
|Description|Hunting for Malware C2 that leverages public smart contracts (EtherHiding), a hidden dead drop nobody can seize.|
|Link|[bsides.barcelona/schedule](https://web.archive.org/web/20261010032733/https://bsides.barcelona/schedule#:~:text=Hunting%20Blockchain%20Dead-Drop%20Resolvers%20in%20Enterprise%20Traffic)||

# Resources

## Blog posts

https://threatlabs.netskope.com/blog/2026/08/blockchain-dead-drop-resolvers-explained

## Suricata rules

```
# 1 tools and scripts (script UA, no header check)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"EVM Smart Contract read via eth_call - script client"; flow:established,to_server; http.method; content:"POST"; http.host; pcre:"/(?:alchemy\.com|bnbchain\.org|tenderly\.co|drpc\.live|meowrpc\.com|\.drpc\.org|\.publicnode\.com|\.quiknode\.pro|\.nodies\.app|rpc-mainnet\.matic\.network|bsc-dataseed\d*?\.binance\.org|arb\d*?\.arbitrum\.io|mainnet\.infura\.io|cloudflare-eth\.com|rpc\.ankr\.com|bsc-mainnet\.public\.blastapi\.io|eth-mainnet\.nodereal\.io|eth\.llamarpc\.com|go\.getblock\.io)$/"; http.request_body; content:"|22|method|22|"; nocase; depth:200; fast_pattern; pcre:"/^\s*?:\s*?\"eth_call\"/Ri"; content:"|22|to|22|"; depth:200; pcre:"/^\s*?:\s*?\"0x[0-9a-fA-F]{40}/Ri"; http.user_agent; pcre:!"/^(?:(?:Mozilla|MetaMask|foundry|web3\.py)\/|Hardhat|Cronos)/"; sid:1; rev:1;)

# 2 liars (spoofed Mozilla, no Origin):
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"EVM Smart Contract read via eth_call - spoofed or missing User-Agent"; flow:established,to_server; http.method; content:"POST"; http.host; pcre:"/(?:alchemy\.com|bnbchain\.org|tenderly\.co|drpc\.live|meowrpc\.com|\.drpc\.org|\.publicnode\.com|\.quiknode\.pro|\.nodies\.app|rpc-mainnet\.matic\.network|bsc-dataseed\d*?\.binance\.org|arb\d*?\.arbitrum\.io|mainnet\.infura\.io|cloudflare-eth\.com|rpc\.ankr\.com|bsc-mainnet\.public\.blastapi\.io|eth-mainnet\.nodereal\.io|eth\.llamarpc\.com|go\.getblock\.io)$/"; http.request_body; content:"|22|method|22|"; nocase; depth:200; fast_pattern; pcre:"/^\s*?:\s*?\"eth_call\"/Ri"; content:"|22|to|22|"; depth:200; pcre:"/^\s*?:\s*?\"0x[0-9a-fA-F]{40}/Ri"; http.header; pcre:"/\A(?:(?!.*User-Agent:)|(?=.*User-Agent:[ \t]*Mozilla\/)(?!.*Origin:))/si"; sid:2; rev:1;)
```

## Blockchain Dead Drop Decoder (Netskope open source software)

https://github.com/netskopeoss/blockchain-ddr-decoder
