# Do7h3R3c0n
Recon framework and methdolgy using go lang tools 

## features 
1) get subdomains using (subdfiner,assetfinder,crt.sh) and remove duplicates
2) check if any subdomain have recorded credntials ex: `https://username@example.com` 
3) get alive subdomains using httpx
4) get urls using gau for every subdomain
5) search for leaked info in gau output like : usernames,passwords,token,apikeys
6) crawl every subdomain using katana
7) search for js files for every url in every subdomain , and look for secrets leaked using mantra
8) collect parameters from katana and gau output 

## usage 
```bash
echo "example.com" > list

./Do7h3R3c0n list 
```
## output example
![Screenshot_179](https://github.com/kiro6/Do7h3R3c0n/assets/57776872/201c44bb-936e-43f0-ac87-7bf9e91b2846)
