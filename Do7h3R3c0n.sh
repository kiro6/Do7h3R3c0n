#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

subfinderDomains='subfinderDomains.txt'
assetfinderDomains='assetfinderDomains.txt'
crtDomains='crtDomains.txt'
allSubDomains='allSubDomains.txt'
aliveSubDomainsUrls='aliveSubDomainsUrls.txt'
aliveSubDomainsUrlsDetailed='aliveSubDomainsUrlsDetailed.txt'
aliveSubDomains='aliveSubDomains.txt'

potentialUsernamesOrPasswords='potentialUsernamesOrPasswords.txt'
potentialPasswords='potentialPasswords.txt'
potentialUsernames='potentialUsernames.txt'
potentialTokens='potentialTokens.txt'

gauUrls='gauUrls.txt'
katanaUrls='katanaUrls.txt'
js='js.txt'
jsSecrets='jsSecrets.txt'

params='params.txt'

# Check if an argument is provided
if [ "$#" -ne 1 ]; then
    echo -e "${RED}[!] No argument was provided!${NC}"
    echo -e "${RED}Usage: DoTheRecon domainsList.txt${NC}"
    exit 1
fi

filepath=$1
if [[ ! -e $filepath ]]; then
    echo -e "${RED}[!] $filepath was not found!${NC}"
    exit 1
fi

echo -e "${BLUE}***********************************${NC}"
echo -e "${BLUE}**** Start subdomain Discovery ****${NC}"
echo -e "${BLUE}***********************************${NC}"

# start subfinder
echo -e "${BLUE}[!]start subfinder${NC}"

subfinder -dL "$filepath"  -silent -recursive -o ${subfinderDomains} >/dev/null

wc -l ${subfinderDomains} | awk "{print \"${GREEN}[*] \" \$1 \" subdomain was discovered by subfinder!${NC}\"}"

# start assetfinder
echo -e "${BLUE}[!]start assetfinder${NC}"

cat "$filepath" | assetfinder -subs-only >${assetfinderDomains}

wc -l ${assetfinderDomains} | awk "{print \"${GREEN}[*] \" \$1 \" subdomain was discovered by assetfinder!${NC}\"}"

# start crt.sh
echo -e "${BLUE}[!]collecting subs from crt.sh${NC}"

while IFS= read -r line; do
    curl -s "https://crt.sh/?q=${line}&output=json" | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | sort -u | tee -a ${crtDomains} >/dev/null
done <"$filepath"

wc -l ${crtDomains} | awk "{print \"${GREEN}[*] \" \$1 \" subdomain was discovered by crt.sh!${NC}\"}"

# remove dublicates
cat ${subfinderDomains} ${assetfinderDomains} ${crtDomains} | sort -u | uniq >${allSubDomains}

wc -l ${allSubDomains} | awk "{print \"${GREEN}[*] \" \$1 \" subdomain was discovered in total!${NC}\"}"

# start httpx
echo -e "${BLUE}[!]start httpx${NC}"

httpx -l ${allSubDomains} -silent -timeout 3 -o ${aliveSubDomainsUrls} >/dev/null
httpx -l ${allSubDomains} -silent -timeout 3 -title -status-code -o ${aliveSubDomainsUrlsDetailed} >/dev/null

# check for potential usernames or passwords
if grep -q '@' ${aliveSubDomainsUrls}; then
    echo -e "${YELLOW}[*]found potential usernames or passwords saved in ${potentialUsernamesOrPasswords} ${NC}"
    grep '@' ${aliveSubDomainsUrls} >${potentialUsernamesOrPasswords}
fi

# clean up subdomains from @ urls
sed -i '/@/d' ${aliveSubDomainsUrls}
wc -l ${aliveSubDomainsUrls} | awk "{print \"${GREEN}[*] \" \$1 \" subdomain is alive!${NC}\"}"

echo -e "${BLUE}************************************${NC}"
echo -e "${BLUE}**** Start Url and JS Discovery ****${NC}"
echo -e "${BLUE}************************************${NC}"

# get alive subdomains without https:// or http://
awk -F[/:?] '{print $4}' ${aliveSubDomainsUrls} >${aliveSubDomains}

# start gau for waybackurls
echo -e "${BLUE}[!]start gau${NC}"

while IFS= read -r sub; do
    mkdir "$sub" 2>/dev/null
    cd $sub
    gau $sub --providers wayback --fc 404 --o ${gauUrls} >/dev/null 2>/dev/null  ## you can add   ,commoncrawl,otx,urlscan

    # Check if the file contains URLs with "pass" paramter for potential passwords
    if grep -q -E '[?&]pass' ${gauUrls}; then
        grep -E '[?&]pass' ${gauUrls} >${potentialPasswords}
        echo -e "${YELLOW}[*]Potential passwords found and saved to ${potentialPasswords} in $sub ${NC}"
    fi

    # Check if the file contains URLs with "name" paramter for potential usernames
    if grep -q -E '[?&]name' ${gauUrls}; then
        grep -E '[?&]name' ${gauUrls} >${potentialUsernames}
        echo -e "${YELLOW}[*]Potential usernames found and saved to ${potentialUsernames} in $sub ${NC}"
    fi

    if grep -q -E '[?&]\b(token|session|sso|api|key|uid|id)\b' ${gauUrls}; then
        grep -E '[?&]\b(token|session|sso)\b' ${gauUrls} >${potentialTokens}
        echo -e "${YELLOW}[*]Potential tokens or ApiKeys found and saved to ${potentialTokens} in $sub ${NC}"
    fi

    cd ..
done < ${aliveSubDomains}

echo -e "${GREEN}[*]done gau${NC}"

# start katana for crawling and url extraction
echo -e "${BLUE}[!]start Katana${NC}"

declare -a urls

while IFS= read -r line; do
    urls+=("$line")
done <${aliveSubDomainsUrls}

for url in "${urls[@]}"; do
    sub=$(echo "$url" | awk -F[/:?] '{print $4}')
    cd $sub
    katana -u $url -silent -o ${katanaUrls} >/dev/null 2>/dev/null
    cd ..
done

echo -e "${GREEN}[!]done Katana${NC}"

# start jsfinder and mantra for search jsfiles for secrets
echo -e "${BLUE}[*]start jsfinder and mantra${NC}"

while IFS= read -r sub; do
    cd $sub >/dev/null 2>/dev/null
    jsfinder -l ${katanaUrls} -s -o ${js} >/dev/null 2>/dev/null
    if [ -e ${js} ]; then
        cat ${js} | mantra -s >${jsSecrets}
        if [ -s ${jsSecrets} ]; then
            echo -e "${YELLOW}[*]JS secrets was found in ${sub} .${NC}"
        fi
    fi
    cd ..
done < ${aliveSubDomains}


echo -e "${GREEN}[*]done jsfinder and mantra${NC}"

echo -e "${BLUE}****************************${NC}"
echo -e "${BLUE}**** Paramter Discovery ****${NC}"
echo -e "${BLUE}****************************${NC}"


echo -e "${BLUE}[!]collect paramters from gau and Katana${NC}"

while IFS= read -r sub; do
    cd $sub >/dev/null 2>/dev/null   
    cat ${gauUrls} ${katanaUrls} | grep -oP '[?&]\K\w+(?==|$)' >${params}
    cd ..
done <${aliveSubDomains}

echo -e "${GREEN}[*] done collect paramters from gau and Katana${NC}"


