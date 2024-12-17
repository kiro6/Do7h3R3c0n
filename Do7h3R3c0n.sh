#!/bin/bash

# Define colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Define output files
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

# Check if the input argument is valid
check_argument() {
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
}

# Subdomain discovery
discover_subdomains() {
    echo -e "${BLUE}***********************************${NC}"
    echo -e "${BLUE}**** Start subdomain Discovery ****${NC}"
    echo -e "${BLUE}***********************************${NC}"

    # Start subfinder
    echo -e "${BLUE}[!]start subfinder${NC}"
    subfinder -dL "$filepath" -s all -silent -recursive -o ${subfinderDomains} >/dev/null
    wc -l ${subfinderDomains} | awk "{print \"${GREEN}[*] \" \$1 \" subdomain(s) discovered by subfinder!${NC}\"}"

    # Start assetfinder
    echo -e "${BLUE}[!]start assetfinder${NC}"
    cat "$filepath" | assetfinder -subs-only >${assetfinderDomains}
    wc -l ${assetfinderDomains} | awk "{print \"${GREEN}[*] \" \$1 \" subdomain(s) discovered by assetfinder!${NC}\"}"

    # Collect subs from crt.sh
    echo -e "${BLUE}[!]collecting subs from crt.sh${NC}"
    while IFS= read -r line; do
        curl -s "https://crt.sh/?q=${line}&output=json" | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | sort -u | tee -a ${crtDomains} >/dev/null
    done <"$filepath"
    wc -l ${crtDomains} | awk "{print \"${GREEN}[*] \" \$1 \" subdomain(s) discovered by crt.sh!${NC}\"}"

    # Combine and deduplicate subdomains
    cat ${subfinderDomains} ${assetfinderDomains} ${crtDomains} | sort -u >${allSubDomains}
    wc -l ${allSubDomains} | awk "{print \"${GREEN}[*] \" \$1 \" total unique subdomain(s) discovered!${NC}\"}"
}

# Check alive subdomains
check_alive_subdomains() {
    echo -e "${BLUE}[!]start httpx${NC}"
    httpx -l ${allSubDomains} -silent -timeout 3 -title -status-code -o ${aliveSubDomainsUrlsDetailed} >/dev/null
    awk '{print $1}' ${aliveSubDomainsUrlsDetailed} >${aliveSubDomainsUrls}

    # Extract potential usernames or passwords
    if grep -q '@' ${aliveSubDomainsUrls}; then
        echo -e "${YELLOW}[*]Potential usernames or passwords found and saved in ${potentialUsernamesOrPasswords}${NC}"
        grep '@' ${aliveSubDomainsUrls} >${potentialUsernamesOrPasswords}
    fi

    # Clean up subdomains from @ URLs
    sed -i '/@/d' ${aliveSubDomainsUrls}
    wc -l ${aliveSubDomainsUrls} | awk "{print \"${GREEN}[*] \" \$1 \" alive subdomain(s)!${NC}\"}"
}

# Collect URLs and JS files
discover_urls_and_js() {
    echo -e "${BLUE}************************************${NC}"
    echo -e "${BLUE}**** Start URL and JS Discovery ****${NC}"
    echo -e "${BLUE}************************************${NC}"

    # Extract alive subdomains without protocol
    awk -F[/:?] '{print $4}' ${aliveSubDomainsUrls} >${aliveSubDomains}

    # Start gau
    echo -e "${BLUE}[!]start gau${NC}"
    while IFS= read -r sub; do
        mkdir "$sub" 2>/dev/null
        cd $sub
        gau $sub --providers wayback --fc 404 --o ${gauUrls} >/dev/null
        # Extract potential sensitive data
        grep -E '[?&]pass' ${gauUrls} >${potentialPasswords} && \
        echo -e "${YELLOW}[*]Potential passwords saved in ${potentialPasswords} for $sub${NC}"
        grep -E '[?&]name' ${gauUrls} >${potentialUsernames} && \
        echo -e "${YELLOW}[*]Potential usernames saved in ${potentialUsernames} for $sub${NC}"
        grep -E '[?&](token|session|sso|api|key|uid|id)' ${gauUrls} >${potentialTokens} && \
        echo -e "${YELLOW}[*]Potential tokens saved in ${potentialTokens} for $sub${NC}"
        cd ..
    done < ${aliveSubDomains}
    echo -e "${GREEN}[*]done gau${NC}"

    # Start Katana
    echo -e "${BLUE}[!]start Katana${NC}"
    declare -a urls
    while IFS= read -r line; do
        urls+=("$line")
    done <${aliveSubDomainsUrls}
    for url in "${urls[@]}"; do
        sub=$(echo "$url" | awk -F[/:?] '{print $4}')
        cd $sub
        katana -u $url -silent -o ${katanaUrls} >/dev/null
        cd ..
    done
    echo -e "${GREEN}[!]done Katana${NC}"

    # JS Discovery
    echo -e "${BLUE}[*]start jsfinder and mantra${NC}"
    while IFS= read -r sub; do
        cd $sub >/dev/null 2>/dev/null
        jsfinder -l ${katanaUrls} -s -o ${js} >/dev/null
        if [ -e ${js} ]; then
            cat ${js} | mantra -s >${jsSecrets}
            [ -s ${jsSecrets} ] && echo -e "${YELLOW}[*]JS secrets found for ${sub}!${NC}"
        fi
        cd ..
    done < ${aliveSubDomains}
    echo -e "${GREEN}[*]done jsfinder and mantra${NC}"
}

# Collect parameters
discover_parameters() {
    echo -e "${BLUE}****************************${NC}"
    echo -e "${BLUE}**** Parameter Discovery ****${NC}"
    echo -e "${BLUE}****************************${NC}"
    while IFS= read -r sub; do
        cd $sub >/dev/null 2>/dev/null
        cat ${gauUrls} ${katanaUrls} | grep -oP '[?&]\K\w+(?==|$)' >${params}
        cd ..
    done <${aliveSubDomains}
    echo -e "${GREEN}[*]Parameter discovery completed${NC}"
}

# Main script execution
check_argument "$@"
discover_subdomains
check_alive_subdomains
discover_urls_and_js
discover_parameters

