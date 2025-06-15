#!/bin/bash

# Simple RDAP query script
# Usage: ./rdap.sh domain.com

if [ $# -eq 0 ]; then
    echo "Usage: $0 <domain>"
    echo "Example: $0 google.com"
    exit 1
fi

DOMAIN="$1"
TLD=$(echo "$DOMAIN" | awk -F. '{print $NF}')

# Common RDAP endpoints for major TLDs
case "$TLD" in
    "com"|"net")
        RDAP_URL="https://rdap.verisign.com/com/v1/domain/$DOMAIN"
        ;;
    "org")
        RDAP_URL="https://rdap.publicinterestregistry.org/rdap/domain/$DOMAIN"
        ;;
    "tv")
        RDAP_URL="https://rdap.nic.tv/domain/$DOMAIN"
        ;;
    "io")
        RDAP_URL="https://rdap.nic.io/domain/$DOMAIN"
        ;;
    "uk")
        RDAP_URL="https://rdap.nominet.uk/uk/domain/$DOMAIN"
        ;;
    *)
        echo "Trying IANA bootstrap service..."
        RDAP_URL="https://rdap.iana.org/domain/$DOMAIN"
        ;;
esac

echo "Querying RDAP for: $DOMAIN"
echo "Endpoint: $RDAP_URL"
echo "----------------------------------------"

curl -s "$RDAP_URL" | jq . || {
    echo "Failed to query RDAP. Trying IANA bootstrap..."
    curl -s "https://rdap.iana.org/domain/$DOMAIN" | jq .
} 