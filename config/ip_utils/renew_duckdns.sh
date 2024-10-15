#!/bin/sh

# Split the comma-separated domains
IFS=','

for domain in $DUCKDNS_DOMAINS; do
    # Update DuckDNS for all domains
    curl "https://www.duckdns.org/update?domains=${domain}&token=${DUCKDNS_TOKEN}&ip="
done

unset IFS
