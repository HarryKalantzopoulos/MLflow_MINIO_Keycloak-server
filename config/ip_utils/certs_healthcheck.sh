#!/bin/sh

# Split the comma-separated domains
IFS=','

for domain in $DUCKDNS_DOMAINS; do
    DEST_DIR=/usr/.certs/$domain
    PRIVATEKEY="$DEST_DIR/privkey.pem"
    PUBLICKEY="$DEST_DIR/fullchain.pem"
    if [ "$domain" = "$MINIO_DOMAIN" ]; then
        PRIVATEKEY="$DEST_DIR/private.key"
        PUBLICKEY="$DEST_DIR/public.crt"
    fi

    if [ ! -f "$PRIVATEKEY" -o ! -f "$PUBLICKEY" ]; then
        echo "Certificates for $domain not found."
        unset IFS
        exit 1
    fi
done
unset IFS
exit 0
