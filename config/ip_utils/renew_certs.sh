#!/bin/sh

# Split the comma-separated domains
IFS=','

# Generate/renew certificates for each domain
for domain in $DUCKDNS_DOMAINS; do
    SOURCE_DIR=/usr/src/.certbot/config/live/$domain.duckdns.org
    DEST_DIR=/usr/.certs/$domain
    mkdir -p "$DEST_DIR"
    certbot certonly --non-interactive --agree-tos \
        --email $EMAIL \
        --preferred-challenges dns \
        --authenticator dns-duckdns \
        --dns-duckdns-token $DUCKDNS_TOKEN \
        --dns-duckdns-propagation-seconds 60 \
        -d $domain.duckdns.org \
        --config-dir /usr/src/.certbot/config \
        --logs-dir /usr/src/.certbot/logs \
        --work-dir /usr/src/.certbot/work

    # Minio domain requires renaming the files
    if [ "$domain" = "$MINIO_DOMAIN" ]; then
        cp $SOURCE_DIR/privkey.pem $DEST_DIR/private.key
        cp $SOURCE_DIR/fullchain.pem $DEST_DIR/public.crt
    else
        cp $SOURCE_DIR/privkey.pem $DEST_DIR/privkey.pem
        cp $SOURCE_DIR/fullchain.pem $DEST_DIR/fullchain.pem
    fi
done

unset IFS