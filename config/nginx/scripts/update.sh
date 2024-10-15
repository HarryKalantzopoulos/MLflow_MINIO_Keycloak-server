#!/bin/sh
set -e

apk add --no-cache bash openssl curl nano
apk update && apk add coreutils
chmod 755 /opt/scripts/cronjob_tls.sh /opt/scripts/generate_tls.sh
echo "Updates finished!"
