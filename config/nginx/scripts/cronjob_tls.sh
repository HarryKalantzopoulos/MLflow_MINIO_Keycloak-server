#!/bin/sh

temp_cron_list=$(mktemp)

pem_file="/etc/nginx/certs/public.pem"
cert_generator="/opt/scripts/generate_tls.sh"
cronjob_tls="/opt/scripts/cronjob_tls.sh"
half_life_days=45


# Create Cronjob if not added yet.
crontab -l > "$temp_cron_list"
if ! grep -q "$cronjob_tls" "$temp_cron_list"; then
    echo "0       5       1       *       *       $cronjob_tls" >> "$temp_cron_list"
    crontab "$temp_cron_list"
    echo "$(date): Cronjob for refreshing TLS added." >> $LOGGER
fi

# If it is the first time.
if [ ! -f $pem_file ]; then
    echo "$(date): TLS not found, create a new one." >> $LOGGER
    /bin/bash -c "$cert_generator >> $LOGGER 2>&1"
    exit 0
fi

# IP is not included in the certificate! Modify generate_tls
# if you need to add more than one IPs line 36.
if ! openssl x509 -in $pem_file -text | grep "IP Address" | grep -q "${HOST_IP}"; then
    echo "$(date): $HOST_IP does not match the certificate. Issue a new one." >> $LOGGER
    /bin/bash -c "$cert_generator >> $LOGGER 2>&1"
    exit 0
fi

echo "$(date): Checking TLS validity." >> $LOGGER

current=$(date "+%s")
expires_at=$(date -d "$(: | openssl x509 -enddate -noout -in "$pem_file" |cut -d= -f 2)" +%s)
days_until_expiry=$(( ($expires_at - $current) / (24 * 60 * 60) ))

if [ $days_until_expiry -le $half_life_days ]; then
  echo "Certificate expires in $days_until_expiry days. Running renewal script." >> "$LOGGER"
  /bin/bash -c "$cert_generator >> $LOGGER 2>&1"
else
  echo "Certificate still valid for $days_until_expiry days. No action required." >> "$LOGGER"
fi

echo "$(date): Finished!." >> "$LOGGER"
