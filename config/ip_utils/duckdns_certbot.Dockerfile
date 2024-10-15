FROM alpine:latest

RUN apk update && apk add coreutils
RUN apk add --update --no-cache curl nano python3 py3-pip

# Requires virtual environment, only apk packages permited.
RUN python3 -m venv /opt/certbot-venv
RUN . /opt/certbot-venv/bin/activate && pip install --no-cache-dir certbot certbot_dns_duckdns

#Include /opt/certbot-venv packages
ENV PATH="/opt/certbot-venv/bin:$PATH"

WORKDIR /usr/src/
RUN mkdir -p /usr/.certs

COPY config_services/ip_utils/renew_duckdns.sh /usr/src/renew_duckdns.sh
COPY config_services/ip_utils/renew_certs.sh /usr/src/renew_certs.sh
COPY config_services/ip_utils/certs_healthcheck.sh /usr/src/certs_healthcheck.sh

RUN chmod +x /usr/src/renew_duckdns.sh /usr/src/renew_certs.sh certs_healthcheck.sh

# Update at 05:00 UTC 1st day of month.
RUN temp_cron_list=$(mktemp) && \
    echo "0       4       13       *       *       /usr/src/renew_certs.sh" >> "$temp_cron_list" && \
    echo "0       4       13       *       *       /usr/src/renew_duckdns.sh" >> "$temp_cron_list"
