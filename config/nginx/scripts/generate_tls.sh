#!/bin/bash

root_dir=/etc/nginx/root_certs
default_dir=/etc/nginx/certs
cert_meta="/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/OU=$SECTOR/CN=$HOST_IP/emailAddress=$EMAIL"

mkdir -p $default_dir
mkdir -p $root_dir

cd $root_dir

check_root_keys() {
    if [[ -f "rootcert.key" && -f "rootcert.pem" ]]; then
        echo "Root keys already exist. Skipping root key generation."
        return 0
    else
        return 1
    fi
}

# Generate a root password.
if ! check_root_keys; then
    openssl genrsa -aes256 -passout pass:$ROOT_PASS -out rootcert.key 2048
    openssl req -new -key rootcert.key  -passin pass:$ROOT_PASS -subj $cert_meta -out rootcert.csr
fi

openssl x509 -req -in rootcert.csr -sha512 -signkey rootcert.key -passin pass:$ROOT_PASS -out rootcert.pem -days 90

#generate service password
openssl genrsa -aes256 -passout pass:$TLS_PASS -out _private.key 2048

#remove password, unecrypted, ready to use for transaction between services.
openssl pkcs8 -inform PEM  -passin pass:$TLS_PASS -outform PEM -in _private.key -topk8 -nocrypt -v1 PBE-SHA1-3DES -out private.key

openssl req -new -key private.key -passin pass:$TLS_PASS -subj $cert_meta -out server.csr
openssl x509 -req -in server.csr -passin pass:$ROOT_PASS -extfile <(printf "subjectAltName=IP:127.0.0.1,IP:$HOST_IP") -SHA256 -CA rootcert.pem -CAkey rootcert.key -CAcreateserial -out public.pem -days 90

mv public.pem "$default_dir/public.pem"
mv private.key "$default_dir/private.key"

cd $default_dir
# Required for MINIO, no pem files
cp public.pem public.crt
chmod 655 public.pem public.crt
# Stricter rules
chmod 600 private.key
