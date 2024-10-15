#!/bin/sh

response_code=$(curl -o /dev/null -s -w "%{http_code}\n" http://mlflow:5000)

if [ "$response_code" = "200" -o "$response_code" = "301" ]; then
    exit 0
fi
echo "Failed with code: $response_code"
exit 1
