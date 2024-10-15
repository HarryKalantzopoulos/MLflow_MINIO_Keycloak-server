#!/bin/sh


mc alias set internal_mc http://minio1:9000 ${MINIO_ROOT_USER} ${MINIO_ROOT_PASSWORD}

bucket_exists=$(mc find internal_mc --maxdepth 2 --name ${MINIO_BUCKET_NAME})

if [ -z "$bucket_exists" ]; then
    mc mb --with-versioning internal_mc/${MINIO_BUCKET_NAME}
else
    echo "${MINIO_BUCKET_NAME} bucket already exists."
fi

exit 0


