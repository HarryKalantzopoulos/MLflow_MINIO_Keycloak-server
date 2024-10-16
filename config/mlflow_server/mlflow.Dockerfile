FROM python:3.10
WORKDIR /usr/src/app
RUN pip install --no-cache-dir --upgrade pip wheel setuptools
RUN pip install --no-cache-dir  mlflow==2.14.3 boto3 psycopg2 cryptography
RUN pip install --no-cache-dir requests python-keycloak==4.2.2 pyjwt defusedxml
COPY config/mlflow_server/basic_auth.ini ./basic_auth.ini
COPY config/mlflow_server/mlflow_auth_plugin/kc_auth.py ./kc_auth.py
COPY config/mlflow_server/mlflow_auth_plugin/utils.py ./utils.py
COPY config/mlflow_server/mlflow_auth_plugin/healthcheck.sh ./healthcheck.sh
RUN chmod +x ./healthcheck.sh
