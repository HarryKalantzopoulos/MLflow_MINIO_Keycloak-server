# MLflow server with MINIO, PostgreSQL and Keycloak.

Setting up an MLflow server with:
* MINIO to store artifacts.
* Keycloak for ID management and authentication.
* PorstgreSQL for database.
* http: Just for local experimentation.

# Components

The main components are Keycloack, MINIO, MLflow, NGINX, Postgresql.

Keycloak is your user ID manager, provided authentication and authorization.

MINIO provides a build-in method to perform a single sign on (SSO) login, by authenticate through Keycloak. The authentication can be done either by web or from terminal.

MLflow provides a basic authentication, but we will modify it in order to gain access with the Keycloak authentication. Users can login to the MLflow webpage via SSO (Keycloak client set for MINIO). They need to request access token from Keycloak and session token from MINIO check: 

config/mlflow_server/mlflow_auth_plugin/kc_auth.py

# Requirements:

* Docker engine + compose or desktop

<span style="color:orange"> **Docker volume permissions:** </span>
 
  - In linux based system, you will need to create  a priori the volumes and set the read-write permissions for each. (e.g. chmod or chown {your_docker_volume}).

  -  For Postgresql, user's id may required. You can acquire them with

  ```bash
    id -u #UID
    id -g #GID
  ```
  and set it in docker compose:
  ```yaml
  db:
    image: postgres:16.3
    user: "UID:GID"
  ```
  remember to chown of the mounted volume beforehand!

**Important to keep the mlflow database intact after restart. Always, keep a backup.**

**Use .example_env to define your own .env**

# Checking development (https, dns)

Rename .example_env to .env an run:

```bash
docker compose up --build -d
```
<span style="color:red"> **Do not use on production** </span>

# MINIO

A multi-node multi-drive MINIO setup is provided. If you want to change it to a single node and drive, make sure to update the docker compose and config/nginx/nginx.conf accordingly.

e.g.:
```docker

minio:

  image: quay.io/minio/minio
  container_name: minio
  environment:
    MINIO_ROOT_USER: ${AWS_ACCESS_KEY_ID}
    MINIO_ROOT_PASSWORD: ${AWS_SECRET_ACCESS_KEY}
    ...
  volumes:
    - ./minio_data/data:/data
  expose:
    - 9000:9000
    - 9001:9001
  healthcheck:
    test: "mc ready local"
    interval: 5s
    timeout: 5s
    retries: 5
  command: server /data --console-address ":9001"
```

# Setting up Keycloak - MINIO

Upon initialization, you will need to start the keycloak and minio services to set up the SSO login for the MINIO. An exported Keycloak environment is given at config/keycloak_only_for_testing/realm-export.json. You may use the file to set up and check the services, but keep in mind to change the keycloak  client, realm, etc.

How to set up Keycloak-MINIO, just follow the official manual:

https://min.io/docs/minio/container/operations/external-iam/configure-keycloak-identity-management.html

You may configure MINIO with environmental variables instead of the webpage.

<span style="color:orange">**Notice:**</span> When you create a new user, there is no attributes in Keycloak *v.24.0.5*, create a group and assign the user into this group instead.


After you configure Keycloak - MINIO, update the environmental variables:

@ .env
```yaml
KEYCLOAK_SCOPE=
KEYCLOAK_CLIENT_ID=
KEYCLOAK_CLIENT_ID_SECRET=
KC_REALM=
```
@ docker-compose.yaml:
From keycloak-web you can remove/change the volumes and the command  "--import-realm". 

Keycloak configurations can be exported and reused. On tab "Realm Settings" go to the top left corner and click on "Action" drop down list and select "Partial Export".

Use the export by:

```yaml
keycloak:
  image: quay.io/keycloak/keycloak:24.0.5
  volumes:
  - ./realm_export.json:/opt/keycloak/data/import/realm_export.json:ro
  command: start --import-realm
```
<span style="color:orange">**Notice:**</span> The users are not exported!

<span style="color:teal">**Notice:**</span> Keycloak < *v.18*, requires to add /auth at your keycloak urls.

MINIO 's openID configuration can be stored as environmental variables, and become immutable. For example, if we want to create a configuration named "KEYCLOAK_IAM" do:

```docker
# KEYCLOAK_IAM is the name of your OPENID configurations
MINIO_IDENTITY_OPENID_CONFIG_URL_KEYCLOAK_IAM:
MINIO_IDENTITY_OPENID_REDIRECT_URI_KEYCLOAK_IAM:
MINIO_IDENTITY_OPENID_VENDOR:
MINIO_IDENTITY_OPENID_REDIRECT_URI_DYNAMIC_KEYCLOAK_IAM:
MINIO_IDENTITY_OPENID_SCOPES_KEYCLOAK_IAM:
MINIO_IDENTITY_OPENID_CLIENT_ID_KEYCLOAK_IAM:
MINIO_IDENTITY_OPENID_CLIENT_SECRET_KEYCLOAK_IAM:
```

<span style="color:orange">**Notice:**</span> Remember to restart your minio container, if SSO does not appear.

## **MLflow**

MLflow has a basic authentication (username/password) to login. However, we are going to use the Keycloak-MINIO authentication to login, track experiments and store artifacts.

To do this, the required files are:

- config_services/mlflow_server/basic_auth.ini
- config_services/mlflow_server/mlflow_auth_plugin/kc_auth.py

*kc_auth.py* contains:
- the SSO pipeline.
- POST request for a registered user to acquire a session token (from MINIO).
- Validation and Refresh token pipeline

## **NGINX**
NGINX reverse proxy is used to connect each service with the domain name. It will re-direct any http to https and it will also work as a load-balancer. The aforementioned SSL certificates are used to achieve a secure communication. SSL certificates generated by certbot are trustworthy, so no further action is required.


## **MLflow client example**
You can check how set a client for experiment tracking into **mlflow_client_example.ipynb**.
