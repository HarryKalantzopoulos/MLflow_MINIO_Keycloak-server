# Branches

The main banch uses DuckDNS, certbot and SNSD MINIO if you want to check:

Same, but with MNMD MINIO got to https://github.com/HarryKalantzopoulos/MLflow_MINIO_Keycloak-server/tree/https_dns_certbot_mnmd

With you public IP and openssl (self signed SSL/TLS) https://github.com/HarryKalantzopoulos/MLflow_MINIO_Keycloak-server/tree/https_self_signed_certs

Only http https://github.com/HarryKalantzopoulos/MLflow_MINIO_Keycloak-server/tree/http_only

# MLflow server with MINIO, PostgreSQL, Keycloak, DNS and certbot.

Setting up an MLflow server with:
* MINIO to store artifacts.
* Keycloak for ID management and authentication.
* PorstgreSQL for database.
* https: DuckDNS with certbot certificates
* http: For internal communication between the containers.

# Components

The main components are Keycloack, MINIO, MLflow, DuckDNS, certbot, NGINX, Postgresql.

Keycloak is your user ID manager, provided authentication and authorization.

MINIO provides a build-in method to perform a single sign on (SSO) login, by authenticate through Keycloak. The authentication can be done either by web or from terminal.

MLflow provides a basic authentication, but we will modify it in order to gain access with the Keycloak authentication. Users can login to the MLflow webpage via SSO (Keycloak client set for MINIO). They need to request access token from Keycloak and session token from MINIO check: 

config/mlflow_server/mlflow_auth_plugin/kc_auth.py

DuckDNS is a free service that allows you to bind your own favorite subdomain under duckdns.org to the public IP address in use from your router. With certbot the SSL/TSL provided are trustworthy.

# Requirements:

* Docker engine + compose or desktop

* Three DuckDNS domains.

* Cronjob calibration, especially for Dynamic IP, check:
  ./config/ip_utils/duckdns_certbot.Dockerfile

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

A single-node single-drive MINIO setup is provided. If you want to change it to a single node and drive, make sure to update the docker compose and config/nginx/nginx.conf accordingly.

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

## **DuckDNS, certbot and cronjob**
This service is required to connect DuckDNS to the public IP address. Afterwards,
certbot will create the ssl credentials for each service (Keycloak, MINIO, MLflow).

These ssl certificates are authorized through the web, so it is not required to set a workflow to trade the public key with other services and users.

In *config_services/ip_utils/duckdns_certbot.Dockerfile*, you can set your desired cronjob. It will update your DuckDNS, with the new IP, along with the SSL certificates.

<span style="color:orange">**Notice:**</span> MINIO SSL certificates should be renamed:
 - fullchain.pem &rarr; public.crt
 - privkey.pem &rarr; private.key

The above certificates are used in NGINX reverse proxy.

## **NGINX**
NGINX reverse proxy is used to connect each service with the domain name. It will re-direct any http to https and it will also work as a load-balancer. The aforementioned SSL certificates are used to achieve a secure communication. SSL certificates generated by certbot are trustworthy, so no further action is required.


## **MLflow client example**
You can check how set a client for experiment tracking into **mlflow_client_example.ipynb**.
