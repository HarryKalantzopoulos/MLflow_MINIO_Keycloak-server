''' 
Authenticate required from Keycloak. For tracking experiments, also from MINIO.
Accepts POST requests for access token, session token(MINIO), and MINIO credentials.
'''
import os
import sys
from typing import Union, Dict, Tuple, Any, Optional
from datetime import datetime
from copy import deepcopy
import logging
from uuid import uuid4
import xml.etree.ElementTree as ET
import requests
import jwt
from jwcrypto.jwt import JWTExpired

from flask import Response, make_response, session, request, jsonify
from keycloak import KeycloakOpenID
from keycloak.exceptions import KeycloakAuthenticationError, KeycloakPostError
from mlflow.server.auth import store as auth_store
from werkzeug.datastructures import Authorization


from utils import (
    save_tokens,
    load_tokens,
    xml_writer,
    xml_reader,
    read_file

)

DEBUG = os.getenv("DEBUG", "false")

_logger = logging.getLogger(__name__)
if DEBUG.lower() == "true":
    _logger.addHandler(logging.StreamHandler(sys.stdout))
    _logger.setLevel(logging.DEBUG)

IP_ADDRESS = os.environ["HOST_IP"]
MLFLOW_S3_ENDPOINT_URL = os.environ["MLFLOW_S3_ENDPOINT_URL"]
KC_URL = os.environ["KC_URL"]
KC_REALM = os.environ["KC_REALM"]

KC_CLIENT_ID = os.environ["KC_CLIENT_ID"]
KC_CLIENT_SECRET = os.environ["KC_CLIENT_SECRET"]

KC_OPENID = KeycloakOpenID(
    server_url= KC_URL,
    realm_name= KC_REALM,
    client_id= KC_CLIENT_ID,
    client_secret_key= KC_CLIENT_SECRET
)

WELL_KNOWN = KC_OPENID.well_known()

MLF_AUTH_STORE = auth_store
REDIRECT_URL = f"https://{IP_ADDRESS}:45000/"

# The following used for python plug-in. Again, Keycloak settings (e.g. realm should match)

def parse_token(token: dict = None) -> dict:
    ''' Retrieve username from token. '''
    _logger.debug("parse token func")

    return {"username":token["preferred_username"], "is_admin":False}

def parse_minio_xml(root:str) -> Tuple[Dict[str,str], bool ]:
    ''' Retrieve key required for user to login. If token is valid, returns True'''
    _logger.debug("parse minio func")  
    namespace = {'ns': 'https://sts.amazonaws.com/doc/2011-06-15/'}

    try:
        minio_required = {
            "access_key_id": root.find('.//ns:AccessKeyId', namespace).text,
            "secret_access_key": root.find('.//ns:SecretAccessKey', namespace).text,
            "session_token": root.find('.//ns:SessionToken', namespace).text,
            "expiration": root.find('.//ns:Expiration', namespace).text
        }

        return minio_required, True

    # access token no longer valid.
    except AttributeError:
        message = root.find('.//ns:Message', namespace).text

        return {"Error": message}, False

def update_user(user_info: dict = None) -> None:
    ''' Update users in the auth database. '''
    _logger.debug("update user func")  

    if MLF_AUTH_STORE.has_user(user_info["username"]) is False:

        MLF_AUTH_STORE.create_user(
            user_info["username"],
            user_info["username"],
            user_info["is_admin"]
    )
    else:

        MLF_AUTH_STORE.update_user(
            user_info["username"],
            user_info["username"],
            user_info["is_admin"]
    )

def check_expiration(tokens:Dict[str,Any]) -> Optional[str]:
    '''
    Checks halftime and expiration of the user's token, stored in the server proceed to:
        1) Request new token (token expired).
        2) Refresh Token (half life passed).
        3) Do nothing (no action required).
    '''
    _logger.debug("check_expiration func")  
    current_time = datetime.now()
    try:

        issued_at = datetime.fromtimestamp(
            KC_OPENID.decode_token( tokens['access_token'])['iat'])
        expired_at = datetime.fromtimestamp(
            KC_OPENID.decode_token( tokens['access_token'])['exp'])
    # Not sure, I think if a token is expired or revoked, decode will throw error
    # At least user_info do.
    except (
        KeycloakAuthenticationError,
        JWTExpired
    ):
        return 'access_token'

    halftime = expired_at - (expired_at - issued_at)/2

    if current_time > expired_at:
        return 'access_token'

    if current_time > halftime:
        return 'refresh_token'

    return None

def request_session_token(access_token:str) -> Union[ET.Element,Dict[str,str]]:
    ''' Request session token from minio server'''
    _logger.debug("request_session_token func") 

    minio_url = MLFLOW_S3_ENDPOINT_URL

    data = {
        'Action': "AssumeRoleWithWebIdentity",
        'Version': "2011-06-15",
        'DurationSeconds': '3600',
        'WebIdentityToken': access_token,
    }

    response = requests.post(minio_url, data=data,timeout=10)

    if response.status_code == 200:

        return str(response.content, "utf-8")

    return {'Error': f'{response.status_code}: Failed to authenticate MINIO'}

def _post_access_token(user:str, passw:str)->Dict[str,str]:
    ''' POST request access token'''
    try:
        tokens = KC_OPENID.token(user, passw)
        _logger.debug("create access token %s", f"{tokens}")
    except KeycloakAuthenticationError:
        return jsonify({'Error 401': 'Username or password are not correct'})

    return tokens

def _post_refresh_tokens(refresh_token:Dict[str,str], user:str, passw:str)->Dict[str,str]:
    ''' POST request refresh token'''

    try:
        tokens = KC_OPENID.refresh_token(refresh_token)
        _logger.debug("refreshed token")
    except KeycloakPostError: # Invalid Token issue
        tokens = KC_OPENID.token(user, passw)
    
    return tokens

def handle_post_request(data: Dict[str,Any]) -> Dict[str,Any]:
    ''' Accept POST request to get access token'''
    _logger.debug("handle_post_request func")  

    use_token = 'access_token'
    username = data.get('username')
    password = data.get('password')

    tokens = load_tokens(username)

    if tokens is not None:

        use_token = check_expiration(tokens)

    if use_token is None:
        _logger.debug("Token is still valid %s",use_token)
        root = xml_reader(username)
        minio_creds,_ = parse_minio_xml( root )
        minio_creds.update(
            {
                "access_token": deepcopy(tokens["access_token"]),
                "iat": KC_OPENID.decode_token( tokens['access_token'])['iat'],
                "exp": KC_OPENID.decode_token( tokens['access_token'])['exp']
            }
        )

        tokens = jwt.encode(minio_creds, "U2hvdWxkU2V0UGFzc3dvcmQ0", algorithm="HS256")
        return jsonify({'token': tokens})

    if use_token == 'access_token':
        tokens = _post_access_token(username, password)
        if 'Error 401' in tokens:
            return tokens

    if use_token == 'refresh_token':
        tokens = _post_refresh_tokens(
            tokens['refresh_token'],
            username,
            password
        )
        if 'Error 401' in tokens:
            return tokens

    save_tokens(username, tokens)
    _logger.debug("store token")

    session_token = request_session_token(tokens['access_token'])

    if isinstance(session_token, dict):
        return jsonify( session_token )
    _logger.debug("wrting xml  %s",session_token)
    xml_writer(username, session_token)

    root = ET.fromstring(session_token)
    minio_creds, isvalid = parse_minio_xml(root)

    if not isvalid:
        return jsonify( minio_creds )
    _logger.debug("creating passport token  %s",minio_creds)
    minio_creds.update(
        {
            "access_token": deepcopy(tokens["access_token"]),
            "iat": KC_OPENID.decode_token( tokens['access_token'])['iat'],
            "exp": KC_OPENID.decode_token( tokens['access_token'])['exp'],
        }
    )

    _logger.debug("passport token  %s",minio_creds)
    tokens = jwt.encode(minio_creds, "U2hvdWxkU2V0UGFzc3dvcmQ0", algorithm="HS256")
    return jsonify({'token': tokens})

def authenticate_request() -> Union[Authorization, Response]:
    ''' Authenticate request '''
    _logger.debug("authenticate_request func")  
    # Process from client side to take the credentials
    if request.method == 'POST':
        data = request.json
        if 'username' in data and 'password' in data:
            return handle_post_request(data)

    resp = make_response()
    token = request.headers.get("Authorization", None)
    code = request.args.get('code', None)
    _logger.debug(f"code:{code}\ntoken: %s",token)
    #Case 1: User sends a token to login through console.
    if token is not None:
        # Bearer added by MLflow
        _logger.debug("Enter Case 1 token: %s",token)

        if token.startswith("Bearer"):
            token = token.replace("Bearer","").strip()
 
            jwt_token = KC_OPENID.decode_token(token)

            user_info = parse_token(jwt_token)
            update_user(user_info)
            _logger.debug(f"Success Case 1:{user_info}")
            return Authorization(auth_type="jwt", data=user_info)

    # Case 2: User has already login from web and he may proceed. Refresh token if required.
    if session.get("user_info", None) is not None:
        _logger.debug(f"Enter Case 2:{session}")

        try:
            access_token = session["access_token"]

            jwt_token = KC_OPENID.decode_token(access_token)
            user_info = parse_token(jwt_token)
            update_user(user_info)
            session["user_info"] = user_info

            return Authorization(auth_type="jwt", data=session["user_info"])

        except KeycloakAuthenticationError:
            _logger.debug(f"Failed Validate 2.1:{session}")
            # Something did not worked, reset session
            session.clear()
            resp.status_code = 401
            resp.set_data(
                "Failed to authenticate. Please refresh or contact the admin."
            )
            resp.headers["WWW-Authenticate"] = 'Bearer error="invalid_token"'
            return resp

    # Case 3.1: Weblogin: Login to Keycloak's webpage, request code
    if code is None and token is None:
        _logger.debug("Enter 3.1")
        if session.get("state", None) is None:
            session["state"] = str(uuid4())
            _logger.debug("Create session: %s", session["state"])

        auth_url = KC_OPENID.auth_url(
            redirect_uri=REDIRECT_URL,
            scope='email',
            state= session["state"]
        )

        resp.status_code = 301
        _logger.debug("Auth url: %s", auth_url)
        resp.headers["WWW-Authenticate"] = f'{auth_url}'

        # Redirect to kc page
        resp.headers["Content-Type"] = "application/x-www-form-urlencoded"
        resp.location = auth_url
        return resp

    # Case 3.2: Weblogin: Use code to request access token.
    if code is not None:
        _logger.debug("Enter 3.2:")
        if session.get("code",None) is None:
            session['code'] = code

        redirect_uri = REDIRECT_URL

        tokens = KC_OPENID.token(
            grant_type= "authorization_code",
            code= code,
            redirect_uri= redirect_uri,
        )

        _logger.debug("Case 3.2 access?: %s", tokens)
        if "access_token" in tokens:
            session['access_token'] = deepcopy(tokens['access_token'])
            session['refresh_token'] = deepcopy(tokens['refresh_token'])

            jwt_token = KC_OPENID.decode_token(tokens['access_token'])
            user_info = parse_token(jwt_token)
            update_user(user_info)
            session["user_info"] = user_info
            _logger.debug("Case 3.2 seems ok?:{session}")
            return Authorization(auth_type="jwt", data=user_info)

    return resp
