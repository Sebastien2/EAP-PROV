import est.client
import ssl
import hashlib
import sys
import jwt
import tempfile
import requests
import base64
import os
import json
from urllib.parse import urlparse
from jsonpath_ng import jsonpath, parse

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def enroll(url, username, jwt_token, cert_hash, common_name):

    host = None
    port = None
    url_parse_res = urlparse(url)

    if url_parse_res.scheme == 'est':
        host = url_parse_res.netloc
        port = 4443 # by default
    else:
        print('We do not support other provisoning protocols yet')
        return

    tempfile_ca = tempfile.NamedTemporaryFile('w+t')
    tempfile_csr = tempfile.NamedTemporaryFile('w+t')

    server_certificate = ssl.get_server_certificate((host, port))
    server_der_certificate_bytes = ssl.PEM_cert_to_DER_cert(server_certificate)

    hash = hashlib.sha256()
    hash.update(server_der_certificate_bytes)
    if cert_hash == hash.hexdigest()[:len(cert_hash)]:
        print('OK')
        url = 'https://' + host + ':' + str(port) + '/.well-known/est/cacerts'
        # disable InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        req = requests.get(url, verify=False)
        tempfile_ca.write(req.content.decode("utf-8"))
        tempfile_ca.seek(0)
    else:
        print('ERROR')
        print('Expected certificate hash:', end='')
        print(cert_hash)
        print('But get this hash from the server:' + hash.hexdigest())
        return

    client = est.client.Client(host, port, tempfile_ca.name)

    # client.set_basic_auth(username, password)
    client.set_jwt(jwt_token)

    # Create CSR and get private key used to sign the CSR.
    country = 'FI'
    state = 'Uusima'
    city = 'Helsinki'

    # Generating a csr programatically with pyopenssl is not possible,
    # I read the https://github.com/plinss/acmebot code and they use another library
    # instead of spending so much time I choose the simple way
    openssl_generate_csr_command = 'openssl req -newkey ec:<(openssl genpkey -genparam -algorithm ec -pkeyopt ec_paramgen_curve:P-256) -keyout key.pem -subj "/C=' + country + '/ST=' + state + '/L=' + city + '/CN=' +  common_name + '" -out ' + tempfile_csr.name + ' -nodes'
    os.system('/bin/bash' + ' -c "' + openssl_generate_csr_command + '"')

    tempfile_csr.seek(0)
    with open(tempfile_csr.name) as f:
        try:
            client_cert = client.simpleenroll(f.read())
            f = open("cert.pem", "w")
            f.write( client_cert)
            print(bcolors.OKCYAN + 
              '################################################\n' +
              '##### Provisioning Completed Successfully ######\n' +
              '################################################\n' +
              bcolors.ENDC)
        except Exception as err:
            print(err)
    
    tempfile_ca.close()
    tempfile_csr.close()

    return True

if __name__ == '__main__':

    # register 'est://' scheme
    for method in filter(lambda s: s.startswith('uses_'), dir(urlparse)):
        getattr(urlparse, method).append('est')

    j = json.loads(sys.argv[1])['provision']

    host = j['url']
    port = 4443 # by default
    jwt_token = j['client_token']
    server_cert_hashes = j['server_cert_hashes']
    payload = None
    username=None

    try:
        # get only the payload without the signature verify
        # add padding to avoid incorrect padding error
        # split the payload from JWT: JWT format -> header.payload.signature
        payload = json.loads(base64.b64decode((jwt_token.split('.')[1] + '===')).decode('utf-8'))
        if payload['sub'] == 'provisioning':
            username = payload['user']
        else:
            print('Invalid JWT!')
    except Exception as err:
        print(err)

    for i in range(0,len(server_cert_hashes)):
        # if download_config(url=host, jwt_token=jwt, cert_hash=server_cert_hashes[i]['h'+str(i)]):
        #     break

        if enroll(url=host, username=username, jwt_token=jwt_token, 
            cert_hash=server_cert_hashes[i]['h'+str(i)], common_name=username):
            break
