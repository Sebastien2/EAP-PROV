import ssl
import sys
import json
import hashlib
import tempfile
import requests
from urllib.parse import urlparse
from jsonpath_ng import jsonpath, parse
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import SubjectAltNameWarning

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

def download_config(url, jwt_token, cert_hash):
    url_obj = urlparse(url)

    server_address = (url_obj.hostname, url_obj.port)
    server_certificate = ssl.get_server_certificate(server_address)
    server_der_certificate_bytes = ssl.PEM_cert_to_DER_cert(server_certificate)

    tempfile_ca = tempfile.NamedTemporaryFile('w+t')

    if hashlib.sha256(server_der_certificate_bytes).hexdigest()[:32] == cert_hash.lower():
        print ('SHA256 of the server certficiate ' + hashlib.sha256(server_der_certificate_bytes).hexdigest())
        print('Server certificate is authenticated successfully')
        tempfile_ca.write(server_certificate)
        tempfile_ca.seek(0)
    else:
        print('The server certificate hash mismatches:')
        print ('The actual SHA256 of the server certficiate ' + hashlib.sha256(server_certificate_bytes).hexdigest())
        print('Expected SHA356 of the server certificate is ' + cert_hash.lower())
        print('Server certificate authentication failed!')
        return False

    # When the server certificate uses only commonName from the X.509 fields
    # then the library throws an error message. To surpress the error the line below has to be executed
    requests.packages.urllib3.disable_warnings(SubjectAltNameWarning)

    req = None

    req = requests.get(url + '/config.json', headers={'Authorization': 'Bearer ' + jwt_token}, verify=tempfile_ca.name) 

    if req is not None:
        print(bcolors.OKCYAN +
              '################################################\n' +
              '########### Printing configurations ############\n' +
              '################################################\n' +
              bcolors.ENDC)
        print(req.content.decode('ascii'))
        with open('config.json', 'w+') as f:
            f.write(req.content.decode('ascii'))
    else:
        print('Server returned empty content')
        return False

    tempfile_ca.close()
    return True


if __name__ == '__main__':

    j = json.loads(sys.argv[1])['config']

    host = j['url']
    jwt = j['client_token']
    server_cert_hashes = j['server_cert_hashes']

    for i in range(0,len(server_cert_hashes)):
        if download_config(url=host, jwt_token=jwt, cert_hash=server_cert_hashes[i]['h'+str(i)]):
            break
