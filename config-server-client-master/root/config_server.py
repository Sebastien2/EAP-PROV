from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
import argparse
import base64
import jwt
import ssl
import os

arg_parser = argparse.ArgumentParser(description='Create a simple configuration server with JWT authorization')
arg_parser.add_argument('--cert', help='Certificate file path, if not provided uses http')
arg_parser.add_argument('--path', help='Path to serve, if not provided uses the current folder')
arg_parser.add_argument('--port', help='Port to serve the server, default http:8080, default https:4443', type=int)
arg_parser.add_argument('--jwtcert', help='Certificate to verify the signature in the JWT')
args=arg_parser.parse_args()

certifacate_path = args.cert

username = None

if args.path is not None:
    os.chdir(args.path)

class AuthHandler(SimpleHTTPRequestHandler):
    def check_user(self, auth_text):
        global username
        aut = str(auth_text).split("Bearer ",1)[1]
        jwt_certificate = open(args.jwtcert,'r').read()
        payload=None

        try:
            payload = jwt.decode(aut, jwt_certificate, algorithms=["ES256"])
            print(payload)
            if payload['sub'] == 'config':
                username = payload['user']
                return True
            else:
                print('Invalid JWT!')
                return False
        except Exception as err:
            print(err)
            return False

    ''' Main class to present webpages and authentication. '''
    def do_HEAD(self):
        print("send header")
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_AUTHHEAD(self):
        print("send header")
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"Test\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        ''' Present frontpage with user authentication. '''
        if self.headers.get('Authorization') == None:
            self.do_AUTHHEAD()
            self.wfile.write(b'no auth header received')
            pass
        elif self.check_user(self.headers.get('Authorization')):
            SimpleHTTPRequestHandler.do_GET(self)
            pass
        else:
            self.do_AUTHHEAD()
            self.wfile.write(str.encode(self.headers.get('Authorization')))
            self.wfile.write(b'\t!not authenticated\n')
            pass

if certifacate_path is not None:
    httpd = TCPServer(('', 4443 if args.port is None else args.port), AuthHandler)
    httpd.socket = ssl.wrap_socket (httpd.socket, certfile=certifacate_path, server_side=True)
    sa = httpd.socket.getsockname()
    print("Serving HTTP on "+ str(sa[0])+ " port "+ str(sa[1])+ "...")
    httpd.serve_forever()
else:
    print('HTTP is not supported, only HTTPS!')