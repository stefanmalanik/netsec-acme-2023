import http.server
import socketserver
import threading
import json
from pathlib import Path
import subprocess
from cryptoutils import CryptoUtils
import re



class Paths:
    PATHS = {
        'dnsconf': '../dns_serv/dns_settings.json',
        'httpconf': '../chall_serv/chall_settings.json',
        'cert': '../verif_serv/chall_cert.pem',
        'pk':  '../verif_serv/chall_cert.key',
        'log': './log.txt'
    }

    @classmethod
    def create_abs_path(cls, strpath: str):
        return (Path(__file__).parent / strpath).resolve()
    
    @classmethod
    def get_path(cls, key):
        return cls.create_abs_path(cls.PATHS[key])

class SubprocessWrapper:

    def __init__(self) -> None:
        self.sbp_container = []

    def start_dns_serv(self, chall, record, auths, port, cu: CryptoUtils, logfile):
        dns_config = {}
        if chall == 'dns01':
            for a in auths.values():
                domain = a['ident']['value']
                # Remove wildcard char
                m = re.match(r'\*\.(.*)', domain)
                if m:
                    domain = m.group(0)
                # Add particular path
                domain = '_acme-challenge.' + domain
                print(a['chall'])
                print(a['ident'])
                if domain not in dns_config:
                    dns_config[domain] = []
                dns_config[domain].append(cu.create_dns_key_auth(a['chall']['token']))
        
        # Start process

        dns_config_path = Paths.get_path('dnsconf')
        with dns_config_path.open('w') as fout:
            json.dump(dns_config, fout)
        dns_proc = subprocess.Popen(['python', Paths.create_abs_path('../dns_serv/main.py').as_posix(),
                                     '--record', record, '--port', str(port), '--file', dns_config_path.as_posix()])
        
        self.sbp_container.append(dns_proc)

    def start_http_serv(self, auths, port, cu: CryptoUtils):
        http_conf = {}
        for a in auths.values():
            # Add particular path
            http_conf[a['chall']['token']] = cu.create_http_key_auth(a['chall']['token'])
        
        # Start process

        http_config_path = Paths.get_path('httpconf')
        with http_config_path.open('w') as fout:
            json.dump(http_conf, fout)
        http_proc = subprocess.Popen(['python', Paths.create_abs_path('../chall_serv/main.py').as_posix(),
                                      '--port', str(port), '--file', http_config_path.as_posix()])
        
        self.sbp_container.append(http_proc)

    def start_validation_serv(self, port):
        pass
        
        serv_proc = subprocess.Popen(['python', Paths.create_abs_path('../verif_serv/main.py').as_posix(),
                                      '--port', str(port), '--cert', Paths.get_path('cert').as_posix(), '--key', Paths.get_path('pk')])
        
        self.sbp_container.append(serv_proc)
    
    def kill_all(self):
        [x.kill() for x in self.sbp_container]
        self.sbp_container = []

    @classmethod
    def create_shutdown_thread(cls, port):
        class MyHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/shutdown':
                    # You received a GET request at "/shutdown"
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'Shutting down server...')
                    # Trigger the server shutdown in a separate thread

                    def shutdown():
                        server.shutdown()
                    threading.Thread(target=shutdown).start()
                else:
                    # Serve other requests using the default behavior
                    super().do_GET()



        # Create the server
        server = socketserver.TCPServer(('', port), MyHandler)

        # Start the server in a separate thread
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        return server_thread