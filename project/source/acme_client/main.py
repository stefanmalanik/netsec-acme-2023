import argparse
import json
import time
import re
from pathlib import Path
import http.server as httpserv

from api_requests import ACME
from cryptoutils import CryptoUtils
from suprocesses import Paths, SubprocessWrapper

CHALL_SERVER_PORT = 5002
DNS_SERVER_PORT = 10053
SHUTDOWN_SERVER_PORT = 5003
VALIDATION_SERVER_PORT = 5001

parser = argparse.ArgumentParser()

parser.add_argument('chall')
parser.add_argument('--dir', required=True)
parser.add_argument('--record', required=True)
parser.add_argument('--domain', action='append')
parser.add_argument('--revoke', action='store_true')
parser.add_argument('--challport', type=int, default=CHALL_SERVER_PORT)
parser.add_argument('--dnsport', type=int, default=DNS_SERVER_PORT)

def main():
    nspace = parser.parse_args()
    print(nspace)
    cu = CryptoUtils()
    sbw = SubprocessWrapper()
    cu.gen_key()
    with ACME(nspace.dir, cu) as acme, Paths.get_path('log').open('w') as logfile:
        # print(acme._get_nonce())


        acme.create_account()
        
        n_tries = 0
        (fin, auth_list, order) = [None] * 3

        while True:
            all_passed = False
            try:
                n_tries += 1
                (fin, auth_list, order) = acme.order_cert(nspace.domain)

                auths = {}
                for auth_id in auth_list:

                    auths[auth_id] = acme.get_auth(auth_id, nspace.chall)
                
                print(auths)
                # Start DNS server

                sbw.start_dns_serv(nspace.chall, nspace.record, auths, nspace.dnsport, cu, logfile)

                if nspace.chall == 'http01':
                    sbw.start_http_serv(auths, nspace.challport, cu)

                time.sleep(1)

                for a_id in auths.copy().keys():
                    if auths[a_id]['chall']['status'] != 'valid':
                        acme.verify_chall(auths[a_id]['chall']['url'])

                    while(auths[a_id]['chall']['status'] not in ['valid', 'invalid']):
                        time.sleep(1)
                        auths[a_id] = acme.get_auth(a_id, nspace.chall)
                print(auths)

                all_passed = all([a['chall']['status'] == 'valid' for a in auths.values()])

            except Exception as e:
                print(e)

            if all_passed and n_tries > 4:
                break
            else:
                sbw.kill_all()
                print(f'[main] Invalid certs, attempt <{n_tries}>! Retrying in 1s ...')
                time.sleep(1)
        
        print('[main] All challenges passed...')

        
        print(acme.get_order_status(order))
        cert_chain = acme.finalize_order(fin, nspace.domain)

        time.sleep(1)
        
        with Paths.get_path('cert').open('w') as pemfile:
            pemfile.write(cert_chain)

        with Paths.get_path('pk').open('wb') as keyfile:
            keyfile.write(cu.get_serial_key(cu.csr_priv_key))
        
        sbw.start_validation_serv(VALIDATION_SERVER_PORT)

        if nspace.revoke:
            print('[main] Revoking...')
            acme.revoke_cert(cert_chain)

        shutdown_thread = SubprocessWrapper.create_shutdown_thread(SHUTDOWN_SERVER_PORT)
        while shutdown_thread.is_alive():
            time.sleep(0.1)

        print('[main] Exiting gracefully...')
        sbw.kill_all()


if __name__ == "__main__":
    main()