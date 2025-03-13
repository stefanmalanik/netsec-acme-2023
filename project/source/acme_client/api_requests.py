import requests

from pathlib import Path
import datetime

from cryptoutils import CryptoUtils

class ACME:
    URL_START = 'https://localhost:14000'
    ROOT_CERT_PATH = (Path(__file__).parent / '../../pebble.minica.pem').as_posix()
    POST_H = {'Content-Type': "application/jose+json"}
    
    def __init__(self, dir_path, cu: CryptoUtils):
        self._dir_path = dir_path
        self.cu = cu
        self.csr = None

    def __enter__(self):
        self.sess = requests.Session()
        self.sess.verify = self.ROOT_CERT_PATH
        self.dir_dicts = self._get_dir().json()
        return self

    def __exit__(self, *vargs):
        self.sess.close()

    def _get_nonce(self):
        assert(self.dir_dicts)
        r = self.sess.head(self.dir_dicts['newNonce'])
        r.raise_for_status()
        return r.headers['Replay-Nonce']

    def _get_dir(self):
        r = self.sess.get(self._dir_path)
        r.raise_for_status()
        return r

    def _post_request(self, url, payload):
        jwt = self.cu.create_jwt(self._get_nonce(), url, payload, use_kid=(self.cu.kid is not None))
        r = self.sess.post(url, json=jwt, headers=self.POST_H)
        return r

    def _post_as_get(self, url):
        jwt = self.cu.create_jwt(self._get_nonce(), url, b'', use_kid=(self.cu.kid is not None))
        r = self.sess.post(url, json=jwt, headers=self.POST_H)
        return r
    
    def create_account(self):
        r = self._post_request(self.dir_dicts['newAccount'], {"termsOfServiceAgreed": True})
        r.raise_for_status()

        self.cu.kid = r.headers['Location']
        # self.orders = r.json()['orders']
    
    def order_cert(self, domain_list):
        now = datetime.datetime.now().astimezone().replace(microsecond=0)
        expiry = now + datetime.timedelta(days=7)
        identifiers = [{"type": "dns", "value": x} for x in domain_list]
        payload = {
            "identifiers": identifiers,
            "notBefore": now.isoformat(),
            "notAfter": expiry.isoformat()
        }

        r = self._post_request(self.dir_dicts['newOrder'], payload)
        assert(r.status_code == 201)
        
        order_url = r.headers['Location']

        r = r.json()
        return (r['finalize'], r['authorizations'], order_url)

    def get_auth(self, auth_url, chall_type):
        r = self._post_as_get(auth_url)
        r.raise_for_status()

        r = r.json()
        ret = {'ident': r['identifier']}
        for c in r['challenges']:
            if c['type'] == 'http-01' and chall_type == 'http01':
                ret['chall'] = c
            if c['type'] == 'dns-01' and chall_type == 'dns01':
                ret['chall'] = c
        return ret
    
    def verify_chall(self, chall_url):
        r = self._post_request(chall_url, {})
        r.raise_for_status()
        print(r.text)
    
    def get_order_status(self, order_url):
        r = self._post_as_get(order_url)
        return r.json()['status']
    
    def finalize_order(self, fin_url, dn_list=None):

        self.csr = self.cu.create_csr(dn_list)

        r = self._post_request(fin_url, {'csr': self.csr})

        order = r.headers['Location']
        if r.json()['status'] == 'processing':
            r = self._post_as_get(order)
            r.raise_for_status()
        r = r.json()
        
        r = self._post_as_get(r['certificate'])
        r.raise_for_status()
        return r.text
    
    def revoke_cert(self, cert):
        cert_der = self.cu.transform_cert_to_der(cert)
        r = self._post_request(self.dir_dicts['revokeCert'], {
            'certificate': cert_der
        })
        r.raise_for_status()
    


