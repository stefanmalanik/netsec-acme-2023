import argparse
import json

from dnslib.server import DNSServer, DNSHandler, BaseResolver
from dnslib import DNSRecord, QTYPE, RCODE, RR, A, TXT

class FixedResolver(BaseResolver):
    def __init__(self, static_ip, txt_dict) -> None:
        super().__init__()
        self.st_ip = static_ip
        self.txt_dict =txt_dict

    def resolve(self, request, handler):
        reply = request.reply()
        # print(request.questions[0].get_qname())
        for q in request.questions:
            ip = str(q.get_qname()).rstrip('.')
            if ip in self.txt_dict and q.qtype == QTYPE.TXT:
                for txt_entry in self.txt_dict[ip]:
                    reply.add_answer(RR(ip, QTYPE.TXT, rdata=TXT(txt_entry)))
                print(f'[dns] Serving TXT {self.txt_dict[ip]} for {ip}')
            elif q.qtype == QTYPE.A:
                reply.add_answer(RR(ip, QTYPE.A, rdata=A(self.st_ip)))
                print(f'[dns] Serving A {self.st_ip} for {ip}')
        return reply

parser = argparse.ArgumentParser()

parser.add_argument('--record', required=True)
parser.add_argument('--port', type=int, required=True)
parser.add_argument('--file')

def main():
    args = parser.parse_args()
    txt_dns = {}
    if args.file:
        with open(args.file, 'r') as fin:
            txt_dns = json.load(fin)
    resolver = FixedResolver(args.record, txt_dns)
    server = DNSServer(resolver, port=args.port, address="0.0.0.0")

    print(f"[dns] DNS server is running on port {args.port}.")
    server.start()

if __name__ == '__main__':
    main()