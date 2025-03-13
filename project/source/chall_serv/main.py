import argparse
import json
from flask import Flask, Response

json_cfg = {}
app = Flask(__name__)

parser = argparse.ArgumentParser()

parser.add_argument('--port', type=int, required=True)
parser.add_argument('--file', required=True)


@app.route('/')
def hello_world():
    return 'Challenge server'

@app.route('/.well-known/acme-challenge/<token>')
def challenge(token):
    global json_cfg
    if token in json_cfg:
        return Response(json_cfg[token], mimetype='application/octet-stream')
    return f'{token} not found', 400

def main():
    args = parser.parse_args()
    with open(args.file) as infile:
        global json_cfg
        json_cfg = json.load(infile)
    app.run(host='0.0.0.0', port=args.port)

if __name__ == "__main__":
    main()