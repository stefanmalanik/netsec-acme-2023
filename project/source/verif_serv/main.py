import argparse
from flask import Flask


app = Flask(__name__)

parser = argparse.ArgumentParser()

parser.add_argument('--port', type=int, required=True)
parser.add_argument('--cert', required=True)
parser.add_argument('--key', required=True)


@app.route('/')
def hello_world():
    return 'Hello world!'

if __name__ == "__main__":
    args = parser.parse_args()
    context = (args.cert, args.key)
    app.run(host='0.0.0.0', port=args.port, ssl_context=context)