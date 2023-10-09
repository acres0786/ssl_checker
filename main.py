import ssl
import socket
import datetime
import json
from flask import Flask, request, jsonify

app = Flask(__name__)

def check_certificate_expiry(domain):
    try:
        # Create an SSL context
        context = ssl.create_default_context()

        # Connect to the domain over HTTPS
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        # Extract the certificate's expiration date
        not_after = cert['notAfter']
        expiration_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")

        return expiration_date.strftime("%Y-%m-%d")

    except Exception as e:
        # If no certificate is found or there's an error, return "-"
        return "-"

@app.route('/check_certificate', methods=['GET'])
def check_certificate():
    domain = request.args.get('domain')
    if domain:
        expiration_date = check_certificate_expiry(domain)
        result = {
            "domain": domain,
            "expiration_date": expiration_date
        }
        return jsonify(result)
    else:
        return jsonify({"error": "Missing 'domain' parameter"}), 400

if __name__ == '__main__':
    app.run(debug=True)
