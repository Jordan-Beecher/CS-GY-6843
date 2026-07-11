#CS-GY 6843 - Computer Networking
#Name - Jordan Beecher
#UNI - jab10032
#NYU Email - jab10032@nyu.edu 

import argparse
import dns.flags
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rcode
import dns.rdata
import socket
import threading
import signal
import os
import sys

import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import ast

def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    key = base64.urlsafe_b64encode(key)
    return key

# Lookup details on fernet in the cryptography.io documentation    
def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8')) #call the Fernet encrypt method
    return encrypted_data    

def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    if isinstance(encrypted_data, str):
        encrypted_data = encrypted_data.encode('utf-8')
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data.decode('utf-8')

salt = b'salt'  # Remember it should be a byte-object
password = 'password'
user_email = 'jab10032@nyu.edu'

encrypted_value = encrypt_with_aes(user_email, password, salt)  # exfil function
decrypted_value = decrypt_with_aes(encrypted_value, password, salt)  # exfil function

# For future use    
def generate_sha256_hash(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()

# A dictionary containing DNS records mapping hostnames to different types of DNS data.
dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],  # List of (preference, mail server) tuples
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: 'ns.example.com.',
        dns.rdatatype.TXT: ('This is a TXT record',),
        dns.rdatatype.SOA: (
            'ns1.example.com.', #mname
            'admin.example.com.', #rname
            2023081401, #serial
            3600, #refresh
            1800, #retry
            604800, #expire
            86400, #minimum
        ),
    },
    'nyu.edu.': {
        dns.rdatatype.MX: [(10, 'mail.nyu.edu.')],
        dns.rdatatype.NS: 'ns1.nyu.edu.',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.TXT: (encrypted_value.decode('utf-8'),),
    },
    'safebank.com.': {
        dns.rdatatype.A: '192.168.1.102',
    },
    # Add more records as needed (see assignment instructions!
}

def run_dns_server(host='127.0.0.1', port=53, stop_event=None):
    # Create a UDP socket and bind it to the local IP address and port
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.settimeout(0.5)

    while True:
        if stop_event and stop_event.is_set():
            print('Stopping DNS server')
            server_socket.close()
            return

        try:
            # Wait for incoming DNS requests
            data, addr = server_socket.recvfrom(1024)
            # Parse the request using the `dns.message.from_wire` method
            request = dns.message.from_wire(data)
            # Create a response message using the `dns.message.make_response` method
            response = dns.message.make_response(request)

            # Get the question from the request
            question = request.question[0]
            qname = question.name.to_text()
            qtype = question.rdtype

            # Check if there is a record in the `dns_records` dictionary that matches the question
            if qname in dns_records and qtype in dns_records[qname]:
                # Retrieve the data for the record and create an appropriate `rdata` object for it
                answer_data = dns_records[qname][qtype]

                rdata_list = []

                if qtype == dns.rdatatype.MX:
                    for pref, server in answer_data:
                        rdata_list.append(MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, server))
                elif qtype == dns.rdatatype.SOA:
                    mname, rname, serial, refresh, retry, expire, minimum = answer_data
                    rdata_list.append(SOA(dns.rdataclass.IN, dns.rdatatype.SOA, mname, rname, serial, refresh, retry, expire, minimum))
                else:
                    if isinstance(answer_data, str):
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data)]
                    else:
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, data) for data in answer_data]

                rrset = dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype)
                for rdata in rdata_list:
                    rrset.add(rdata)
                response.answer.append(rrset)
            else:
                response.set_rcode(dns.rcode.NXDOMAIN)

            # Set the response flags for authoritative answer
            response.flags |= dns.flags.AA
            response.flags |= dns.flags.RA

            # Send the response back to the client using the `server_socket.sendto` method and put the response to_wire(), return to the addr you received from
            print("Responding to request:", qname)
            server_socket.sendto(response.to_wire(), addr)
        except socket.timeout:
            continue
        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            sys.exit(0)


def run_dns_server_user(host='127.0.0.1', port=53):
    print("Input 'q' and hit 'enter' to quit")
    print(f"DNS server is running on {host}:{port}...")

    def user_input():
        while True:
            cmd = input()
            if cmd.lower() == 'q':
                print('Quitting...')
                os.kill(os.getpid(), signal.SIGINT)

    input_thread = threading.Thread(target=user_input)
    input_thread.daemon = True
    input_thread.start()
    run_dns_server(host=host, port=port)


def parse_args():
    parser = argparse.ArgumentParser(description='Run a simple DNS server')
    parser.add_argument('--host', default='127.0.0.1', help='Bind host address')
    parser.add_argument('--port', type=int, default=53, help='Bind UDP port')
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    run_dns_server_user(host=args.host, port=args.port)
    #print("Encrypted Value:", encrypted_value)
    #print("Decrypted Value:", decrypted_value)