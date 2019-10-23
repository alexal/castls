#!/bin/python

import argparse
import socket
import ssl
import subprocess
import sys
import tempfile


def check_installation(version):
    current_version = sys.version_info
    if current_version[0] == version[0] and current_version[1] >= version[1]:
        pass
    else:
        sys.stderr.write(
            "[%s] - Error: Your Python interpreter must be %d.%d or greater (within major version %d)\n" % (
                sys.argv[0], version[0], version[1], version[0]))
        sys.exit(-1)
    return 0


check_installation((3, 0))

parser = argparse.ArgumentParser()
parser.add_argument("host", type=str, help="")
parser.add_argument("port", type=int, help="")
args = parser.parse_args()


class CasSocket:
    def __init__(self, host, port):
        self.cas = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect(host, port)

    def connect(self, host, port):
        self.cas.connect((host, port))
        self.send()

    def send(self):
        msg = bytearray([0, 0x53, 0x41, 0x43,
                         0x10, 0, 0, 0, 0, 0, 0, 0,
                         0x10, 0, 0, 0,
                         0, 0, 0, 0,
                         2, 0, 0, 0,
                         5, 0, 0, 0])
        self.cas.sendall(msg)

    def receive(self):
        msg = bytearray([])
        while len(msg) < 28:
            chunk = self.cas.recv(28 - len(msg))
            if chunk == b'':
                raise RuntimeError(
                    "Socket connection is broken. Please verify the host and port and make sure that you are "
                    "connecting to the binary port of the CAS server.")
            msg = msg + chunk

        return msg

    @staticmethod
    def get_value(msg, offset, len):
        val = 0
        offset += len
        offset -= 1
        while len > 0:
            val *= 256
            val += msg[offset]
            offset -= 1
            len -= 1

        return val

    def close(self):
        self.cas.close()


def main():
    cas = CasSocket(args.host, args.port)
    msg = cas.receive()

    eye = cas.get_value(msg, 0, 4)
    total_sz = cas.get_value(msg, 4, 8)
    hdr_sz = cas.get_value(msg, 12, 4)
    r_type = cas.get_value(msg, 20, 4)
    tag = cas.get_value(msg, 24, 4)

    if eye != 0x43415300 or r_type != 3 or hdr_sz != 16 or total_sz != 16:
        print(
            "Invalid response from the server. Please verify the host and port and make sure that you are connecting "
            "to the binary port of the CAS server.")

    if tag == 5:
        wrapped_socket = ssl.wrap_socket(cas.cas, server_side=False, cert_reqs=ssl.CERT_NONE, ciphers=None)
        fp = tempfile.NamedTemporaryFile()
        fp.write(str.encode(ssl.DER_cert_to_PEM_cert(wrapped_socket.getpeercert(True))))
        fp.seek(0)
        cert_txt = subprocess.check_output(["openssl", "x509", "-text", "-noout", "-in", fp.name])
        print(cert_txt.decode("utf-8"))

        fp.close()
        wrapped_socket.close()

    elif tag == 7:
        print("Server is a CAS Binary port, but SSL is not configured")
    else:
        print("Server is a CAS Binary port, but an unexpected response type {} was received".format(tag))

    cas.close()


if __name__ == '__main__':
    main()
