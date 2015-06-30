import socket
from stundef import STUN_TRANSPORT_PROTO_TCP, STUN_TRANSPORT_PROTO_UDP

_SOCK_TYPE = {
    STUN_TRANSPORT_PROTO_TCP: socket.SOCK_STREAM,
    STUN_TRANSPORT_PROTO_UDP: socket.SOCK_DGRAM,
    }

class SocketConnection(object):
    def __init__(self):
        object.__init__(self)
        self._sock = None

    def close(self):
        if self._sock:
            self._sock.close()
            self._sock = None

    def connect(self, address, proto):
        self._sock = socket.socket(socket.AF_INET, _SOCK_TYPE[proto])
        self._sock.connect(address)

    def send(self, string):
        self._sock.sendall(string)

    def recv(self, bufsize):
        return self._sock.recv(bufsize)
