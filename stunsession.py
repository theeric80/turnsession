from stundef import *
from stunmsg import StunRequest, StunResponse
from stunutils import xaddr_to_addr, addr_to_xaddr

class TurnSession(object):
    def __init__(self, connection):
        object.__init__(self)

        self.server_address = '127.0.0.1'
        self.server_port = 3478
        self.transport_proto = STUN_TRANSPORT_PROTO_UDP

        self.peer_address = '127.0.0.1'
        self.peer_port = 32355

        self.username = ''
        self.password = ''

        self.dont_fragment = 1
        self.allocation_lifetime = STUN_DEFAULT_ALLOCATE_LIFETIME

        self._relayed_address = ''
        self._relayed_port = 0

        self._realm = ''
        self._nonce = ''

        self._conn = connection

    def close(self):
        if self._conn:
            self._conn.close()

    def connect(self):
        self._conn.connect(
                (self.server_address, self.server_port),
                self.transport_proto)

    def allocate(self):
        response = self._send_request(self._build_allocate_request())
        self._nonce = response.get_attribute(STUN_ATTR_NONCE)[0]

        if (response.failed() and
            response.error()[0] == STUN_ERROR_UNAUTHORIZED):
            self._realm = response.get_attribute(STUN_ATTR_REALM)[0]
            response = self._send_request(self._build_allocate_request())

        if response.succeeded():
            _, self._relayed_port, self._relayed_address = xaddr_to_addr(
                    *response.get_attribute(STUN_ATTR_XOR_RELAYED_ADDRESS))

            self.allocation_lifetime = response.get_attribute(
                    STUN_ATTR_LIFETIME)[0]

        return response

    def refresh(self):
        response = self._send_request(self._build_refresh_request())
        if response.succeeded():
            self.allocation_lifetime = response.get_attribute(
                    STUN_ATTR_LIFETIME)[0]
        return response

    def create_permission(self):
        return self._send_request(self._build_create_permission_request())

    def bind_channel(self, channel):
        return self._send_request(self._build_channel_bind_request(channel))

    def send_channel_data(self):
        pass
    def recv_channel_data(self):
        pass
    def send_indication(self):
        pass
    def recv_indication(self):
        pass

    def _send_request(self, req):
        # TODO: logging
        self._conn.send(req.pack())
        response = self._recv_response()
        if response.failed():
            print ('[TurnSession] _send_request Failed. '
                   'Error = {0}, {1}'.format(*response.error()))
        return response

    def _recv_response(self):
        buff = self._conn.recv()
        header_len = STUN_HEADER_LENGTH
        header, attributes = buff[:header_len], buff[header_len:]
        return StunResponse(header, attributes)

    def _create_stun_request(self, method):
        req = StunRequest(method)
        req.add_attribute(STUN_ATTR_NONCE, self._nonce)
        if self._realm:
            req.add_lt_credential(self.username, self.password)
            req.add_attribute(STUN_ATTR_REALM, self._realm)
        return req

    def _build_allocate_request(self):
        req = self._create_stun_request(STUN_METHOD_ALLOCATE)
        req.add_attribute(STUN_ATTR_LIFETIME, self.allocation_lifetime)
        req.add_attribute(
                STUN_ATTR_REQUESTED_TRANSPORT,
                STUN_REQUESTED_TRANSPORT_UDP<<24)
        if self.dont_fragment:
            req.add_attribute(STUN_ATTR_DONT_FRAGMENT)
        return req

    def _build_refresh_request(self):
        req = self._create_stun_request(STUN_METHOD_REFRESH)
        req.add_attribute(STUN_ATTR_LIFETIME, self.allocation_lifetime)
        return req

    def _build_create_permission_request(self):
        req = self._create_stun_request(STUN_METHOD_CREATE_PERMISSION)
        req.add_attribute(
                STUN_ATTR_XOR_PEER_ADDRESS,
                *addr_to_xaddr(1, self.peer_port, self.peer_address))
        return req

    def _build_channel_bind_request(self, channel):
        req = self._create_stun_request(STUN_METHOD_CHANNEL_BIND)
        req.add_attribute(STUN_ATTR_CHANNEL_NUMBER, channel<<16)
        req.add_attribute(
                STUN_ATTR_XOR_PEER_ADDRESS,
                *addr_to_xaddr(1, self.peer_port, self.peer_address))
        return req
