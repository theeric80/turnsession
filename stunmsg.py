import binascii
import hmac
import hashlib
import cStringIO
import struct
from functools import partial
from saslPrep import saslPrep
from stundef import *

_STUN_HEADER_FMT = '!H H I 12s'

_STUN_ATTR_HEADER_FMT = '!H H'
_STUN_ATTR_HEADER_LENGTH = struct.calcsize(_STUN_ATTR_HEADER_FMT)

_STUN_ATTR_FMT = {
    STUN_ATTR_USERNAME: '$',
    STUN_ATTR_MESSAGE_INTEGRITY: '20s',
    STUN_ATTR_ERROR_CODE: 'I $',
    STUN_ATTR_REALM: '$',
    STUN_ATTR_NONCE: '$',
    STUN_ATTR_XOR_MAPPED_ADDRESS: 'H H I',
    STUN_ATTR_SOFTWARE: '$',
    STUN_ATTR_CHANNEL_NUMBER: 'I',
    STUN_ATTR_LIFETIME: 'I',
    STUN_ATTR_XOR_PEER_ADDRESS: 'H H I',
    STUN_ATTR_XOR_RELAYED_ADDRESS: 'H H I',
    STUN_ATTR_REQUESTED_TRANSPORT: 'I',
    STUN_ATTR_DONT_FRAGMENT: '',
    STUN_ATTR_MAPPED_ADDRESS: 'H H I',
}

# TODO: RFFU
_STUN_ATTR_RFFU = {
    STUN_ATTR_CHANNEL_NUMBER: 16,
    STUN_ATTR_EVEN_PORT:7,
    STUN_ATTR_REQUESTED_TRANSPORT: 24,
}

_TID = 0x10000001

def _gen_transaction_id():
    global _TID
    _TID += 1
    return _TID

def _pack_bigint(l, length=0):
    h = hex(l)[2:].rstrip('I')
    if length > 0:
        h = h.zfill(length*2)
    return binascii.unhexlify(h)

def _zpadsize(size, boundary):
    return (boundary - size%boundary) % boundary

def _zpad(data, boundary):
    size = _zpadsize(len(data), boundary)
    return data + (b'\x00'*size)

def _msg_integrity_len():
    attr = _STUN_ATTR_FMT[STUN_ATTR_MESSAGE_INTEGRITY]
    return _STUN_ATTR_HEADER_LENGTH + struct.calcsize(attr)

def _get_class_by_type(msg_type):
    CLASS_MASK = 0b0000000100010000
    return msg_type & CLASS_MASK

def _get_method_by_type(msg_type):
    METHOD_MASK = 0b1111111011101111
    return msg_type & METHOD_MASK

def pack_header(method, length, tid):
    # TODO: logging
    data = struct.pack(
            _STUN_HEADER_FMT,
            method, length, STUN_MAGIC_COOKIE, _pack_bigint(tid, 12))
    return data

def unpack_header(value):
    return struct.unpack(_STUN_HEADER_FMT, value)

def pack_attribute(attr, *values):
    # TODO: logging
    ifmt = ((n, f) for n, f in enumerate(_STUN_ATTR_FMT[attr].split(' ')))
    vfmt =  ' '.join(f if f!='$' else '%ds'%len(values[i]) for i, f in ifmt)

    data = struct.pack(
            _STUN_ATTR_HEADER_FMT + vfmt,
            attr, struct.calcsize(vfmt), *values)
    data = _zpad(data, 4)
    return data

def unpack_attr_header(value):
    return struct.unpack(_STUN_ATTR_HEADER_FMT, value)

def unpack_attribute(attr, value):
    # TODO: logging
    if not _STUN_ATTR_FMT.has_key(attr):
        #print 'unpack_attribute: Skip attribute: {:#06x}'.format(attr)
        return []

    result = []
    offset = 0
    for f in _STUN_ATTR_FMT[attr].split(' '):
        fmt = f if f!='$' else '{0}s'.format(len(value)-offset)
        data = struct.unpack_from('!'+fmt, value, offset)
        offset += struct.calcsize(fmt)
        result.extend(data)
    return result

class StunRequest(object):
    def __init__(self, method):
        object.__init__(self)
        self.method = method

        self._attributes = {STUN_ATTR_NONCE: (b'nonce',)}
        self._passwd = None

    def add_lt_credential(self, uname, passwd):
        uname_ = (self._build_username(uname),)
        self._attributes[STUN_ATTR_USERNAME] = uname_
        self._passwd = self._build_password(passwd)

    def add_attribute(self, attr, *values):
        self._attributes[attr] = values

    def pack(self):
        body = self._pack_attributes()
        body_len = len(body)

        if self._has_realm():
            hdr = self._pack_header(body_len + _msg_integrity_len())
            body += self._pack_message_integrity(hdr + body)
        else:
            hdr = self._pack_header(body_len)
        return hdr + body

    def _build_username(self, uname):
        return saslPrep(unicode(uname, 'utf-8')).encode('utf-8')

    def _build_password(self, passwd):
        return saslPrep(unicode(passwd, 'utf-8')).encode('utf-8')

    def _build_message_integrity(self, msg):
        realm = self._attributes[STUN_ATTR_REALM][0]
        uname = self._attributes[STUN_ATTR_USERNAME][0]
        passwd = self._passwd

        key = hashlib.md5('{0}:{1}:{2}'.format(uname, realm, passwd))
        return hmac.new(key.digest(), msg, hashlib.sha1).digest()

    def _pack_header(self, length):
        return pack_header(self.method, length, _gen_transaction_id())

    def _pack_attributes(self):
        _p = pack_attribute
        return b''.join(_p(a, *v) for a, v in self._attributes.iteritems())

    def _pack_message_integrity(self, msg):
        value = self._build_message_integrity(msg)
        return pack_attribute(STUN_ATTR_MESSAGE_INTEGRITY, value)

    def _has_realm(self):
        return self._attributes.has_key(STUN_ATTR_REALM)

class StunResponse(object):
    def __init__(self, header, attributes):
        object.__init__(self)
        msg_type, _, _, _ = unpack_header(header)
        self.class_ = _get_class_by_type(msg_type)
        self.method = _get_method_by_type(msg_type)
        self._attributes = {}

        self._build(attributes)

    def _build(self, data):
        fp = cStringIO.StringIO(data)

        hdr_size = _STUN_ATTR_HEADER_LENGTH
        for hdr in iter(partial(fp.read, hdr_size), ''):
            type_, length = unpack_attr_header(hdr)
            assert(len(hdr) == hdr_size)

            value = fp.read(length)
            attr = unpack_attribute(type_, value)
            assert(len(value) == length)

            self._attributes[type_] = attr

            # Ignore the padding
            fp.read(_zpadsize(length, 4))

        fp.close()

    def _decode_errno(self, errno):
        hi = errno & 0x0F00
        lo = errno & 0x00FF
        return (hi>>8)*100 + lo

    def __getattribute__(self, name):
        stun_attr = getattr(globals(), 'STUN_ATTR_'+name.upper(), None)
        if stun_attr:
            return object.__getattribute__(self, '_attributes')[stun_attr]
        return object.__getattribute__(self, name)

    def get_attribute(self, attr):
        return self._attributes[attr]

    def succeeded(self):
        return self.class_ == STUN_CLASS_SUCCESS_RESPONSE

    def failed(self):
        return self.class_ == STUN_CLASS_ERROR_RESPONSE

    def error(self):
        errno, reason = self._attributes.get(STUN_ATTR_ERROR_CODE, (0, ''))
        return self._decode_errno(errno), reason
