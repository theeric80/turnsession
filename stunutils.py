from itertools import imap
from stundef import STUN_MAGIC_COOKIE

def _xor_transport_addr(family, port, addr):
    # TODO: IPv6
    assert(family == 0x01)
    _port = port ^ (STUN_MAGIC_COOKIE >> 16)
    _addr = addr ^ (STUN_MAGIC_COOKIE)
    return _port, _addr

def xaddr_to_addr(family, x_port, x_addr):
    _port, _addr = _xor_transport_addr(family, x_port, x_addr)
    _addr = '{0}.{1}.{2}.{3}'.format(
            (_addr & 0xFF000000) >> 24,
            (_addr & 0x00FF0000) >> 16,
            (_addr & 0x0000FF00) >> 8,
            (_addr & 0x000000FF))
    return family, _port, _addr

def addr_to_xaddr(family, port, addr):
    _addr = 0
    for x in imap(int, addr.split('.')):
        _addr = _addr << 8
        _addr = _addr | (x&0xFF)
    _port, _addr = _xor_transport_addr(family, port, _addr)
    return family, _port, _addr
