import traceback
import time
import base64
import hmac
import hashlib
from stundef import *
from stunconn import  SocketConnection
from stunsession import TurnSession

def build_ephemeral_credential(ttl, secret, uname):
    now = time.time()
    timestamp = int(now + ttl)
    _uname = '{0}:{1}'.format(timestamp, uname)

    key = secret.encode('utf8')
    msg = _uname.encode('utf8')
    _passwd = base64.b64encode(hmac.new(key, msg, hashlib.sha1).digest())
    return _uname, _passwd

def main():
    jp02_turn_001 = '52.68.154.117'

    conn = SocketConnection()
    session = TurnSession(conn)
    session.server_address = jp02_turn_001
    session.transport_proto = STUN_TRANSPORT_PROTO_TCP
    session.username = 'ninefingers'
    session.password = 'youhavetoberealistic'

    use_ephemeral_credential = True
    if use_ephemeral_credential:
        ttl, secret = 86400, 'logen'
        session.username, session.password = \
                build_ephemeral_credential(ttl, secret, session.username)

    session.connect()

    try:
        print 'STUN_METHOD_ALLOCATE'
        response = session.allocate()
        assert(response.succeeded())

        print 'Relayed X-ADDRESS: {0}:{1}'.format(
                session._relayed_address, session._relayed_port)

        print 'STUN_METHOD_CREATE_PERMISSION'
        response = session.create_permission()
        assert(response.succeeded())

        print 'STUN_METHOD_CHANNEL_BIND'
        response = session.bind_channel(STUN_MIN_CHANNEL_NUMBER)
        assert(response.succeeded())

        print 'STUN_METHOD_REFRESH'
        response = session.refresh()
        assert(response.succeeded())
    except:
        traceback.print_exc()
    finally:
        session.close()

if __name__ == '__main__':
    main()
