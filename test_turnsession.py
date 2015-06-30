import traceback
from stundef import *
from stunconn import  SocketConnection
from stunsession import TurnSession

def main():
    jp02_turn_001 = '52.68.154.117'

    conn = SocketConnection()
    session = TurnSession(conn)
    session.server_address = jp02_turn_001
    session.transport_proto = STUN_TRANSPORT_PROTO_TCP
    session.username = 'ninefingers'
    session.password = 'youhavetoberealistic'

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
    except:
        traceback.print_exc()
    finally:
        session.close()

if __name__ == '__main__':
    main()
