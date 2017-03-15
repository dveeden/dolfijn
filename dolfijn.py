#!/bin/env python3
import socket
import select
import struct

# This is the library which is used by the other tools in this repo.


MYSQL_CAP_SSL = (1 << 11)


class Handshake:
    """MySQL Handshake V10"""

    def __init__(self, packet=None, payload=None):
        self.source = None
        if payload:
            self.from_payload(payload)
        elif packet:
            self.from_packet(packet)

    def from_payload(self, payload):
        if self.source is None:
            self.source = 'payload'
        self.protocol_version = payload[0]

        position = payload.index(b'\x00', 1)
        self.server_version = payload[1:position].decode('ascii')
        position = position + 1

        self.connection_id = struct.unpack('i',
                                           payload[position:position+4])[0]
        position = position + 4

        self.auth_plugin_data1 = payload[position:position+8]
        position = position + 8

        filler = payload[position]
        position = position + 1

        self.capstart = position
        caps1 = payload[position+1] << 8
        caps1 = caps1 | payload[position]
        self.caps1 = caps1

    def from_packet(self, packet):
        if self.source is None:
            self.source = 'packet'
        self.packet = packet
        payload = decode_packet(packet)[2]
        self.from_payload(payload)

    @property
    def has_ssl(self):
        return self.caps1 & MYSQL_CAP_SSL == MYSQL_CAP_SSL

    def packet_no_ssl(self):
        payload_start = 4
        capposition = payload_start + self.capstart
        caps_bin = self.packet[capposition:capposition+2]
        caps = caps_bin[1] << 8
        caps = caps | caps_bin[0]
        newcaps = caps ^ MYSQL_CAP_SSL
        packet = (self.packet[:capposition]
                  + newcaps.to_bytes(2, 'little')
                  + self.packet[capposition+2:])
        return packet


class Response:
    """MySQL HandshakeResponse41"""

    def __init__(self, packet=None, payload=None):
        if payload:
            self.from_payload(payload)
        elif packet:
            self.from_packet(packet)

    def from_packet(self, packet):
        payload = decode_packet(packet)[2]
        self.from_payload(payload)

    def from_payload(self, payload):
        caps = payload[1] << 8
        caps = caps | payload[0]
        self.caps = caps

    @property
    def has_ssl(self):
        try:
            return self.caps & MYSQL_CAP_SSL == MYSQL_CAP_SSL
        except AttributeError:
            return None


def decode_packet(packet):
    payload_length = struct.unpack('i', packet[:3] + b'\x00')[0]
    sequence_id = packet[3]
    payload = packet[4:]
    return (payload_length, sequence_id, payload)
