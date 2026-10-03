#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import hmac
import os
import struct


KEY_SIZE = 32
TAG_SIZE = hashlib.sha256().digest_size
HEADER = struct.Struct(">BQ Q")
VERSION = 1


def generate_key():
    """Return a fresh 256-bit symmetric channel key."""
    return os.urandom(KEY_SIZE)


def _authenticate(key, version, seq, msg):
    return hmac.new(key, struct.pack(">BQ Q", version, seq, len(msg)) + msg,
                    hashlib.sha256).digest()


class Sender:
    def __init__(self, key):
        if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_SIZE:
            raise ValueError("invalid channel key")
        self._key = bytes(key)

    def send(self, seq, msg):
        if not isinstance(seq, int) or seq < 0 or seq > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("seq must be an unsigned 64-bit integer")
        if not isinstance(msg, (bytes, bytearray)):
            raise TypeError("msg must be bytes")

        msg = bytes(msg)
        tag = _authenticate(self._key, VERSION, seq, msg)
        return HEADER.pack(VERSION, seq, len(msg)) + msg + tag


class Receiver:
    def __init__(self, key):
        if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_SIZE:
            raise ValueError("invalid channel key")
        self._key = bytes(key)
        self._seen = set()

    def recv(self, packet):
        if not isinstance(packet, (bytes, bytearray)):
            return None
        packet = bytes(packet)

        if len(packet) < HEADER.size + TAG_SIZE:
            return None

        try:
            version, seq, msg_len = HEADER.unpack(packet[:HEADER.size])
        except struct.error:
            return None

        if version != VERSION:
            return None

        if len(packet) != HEADER.size + msg_len + TAG_SIZE:
            return None

        msg = packet[HEADER.size:HEADER.size + msg_len]
        tag = packet[HEADER.size + msg_len:]
        expected_tag = _authenticate(self._key, version, seq, msg)

        if not hmac.compare_digest(tag, expected_tag):
            return None

        if seq in self._seen:
            return None
        self._seen.add(seq)

        return seq, msg


def make_sender(key):
    return Sender(key)


def make_receiver(key):
    return Receiver(key)
