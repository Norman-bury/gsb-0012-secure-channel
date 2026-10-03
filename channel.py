#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""安全信道：HMAC-SHA256 认证 + 严格长度校验 + 序号去重。

报文布局（全部大端）：
  magic   1 字节  = 0x5C
  seq     8 字节  消息序号（uint64）
  mlen    4 字节  消息体长度（uint32）
  msg     mlen 字节
  mac     32 字节 HMAC-SHA256(key, magic || seq || mlen || msg)

任何对内容、序号、长度的篡改都会让 MAC 校验失败；截断会破坏定长结构或
MAC，同样被拒；乱序天然允许（不要求序号连续或递增）；重放通过已见序号
集合拒绝。
"""

import hashlib
import hmac
import os
import struct

_MAGIC = b"\x5c"
_HEADER = struct.Struct(">cQI")  # magic, seq, mlen
_MAC_LEN = hashlib.sha256().digest_size  # 32


def generate_key():
    """生成 32 字节随机对称密钥。"""
    return os.urandom(32)


def _mac(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


class _Sender:
    def __init__(self, key):
        if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
            raise ValueError("key 必须是至少 16 字节的字节串")
        self._key = bytes(key)

    def send(self, seq, msg):
        if not isinstance(seq, int) or seq < 0 or seq > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("seq 必须是 0..2^64-1 的整数")
        if not isinstance(msg, (bytes, bytearray)):
            raise TypeError("msg 必须是字节串")
        if len(msg) > 0xFFFFFFFF:
            raise ValueError("消息过长")
        msg = bytes(msg)
        header = _HEADER.pack(_MAGIC, seq, len(msg))
        body = header + msg
        return body + _mac(self._key, body)


class _Receiver:
    def __init__(self, key):
        if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
            raise ValueError("key 必须是至少 16 字节的字节串")
        self._key = bytes(key)
        self._seen = set()

    def recv(self, packet):
        try:
            if not isinstance(packet, (bytes, bytearray)):
                return None
            packet = bytes(packet)

            # 定长头 + 至少 32 字节 MAC，缺一不可（截断必被拒）。
            if len(packet) < _HEADER.size + _MAC_LEN:
                return None

            header = packet[:_HEADER.size]
            tag = packet[-_MAC_LEN:]
            magic, seq, mlen = _HEADER.unpack(header)

            # 魔数、声明长度与实际长度必须完全一致（防截断/拼接）。
            if magic != _MAGIC:
                return None
            if len(packet) != _HEADER.size + mlen + _MAC_LEN:
                return None

            msg = packet[_HEADER.size:_HEADER.size + mlen]

            # 常量时间 MAC 校验，覆盖 magic/seq/mlen/msg 全部字段。
            expected = _mac(self._key, header + msg)
            if not hmac.compare_digest(expected, tag):
                return None

            # 重放拒绝：同一序号只接受一次。乱序不影响判定。
            if seq in self._seen:
                return None
            self._seen.add(seq)
            return seq, msg
        except Exception:
            return None


def make_sender(key):
    return _Sender(key)


def make_receiver(key):
    return _Receiver(key)
