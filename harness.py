#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""题 5（安全信道对抗）判分 harness。

模型在 channel.py 里实现三个东西：
  generate_key() -> bytes
  make_sender(key) -> 有 .send(seq, msg) -> packet bytes 的对象
  make_receiver(key) -> 有 .recv(packet) -> (seq, msg) 或 None 的对象

harness 模拟一个本地攻击者夹在收发两端之间，对每条消息随机做篡改、重放、
乱序、截断四种手脚。判分标准：合法消息原样送达且恰好一次，被动手脚的消息
100% 被拒收，一次静默接受都不允许。

用法：
  python3 harness.py                # 跑全部回合
  python3 harness.py --rounds 20    # 自定义回合数
"""

import argparse
import random
import sys

try:
    from channel import generate_key, make_sender, make_receiver
except ImportError as e:
    print("找不到 channel.py，或缺少 generate_key / make_sender / make_receiver", file=sys.stderr)
    print(e, file=sys.stderr)
    sys.exit(2)

SEED = 20261003


def tamper(packet, rng):
    p = bytearray(packet)
    if not p:
        return bytes(p)
    idx = rng.randrange(len(p))
    p[idx] ^= 0xFF
    return bytes(p)


def truncate(packet, rng):
    p = bytes(packet)
    if len(p) <= 1:
        return p
    cut = rng.randrange(1, len(p))
    return p[:cut]


def run_round(rng, M, key):
    messages = [bytes(rng.randrange(256) for _ in range(rng.randint(8, 64)))
                for _ in range(M)]

    sender = make_sender(key)
    packets = [sender.send(seq, messages[seq]) for seq in range(M)]

    fates = {}
    delivered = []  # (packet, seq, kind)
    for seq in range(M):
        r = rng.random()
        if r < 0.15:
            fates[seq] = "drop"
        elif r < 0.35:
            fates[seq] = "tamper"
            delivered.append((tamper(packets[seq], rng), seq, "tamper"))
        elif r < 0.45:
            fates[seq] = "truncate"
            delivered.append((truncate(packets[seq], rng), seq, "truncate"))
        else:
            fates[seq] = "legit"
            delivered.append((packets[seq], seq, "legit"))
            for _ in range(rng.randint(0, 2)):  # 重放 0~2 份
                delivered.append((packets[seq], seq, "replay"))

    rng.shuffle(delivered)

    receiver = make_receiver(key)
    accepted = {}
    for packet, seq, kind in delivered:
        res = receiver.recv(packet)
        if res is not None:
            accepted.setdefault(seq, []).append(res)

    failures = []
    for seq in range(M):
        fate = fates[seq]
        accs = accepted.get(seq, [])
        if fate in ("tamper", "truncate"):
            if accs:
                failures.append((fate, seq, "坏消息被静默接受"))
        elif fate == "legit":
            if len(accs) == 0:
                failures.append(("legit", seq, "合法消息被拒"))
            elif len(accs) > 1:
                failures.append(("replay", seq, "重放没被拒"))
            elif accs[0][0] != seq or accs[0][1] != messages[seq]:
                failures.append(("legit", seq, "内容或序号错误"))
        # drop：消息被截断丢弃，无期望
    return failures


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=50)
    ap.add_argument("--msgs", type=int, default=20)
    args = ap.parse_args()

    rng = random.Random(SEED)
    total_fail = []
    for _ in range(args.rounds):
        key = generate_key()
        total_fail.extend(run_round(rng, args.msgs, key))

    print("=" * 60)
    print(f"回合 {args.rounds}，每回合 {args.msgs} 条消息")
    if total_fail:
        print(f"[FAIL] 共 {len(total_fail)} 处失守：")
        for kind, seq, why in total_fail[:20]:
            print(f"  {kind} seq={seq}: {why}")
    else:
        print("[PASS] 零失守，合法消息原样送达，坏消息全部拒收")
    print("=" * 60)
    sys.exit(0 if not total_fail else 1)


if __name__ == "__main__":
    main()
