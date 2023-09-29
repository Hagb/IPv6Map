from socket import *
from enum import IntEnum


class V6PacketHeader(IntEnum):
    PUNCH_PING = 0
    PUNCH_PONG = 1
    PUNCH_FROM_CLIENT = 2
    PUNCH_FROM_RELAY = 3


def main():
    s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
    s.bind(('::', 12321, 0, 0))
    while True:
        data, ip = s.recvfrom(32)
        if len(data) < 2 and data[0] == ord('6'):
            continue
        if data[1] == V6PacketHeader.PUNCH_PING:
            s.sendto(b'6'+V6PacketHeader.PUNCH_PONG.to_bytes(1, 'big'), ip)
            print(f"get ping from {ip}")
            continue
        if data[1] == V6PacketHeader.PUNCH_FROM_CLIENT:
            if len(data) != 1 + 1 + 1 + 16 + 2:
                continue
            from_addr_bytes = \
                inet_pton(AF_INET6, ip[0])+ip[1].to_bytes(2, 'big')
            to_addr = (inet_ntop(
                AF_INET6, data[3:3+16]), int.from_bytes(data[3+16:3+16+2], 'big'), 0, 0)
            s.sendto(
                b'6' +
                V6PacketHeader.PUNCH_FROM_RELAY.to_bytes(1, 'big') +
                data[2:3] + from_addr_bytes,
                to_addr)
            print(
                f"receive and forward punch request ({data[2]}): {ip} to {to_addr}")
            continue
        print(f"unknown packet type {data[1]}")


if __name__ == '__main__':
    main()
