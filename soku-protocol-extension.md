# Soku protocol extension for IPv6

## Terms

This document uses terms in [delthas/touhou-protocol-docs](https://github.com/delthas/touhou-protocol-docs/blob/master/protocol_123.md#terms).

- Relay: a server, whose address is the AAAA record of `v6relay.hagb.name` and port is `12321`, runs [`relay.py`](./relay.py) to provides IPv6 UDP hole-punching service;
- IPv6Mapped game client: a game client with IPv6Map Mod loaded;
- IPv6-mapped IPv4 address: virtual IPv4 address mapped to IPv6 address, passed to Hisoutensoku from the network functions hooked by IPv6Map. For more details, refer to the comments of [src/ipv6map.h](./src/ipv6map.h).

## Packets

Packets mentioned in [delthas/touhou-protocol-docs](https://github.com/delthas/touhou-protocol-docs/blob/master/protocol_123.md#packets) will be used to introduce the following packets.

In an IPv6Mapped game client, all the following packets take effect only when the game client hosts or connects to other game client.

### `PUNCH_PING`

```
0x36 0x00
```

PS: `0x36` == `'6'`

This packet is used to get in touch with the relay and punch with other peers.

Receive:

- When an IPv6Mapped game client receives it, no action or any response is required;
- When the relay receives it, the relay will sent `PUNCH_PONG` packet in response.

Send:

- an IPv6Mapped game client sends it to the relay every 3s
- Soon after a game client received a `PUNCH_FROM_RELAY` packet, the IPv6Mapped game client sends it to `[destination_address]:destination_port` (here `destination_address` and `destination_port` is from the received `PUNCH_FROM_RELAY` packet).

### `PUNCH_PONG`

```
0x36 0x01
```

This packet is only sent by the relay in response to a `PUNCH_PING` packet

Receive:

- No action is required after receiving `PUNCH_PONG` packet

Send:

- When the relay receives `PUNCH_PING`, the relay will send `PUNCH_PONG` packet in response.

### `PUNCH_FROM_CLIENT`

```
0x36 0x02 <is_response> <destination_address(in6_addr)> <destination_port(port)>
is_response = { 1 bytes: 0x00 or 0x01 }
in6_addr = { 16 bytes: IPv6 address bytes in network order}
port = { 2 bytes: port in network order }
```

The packet is sent by an IPv6Mapped game client to the relay, as a request for UDP hole punching.

Receive:

- After the relay receives a `PUNCH_FROM_CLIENT` packet, the relay will sent an `PUNCH_FROM_RELAY` packet to `[destination_address]:destination_port` (here the `destination_address` and `destination_port` are from the received `PUNCH_FROM_CLIENT` packet). In the sent `PUNCH_FROM_RELAY` packet, `is_response` is same as the `PUNCH_FROM_CLIENT` packet, `destination_address` is the source address of the `PUNCH_FROM_CLIENT` packet, and `destionation_port` is the source port of the `PUNCH_FROM_CLIENT` packet.

Send:

- When an IPv6Mapped game client wants to send a `HELLO` packet where `peer_address`==`target_address` and `peer_address` is an IPv6-mapped IPv4 address, the IPv6Mapped game client will also send a `PUNCH_FROM_CLIENT` packet to the relay. In this `PUNCH_FROM_CLIENT` packet, `is_response` is set to `0x00`, `destination_address` is set to the IPv6 address of the original `peer_address`, and `destination_port` is the same as the `port` of the original `peer_address`.
- After an IPv6Mapped game client receives a `PUNCH_FROM_RELAY` packet from the relay, the IPv6Mapped game client will send a `PUNCH_PING` packet to `[destination_address]:destination` (here the `destination_address` and `destination_port` are from the received `PUNCH_FROM_RELAY` packet). At the same time, if `is_response` of the received `PUNCH_FROM_RELAY` is `0x00`, the IPv6Mapped game client will also send a `PUNCH_FROM_CLIENT` packet to the relay. In this `PUNCH_FROM_CLIENT`, `destination_address` and `destination_port` is same as the `PUNCH_FROM_RELAY` packet while `is_response` is `0x01`.

### `PUNCH_FROM_RELAY`

```
0x36 0x03 <is_response> <destination_address(in6_addr)> <destination_port(port)>
in6_addr = { 16 bytes: IPv6 address bytes in network order}
port = { 2 bytes: port in network order }
```

When receving a `PUNCH_FROM_CLIENT` packet, The relay sends a `PUNCH_FROM_RELAY` packet to `[destination_address]:destination_port` as a request for UDP hole punching

For more details, refer to [`PUNCH_FROM_CLIENT`](#punch_from_client).

### `V6_SOKU_HELLO`

```
0x36 0x04 <peer_address(in6_addr)> <peer_port(port)> <target_address(in6_addr)> <target_port(port)> <stuff>
in6_addr = { 16 bytes: IPv6 address bytes in network order}
port = { 2 bytes: port in network order }
stuff = { 4 bytes }
```

It is the IPv6 version of the `HELLO` packet of Hisoutensoku.

Receive:

- When receiving a `V6_SOKU_HELLO` packet, an IPv6Mapped game client will convert it into a `HELLO` packet where `peer_address(sockaddr_in)` is the IPv6-mapped IPv4 address of `peer_address(in6_addr)` with `peer_port` as port, `target_address(sockaddr_in)` is got by the same method from `target_address(in6_addr)` and `target_port`, and `stuff` is the same as `stuff` of the `V6_SOKU_HELLO` packet. And then this `HEELO` packet instead of the received `V6_SOKU_HELLO` will be return to Hisoutensoku.

Send:

- When an IPv6Mapped game client want to send a `HELLO` packet where `peer_address`!=`target_address` and at least one of them is an IPv6-mapped IPv4 address, then an `V6_SOKU_HELLO` packet instead of the original `HELLO` packet will be sent. In the `V6_SOKU_HELLO`, `peer_address(in6_addr)` and `peer_port` is converted from `peer_address(sockaddr_in)` of the original `HELLO` packet, `target_`* ones are converted from `target_address(sockaddr_in)`, and `stuff` is the same as `stuff` of the original `HELLO` packet. Notice that IPv4 address is converted into IPv4-mapped IPv6 address.

### `V6_SOKU_REDIRECT`

```
0x36 0x05 <child_id> <target_address(in6_addr)> <target_port(port)> <stuff>
child_id = { 4 bytes }
in6_addr = { 16 bytes: IPv6 address bytes in network order}
port = { 2 bytes: port in network order }
stuff = { 48 bytes }
```

It is the IPv6 version of the `REDIRECT` packet of Hisoutensoku.

Receive: similar to [`V6_SOKU_HELLO`](#v6_soku_hello).

Send: When an IPv6Mapped game client want to send a `REDIRECT` packet where `target_address` is an IPv6-mapped IPv4 address, then a `V6_SOKU_REDIRECT` packet instead of the original `REDIRECT` packet will be sent. Similar to [`V6_SOKU_HELLO`](#v6_soku_hello).  