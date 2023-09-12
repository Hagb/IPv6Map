# IPv6Map

This DLL makes IPv4-only programs use dual-stack UDP socket, and maps IPv6 addresses to IPv4 for them.

It is inspired by [Autopunch](https://github.com/delthas/autopunch/), and uses many codes from that.

Still in early development. Use at your risk.

## How to use

TODO ([a loader like Autopunch loader](https://github.com/delthas/autopunch/tree/master/autopunch-loader) is needed)

## Use in Touhou Hisoutensoku

Download the zip and unpack files into `modules/a name you like/`. Load `IPv6MapSokuMod.dll` in `SWRSToys.ini`.

- Join other player: copy the address (IPv4 or IPv6) into clipboard, and let Soku read the address from clipboard
- Host: host as usual, and other players can join you by both IPv4 and IPv6
- If you are mod developer: you can [interact with IPv6Map](#Interact-with-your-code) in a Soku mod to let Soku join a specified IPv6 (or IPv4) address. Notice that the hook only enabled for Soku itself (for more details, search `BUILD_FOR_SOKU` in [`src/IPv6Map/my_socket.c`](./src/IPv6Map/my_socket.c)), for hooks of `WSA*` hasn't been implemented and I am afraid that them would be called.

It should be compatible with [Autopunch Mod](https://github.com/SokuDev/SokuMods/blob/master/modules/Autopunch/Autopunch.c), [SokuLobbiesMod](https://github.com/Gegel85/SokuLobbies), [InGameHostlist](https://github.com/SokuDev/InGameHostlist) and [Giuroll](https://github.com/Giufinn/giuroll). If there is any problem, please report to me.

## Interact with your code

(C/C++) Include the header [`src/ipv6map.h`](./src/ipv6map.h) (which can be used as a standalone header).

Refer to the comments in [`src/ipv6map.h`](./src/ipv6map.h).

## TODO

- implement hooks of `WSA*` functions
- IPv6-mapped IPv4 address collection
- static mapping
- a loader like 
