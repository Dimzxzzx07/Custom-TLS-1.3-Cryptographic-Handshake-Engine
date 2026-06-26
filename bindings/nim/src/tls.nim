import std/[sequtils, strutils]

type TLSContext = object
  clientRandom: array[32, byte]
  serverRandom: array[32, byte]
  handshakeDone: bool

proc newTLSContext(): TLSContext =
  TLSContext(
    clientRandom: [0.byte, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    serverRandom: [0.byte, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    handshakeDone: false
  )

proc parseClientHello(ctx: var TLSContext, data: seq[byte]): bool =
  if data.len < 40:
    return false
  for i in 0..31:
    ctx.clientRandom[i] = data[4 + i]
  return true
