import ./tls

proc buildServerHello(ctx: TLSContext, data: var seq[byte]): bool =
  data.setLen(35)
  data[0] = 0x02.byte
  data[1] = 0x03.byte
  data[2] = 0x04.byte
  for i in 0..31:
    data[3 + i] = ctx.serverRandom[i]
  return true
