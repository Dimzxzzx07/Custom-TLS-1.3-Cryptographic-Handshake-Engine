type asn1_node = {
  tag: int;
  length: int;
  value: string option;
  children: asn1_node list;
}

let parse_asn1 data =
  let rec parse pos =
    if pos >= String.length data then None
    else
      let tag = int_of_char data.[pos] in
      let len = int_of_char data.[pos+1] in
      let value = String.sub data (pos+2) len in
      Some {tag; length=len; value=Some value; children=[]}
  in
  parse 0
