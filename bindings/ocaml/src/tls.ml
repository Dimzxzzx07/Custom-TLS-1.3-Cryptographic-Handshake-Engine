type tls_record = {
  content_type: int;
  version: int;
  length: int;
  fragment: string;
}

let read_record data =
  if String.length data < 5 then None
  else
    let content_type = int_of_char data.[0] in
    let version = (int_of_char data.[1] lsl 8) + int_of_char data.[2] in
    let length = (int_of_char data.[3] lsl 8) + int_of_char data.[4] in
    let fragment = String.sub data 5 length in
    Some {content_type; version; length; fragment}
