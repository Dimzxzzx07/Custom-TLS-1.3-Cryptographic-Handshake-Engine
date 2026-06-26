package body ASN1 is
   function Decode_Length (Data : in TLV_Array; Pos : in out Natural) return Natural is
      Result : Natural := 0;
   begin
      if Data (Pos) < 128 then
         Result := Natural (Data (Pos));
         Pos := Pos + 1;
      else
         Pos := Pos + 1;
         Result := Natural (Data (Pos));
         Pos := Pos + 1;
      end if;
      return Result;
   end Decode_Length;
end ASN1;
