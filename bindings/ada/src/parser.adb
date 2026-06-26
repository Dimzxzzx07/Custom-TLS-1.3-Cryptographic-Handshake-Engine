package body Parser is
   function Parse_ASN1 (Data : in TLV_Array; Len : in Natural) return Boolean is
      Pos : Natural := 0;
   begin
      while Pos < Len loop
         if Data (Pos) = 16#30# then
            return True;
         end if;
         Pos := Pos + 1;
      end loop;
      return False;
   end Parse_ASN1;
end Parser;
