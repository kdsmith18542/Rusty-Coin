impl < __Context > :: bincode :: Decode < __Context > for TxInput
{
    fn decode < __D : :: bincode :: de :: Decoder < Context = __Context > >
    (decoder : & mut __D) ->core :: result :: Result < Self, :: bincode ::
    error :: DecodeError >
    {
        core :: result :: Result ::
        Ok(Self
        {
            txid : :: bincode :: Decode :: decode(decoder) ?, output_index :
            :: bincode :: Decode :: decode(decoder) ?, signature : :: bincode
            :: Decode :: decode(decoder) ?, public_key : :: bincode :: Decode
            :: decode(decoder) ?,
        })
    }
} impl < '__de, __Context > :: bincode :: BorrowDecode < '__de, __Context >
for TxInput
{
    fn borrow_decode < __D : :: bincode :: de :: BorrowDecoder < '__de,
    Context = __Context > > (decoder : & mut __D) ->core :: result :: Result <
    Self, :: bincode :: error :: DecodeError >
    {
        core :: result :: Result ::
        Ok(Self
        {
            txid : :: bincode :: BorrowDecode ::< '_, __Context >::
            borrow_decode(decoder) ?, output_index : :: bincode ::
            BorrowDecode ::< '_, __Context >:: borrow_decode(decoder) ?,
            signature : :: bincode :: BorrowDecode ::< '_, __Context >::
            borrow_decode(decoder) ?, public_key : :: bincode :: BorrowDecode
            ::< '_, __Context >:: borrow_decode(decoder) ?,
        })
    }
}