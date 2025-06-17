impl < __Context > :: bincode :: Decode < __Context > for TxOutput
{
    fn decode < __D : :: bincode :: de :: Decoder < Context = __Context > >
    (decoder : & mut __D) ->core :: result :: Result < Self, :: bincode ::
    error :: DecodeError >
    {
        core :: result :: Result ::
        Ok(Self
        {
            value : :: bincode :: Decode :: decode(decoder) ?, pubkey_hash :
            :: bincode :: Decode :: decode(decoder) ?,
        })
    }
} impl < '__de, __Context > :: bincode :: BorrowDecode < '__de, __Context >
for TxOutput
{
    fn borrow_decode < __D : :: bincode :: de :: BorrowDecoder < '__de,
    Context = __Context > > (decoder : & mut __D) ->core :: result :: Result <
    Self, :: bincode :: error :: DecodeError >
    {
        core :: result :: Result ::
        Ok(Self
        {
            value : :: bincode :: BorrowDecode ::< '_, __Context >::
            borrow_decode(decoder) ?, pubkey_hash : :: bincode :: BorrowDecode
            ::< '_, __Context >:: borrow_decode(decoder) ?,
        })
    }
}