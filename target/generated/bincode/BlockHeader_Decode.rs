impl < __Context > :: bincode :: Decode < __Context > for BlockHeader
{
    fn decode < __D : :: bincode :: de :: Decoder < Context = __Context > >
    (decoder : & mut __D) ->core :: result :: Result < Self, :: bincode ::
    error :: DecodeError >
    {
        core :: result :: Result ::
        Ok(Self
        {
            version : :: bincode :: Decode :: decode(decoder) ?,
            prev_block_hash : :: bincode :: Decode :: decode(decoder) ?,
            merkle_root : :: bincode :: Decode :: decode(decoder) ?, timestamp
            : :: bincode :: Decode :: decode(decoder) ?, bits : :: bincode ::
            Decode :: decode(decoder) ?, nonce : :: bincode :: Decode ::
            decode(decoder) ?, ticket_hash : :: bincode :: Decode ::
            decode(decoder) ?,
        })
    }
} impl < '__de, __Context > :: bincode :: BorrowDecode < '__de, __Context >
for BlockHeader
{
    fn borrow_decode < __D : :: bincode :: de :: BorrowDecoder < '__de,
    Context = __Context > > (decoder : & mut __D) ->core :: result :: Result <
    Self, :: bincode :: error :: DecodeError >
    {
        core :: result :: Result ::
        Ok(Self
        {
            version : :: bincode :: BorrowDecode ::< '_, __Context >::
            borrow_decode(decoder) ?, prev_block_hash : :: bincode ::
            BorrowDecode ::< '_, __Context >:: borrow_decode(decoder) ?,
            merkle_root : :: bincode :: BorrowDecode ::< '_, __Context >::
            borrow_decode(decoder) ?, timestamp : :: bincode :: BorrowDecode
            ::< '_, __Context >:: borrow_decode(decoder) ?, bits : :: bincode
            :: BorrowDecode ::< '_, __Context >:: borrow_decode(decoder) ?,
            nonce : :: bincode :: BorrowDecode ::< '_, __Context >::
            borrow_decode(decoder) ?, ticket_hash : :: bincode :: BorrowDecode
            ::< '_, __Context >:: borrow_decode(decoder) ?,
        })
    }
}