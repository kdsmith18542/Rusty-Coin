impl < __Context > :: bincode :: Decode < __Context > for Transaction
{
    fn decode < __D : :: bincode :: de :: Decoder < Context = __Context > >
    (decoder : & mut __D) ->core :: result :: Result < Self, :: bincode ::
    error :: DecodeError >
    {
        core :: result :: Result ::
        Ok(Self
        {
            version : :: bincode :: Decode :: decode(decoder) ?, inputs : ::
            bincode :: Decode :: decode(decoder) ?, outputs : :: bincode ::
            Decode :: decode(decoder) ?, lock_time : :: bincode :: Decode ::
            decode(decoder) ?,
        })
    }
} impl < '__de, __Context > :: bincode :: BorrowDecode < '__de, __Context >
for Transaction
{
    fn borrow_decode < __D : :: bincode :: de :: BorrowDecoder < '__de,
    Context = __Context > > (decoder : & mut __D) ->core :: result :: Result <
    Self, :: bincode :: error :: DecodeError >
    {
        core :: result :: Result ::
        Ok(Self
        {
            version : :: bincode :: BorrowDecode ::< '_, __Context >::
            borrow_decode(decoder) ?, inputs : :: bincode :: BorrowDecode ::<
            '_, __Context >:: borrow_decode(decoder) ?, outputs : :: bincode
            :: BorrowDecode ::< '_, __Context >:: borrow_decode(decoder) ?,
            lock_time : :: bincode :: BorrowDecode ::< '_, __Context >::
            borrow_decode(decoder) ?,
        })
    }
}