impl < __Context > :: bincode :: Decode < __Context > for Hash
{
    fn decode < __D : :: bincode :: de :: Decoder < Context = __Context > >
    (decoder : & mut __D) ->core :: result :: Result < Self, :: bincode ::
    error :: DecodeError >
    {
        core :: result :: Result ::
        Ok(Self
        {
            0 :
            (<::bincode::serde::Compat<_> as
            ::bincode::Decode::<__Context>>::decode(decoder)?).0,
        })
    }
} impl < '__de, __Context > :: bincode :: BorrowDecode < '__de, __Context >
for Hash
{
    fn borrow_decode < __D : :: bincode :: de :: BorrowDecoder < '__de,
    Context = __Context > > (decoder : & mut __D) ->core :: result :: Result <
    Self, :: bincode :: error :: DecodeError >
    {
        core :: result :: Result ::
        Ok(Self
        {
            0 :
            (<::bincode::serde::BorrowCompat<_> as
            ::bincode::BorrowDecode::<'_,
            __Context>>::borrow_decode(decoder)?).0,
        })
    }
}