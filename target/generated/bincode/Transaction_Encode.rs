impl :: bincode :: Encode for Transaction
{
    fn encode < __E : :: bincode :: enc :: Encoder >
    (& self, encoder : & mut __E) ->core :: result :: Result < (), :: bincode
    :: error :: EncodeError >
    {
        :: bincode :: Encode :: encode(&self.version, encoder) ?; :: bincode
        :: Encode :: encode(&self.inputs, encoder) ?; :: bincode :: Encode ::
        encode(&self.outputs, encoder) ?; :: bincode :: Encode ::
        encode(&self.lock_time, encoder) ?; core :: result :: Result :: Ok(())
    }
}