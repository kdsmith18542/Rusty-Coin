impl :: bincode :: Encode for TxInput
{
    fn encode < __E : :: bincode :: enc :: Encoder >
    (& self, encoder : & mut __E) ->core :: result :: Result < (), :: bincode
    :: error :: EncodeError >
    {
        :: bincode :: Encode :: encode(&self.txid, encoder) ?; :: bincode ::
        Encode :: encode(&self.output_index, encoder) ?; :: bincode :: Encode
        :: encode(&self.signature, encoder) ?; :: bincode :: Encode ::
        encode(&self.public_key, encoder) ?; core :: result :: Result ::
        Ok(())
    }
}