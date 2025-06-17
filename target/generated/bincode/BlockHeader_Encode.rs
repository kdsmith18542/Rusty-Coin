impl :: bincode :: Encode for BlockHeader
{
    fn encode < __E : :: bincode :: enc :: Encoder >
    (& self, encoder : & mut __E) ->core :: result :: Result < (), :: bincode
    :: error :: EncodeError >
    {
        :: bincode :: Encode :: encode(&self.version, encoder) ?; :: bincode
        :: Encode :: encode(&self.prev_block_hash, encoder) ?; :: bincode ::
        Encode :: encode(&self.merkle_root, encoder) ?; :: bincode :: Encode
        :: encode(&self.timestamp, encoder) ?; :: bincode :: Encode ::
        encode(&self.bits, encoder) ?; :: bincode :: Encode ::
        encode(&self.nonce, encoder) ?; :: bincode :: Encode ::
        encode(&self.ticket_hash, encoder) ?; core :: result :: Result ::
        Ok(())
    }
}