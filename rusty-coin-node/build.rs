fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .compile(
            &["proto/rustcoin.proto"], 
            &["proto/"]
        )?;
    Ok(())
}