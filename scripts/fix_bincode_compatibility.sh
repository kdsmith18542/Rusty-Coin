#!/bin/bash

# Script to fix bincode v1.3 compatibility issues
# This script removes bincode v2.0 API usage and replaces with v1.3 API

echo "Fixing bincode compatibility issues..."

# Function to fix a file
fix_file() {
    local file=$1
    echo "Fixing $file..."
    
    # Remove bincode derive imports
    sed -i 's/use bincode::{Encode, Decode};//g' "$file"
    sed -i 's/, bincode::Encode, bincode::Decode//g' "$file"
    sed -i 's/, Encode, Decode//g' "$file"
    
    # Fix serialization method calls
    sed -i 's/bincode::encode_to_vec(self, bincode::config::standard())/bincode::serialize(self)/g' "$file"
    sed -i 's/bincode::decode_from_slice(data, bincode::config::standard()).map(|(msg, _)| msg)/bincode::deserialize(data)/g' "$file"
    
    # Fix error types
    sed -i 's/bincode::error::EncodeError/Box<bincode::ErrorKind>/g' "$file"
    sed -i 's/bincode::error::DecodeError/Box<bincode::ErrorKind>/g' "$file"
    
    # Fix error module access
    sed -i 's/bincode::error::/bincode::/g' "$file"
    
    echo "Fixed $file"
}

# Fix all Rust files in the project
find . -name "*.rs" -not -path "./target/*" | while read -r file; do
    if grep -q "bincode" "$file"; then
        fix_file "$file"
    fi
done

echo "Bincode compatibility fixes complete!"
