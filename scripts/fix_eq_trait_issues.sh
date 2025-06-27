#!/bin/bash

# Script to fix Eq trait issues by removing Eq from structs containing floats or other non-Eq types

echo "Fixing Eq trait issues..."

# Function to fix a file
fix_file() {
    local file=$1
    echo "Fixing $file..."
    
    # Remove Eq from derives that contain floats or other problematic types
    # This is a conservative approach - remove Eq from any struct that might have issues
    
    # For structs containing f32, f64, or other non-Eq types
    sed -i 's/#\[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize\)]/#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]/g' "$file"
    sed -i 's/, Eq,/,/g' "$file"
    sed -i 's/, Eq]/]/g' "$file"
    
    echo "Fixed $file"
}

# Fix all Rust files in the project
find . -name "*.rs" -not -path "./target/*" | while read -r file; do
    if grep -q "derive.*Eq" "$file"; then
        fix_file "$file"
    fi
done

echo "Eq trait fixes complete!"
