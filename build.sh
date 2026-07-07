#!/bin/bash
# Build script for CB-MPC Security Disclosures PoCs

set -e

echo "========================================"
echo "🔒 CB-MPC Security Disclosures - Build"
echo "========================================"
echo ""

echo "📦 Compiling Negative Size PoC..."
g++ -std=c++17 -O0 -o poc_neg poc_negative_size_fixed.cpp
if [ $? -eq 0 ]; then
    echo "✅ poc_neg built successfully"
else
    echo "❌ Failed to build poc_neg"
    exit 1
fi

echo ""
echo "📦 Compilation Complete!"
echo ""
echo "========================================"
echo "🚀 Running Proof of Concepts..."
echo "========================================"
echo ""

echo "🔴 Running Negative Size PoC..."
./poc_neg

echo ""
echo "========================================"
echo "✅ All PoCs Completed!"
echo "========================================"
echo ""
echo "To run individual PoCs:"
echo "  ./poc_neg         # Negative size vulnerability"
