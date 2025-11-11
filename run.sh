#!/bin/bash

# DIY Code Signing with AWS KMS and AWS Private CA
# Usage: ./run.sh [file_to_sign] [algorithm]
#
# Arguments:
#   file_to_sign: Path to the file you want to sign (optional, defaults to README.md)
#   algorithm: RSA2048, RSA3072, RSA4096, ECDSA256, ECDSA384, ECDSA521, MLDSA44, MLDSA65, MLDSA87 (optional, defaults to RSA2048)

FILE_TO_SIGN=${1:-"README.md"}
ALGORITHM=${2:-"RSA2048"}

echo "Running DIY Code Signing example..."
echo "File to sign: $FILE_TO_SIGN"
echo "Algorithm: $ALGORITHM"
echo ""

# Check if file exists
if [ ! -f "$FILE_TO_SIGN" ]; then
  echo "Error: File '$FILE_TO_SIGN' not found!"
  echo ""
  echo "Usage: ./run.sh [file_to_sign] [algorithm]"
  echo "Example: ./run.sh myfile.jar MLDSA65"
  exit 1
fi

# Compile the project first
echo "Compiling project..."
mvn clean compile

if [ $? -ne 0 ]; then
  echo "Error: Compilation failed!"
  exit 1
fi

echo ""
echo "Running code signing example..."

# Run the Maven command
mvn exec:java -Dexec.args="$FILE_TO_SIGN $ALGORITHM"
