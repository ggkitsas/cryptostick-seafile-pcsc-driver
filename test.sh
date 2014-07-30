#!/bin/sh

echo "Fetching serial number"
./get_serial_no > get_serial_no.log

echo "Fetching public key"
./get_public_key > get_public_key.log

echo "Testing VERIFY"
echo "Please provide user PIN"
./verify > verify.log

echo "Testing DECIPHER"
echo "Please provide userPIN"
./decipher > decipher.log
