#!/bin/bash

# Exit on any error
set -e

echo "=========================================="
echo "    FileLocker Concurrency & Basic Test   "
echo "=========================================="

VAULT_DIR="$(pwd)/test_vault"
MOUNT_DIR="$(pwd)/test_mount"

echo "[*] Cleaning up old test directories..."
fusermount -u $MOUNT_DIR 2>/dev/null || true
rm -rf $VAULT_DIR $MOUNT_DIR
mkdir -p $VAULT_DIR
mkdir -p $MOUNT_DIR

echo ""
echo "[*] Step 1: Initializing the Vault"
echo "--> You will be prompted to create a password for the test vault."
./fort++ init $VAULT_DIR

echo ""
echo "[*] Step 2: Mounting the Vault via FUSE"
echo "--> You will be prompted to enter the password to unlock the vault."
./openfort $VAULT_DIR $MOUNT_DIR

# Give FUSE a second to fully mount
sleep 1

echo ""
echo "[*] Step 3: Testing File Creation and Encryption"
echo "Creating test1.txt and test2.txt in the mounted folder..."

# Test basic writes
echo "This is the first test file." > $MOUNT_DIR/test1.txt
echo "This is the second test file." > $MOUNT_DIR/test2.txt

# Test parallel writes (the race condition we just fixed)
echo "Testing parallel writes to the same file..."
for i in {1..50}; do
    echo "Parallel write line $i" >> $MOUNT_DIR/test3_parallel.txt &
done
wait

echo "Files created successfully!"

echo ""
echo "[*] Step 4: Testing File Reads"
echo "Contents of test1.txt:"
cat $MOUNT_DIR/test1.txt
echo "------------------------------------------"
echo "Number of lines in test3_parallel.txt (should be 50):"
wc -l < $MOUNT_DIR/test3_parallel.txt
echo "------------------------------------------"

echo ""
echo "[*] Step 5: Checking the Encrypted Vault"
echo "Listing the actual encrypted directory ($VAULT_DIR):"
echo "You should see URL-safe base64 encoded filenames, not 'test1.txt'"
ls -l $VAULT_DIR

echo ""
echo "[*] Step 6: Unmounting and Cleaning Up"
fusermount -u $MOUNT_DIR
echo "Successfully unmounted $MOUNT_DIR."

echo "Cleaning up directories..."
rm -rf $VAULT_DIR $MOUNT_DIR

echo "=========================================="
echo "             Test Complete!               "
echo "=========================================="
