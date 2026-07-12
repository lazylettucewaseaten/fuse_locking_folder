#!/bin/bash
set -e

VAULT_DIR="./test_vault"
MOUNT_DIR="./test_mount"

fusermount -u $MOUNT_DIR 2>/dev/null || true
rm -rf $VAULT_DIR $MOUNT_DIR
mkdir -p $VAULT_DIR
mkdir -p $MOUNT_DIR

echo "init"
# Use python pexpect to supply password for fort++
python3 -c "
import pexpect
child = pexpect.spawn('./fort++ init $VAULT_DIR')
child.expect('Enter Password:')
child.sendline('pass')
child.expect('Confirm Password:')
child.sendline('pass')
child.expect(pexpect.EOF)
print(child.before.decode())
"

echo "mounting"
# Mount with debug flags and put in background
python3 -c "
import pexpect
child = pexpect.spawn('./openfort $VAULT_DIR $MOUNT_DIR -f -d')
child.expect('Enter password:')
child.sendline('pass')
with open('fuse_debug.log', 'w') as f:
    while True:
        try:
            line = child.readline().decode()
            if not line: break
            f.write(line)
        except:
            break
" &
FUSE_PID=$!
sleep 2 # Wait for mount

echo "Testing file creation..."
echo "This is the first test file." > $MOUNT_DIR/test1.txt || echo "Failed to write test1.txt"

kill $FUSE_PID || true
fusermount -u $MOUNT_DIR || true

echo "Debug Log:"
cat fuse_debug.log | grep -A 5 -B 5 "EIO" || cat fuse_debug.log | tail -n 50
