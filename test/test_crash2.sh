#!/bin/bash
set -e
VAULT_DIR="./test_vault"
MOUNT_DIR="./test_mount"
fusermount -u $MOUNT_DIR 2>/dev/null || true

python3 -c "
import pexpect, sys
child = pexpect.spawn('./openfort ./test_vault ./test_mount -f -d')
child.expect('Enter password:')
child.sendline('pass')
f = open('fuse_crash.log', 'wb')
while True:
    try:
        data = child.read_nonblocking(size=1024, timeout=None)
        f.write(data)
        f.flush()
    except pexpect.EOF:
        break
    except pexpect.TIMEOUT:
        pass
" &
FUSE_PID=$!
sleep 2

echo "Testing file creation..."
echo "This is a test" > $MOUNT_DIR/test1.txt || echo "Failed write"
sleep 1
cat fuse_crash.log

kill $FUSE_PID || true
fusermount -u $MOUNT_DIR 2>/dev/null || true
