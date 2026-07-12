#!/bin/bash
set -e
VAULT_DIR="./test_vault"
MOUNT_DIR="./test_mount"
fusermount -u $MOUNT_DIR 2>/dev/null || true
rm -rf $VAULT_DIR $MOUNT_DIR
mkdir -p $VAULT_DIR $MOUNT_DIR

python3 -c "
import pexpect
child = pexpect.spawn('./fort++ init $VAULT_DIR')
child.expect('Enter Password:')
child.sendline('pass')
child.expect('Confirm Password:')
child.sendline('pass')
child.expect(pexpect.EOF)
"

# Instead of pexpect for openfort, let's use a small C program to provide password or just expect
cat << 'EOF2' > pass.expect
#!/usr/bin/expect -f
spawn ./openfort ./test_vault ./test_mount -f -d
expect "Enter password:"
send "pass\r"
expect eof
EOF2
chmod +x pass.expect

./pass.expect > fuse_crash.log 2>&1 &
FUSE_PID=$!
sleep 2

echo "This is a test" > $MOUNT_DIR/test1.txt || echo "Failed write"
sleep 1
cat fuse_crash.log
