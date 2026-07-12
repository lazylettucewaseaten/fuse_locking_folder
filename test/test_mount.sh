#!/bin/bash
set -e
VAULT_DIR="$(pwd)/test_vault"
MOUNT_DIR="$(pwd)/test_mount"
python3 -c "
import pexpect, sys
child = pexpect.spawn('./openfort $VAULT_DIR $MOUNT_DIR')
child.expect('Enter password:')
child.sendline('pass')
child.expect(pexpect.EOF)
" 
sleep 2
hexdump -C $MOUNT_DIR/test3_parallel.txt > hexdump.txt 2>&1
cat hexdump.txt
fusermount -u $MOUNT_DIR 2>/dev/null || true
