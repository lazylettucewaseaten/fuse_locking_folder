#!/bin/bash
set -e
VAULT_DIR="$(pwd)/test_vault"
MOUNT_DIR="$(pwd)/test_mount"
fusermount -u $MOUNT_DIR 2>/dev/null || true
rm -rf $VAULT_DIR $MOUNT_DIR
mkdir -p $VAULT_DIR $MOUNT_DIR

python3 -c "
import pexpect, sys
child = pexpect.spawn('./fort++ init $VAULT_DIR')
child.expect('Enter Password:')
child.sendline('pass')
child.expect('Confirm Password:')
child.sendline('pass')
child.expect(pexpect.EOF)
"

python3 -c "
import pexpect, sys
child = pexpect.spawn('./openfort $VAULT_DIR $MOUNT_DIR')
child.expect('Enter password:')
child.sendline('pass')
child.expect(pexpect.EOF)
" 

sleep 2

for i in {1..50}; do
    echo "Parallel write line $i" >> $MOUNT_DIR/test3_parallel.txt &
done
wait

ls -l $MOUNT_DIR/test3_parallel.txt
wc -l < $MOUNT_DIR/test3_parallel.txt
cat $MOUNT_DIR/test3_parallel.txt

fusermount -u $MOUNT_DIR 2>/dev/null || true
