sed -i 's/return -EIO;/{\nofstream dbg("\/tmp\/fuse_debug.log", ios::app);\ndbg << "EIO at " << __LINE__ << "\\n";\nreturn -EIO;\n}/g' securelettuce/openvault/filesystem/fuse_op.cpp
make
