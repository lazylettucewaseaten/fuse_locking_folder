// filesystem_ops.hpp
#pragma once



#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>

// --- Filesystem Logic ---
void build_name_map();


// This makes the functions visible to other .cpp files, like main.cpp.
int lz_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi);
int lz_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags);
int lz_open(const char *path, struct fuse_file_info *fi);
int lz_create(const char *path, mode_t mode, struct fuse_file_info *fi);
int lz_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
int lz_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
int lz_unlink(const char *path);
int lz_release(const char *path, struct fuse_file_info *fi);
int lz_truncate(const char *path, off_t size, struct fuse_file_info *fi);

// --- FUSE Operations Struct ---
extern struct fuse_operations lz_oper;

