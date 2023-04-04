/*
Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>

DECAF is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU GPL, version 3 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about DECAF and other softwares, see our
web site at:
http://sycurelab.ecs.syr.edu/

If you have any questions about DECAF,please post it on
http://code.google.com/p/decaf-platform/
*/
#ifndef DECAF_VM_COMPRESS_H
#define DECAF_VM_COMPRESS_H

#define IOBUF_SIZE 4096

#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus

#include "hw/hw.h" // AWH
#include <zlib.h>
#include <stdint.h>

typedef struct{
    z_stream zstream;
    void *f;
    uint8_t buf[IOBUF_SIZE];
} DECAF_CompressState_t;

extern int decaf_compress_open(DECAF_CompressState_t *s, void *f);
extern int decaf_compress_buf(DECAF_CompressState_t *s, const uint8_t *buf, int len);
extern void decaf_compress_close(DECAF_CompressState_t *s);
extern int decaf_decompress_open(DECAF_CompressState_t *s, void *f);
extern int decaf_decompress_buf(DECAF_CompressState_t *s, uint8_t *buf, int len);
extern void decaf_decompress_close(DECAF_CompressState_t *s);
extern void decaf_vm_compress_init(void); //dummy init

#ifdef __cplusplus
}
#endif // __cplusplus

#endif //DECAF_VM_COMPRESS_H
