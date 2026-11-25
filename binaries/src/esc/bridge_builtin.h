#ifndef BRIDGE_BUILTIN_H
#define BRIDGE_BUILTIN_H

#include <stddef.h>
#include <stdint.h>

struct brb_sha256_ctx {
	uint32_t state[8];
	uint64_t length;
	unsigned char block[64];
	size_t used;
};

void brb_sha256_init(struct brb_sha256_ctx *ctx);
void brb_sha256_update(struct brb_sha256_ctx *ctx, const void *data,
		       size_t len);
void brb_sha256_final(struct brb_sha256_ctx *ctx, unsigned char out[32]);
void brb_sha256_hex(const unsigned char digest[32], char out[65]);

#endif
