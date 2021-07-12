#include <stdio.h>
#include <stdint.h>

#define LLL v >> (mask-c+1) 
#define RRR v << (mask-c+1) 
  
#define __DECLARE_ROTATE(bits, type)                   \
    static inline type rotl##bits(const type v, int c) \
    {                                                  \
        const int mask = (bits) - (1);                 \
        c &= mask;                                     \
                                                       \
        return (v << c) | (LLL);                      \
    }                                                  \
                                                       \
    static inline type rotr##bits(const type v, int c) \
    {                                                  \
        const int mask = (bits) - (1);                 \
        c &= mask;                                     \
                                                       \
        return (v >> c) | (RRR);                      \
    }

#define DECLARE_ROTATE(bits) __DECLARE_ROTATE(bits, uint##bits##_t)


DECLARE_ROTATE(64);
DECLARE_ROTATE(32);
DECLARE_ROTATE(16);
DECLARE_ROTATE(8);

int main(void) {
	uint64_t op64=0xdeadbeefdeadbeef;
	uint32_t op32=0xdeadbeef;
	uint16_t op16=0xbeef;
	uint8_t op8=0xbe;

	printf("=== original ==\n");

	printf("%llx\n", op64);
	printf("%lx\n", op32);
	printf("%x\n", op16);
	printf("%x\n", op8);

	op64 = rotl64(op64,22);
	op32 = rotl32(op32,22);
	op16 = rotl16(op16,3);
	op8 = rotl8(op8,4);


	printf("=== rotl 22,22,3,4 bits respectively ==\n");

	printf("%llx\n", op64);
	printf("%lx\n", op32);
	printf("%x\n", op16);
	printf("%x\n", op8);

	op64 = rotr64(op64,22);
	op32 = rotr32(op32,22);
	op16 = rotr16(op16,3);
	op8 = rotr8(op8,4);

	printf("=== rotr 22,22,3,4 bits respectively ==\n");

	printf("%llx\n", op64);
	printf("%lx\n", op32);
	printf("%x\n", op16);
	printf("%x\n", op8);



}
