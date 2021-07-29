#define MMM (sz+mask)&~mask
#include <stdint.h>

#include <stdio.h>

static inline uintptr_t align_up(uintptr_t sz, size_t alignment)
{
    uintptr_t mask = alignment - 1;
    if ((alignment & mask) == 0) {  /* power of two? */
        return MMM;       
    }
    return (((sz + mask) / alignment) * alignment);
}



int main(void)
{

	int ret;
	ret = align_up(120, 4); /* should be 120 */ 
	printf("%d\n", ret);
	ret = align_up(121, 4); /* should be 124 */ 
	printf("%d\n", ret);
	ret = align_up(122, 4); /* should be 124 */ 
	printf("%d\n", ret);
	ret = align_up(123, 4); /* should be 124 */ 
	printf("%d\n", ret);
}
