#include<stdio.h>
#include<stdint.h>

//static const size_t rcache_size=2048;
struct SecureRandom
{
	//u8 rcache[rcache_size];
	//size_t tail;
	FILE* devurandom;
};
static void mkSecureRandom(struct SecureRandom* sr)
{
	sr->devurandom=fopen("/dev/urandom","rb");
}
struct SecureRandom gsr;
extern void randombytes(uint8_t* out,uint64_t sz)
{
	static int is_init=0;
	if(is_init==0)
	{
		mkSecureRandom(&gsr);
		is_init=1;
	}
	if(fread(out,1,sz,gsr.devurandom) != sz)
	{
		fprintf(stderr,"Entropy failure warning!");
	}
}

