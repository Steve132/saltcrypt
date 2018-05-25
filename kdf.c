#include "tweetnacl.h"
#include <stdint.h>
#include <stddef.h>

#define BSIZE crypto_hashblocks_BLOCKBYTES
#define HSIZE crypto_hash_BYTES
#define KSIZE crypto_secretbox_KEYBYTES

#if SIZE_MAX > 0xFFFFFFFF
#define OWIDE UINT64_C(0x5c5c5c5c5c5c5c5c)
#define IWIDE UINT64_C(0x3636363636363636)
#else
#define OWIDE UINT32_C(0x5c5c5c5c)
#define IWIDE UINT32_C(0x36363636)
#endif 
#define HWCOUNT (HSIZE/sizeof(size_t))
#define FOR(i,n) for (i = 0;i < n;++i)
//msg is, by design, exactly HSIZE
//therefore
typedef uint8_t u8;

static void hmac(u8* outhash,
	const u8* inkey,size_t keylen,
	const u8* inmsg) {
	size_t i;	
	u8 key[BSIZE],okey[BSIZE+HSIZE],ikey[BSIZE+HSIZE];
	
	if(keylen > BSIZE) {
		crypto_hash(key,inkey,keylen);
	}
	else if(keylen < BSIZE) {
		FOR(i,keylen) key[i]=inkey[i];
		FOR(i,BSIZE-keylen) key[keylen+i]=0;
	}
	FOR(i,BSIZE/sizeof(size_t)){
		size_t kwide=((size_t*)key)[i];
		((size_t*)okey)[i]=kwide^OWIDE;
		((size_t*)ikey)[i]=kwide^IWIDE;
	}
	//hash(o_key_pad ∥ hash(i_key_pad ∥ message))
	FOR(i,HWCOUNT){
		size_t* ikp=(size_t*)(ikey+BSIZE);
		const size_t* imsp=(const size_t*)inmsg;
		ikp[i]=imsp[i];
	}
	crypto_hash(&okey[BSIZE],ikey,BSIZE+HSIZE);
	crypto_hash(outhash,okey,BSIZE+HSIZE);
}

//this implementation,salt MUST be HSIZE bytes with bytes[-4:]==0x00000001
static void pbkdf2(u8* outkey,const u8* password,size_t pwlength,const u8* salt,size_t iters)
{
	size_t U[HWCOUNT];
	size_t* T=(size_t*)outkey;
	size_t i,b;

	FOR(i,HWCOUNT){ T[i]=0; };
	
	hmac((u8*)U,password,pwlength,salt);
	FOR(i,iters){
		FOR(b,HWCOUNT) T[b]^=U[b];
		hmac((u8*)U,password,pwlength,(const u8*)U);
	}
}
//this implementation KSIZE must be a multiple of sizeof(size_t) AND KSIZE <= HSIZE
static const u8 saltcrypt_salt[HSIZE]="\x29\x17\xc8\x2b\x2c\x79\x37\xe0\x7c\x5e\x65\x40\xad\x42\xef\x6b\xc0\x9a\x57\x65\xf1\xa4\x4e\x8e\x5e\x84\xbe\xfa\x00\x00\x00\x01";
void kdf(u8* outkey,const u8* password,size_t pwlength,size_t iters)
{
	size_t pbkdkey[HWCOUNT];
	size_t i;
	pbkdf2((u8*)pbkdkey,password,pwlength,saltcrypt_salt,iters);
	FOR(i,KSIZE/sizeof(size_t)) {
		((size_t*)outkey)[i]=pbkdkey[i];
	}
}
