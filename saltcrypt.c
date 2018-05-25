#include "tweetnacl.h"

#include<stdio.h>
#include<stdint.h>
#include<stddef.h>
#include<string.h>
#include<ctype.h>
#include<stdlib.h>
#include<limits.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#define PM (32*PATH_MAX)
#define NBDIFF (crypto_secretbox_NONCEBYTES-crypto_secretbox_BOXZEROBYTES)

extern void kdf(uint8_t* outkey,const uint8_t* password,size_t pwlength,size_t iters);
extern void randombytes(uint8_t* out,uint64_t sz);

size_t estimate_cipher_space(size_t plain)
{
	size_t mlen=plain+crypto_secretbox_ZEROBYTES;
	return mlen+NBDIFF; //assumes NONCE > BOXZERO
}
size_t estimate_plaintext_space(size_t cipher)
{
	return cipher-NBDIFF;
}



//the plaintext must be padded with crypto_secretbox_ZEROBYTES memory
void encrypt(uint8_t* cipherout,uint8_t* plain,size_t mlen,const uint8_t* key)
{
	uint8_t nonce[crypto_secretbox_NONCEBYTES];
	randombytes(nonce,crypto_secretbox_NONCEBYTES);
	memset(plain,0,crypto_secretbox_ZEROBYTES);
	
	crypto_secretbox(cipherout+NBDIFF,plain,mlen+crypto_secretbox_ZEROBYTES,nonce,key);
	memcpy(cipherout,nonce,crypto_secretbox_NONCEBYTES);
}

int decrypt(uint8_t* plainout,uint8_t* cipher,size_t cipherlen,const uint8_t* key)
{
	uint8_t nonce[crypto_secretbox_NONCEBYTES];
	memcpy(nonce,cipher,crypto_secretbox_NONCEBYTES);
	memset(cipher,0,crypto_secretbox_NONCEBYTES);
	
	int result=crypto_secretbox_open(plainout,cipher+NBDIFF,cipherlen-NBDIFF,nonce,key);
	return result;
}

size_t filesize(FILE* fp)
{
	fseek(fp, 0L, SEEK_END);
	size_t sz = ftell(fp);
	fseek(fp,0L,SEEK_SET);
	return sz;
}

//notes:  ifand only if bigger than memory
//        use fallocate with insert and collapse and mmap 
//	  use mmap,memmov,ftruncate for both as a fallback
//	  use fread+fwrite

/*Steve132: You might go the other way.  Map the file in first, then do MAP_FIXED one page below that.
[22:33] <Steve132> jjuran: with an empty file?  That's actually a very good idea
[22:33] <Steve132> The file would have to be a whole page long right?
[22:35] <jjuran> Steve132: But I'd try /dev/zero first.
[22:37] <jjuran> Another option is to mmap /dev/zero for the number of pages in the file plus one, then MAP_FIXED the file.
[22:39] <Steve132> because if you do only that one then map_fixed on the file can invalidate the mapping and therefore theoretically allow the page below to be reclaimedwhen I need it to actually *be* zero
sysconf(_SC_PAGE_SIZE)
*/
uint8_t* readnew(const char* fnin,size_t* szout,size_t prefix)
{
	*szout=0;
	FILE* fio=fopen(fnin,"rb");
	if(!fio) return 0;
	size_t sz=filesize(fio);
	uint8_t* inmem=malloc(sz+prefix);
	if(!inmem) return 0;
	size_t rnum=fread(inmem+prefix,1,sz,fio);
	fclose(fio);
	if(rnum!=sz)
	{
		free(inmem);
		return 0;
	}
	*szout=sz;
	memset(inmem,0,prefix);
	return inmem;
}

int encrypt_file_mem(const char* fnin,const char* fnout,const uint8_t* key)
{
	size_t sz;
	uint8_t nonce[crypto_secretbox_NONCEBYTES];
	uint8_t* plaintext=readnew(fnin,&sz,crypto_secretbox_ZEROBYTES);
	
	size_t ciphsize=estimate_cipher_space(sz);
	
	FILE* foo=fopen(fnout,"wb");
	if(!foo)
	{
		free(plaintext);
		return -1;
	}

	//int fd=open(fnout,O_CREAT | O_RDWR);
	//uint8_t* ciphout=mmap(NULL,ciphsize,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);

	randombytes(nonce,crypto_secretbox_NONCEBYTES);
	//memset(plaintext,0,crypto_secretbox_ZEROBYTES);
	uint8_t* ciphout=malloc(ciphsize);
	if(!ciphout) 
	{
		/*for(size_t i=0;i<sz;i++) 
		{
			plaintext[i]=0; #not needed...but ONLY because plaintext is in a file.
		}*/
		free(plaintext);
		return -1;
	}
	crypto_secretbox(ciphout+NBDIFF,plaintext,sz+crypto_secretbox_ZEROBYTES,nonce,key);
	/*for(size_t i=0;i<sz;i++) 
	{
		plaintext[i]=0;
	}*/
	memcpy(ciphout,nonce,crypto_secretbox_NONCEBYTES);
	free(plaintext);
	fwrite(ciphout,1,ciphsize,foo);
	//munmap(ciphout);
	free(ciphout);
	return 0;
}

int decrypt_file_mem(const char* fnin,const char* fnout,const uint8_t* key)
{
	size_t sz;
	uint8_t nonce[crypto_secretbox_NONCEBYTES];
	
	uint8_t* ciphertext=readnew(fnin,&sz,0);
	FILE* foo=fopen(fnout,"wb");
	
	if(!ciphertext || !foo)
	{
		return -1;
	}
	
	size_t plainsize=estimate_plaintext_space(sz);
	
	uint8_t* plainout=malloc(plainsize);
	
	memcpy(nonce,ciphertext,crypto_secretbox_NONCEBYTES);
	memset(ciphertext,0,crypto_secretbox_BOXZEROBYTES+NBDIFF);
	
	crypto_secretbox_open(plainout,ciphertext+NBDIFF,sz-NBDIFF,nonce,key);
	
	free(ciphertext);
	fwrite(plainout+crypto_secretbox_ZEROBYTES,1,plainsize-crypto_secretbox_ZEROBYTES,foo);
	free(plainout);
	return 0;
}
void print_hex(const uint8_t *s,size_t len)
{
	size_t i;
	for(i=0;i<len;i++)
	{
		unsigned int v=(unsigned int)s[i];
		fprintf(stderr,"%02X", v);
	}
	fprintf(stderr,"\n");
}

void print_help(const char* arg0)
{
	printf("Usage: %s <inputfile> [-o outputfile] [-p password] [-k keyfile]",arg0);
	printf("\n-p,--password\n\tPrompt for password.  The key is derived from this password.  If keyfile is set, then the derived key is written to the keyfile. This option is implied if keyfile is not set.");
	printf("\n-k,--keyfile\n\tThe keyfile.  Keyfile is plaintext file with just a 32-byte 64-character hex string.  If -p is not present, use this file as the key");
	printf("\n-o,--outfile\n\tThe output file.  If inputfile has a '.nacl' extension, the default mode will be encryption and the outputfile defaults to <inputfile>.nacl");
	printf("\n-h,--help\n\tShow this help message");
	printf("\nExamples:");
	printf(
	"\n\n%s -p -k mykey.tnk\n\tDerive the key and write it to mykey.tnk"
	"\n\n%s data.tar.nacl\n\tDecrypt data.tar.nacl and write it to data.tar.  Prompt for password"
	"\n\n%s data.tar.nacl -k mykey.tnk\n\tDecrypt data.tar.nacl and write it to data.tar.  Use mykey.tnk as the secret key"
	"\n\n%s data.tar\n\tEncrypt data.tar to data.tar.nacl.  Prompt for password"
	,arg0,arg0,arg0,arg0);
	printf("\n");
}

//Todo: force encryption mode? -e/-d

int main(int argc,const char** argv)
{
	const char* inputfile=0;
	const char* outputfile=0;
	const char* keyfile=0;
	int password_mode=0;
	uint8_t key[crypto_secretbox_KEYBYTES];
	
	for(size_t ai=1;ai<argc;ai++)
	{
		const char* carg=argv[ai];
		if(carg[0]=='-')
		{
			char optionchar=carg[1];
			if(optionchar=='-') optionchar=tolower(carg[2]);
			switch(optionchar)
			{
			case 'p':
				password_mode=1;
				continue;
			case 'o':
				outputfile=argv[++ai];
				continue;
			case 'k':
				keyfile=argv[++ai];
				continue;
			case 'h':
				print_help(argv[0]);
				continue;
			default:
				fprintf(stderr,"Unrecognized option %s\n",carg);
				return -1;
			};
		}
		else
		{
			inputfile=carg;
			continue;
		}
	}
	
	
	if(!inputfile && !password_mode)
	{
		fprintf(stderr,"Error: missing input file.\n");
		//print_help(argv[0]);
		return -1;
	}
	
	if(!keyfile)
	{
		password_mode=1;
	}
	
	
	if(password_mode)
	{
		const size_t PWMAX=2048;
		char password[PWMAX];
		fprintf(stderr,"What is your password: ");
		if(fgets(password,PWMAX,stdin) == NULL)
		{
			fprintf(stderr,"Password read error\n");
			return -1;
		}
		password[strcspn(password, "\n")]=0;
		size_t pwlen=strnlen(password,PWMAX);
		fprintf(stderr,"Deriving key...");
		kdf(key,(const uint8_t*)password,pwlen,1UL << 18);
		fprintf(stderr,"Deriving key complete.");
		if(keyfile)
		{
			FILE* kfo=fopen(keyfile,"w");
			for(size_t ki=0;ki<crypto_secretbox_KEYBYTES;ki++)
			{
				fprintf(kfo,"%02X",(unsigned int)key[ki]);
			}
			fclose(kfo);
		}
		if(!inputfile)
		{
			return 0;
		}
	}
	else if(keyfile)
	{
		FILE* kfi=fopen(keyfile,"r");
		//fgets(hkey,2*crypto_secretbox_KEYBYTES,kfi);
		unsigned int v;
		for(size_t ki=0;ki<crypto_secretbox_KEYBYTES;ki++)
		{
			if(fscanf(kfi, "%2x", &v) != 1)
			{
				fprintf(stderr,"Could not understand key file.");
				return -1;
			}
			key[ki] = (uint8_t)v;
		}
		fclose(kfi);
	}
	
	size_t ifnlen=strlen(inputfile);
	int is_encrypting=strcmp(inputfile+ifnlen-5,".nacl")!=0;
	
	char newoutput[PM];
	
	if(!outputfile)
	{
		size_t dex=ifnlen > PM ? PM : ifnlen;
		memset(newoutput,0,PM);
		strncpy(newoutput,inputfile,PM);
		if(is_encrypting)
		{
			strncpy(newoutput+dex,".nacl",PM-dex);
		}
		else
		{
			dex-=5;
			memset(newoutput+dex,0,5);
		}
		outputfile=newoutput;
	}
	
	if(is_encrypting)
	{
		encrypt_file_mem(inputfile,outputfile,key);
	}
	else
	{
		decrypt_file_mem(inputfile,outputfile,key);
	}
	
	
	return 0;
}



/*
 * const uint8_t pw[]="Hello world";
 u int8_t outkey[32];            **
 kdf(outkey,pw,11,1<<10);
 print_hex(outkey,32);
 
 size_t mlen=14;
 uint8_t test[crypto_secretbox_ZEROBYTES+mlen];
 memset(test,0,crypto_secretbox_ZEROBYTES);
 size_t k;
 for(k=0;k<mlen;k++)
 {
 test[crypto_secretbox_ZEROBYTES+k]='a'+k;
 }
 size_t cipherspace=estimate_cipher_space(mlen);
 uint8_t* cipher=malloc(cipherspace);
 encrypt(cipher,test,mlen,outkey);
 print_hex(cipher,cipherspace);
 size_t plainspace=estimate_plaintext_space(cipherspace);
 uint8_t* newplain=malloc(plainspace);
 
 int r=decrypt(newplain,cipher,cipherspace,outkey);
 fprintf(stderr,"result:%d\n",r);
 print_hex(newplain,plainspace);*/