#!/usr/bin/env python3
import tweetnacl
import argparse
from hashlib import pbkdf2_hmac
from os import urandom
from binascii import hexlify,unhexlify
from ctypes import byref

def kdf(password):
	return pbkdf2_hmac('sha256', bytearray(password,'utf8'), b'saltcrypt', 2**22, dklen=None)

def encrypt(inby,key):
	inpf_bytes=bytearray(inby) 
	output=[tweetnacl.u8()]*(len(inpf_bytes)+16)
	nonce=urandom(24)
	print('nonce:'+str(hexlify(nonce)))
	tweetnacl.crypto_secretbox_xsalsa20poly1305_tweet(output,inpf_bytes,len(inpf_bytes),nonce,key)
	return (b'naclfile')+bytearray(nonce)+bytearray(output)

def decrypt(inby,key):
	inpf_bytes=bytearray(inby)
	prefix=inpf_bytes[:8]
	inpf_bytes=inpf_bytes[8:]
	if(prefix != b'naclfile'):
		raise Exception("File does not appear to be a valid naclfile")
	nonce=inpf_bytes[:24]
	print('nonce:'+str(hexlify(nonce)))
	inpf_bytes=inpf_bytes[24:]

	output=bytearray(b'\00'*(len(inpf_bytes)+32))
	tweetnacl.crypto_secretbox_xsalsa20poly1305_tweet_open(output,inpf_bytes,len(inpf_bytes),nonce,key)
	return bytearray(output[:])

if __name__=='__main__':
	parser=argparse.ArgumentParser()
	parser.add_argument('input',type=str)
	parser.add_argument('--output','-o',type=str)
	args=parser.parse_args()

	encrypting=not(args.input[-5:] == '.nacl')

	inpf=open(args.input,'rb')

	if(args.output is None):
		if(encrypting):
			args.output=args.input+'.nacl'
		else:
			args.output=args.input[:-5]


	
	#password=input('Enter your password: ')
	print("Deriving Key...")
	#key=kdf(password)
	key=b'1b4505c0490392948c46d74c386a4c0a632d73e914c3d076ec375aedd9bdfa01'
	print("Key derived.")
	
	#if(encrypting):
	#	print("Encrypting %s to %s" % (args.input,args.output))
	#	encrypt(inpf,outpf,key)
	#else:
	#	print("Decrypting %s to %s" % (args.input,args.output))
	#	decrypt(inpf,outpf,key)

	content=b'abcdefghiabcdefghiabcdefghiabcdefghiabcdefghi'
	cip=encrypt(content,key)
	print(cip)
	plain=decrypt(cip,key)
	print(plain)
	
	
	
	
	
	
