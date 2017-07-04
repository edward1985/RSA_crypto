//
//  prsa.h
//  cmd+test
//
//  Created by edward yang on 2017/6/22.
//  Copyright © 2017年 edward yang. All rights reserved.
//

#import <Foundation/Foundation.h>
#include "openssl/md5.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>


@interface Prsa : NSObject
//padding.
+ (NSData *) remove_padding:(NSData *)message blockSize:(int8_t)blockSize;
+ (NSData *) add_padding:(NSData *)message blockSize:(int8_t)blockSize;

//mix data
+ (unsigned char *) mix_data:(unsigned char *)data messLen:(int) size;

//print data
+ (void) print_data:(NSData* )data;
+ (void) print_chars:(unsigned char* )data length:(int)len;
//base64
+ (NSString *)encodeDataToBase64:(NSData *) data;
+ (NSData *)decodeBase64ToData:(NSString *) base64;


+ (NSString *)encodeStringToBase64:(NSString *) data;
+ (NSString *)decodeBase64ToString:(NSString *) base64;

//utf8 coding
+ (NSData *)encodeStringToUtf8:(NSString *)data;
+ (NSString *)decodeUtf8ToString:(NSData *)data;

//sha256
+ (NSData*) sha256Data:(NSData *) data;
+ (NSString *) sha256String:(NSString *) data;

//AES  AES128 CBC mode.
+ (NSData *) aes_encrypt:(NSData *)message password:(NSData *)pkey;
+ (NSData *) aes_decrypt:(NSData *)messageCode password:(NSData *) pkey ;

// typically , message and pkey are strings.
// using base64
//test
//NSString *dmess = [Prsa aes_encrypt_string:@"abc" password:@"123"];
//NSLog(@"encode= '%@'",dmess);
//NSLog(@"decode= '%@'",[Prsa aes_decrypt_string:dmess password:@"123"]);
+ (NSString *) aes_encrypt_string:(NSString *)message password:(NSString *)pkey;
+ (NSString *) aes_decrypt_string:(NSString *)messageCode password:(NSString *) pkey ;

//random key
+(NSData *) gen_random_key:(int) length;

//RSA
/* RSA API test
 //        unsigned char * s=(unsigned char *)malloc(128);
 //        [data getBytes:s length:7];
 //         unsigned char * d=(unsigned char *)malloc(128);
 //        unsigned char * m=(unsigned char *)malloc(128);
 //
 //        x = RSA_public_encrypt(7,s, d, r, RSA_PKCS1_PADDING);
 //        [Prsa print_chars:d length:128];
 //
 //        NSData * tempx=[[NSData alloc] initWithBytes:d length:128];
 //        unsigned char * dx = (unsigned char *)[tempx bytes];
 //
 //        x = RSA_private_decrypt(128,dx, m, r, RSA_PKCS1_PADDING);
 //        [Prsa print_chars:m length:128] ;
 */
//+ (RSA *) rsa_load_pub:(NSString *)pub_key;
//+ (RSA *) rsa_load_pri:(NSString *)pri_key;


//RSA Test
//BIGNUM *bnn, *bne;int x=0;bne = BN_new();BN_set_word(bne, 65535);
//RSA *r = RSA_new();RSA_generate_key_ex(r,1024, bne,NULL);
//
//NSData *data = [@"abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghiabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghi" dataUsingEncoding:NSUTF8StringEncoding];
//
//NSData* rdata = [Prsa rsa_pub_encrypt:data public:r padding:RSA_PKCS1_PADDING];
//[Prsa print_data:rdata];
//NSData* rrr = [Prsa rsa_pri_decrypt:rdata private:r padding:RSA_PKCS1_PADDING];
//[Prsa print_data:rrr];
//OR
//NSData* rdata = [Prsa rsa_pri_encrypt:data private:r padding:RSA_PKCS1_PADDING];
//[Prsa print_data:rdata];
//NSData* rrr = [Prsa rsa_pub_decrypt:rdata public:r padding:RSA_PKCS1_PADDING];
//[Prsa print_data:rrr];

+ (NSData *) rsa_pub_encrypt:(NSData *)message public:(RSA *)pub padding:(int) padding;
+ (NSData *) rsa_pub_decrypt:(NSData *)message public:(RSA *)pub padding:(int) padding;
+ (NSData *) rsa_pri_encrypt:(NSData *)message private:(RSA *)pri padding:(int) padding;
+ (NSData *) rsa_pri_decrypt:(NSData *)message private:(RSA *)pri padding:(int) padding;

+ (RSA*) rsa_read_pub_file_pem:(char*) fpath;
+ (RSA*) rsa_read_pri_file_pem:(char*)fpath;
+ (RSA*) rsa_read_pub_string_pem:(char *)pubkey;
+ (RSA*) rsa_read_pri_string_pem:(char *)prikey;

+(void) rsa_test;
//

@end
