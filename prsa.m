//
//  prsa.m
//  cmd+test
//
//  Created by edward yang on 2017/6/22.
//  Copyright © 2017年 edward yang. All rights reserved.
//

#import "prsa.h"


@implementation Prsa:NSObject
// utf8 <=> string
+ (NSData *)encodeStringToUtf8:(NSString *)data
{
    NSData * ret = [data dataUsingEncoding:NSUTF8StringEncoding];
    return ret;
}

+ (NSString *)decodeUtf8ToString:(NSData *)data;
{
    NSString * ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    //NSLog(@"%@",ret);
    return ret;
}

// Do it twice, the data will back to original.
//unsigned char * dd=(Byte *)[[@"1234567890" dataUsingEncoding:NSUTF8StringEncoding] bytes];int ll=7;
//[Prsa mix_data:dd messLen:ll];
//for(int i=0;i<ll+3;i++){    printf("%c ",dd[i]);}
+ (unsigned char *) mix_data:(unsigned char *)data messLen:(int) size
{
    //123456789 => 927456381. data[2i] replace data[N-2i-1], i=0,1..N/2; 1=>1; 12=>21; 123=>321; 1234=>4231; 12345=>52341;123456=>624351
    int n = size/2;
    unsigned char tmp=0;
    for(int i=0;i<n;i=i+2){
        tmp = data[i];
        data[i]=data[size-i-1];
        data[size-i-1]=tmp;
    }
    return data;
}

//print data
+ (void) print_data:(NSData* )data
{
    printf("--");
    unsigned char * tt = (Byte*)[data bytes];
    for(int i=0;i<[data length];i++)
    {
        printf("%02x",tt[i]);
    }
}

+ (void) print_chars:(unsigned char* )data length:(int)len
{
    for(int i=0;i<len;i++)
    {
        printf("%02x",data[i]);
    }
}

// string <=> base64
+ (NSString *)encodeDataToBase64:(NSData *) data
{
   NSString *ret = [data base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithCarriageReturn];
    NSLog(@"%@",ret);
    return ret;
}

+ (NSData *)decodeBase64ToData:(NSString *) base64
{
    NSData * ret = [[NSData alloc] initWithBase64EncodedString:base64 options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
    //NSString *tt = [[NSString alloc] initWithData:ret encoding:NSUTF8StringEncoding];
    //NSLog(@"%@",tt);
    return ret;
}

+ (NSString *)encodeStringToBase64:(NSString *) data
{
    NSData *d = [data dataUsingEncoding:NSUTF8StringEncoding];
    NSString *ret = [d base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];

    return ret;
}

+ (NSString *)decodeBase64ToString:(NSString *) base64
{
    NSData * ret = [[NSData alloc] initWithBase64EncodedString:base64 options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
    NSString *tt = [[NSString alloc] initWithData:ret encoding:NSUTF8StringEncoding];
    //NSLog(@"%@",tt);
    return tt;
}

// sha
/*
- (NSString *)hmac:(NSString *)plaintext withKey:(NSString *)key
{
    const char *cKey  = [key cStringUsingEncoding:NSASCIIStringEncoding];
    const char *cData = [plaintext cStringUsingEncoding:NSASCIIStringEncoding];
    unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, cKey, strlen(cKey), cData, strlen(cData), cHMAC);
    NSData *HMACData = [NSData dataWithBytes:cHMAC length:sizeof(cHMAC)];
    const unsigned char *buffer = (const unsigned char *)[HMACData bytes];
    NSMutableString *HMAC = [NSMutableString stringWithCapacity:HMACData.length * 2];
    for (int i = 0; i < HMACData.length; ++i){
        [HMAC appendFormat:@"%02x", buffer[i]];
    }
    
    return HMAC;
}
*/
//String to sha256, encoded by base64

+ (NSString *) sha256String:(NSString *) data
{
    NSData *tt = [Prsa encodeStringToUtf8:data];
    NSData *tdata = [Prsa sha256Data:tt];
    NSString *ret = [Prsa encodeDataToBase64:tdata];
    return ret;
}
//data to sha256 , without encoding
//NSString *tt = @"hello 我们要 厌离娑婆 。 ";
//NSData *tdata = [tt dataUsingEncoding:NSUTF8StringEncoding];
//
//NSData *withpad=[Prsa add_padding:tdata blockSize:16];
//
//NSLog(@" --- %@",[[NSString alloc] initWithData:withpad encoding:NSUTF8StringEncoding]);
//
//NSData *pad=[Prsa remove_padding:withpad blockSize:16];
//
//NSLog(@" --- %@",[[NSString alloc] initWithData:pad encoding:NSUTF8StringEncoding]);
+ (NSData *) sha256Data:(NSData *) data
{
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    
    if(CC_SHA256(data.bytes, data.length, digest))
    {
        NSData *ret = [[NSData alloc] initWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
        return ret;
    }
    else{
        return nil;
    }

}

+ (NSData *) add_padding:(NSData *)message blockSize:(int8_t)blockSize
{
    //put size of the padding into the back of the message
    unsigned long len = 0, plen = 0;
    unsigned long mlen = [message length];
   
    len = (mlen/blockSize+1)*blockSize;
    
    plen = len - mlen;//length need to be pack into the data
    
    Byte *byteData = (Byte*)malloc(len);
    
    [message getBytes:byteData];
    
//    for(int i=0;i<mlen;i++){
////        byteData[i]= message[i];
//    }
    
    for(int i=0;i<plen;i++){
        byteData[len-i-1] = plen;
    }
    
    NSData *ret = [[NSData alloc] initWithBytes:byteData length:len];
    free(byteData);
    return ret;
}


+ (NSData *) remove_padding:(NSData *)message blockSize:(int8_t)blockSize
{
    //put size of the padding into the back of the message
    unsigned long len = 0, plen = 0;
    unsigned long mlen = [message length];
    
    Byte *byteData = (Byte *)[message bytes];
    plen = (int)byteData[mlen-1];
    
    return [message subdataWithRange:NSMakeRange(0,mlen-plen)];
}

//test code
//NSData *pkey = [@"abc232434354563457345643456457" dataUsingEncoding:NSUTF8StringEncoding];
//NSData *temp = [Prsa aes_encrypt:[@"abc" dataUsingEncoding:NSUTF8StringEncoding] password:pkey ];
//
//NSData *tx = [Prsa aes_decrypt:temp password:pkey];
//
//NSData *xx = [Prsa remove_padding:temp blockSize:16];
//NSLog(@"temp= '%@'",xx);

+ (NSData *) aes_encrypt:(NSData *)message password:(NSData *)pkey;
{
    NSData * nmessage = [Prsa add_padding:message blockSize:kCCKeySizeAES128];
    NSData * npkey = [Prsa add_padding:pkey blockSize:kCCKeySizeAES128];
    
    NSData *iv = [[Prsa sha256Data:npkey] subdataWithRange:NSMakeRange(0,kCCKeySizeAES128)];

    
    
    CCCryptorRef cref;
    
    // finally, we need to use our own functions for the AES and RSA algorithm. It will be time cost to handle all
    // system to get the same result.
    CCCryptorStatus tt = CCCryptorCreateWithMode(kCCEncrypt,kCCModeCBC,kCCAlgorithmAES,ccNoPadding,
                                                 [iv bytes],
                                                 [npkey bytes],
                                                 kCCKeySizeAES128,NULL,0,0,0,
                                                 &cref);
    
    NSUInteger nmessageLength = nmessage.length;
    
    char *outData = malloc(nmessageLength);
    memset(outData, 0, nmessageLength);
    size_t outLength = 0;
    
    CCCryptorUpdate(cref, nmessage.bytes, nmessageLength, outData, nmessageLength, &outLength);
    
    NSData *data = [NSData dataWithBytes: outData length: outLength];
    
    CCCryptorRelease(cref);
    
    NSString *txx = [Prsa encodeDataToBase64:data];
    NSLog(@"aes_result:%@",txx);
    
    free(outData);
    
    return data;
}


+ (NSData *) aes_decrypt:(NSData *)cmessage password:(NSData *)pkey;
{
    unsigned long mlen = [cmessage length];
    
    NSData * npkey = [Prsa add_padding:pkey blockSize:kCCKeySizeAES128];
    NSData *iv = [[Prsa sha256Data:npkey] subdataWithRange:NSMakeRange(0,kCCKeySizeAES128)];
    
    
    CCCryptorRef cref;
    
    // finally, we need to use our own functions for the AES and RSA algorithm. It will be time cost to handle all
    // system to get the same result.
    CCCryptorStatus tt = CCCryptorCreateWithMode(kCCDecrypt,kCCModeCBC,kCCAlgorithmAES,ccNoPadding,
                                                 [iv bytes],
                                                 [npkey bytes],
                                                 kCCKeySizeAES128,NULL,0,0,0,
                                                 &cref);
    
    NSUInteger nmessageLength = mlen;
    
    char *outData = malloc(nmessageLength);
    memset(outData, 0, nmessageLength);
    size_t outLength = 0;
    
    CCCryptorUpdate(cref, cmessage.bytes, nmessageLength, outData, nmessageLength, &outLength);
    
    NSData *data = [NSData dataWithBytes: outData length: outLength];
    
    CCCryptorRelease(cref);
    
//    NSString *txx = [Prsa encodeDataToBase64:data];
//    NSLog(@"aes_result:%@",txx);
    
    free(outData);
    
    return [Prsa remove_padding:data blockSize:kCCKeySizeAES128];
}

+ (NSString *) aes_encrypt_string:(NSString *)message password:(NSString *)pkey
{
    NSData * ret =[Prsa aes_encrypt:[message dataUsingEncoding:NSUTF8StringEncoding] password:[pkey dataUsingEncoding:NSUTF8StringEncoding]];
    return [Prsa encodeDataToBase64:ret];
}
+ (NSString *) aes_decrypt_string:(NSString *)messageCode password:(NSString *) pkey
{
    NSData * input = [Prsa decodeBase64ToData:messageCode];
    NSData *ret = [Prsa aes_decrypt:input password:[pkey dataUsingEncoding:NSUTF8StringEncoding]];
    return [Prsa decodeUtf8ToString:ret];
}


//RSA
+ (NSData *) rsa_pub_encrypt:(NSData *)message public:(RSA *)pub padding:(int) padding
{
    if(padding==RSA_PKCS1_PADDING)
    {
        int blockLen = RSA_size(pub);
        int messLen = [message length];

        int mblockLen = blockLen-11;
        int tolen = (messLen/mblockLen +1)*blockLen;
        
        unsigned char * from = (unsigned char * )[message bytes];
        unsigned char * to = (unsigned char *) malloc(tolen);
//        memset(to,0,tolen);
        
        int tret=1,tlen=0,count=0,llen=0;
        while(tlen<messLen && tret>0)
        {
          llen = MIN(mblockLen,messLen-tlen);
          tret = RSA_public_encrypt(llen,&from[count*mblockLen], &to[count*blockLen], pub, RSA_PKCS1_PADDING);
          count=count+1;
          tlen = tlen + llen;
        }
        NSData *ret = [[NSData alloc] initWithBytes:to length:count*blockLen];

        return ret;
    }else if(padding==RSA_NO_PADDING)
    {
        return nil;
    }

    return nil;
}
+ (NSData *) rsa_pub_decrypt:(NSData *)message public:(RSA *)pub padding:(int) padding
{
    int mlen = [message length];
    int blockLen = RSA_size(pub);
    if(mlen % blockLen != 0 ) return nil;
    
    if(padding==RSA_PKCS1_PADDING)
    {
        int tBlockLen = blockLen - 11;
        int toLen = (mlen/blockLen+1)*blockLen;
        unsigned char * from = (unsigned char * )[message bytes];
        unsigned char * to = (unsigned char *) malloc(toLen);
        
        //        memset(to,0,toLen);
        
        int tret=1,tlen=0,count=0,receiveLen=0;
        while(tlen<mlen && tret>0)
        {
            tret = RSA_public_decrypt(blockLen,&from[count*blockLen], &to[count*tBlockLen], pub, RSA_PKCS1_PADDING);
            count=count+1;
            tlen = count*blockLen;
            receiveLen = receiveLen + tret;
        }
        NSData *ret = [[NSData alloc] initWithBytes:to length:receiveLen];
        
        return ret;
    }
    return nil;
    
}
+ (NSData *) rsa_pri_decrypt:(NSData *)message private:(RSA *)pri padding:(int) padding
{
    int mlen = [message length];
    int blockLen = RSA_size(pri);
    if(mlen % blockLen != 0 ) return nil;
    
    if(padding==RSA_PKCS1_PADDING)
    {
        int tBlockLen = blockLen - 11;
        int toLen = (mlen/blockLen+1)*blockLen;
        unsigned char * from = (unsigned char * )[message bytes];
        unsigned char * to = (unsigned char *) malloc(toLen);
        
//        memset(to,0,toLen);
        
        int tret=1,tlen=0,count=0,receiveLen=0;
        while(tlen<mlen && tret>0)
        {
            tret = RSA_private_decrypt(blockLen,&from[count*blockLen], &to[count*tBlockLen], pri, RSA_PKCS1_PADDING);
            count=count+1;
            tlen = count*blockLen;
            receiveLen = receiveLen + tret;
        }
        NSData *ret = [[NSData alloc] initWithBytes:to length:receiveLen];
        
        return ret;
    }
    return nil;
    
}
+ (NSData *) rsa_pri_encrypt:(NSData *)message private:(RSA *)pri padding:(int) padding
{
    if(padding==RSA_PKCS1_PADDING)
    {
        int blockLen = RSA_size(pri);
        int messLen = [message length];
        
        int mblockLen = blockLen-11;
        int tolen = (messLen/mblockLen +1)*blockLen;
        
        unsigned char * from = (unsigned char * )[message bytes];
        unsigned char * to = (unsigned char *) malloc(tolen);
        //        memset(to,0,tolen);
        
        int tret=1,tlen=0,count=0,llen=0;
        while(tlen<messLen && tret>0)
        {
            llen = MIN(mblockLen,messLen-tlen);
            tret = RSA_private_encrypt(llen,&from[count*mblockLen], &to[count*blockLen], pri, RSA_PKCS1_PADDING);
            count=count+1;
            tlen = tlen + llen;
        }
        NSData *ret = [[NSData alloc] initWithBytes:to length:count*blockLen];
        
        return ret;
    }else if(padding==RSA_NO_PADDING)
    {
        return nil;
    }
    
    return nil;
    
}


//read
//const char *pubkey1 = "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAOEZDppAAh/Tc2dfoHvRzd48ErbcGCcLtBxPF7wdKGwYMBpE/IalfUAU\nzVmPEuxOV/905F+fYixjDTgZER6A0HcFxo5E3G2a9VYiFjIZ3/oO3sro1qDDR0oz\nkjEldwMuA2pKc7bW8XOi2TZav44apSdpplTDxMujH0fAfIlfAZtPAgMA//8=\n-----END RSA PUBLIC KEY-----";
//const char *privatekey1="-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQC9i9RueM7X21OlSrhig+9RCHl2qE5H3LOzeaNQAhQRAeRLQkIa\neiECZWpRXx2tYd+jTa9hX2998q7byM+fIdt7r1Czx3J4GtlC3BKIujq3SLthECA7\nB+5ABFQTIMzvjyyQH0pBHp/IoKaaPTD4h2XYfa2/MJzKCiYZMsA1IRBa0wIDAP//\nAoGAXszy7qc4UmuS9Ckf+t1pKVc/Xtix52DH/NYdxNye99SDCyrRjGGLLeb4oGUL\nk8ecCh+fi3mvk5RYimKsQYnHd3mccIzlgfMT+VHPEgQIDJ9RwKLzZAX2N0qahqkF\nJC9uSgn933Pwhpurj4dicOHfrfMHaFJmHGfqAcxZrY4ePG8CQQDr8K7t5urqx/yf\nvAMC1SoRmc6pqiIZQpMGw7wmQS2QArYh/mmnBvMxLs0XMgRU5L4GxM4rKn9kafrw\n3VksrcmpAkEAzald0GBIH8he4O9yjNJ6X+pxpF48dwez3E41g+kjGcHGF0pYpmFl\n/wPNllE7aqGQB/HTz4SBWkg4o1g/SoUmGwJBAI683qBcxdSkptHNEGNkFmJSPZ9T\nwwqpGBk8vOyldNTG6LQDXC/e3ThLN2/Suv+SjSQnbZz8x6Qn3W5aZs/1RqcCQELv\nPvB9FlY2W19OLTUUAVnStdj1aGEhieHf8filS8rAxEn+w0LBe6RvkEtZMVCQb2GV\nTMWZZHaXcc5TGcRJg8UCQQDZNMO/x3AOepsvQ/mNjJTqYAbmlJWz0IKCjKactUWs\nnAyJbVbL2zfHpVeJZsOmICxmKY/EHFPa3P8MsRvU4ran\n-----END RSA PRIVATE KEY-----";
//
//RSA* r=[Prsa rsa_read_pub_string_pem:pubkey1 ];

+ (RSA*) rsa_read_pub_file_pem:(char*) fpath
{
    FILE *fp = fopen(fpath,"r");
    RSA *r1 = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return r1;
}
+ (RSA*) rsa_read_pri_file_pem:(char*)fpath
{
    FILE *fp = fopen(fpath,"r");
    RSA *r1 = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return r1;
}
+ (RSA*) rsa_read_pub_string_pem:(char *)pubkey
{
    RSA *rpub = RSA_new();
    
    BIO * bio = BIO_new(BIO_s_mem());
    BIO_puts(bio, pubkey);
    
    RSA* rsa = PEM_read_bio_RSAPublicKey(bio, &rpub, NULL, NULL);
    return rsa;

}
+ (RSA*) rsa_read_pri_string_pem:(char *)prikey
{
    RSA *rpri = RSA_new();
    BIO * bio = BIO_new(BIO_s_mem());
    BIO_puts(bio, prikey);
    RSA* rsa = PEM_read_bio_RSAPrivateKey(bio, &rpri, NULL, NULL);
    return rsa;

}


+ (void)rsa_test
{
    // When input strings , you need to make sure that the each line should have \n, and the last line have not to have \n .
    const char *pubkey1 = "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAOEZDppAAh/Tc2dfoHvRzd48ErbcGCcLtBxPF7wdKGwYMBpE/IalfUAU\nzVmPEuxOV/905F+fYixjDTgZER6A0HcFxo5E3G2a9VYiFjIZ3/oO3sro1qDDR0oz\nkjEldwMuA2pKc7bW8XOi2TZav44apSdpplTDxMujH0fAfIlfAZtPAgMA//8=\n-----END RSA PUBLIC KEY-----";
    const char *privatekey1="-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQC9i9RueM7X21OlSrhig+9RCHl2qE5H3LOzeaNQAhQRAeRLQkIa\neiECZWpRXx2tYd+jTa9hX2998q7byM+fIdt7r1Czx3J4GtlC3BKIujq3SLthECA7\nB+5ABFQTIMzvjyyQH0pBHp/IoKaaPTD4h2XYfa2/MJzKCiYZMsA1IRBa0wIDAP//\nAoGAXszy7qc4UmuS9Ckf+t1pKVc/Xtix52DH/NYdxNye99SDCyrRjGGLLeb4oGUL\nk8ecCh+fi3mvk5RYimKsQYnHd3mccIzlgfMT+VHPEgQIDJ9RwKLzZAX2N0qahqkF\nJC9uSgn933Pwhpurj4dicOHfrfMHaFJmHGfqAcxZrY4ePG8CQQDr8K7t5urqx/yf\nvAMC1SoRmc6pqiIZQpMGw7wmQS2QArYh/mmnBvMxLs0XMgRU5L4GxM4rKn9kafrw\n3VksrcmpAkEAzald0GBIH8he4O9yjNJ6X+pxpF48dwez3E41g+kjGcHGF0pYpmFl\n/wPNllE7aqGQB/HTz4SBWkg4o1g/SoUmGwJBAI683qBcxdSkptHNEGNkFmJSPZ9T\nwwqpGBk8vOyldNTG6LQDXC/e3ThLN2/Suv+SjSQnbZz8x6Qn3W5aZs/1RqcCQELv\nPvB9FlY2W19OLTUUAVnStdj1aGEhieHf8filS8rAxEn+w0LBe6RvkEtZMVCQb2GV\nTMWZZHaXcc5TGcRJg8UCQQDZNMO/x3AOepsvQ/mNjJTqYAbmlJWz0IKCjKactUWs\nnAyJbVbL2zfHpVeJZsOmICxmKY/EHFPa3P8MsRvU4ran\n-----END RSA PRIVATE KEY-----";
    
    const char *pubkey = "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAMcwGzMMThI+T6n1T0kSHozgeXTYv+8dOeySRdVz1m5/rCWPhuKwgWxr\nqHXxBnPmVeao30je/dtlXiU+1aSg+61Q1o6R0EWfnyN3u4yhWD4/g8BjQ6WhF3yQ\nP0mKbRQBXMl1UivkRGzR64fojvBahjrw3XxNQTz2A+30iT7sBjvjAgMBAAE=\n-----END RSA PUBLIC KEY-----";
    
    
    BIGNUM *bnn, *bne;
    bne = BN_new();
    BN_set_word(bne, 65535);
    int ret;
    //
    //
    
    //
    //generate rsa
    RSA *r = RSA_new();
    
    RSA_generate_key_ex(r,1024, bne,NULL);
    
    RSA_print_fp(stdout, r, 0);
    
    //write into pem files
    FILE *fp = fopen("/Users/edwardyang/Desktop/apub.pem","w+");
    FILE *fp1 = fopen("/Users/edwardyang/Desktop/apri.pem","w+");
    PEM_write_RSAPublicKey(fp, r);
    PEM_write_RSAPrivateKey(fp1, r, NULL, NULL, 0, NULL, NULL);
    
    fclose(fp);
    fclose(fp1);
    
    //read RSA from file
    FILE *fp3 = fopen("/Users/edwardyang/Desktop/apub.pem","r");
    FILE *fp4 = fopen("/Users/edwardyang/Desktop/apri.pem","r");
    
    RSA *r1 = PEM_read_RSAPublicKey(fp3, NULL, NULL, NULL);
    RSA *r2=  PEM_read_RSAPrivateKey(fp4, NULL, NULL, NULL);
    
    ret = RSA_check_key(r2);
    //ret = RSA_check_key(r1);//only has public
    
    //read from memory
    RSA *rrsa = RSA_new();
    
    BIO * bio = BIO_new(BIO_s_mem());
    BIO_puts(bio, pubkey1);
    
    RSA* rsa = PEM_read_bio_RSAPublicKey(bio, &rrsa, NULL, NULL);
    
    RSA *rrsb = RSA_new();
    BIO * biob = BIO_new(BIO_s_mem());
    BIO_puts(bio, privatekey1);
    RSA* rsab = PEM_read_bio_RSAPrivateKey(bio, &rrsb, NULL, NULL);
    if (rsab == NULL) {
        return;
    }
    
    //read from files.
    BIO *bio_private= BIO_new(BIO_s_file());
    BIO_read_filename(bio_private,"/Users/edwardyang/Desktop/apri.pem");
    
    RSA* rsac = PEM_read_bio_RSAPrivateKey(bio_private, &rrsb, NULL, NULL);
    if (rsac == NULL) {
        return;
    }

    
}



@end
