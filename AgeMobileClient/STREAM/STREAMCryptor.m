/*
 The MIT License (MIT)
 Copyright © 2019 Ivan Rodriguez. All rights reserved.
 
 Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 and associated documentation files (the "Software"), to deal in the Software without restriction,
 including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in all copies or substantial
 portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
 LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#import "STREAMCryptor.h"
#include "sodium.h"
#import "NonceEncoder.h"

@interface STREAMCryptor ()

@property (nonatomic, strong) NonceEncoder *nonceEncoder;

@end

@implementation STREAMCryptor

- (instancetype)init {
    if (self = [super init]) {
        _nonceEncoder = [NonceEncoder new];
    }
    
    return self;
}

- (NSData * _Nullable)encryptData:(NSData *)plaintextData
                              key:(NSData *)key
                      isLastBlock:(BOOL)isLastBlock {
    
    unsigned char ciphertext[plaintextData.length + crypto_aead_chacha20poly1305_ABYTES];
    unsigned long long ciphertext_len;
    
    
    NSData *nonce = [self.nonceEncoder nextIsLastBlock:isLastBlock];
    
    crypto_aead_chacha20poly1305_encrypt(ciphertext, &ciphertext_len,
                                         plaintextData.bytes, plaintextData.length,
                                         /* additional_data= */ NULL, /* additional_data_length= */ 0,
                                         /* nsec= */ NULL, nonce.bytes, key.bytes);
    
    return [NSData dataWithBytes:ciphertext length:ciphertext_len];
}

- (NSData * _Nullable)decryptData:(NSData *)ciphertext
                              key:(NSData *)key
                      isLastBlock:(BOOL)isLastBlock {
    unsigned char decrypted[ciphertext.length];
    unsigned long long decrypted_len;
    NSData *nonce = [self.nonceEncoder nextIsLastBlock:isLastBlock];
    
    if (crypto_aead_chacha20poly1305_decrypt(decrypted, &decrypted_len,
                                             /* nsec= */ NULL,
                                             ciphertext.bytes, ciphertext.length,
                                             /* additional_data= */ NULL, /* additional_data_length= */ 0,
                                             nonce.bytes, key.bytes) != 0) {
        return nil;
    }
    
    return [NSData dataWithBytes:decrypted length:decrypted_len];
}

@end
