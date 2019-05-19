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

#import "Age.h"
#include "sodium.h"
#import "CryptoService.h"
#import "X25519Key.h"
#import "NSData+Helper.h"
#import "CiphertextObject.h"
#import "AgeObject.h"

@interface Age ()

@end

@implementation Age

#pragma mark - Public

- (void)X25519_encryptData:(NSData *)data
                publicKeys:(NSArray<NSData *> *)publicKeys
                 X25519Key:(X25519Key *)X25519Key
                completion:(void (^)(AgeObject *ageObject))completion {
    CryptoService *crypto = [CryptoService new];
    [crypto encryptData:data completion:^(CiphertextObject * _Nonnull ciphertext) {
        dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^(void) {
            AgeObject *obj = [AgeObject objectWithType:[X25519Key typeString]
                                            ciphertext:ciphertext.ciphertext
                                             publicKey:[X25519Key.publicKey rawBase64Encoded]];
            for (NSData *pk in publicKeys) {
                NSData *sharedKey = [[X25519Key sharedSecretWithPublicKey:pk] sha256Digest];
                NSData *encryptedFileKey = [self chacha20poly1305Encrypt:ciphertext.key key:sharedKey];
                [obj appendHexEncoding:[pk firstEightBytesHexEncoded] andEncryptedKey:[encryptedFileKey rawBase64Encoded]];
            }
            dispatch_async(dispatch_get_main_queue(), ^(void){
                completion(obj);
            });
        });
    }];
}

#pragma mark - Private

- (NSData *)chacha20poly1305Encrypt:(NSData *)data
                                key:(NSData *)key {
    // We use zero nonces because all keys are single use.
    unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES] = {0};
    unsigned char ciphertext[data.length + crypto_aead_chacha20poly1305_ABYTES];
    unsigned long long ciphertext_len;
    
    crypto_aead_chacha20poly1305_encrypt(ciphertext, &ciphertext_len,
                                         data.bytes, data.length,
                                         /* additional_data= */ NULL, /* additional_data_length= */ 0,
                                         /* nsec= */ NULL, nonce, key.bytes);
    
    return [NSData dataWithBytes:ciphertext length:ciphertext_len];
}

@end
