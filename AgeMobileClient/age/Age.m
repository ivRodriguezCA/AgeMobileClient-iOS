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
#import "KeyStorageProtocol.h"

@interface Age ()

@end

@implementation Age

#pragma mark - Public

- (void)X25519_encryptData:(NSData *)data
                publicKeys:(NSArray<NSData *> *)publicKeys
                 X25519Key:(X25519Key *)X25519key
                completion:(void (^)(AgeObject *ageObject))completion {
    CryptoService *crypto = [CryptoService new];
    [crypto encryptData:data completion:^(CiphertextObject * _Nonnull ciphertext) {
        dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^(void) {
            AgeObject *obj = [AgeObject objectWithCiphertext:ciphertext.ciphertext
                                             publicKey:[X25519key.publicKey rawBase64Encoded]];
            for (NSData *pk in publicKeys) {
                NSData *sharedKey = [[X25519key sharedSecretWithPublicKey:pk] sha256Digest];
                NSData *encryptedFileKey = [self chacha20poly1305Encrypt:ciphertext.key key:sharedKey];
                [obj appendType:[X25519Key typeString]
                    hexEncoding:[pk firstEightBytesHexEncoded]
                andEncryptedKey:[encryptedFileKey rawBase64Encoded]];
            }
            dispatch_async(dispatch_get_main_queue(), ^(void){
                completion(obj);
            });
        });
    }];
}

- (void)X25519_decryptFromRawInput:(NSString *)rawInput
                        keyStorage:(id<KeyStorageProtocol>)keyStorage
                        completion:(void (^)(NSData * _Nullable plaintext, NSError * _Nullable error))completion {
    AgeObject *obj = [AgeObject objectWithRawInput:rawInput
                                         keyStorage:keyStorage];
    if (obj == nil) {
        NSError *error = [NSError errorWithDomain:@"com.ivrodriguez.AgeMobileClient" code:001 userInfo:@{NSLocalizedDescriptionKey: @"Failed to parse input."}];
        completion(nil, error);
        return;
    }
    
    NSData *encryptionKey = [obj.X25519key sharedSecretWithPublicKey:obj.senderPublicKey];
    NSData *fileKey = [self chacha20poly1305Decrypt:obj.encryptedKey key:encryptionKey];
    if (fileKey == nil) {
        NSError *error = [NSError errorWithDomain:@"com.ivrodriguez.AgeMobileClient" code:001 userInfo:@{NSLocalizedDescriptionKey: @"Failed to decrypt file key."}];
        completion(nil, error);
        return;
    }
    
    CryptoService *crypto = [CryptoService new];
    [crypto decryptData:obj.payload key:fileKey completion:^(NSData * _Nullable plaintext, NSError * _Nullable error) {
        if (error != nil) {
            completion(nil, error);
            return;
        }
        
        completion(plaintext, nil);
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

- (NSData *)chacha20poly1305Decrypt:(NSData *)data
                                key:(NSData *)key {
    // We use zero nonces because all keys are single use.
    unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES] = {0};
    unsigned char decrypted[data.length];
    unsigned long long decrypted_len;
    
    if (crypto_aead_chacha20poly1305_decrypt(decrypted, &decrypted_len,
                                             /* nsec= */ NULL,
                                             data.bytes, data.length,
                                             /* additional_data= */ NULL, /* additional_data_length= */ 0,
                                             nonce, key.bytes) != 0) {
        return nil;
    }
    
    return [NSData dataWithBytes:decrypted length:decrypted_len];
}

@end
