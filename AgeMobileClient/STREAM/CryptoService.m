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

#import "CryptoService.h"
#include "sodium.h"
#import "STREAMCryptor.h"
#import "CiphertextObject.h"

// Blocks are of size 64KiB. 1 KiB = 1,024 KB.
// More info: https://en.wikipedia.org/wiki/Kibibyte
#define kSTREAMBlockSize 64.0*65536000.0

@implementation CryptoService

#pragma mark - Public

- (void)encryptData:(NSData *)plaintext
         completion:(void (^)(CiphertextObject *ciphertext))completion {
    dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^(void) {
        unsigned char rawKey[crypto_aead_chacha20poly1305_KEYBYTES];
        crypto_aead_chacha20poly1305_keygen(rawKey);
        NSData *key = [NSData dataWithBytes:rawKey length:crypto_aead_chacha20poly1305_KEYBYTES];
        
        STREAMCryptor *cryptor = [STREAMCryptor new];
        NSArray<NSData *> *blocks = [self divideDataInBlocks:plaintext];
        NSMutableArray<NSData *> *ciphertextBlocks = [NSMutableArray new];
        for (NSUInteger idx = 0; idx < blocks.count; idx++) {
            NSData *data = blocks[idx];
            BOOL isLastBlock = idx == blocks.count - 1;
            NSData *ciphertextBlock = [cryptor encryptData:data key:key isLastBlock:isLastBlock];
            [ciphertextBlocks addObject:ciphertextBlock];
        }
        
        CiphertextObject *ciphertext = [CiphertextObject objectWithKey:key andCiphertext:[ciphertextBlocks copy]];
        
        dispatch_async(dispatch_get_main_queue(), ^(void){
            completion(ciphertext);
        });
    });
}

- (void)decryptData:(NSData *)ciphertext
                key:(NSData *)key
         completion:(void (^)(NSData * _Nullable plaintext, NSError * _Nullable error))completion {
    dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^(void){
        STREAMCryptor *cryptor = [STREAMCryptor new];
        NSArray<NSData *> *blocks = [self divideDataInBlocks:ciphertext];
        NSMutableArray<NSData *> *plaintextBlocks = [NSMutableArray new];
        for (NSUInteger idx = 0; idx < blocks.count; idx++) {
            NSData *data = blocks[idx];
            BOOL isLastBlock = idx == blocks.count - 1;
            NSData *plaintextBlock = [cryptor decryptData:data key:key isLastBlock:isLastBlock];
            if (plaintextBlock == nil) {
                NSString *errorDesc = [NSString stringWithFormat:@"Failed to decrypt block at index %lu.", (unsigned long)idx];
                NSError *error = [NSError errorWithDomain:@"com.ivrodriguez.AgeMobileClient" code:001 userInfo:@{NSLocalizedDescriptionKey: errorDesc}];
                dispatch_async(dispatch_get_main_queue(), ^(void){
                    completion(nil, error);
                });
                return;
            }
            [plaintextBlocks addObject:plaintextBlock];
        }
        NSMutableData *plaintext = [NSMutableData new];
        for (NSData *d in plaintextBlocks) {
            [plaintext appendData:d];
        }
        dispatch_async(dispatch_get_main_queue(), ^(void){
            completion([plaintext copy], nil);
        });
    });
}

#pragma mark - Private

- (NSArray<NSData *> *)divideDataInBlocks:(NSData *)data {
    if (data.length < kSTREAMBlockSize) {
        return @[data];
    }
    
    NSMutableArray *blocks = [NSMutableArray new];
    NSRange range;
    for (NSUInteger loc = 0; loc < data.length; loc += kSTREAMBlockSize) {
        NSUInteger len = kSTREAMBlockSize;
        if (loc + kSTREAMBlockSize > data.length) {
            len = data.length - loc;
        }
        range = NSMakeRange(loc, len);
        NSData *subData = [data subdataWithRange:range];
        [blocks addObject:subData];
    }
    return [blocks copy];
}

@end
