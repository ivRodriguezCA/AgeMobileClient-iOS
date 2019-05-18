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
#import <CommonCrypto/CommonCrypto.h>

#import "X25519Key.h"
#include "sodium.h"

@interface X25519Key ()

@property (nonatomic, strong) NSData *publicKey;
@property (nonatomic, strong) NSData *privateKey;
@property (nonatomic, strong) NSDate *createdAt;

@end

@implementation X25519Key

#pragma mark - Public

- (instancetype)init {
    if (self = [super init]) {
        unsigned char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
        unsigned char ed25519_skpk[crypto_sign_ed25519_SECRETKEYBYTES];
        unsigned char curve25519_pk[crypto_scalarmult_curve25519_BYTES];
        unsigned char curve25519_skpk[crypto_scalarmult_curve25519_BYTES];
        
        crypto_sign_ed25519_keypair(ed25519_pk, ed25519_skpk);
        
        __unused int pkResult = crypto_sign_ed25519_pk_to_curve25519(curve25519_pk, ed25519_pk);
        __unused int skResult = crypto_sign_ed25519_sk_to_curve25519(curve25519_skpk, ed25519_skpk);
        
        _publicKey = [NSData dataWithBytes:curve25519_pk length:crypto_scalarmult_curve25519_BYTES];
        _privateKey = [NSData dataWithBytes:curve25519_skpk length:crypto_scalarmult_curve25519_BYTES];
        _createdAt = [NSDate date];
    }
    
    return self;
}

- (NSString *)description {
    NSString *line1 = [NSString stringWithFormat:@"# created: %@\n", [self createdAtString]];
    NSString *line2 = [NSString stringWithFormat:@"# pubkey:%@\n", [self publicKeyString]];
    NSString *line3 = [NSString stringWithFormat:@"AGE_PRIVATE_KEY_%@", [self privateKeyString]];
    
    return [NSString stringWithFormat:@"%@%@%@", line1, line2, line3];
}

#pragma mark - Private

- (NSString *)publicKeyString {
    return [[self.publicKey base64EncodedStringWithOptions:0] stringByReplacingOccurrencesOfString:@"=" withString:@""];
}

- (NSString *)privateKeyString {
    return [[self.privateKey base64EncodedStringWithOptions:0] stringByReplacingOccurrencesOfString:@"=" withString:@""];
}

- (NSString *)createdAtString {
    NSDateFormatter *formatter = [NSDateFormatter new];
    formatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss'Z'Z";
    
    return [formatter stringFromDate:self.createdAt];
}

@end
