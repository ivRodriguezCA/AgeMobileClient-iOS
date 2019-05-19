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

#import "X25519Key.h"
#include "sodium.h"
#import "NSData+Helper.h"
#import "NSString+Helper.h"

static NSString * const kCreatedAtText = @"# created: ";
static NSString * const kPublicKeyText = @"# pubkey:";
static NSString * const kPrivateKeyText = @"AGE_PRIVATE_KEY_";

static NSUInteger const kCurve25519KeyLength = 32;

@interface X25519Key ()

@property (nonatomic, strong) NSData *publicKey;
@property (nonatomic, strong) NSData *privateKey;
@property (nonatomic, strong) NSDate *createdAt;

@end

@implementation X25519Key

#pragma mark - Public

+ (NSString *)typeString {
    return @"X25519";
}

- (instancetype)init {
    unsigned char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
    unsigned char ed25519_skpk[crypto_sign_ed25519_SECRETKEYBYTES];
    unsigned char curve25519_pk[crypto_scalarmult_curve25519_BYTES];
    unsigned char curve25519_skpk[crypto_scalarmult_curve25519_BYTES];
    
    crypto_sign_ed25519_keypair(ed25519_pk, ed25519_skpk);
    
    __unused int pkResult = crypto_sign_ed25519_pk_to_curve25519(curve25519_pk, ed25519_pk);
    __unused int skResult = crypto_sign_ed25519_sk_to_curve25519(curve25519_skpk, ed25519_skpk);
    
    return [[X25519Key alloc]
            initWithPublicKey:[NSData dataWithBytes:curve25519_pk length:crypto_scalarmult_curve25519_BYTES]
            privateKey:[NSData dataWithBytes:curve25519_skpk length:crypto_scalarmult_curve25519_BYTES]
            createdAt:[NSDate date]];
}

- (instancetype)initFromDisk:(NSString * _Nonnull)keyString {
    NSArray *components = [keyString componentsSeparatedByString:@"\n"];
    if (components.count != 3) {
        return nil;
    }
    
    NSString *dateString = components.firstObject;
    if (![dateString containsString:kCreatedAtText]) {
        return nil;
    }
    
    NSString *pKeyString = components[1];
    if (![pKeyString containsString:kPublicKeyText]) {
        return nil;
    }
    
    NSString *sKeyString = components.lastObject;
    if (![sKeyString containsString:kPrivateKeyText]) {
        return nil;
    }
    
    NSString *createdAtString = [dateString stringByReplacingOccurrencesOfString:kCreatedAtText withString:@""];
    NSDate *createdAt = [X25519Key createdAtFromString:createdAtString];
    
    NSString *publicKeyString = [pKeyString stringByReplacingOccurrencesOfString:kPublicKeyText withString:@""];
    NSData *publicKey = [publicKeyString dataFromRawBase64Encoded];
    
    NSString *privateKeyString = [sKeyString stringByReplacingOccurrencesOfString:kPrivateKeyText withString:@""];
    NSData *privateKey = [privateKeyString dataFromRawBase64Encoded];
    
    return [[X25519Key alloc] initWithPublicKey:publicKey privateKey:privateKey createdAt:createdAt];
}

- (NSData *)publicKeySHA256 {
    if (self.publicKey == nil) {
        return [NSData data];
    }
    
    return [self.publicKey sha256Digest];
}

- (NSUInteger)keyLength {
    return kCurve25519KeyLength;
}

- (NSData * _Nullable)sharedSecretWithPublicKey:(NSData *)x25519PublicKey {
    NSUInteger keyLength = [self keyLength];
    if (x25519PublicKey.length != keyLength) {
        return nil;
    }
    
    unsigned char scalarmult_q[crypto_scalarmult_BYTES];
    
    if (crypto_scalarmult(scalarmult_q, self.privateKey.bytes, x25519PublicKey.bytes) != 0) {
        return nil;
    }
    
    return [NSData dataWithBytes:scalarmult_q length:crypto_scalarmult_BYTES];
}

- (NSString *)description {
    NSString *line1 = [NSString stringWithFormat:@"%@%@\n", kCreatedAtText, [self createdAtString]];
    NSString *line2 = [NSString stringWithFormat:@"%@%@\n", kPublicKeyText, [self publicKeyString]];
    NSString *line3 = [NSString stringWithFormat:@"%@%@", kPrivateKeyText, [self privateKeyString]];
    
    return [NSString stringWithFormat:@"%@%@%@", line1, line2, line3];
}

- (BOOL)isEqual:(id)object {
    if (![object isKindOfClass:[self class]]) {
        return NO;
    }
    
    X25519Key *keyObject = object;
    
    return [self.publicKey isEqualToData:keyObject.publicKey] &&
    [self.privateKey isEqualToData:keyObject.privateKey];
}

#pragma mark - Private

- (instancetype)initWithPublicKey:(NSData * _Nonnull)publicKey privateKey:(NSData * _Nonnull)privateKey createdAt:(NSDate * _Nonnull)createdAt {
    if (self = [super init]) {
        _publicKey = publicKey;
        _privateKey = privateKey;
        _createdAt = createdAt;
    }
    
    return self;
}

- (NSString *)publicKeyString {
    return [self.publicKey rawBase64Encoded];
}

- (NSString *)privateKeyString {
    return [self.privateKey rawBase64Encoded];
}

- (NSString *)createdAtString {
    NSDateFormatter *formatter = [NSDateFormatter new];
    formatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss'Z'Z";
    
    return [formatter stringFromDate:self.createdAt];
}

+ (NSDate *)createdAtFromString:(NSString *)stringDate {
    NSDateFormatter *formatter = [NSDateFormatter new];
    formatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss'Z'Z";
    
    return [formatter dateFromString:stringDate];
}

@end
