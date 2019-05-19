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

#import "AgeObject.h"
#import "X25519Key.h"
#import "KeyStorageProtocol.h"
#import "NSString+Helper.h"

static NSString * const kRecipientLineBeginning = @"->";
static NSString * const kCiphertextSeparator = @"---";

// Eventually we'll support all of these types:
// #define kSupportedKeyTypes @[@"X25519", @"Argon2id", @"ssh-rsa", @"ssh-ed25519"]
#define kSupportedKeyTypes @[@"X25519"]

NS_ASSUME_NONNULL_BEGIN

@interface Recipient : NSObject

+ (instancetype)withType:(NSString *)type
             hexEncoding:(NSString *)hexEncoding
            encryptedKey:(NSString *)rawBase64EncryptedKey;

@end

NS_ASSUME_NONNULL_END

@interface Recipient ()

@property (nonatomic, copy) NSString *type;
@property (nonatomic, copy) NSString *hexEncoding;
@property (nonatomic, copy) NSString *rawBase64EncryptedKey;

@end

@implementation Recipient

+ (instancetype)withType:(NSString *)type
             hexEncoding:(NSString *)hexEncoding
            encryptedKey:(NSString *)rawBase64EncryptedKey {
    Recipient *rpt = [Recipient new];
    rpt.type = type;
    rpt.hexEncoding = hexEncoding;
    rpt.rawBase64EncryptedKey = rawBase64EncryptedKey;
    
    return rpt;
}

@end

@interface AgeObject ()

@property (nonatomic, strong) NSData *ciphertext;
@property (nonatomic, copy) NSString *rawBase64PublicKey;
@property (nonatomic, strong) NSArray<Recipient *> *recipients;

// Properties for decryption process.
@property (nonnull, strong) X25519Key *X25519key;
@property (nonnull, strong) NSData *senderPublicKey;
@property (nonnull, strong) NSData *encryptedKey;
@property (nonnull, strong) NSData *payload;

@end

@implementation AgeObject

+ (instancetype)objectWithCiphertext:(NSData *)ciphertext
                           publicKey:(NSString *)rawBase64PublicKey {
    AgeObject *obj = [AgeObject new];
    obj.ciphertext = ciphertext;
    obj.rawBase64PublicKey = rawBase64PublicKey;
    obj.recipients = [NSArray new];
    
    return obj;
}

+ (instancetype)objectWithRawInput:(NSString *)rawOutput
                        keyStorage:(id<KeyStorageProtocol>)keyStorage {
    NSArray<NSString *> *lines = [rawOutput componentsSeparatedByString:@"\n"];
    // The file format defines the minimum number of lines as 4
    if (lines.count < 4) {
        return nil;
    }
    
    X25519Key *X25519key;
    NSData *senderPublicKey;
    NSData *encryptedKey;
    
    for (NSUInteger idx = 0; idx < lines.count; idx++) {
        NSString *line = lines[idx];
        
        if ([line hasPrefix:kRecipientLineBeginning]) {
            // After we find our key information just ignore all other recipients' entries.
            if (X25519key != nil) {
                continue;
            }
            
            NSArray<NSString *> *recipientComponents = [line componentsSeparatedByString:@" "];
            // X25519 keys always have 4 elements
            if (recipientComponents.count != 4) {
                continue;
            }
            // The second element is the key type.
            NSString *type = recipientComponents[1];
            if ([type isEqualToString:[X25519Key typeString]]) {
                // For X25519 keys, the 3rd element is the recipient's public key id.
                NSString *hexEncoding = recipientComponents[2];
                X25519key = [keyStorage retrieveX25519KeyWithHexEncoded:hexEncoding];
                // If we cannot find this key id on our KeyStorage it's someone else's key.
                if (X25519key == nil) {
                    continue;
                }
                // For X25519 keys, the 4th element is the sender's public key.
                NSString *rawBase64SenderPublicKey = recipientComponents[3];
                senderPublicKey = [rawBase64SenderPublicKey dataFromRawBase64Encoded];
                // For X25519 keys, the line right after the recipient data is the encrypted file key.
                idx++;
                NSString *rawBase64EncryptedKey = lines[idx];
                encryptedKey = [rawBase64EncryptedKey dataFromRawBase64Encoded];
            }
            
        } else if ([line hasPrefix:kCiphertextSeparator]) {
            continue;
            
        } else {
            NSString *ciphertextString = [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            NSData *ciphertext = [ciphertextString dataFromHexString];
            // If any of these values is missing something went wrong.
            if (X25519key == nil || senderPublicKey == nil || encryptedKey == nil || ciphertext == nil) {
                return nil;
            }
            
            AgeObject *objc = [AgeObject new];
            objc.X25519key = X25519key;
            objc.senderPublicKey = senderPublicKey;
            objc.encryptedKey = encryptedKey;
            objc.payload = ciphertext;
            return objc;
        }
    }

    return nil;
}

- (void)appendType:(NSString *)type
       hexEncoding:(NSString *)hexEncoding
   andEncryptedKey:(NSString *)rawBase64EncryptedKey {
    NSMutableArray *mutableRecipients = [self.recipients mutableCopy];
    Recipient *rpt = [Recipient withType:type hexEncoding:hexEncoding encryptedKey:rawBase64EncryptedKey];
    [mutableRecipients addObject:rpt];
    
    self.recipients = [mutableRecipients copy];
}

- (NSString *)output {
    NSMutableString *desc = [NSMutableString new];
    for (Recipient *rpt in self.recipients) {
        // Add a new line for each recipient exept the first one.
        if (desc.length > 0) {
            [desc appendString:@"\n"];
        }
        [desc appendFormat:@"%@ %@ %@ %@", kRecipientLineBeginning, rpt.type, rpt.hexEncoding, self.rawBase64PublicKey];
        [desc appendFormat:@"\n%@", rpt.rawBase64EncryptedKey];
    }
    [desc appendFormat:@"\n%@", kCiphertextSeparator];
    [desc appendFormat:@"\n%@", [self prettyPrintData:self.ciphertext]];
    
    return [desc copy];
}

#pragma mark - Private

- (NSString *)prettyPrintData:(NSData *)data {
    NSString *dataString = [NSString stringWithFormat:@"%@", data];
    dataString = [dataString stringByReplacingOccurrencesOfString:@"<" withString:@""];
    dataString = [dataString stringByReplacingOccurrencesOfString:@">" withString:@""];
    dataString = [dataString stringByReplacingOccurrencesOfString:@" " withString:@""];
    return dataString;
}

@end
