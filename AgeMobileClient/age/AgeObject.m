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

@interface Recipient : NSObject

+ (instancetype)withHexEncoding:(NSString *)hexEncoding
                   encryptedKey:(NSString *)rawBase64EncryptedKey;

@end

@interface Recipient ()

@property (nonatomic, copy) NSString *hexEncoding;
@property (nonatomic, copy) NSString *rawBase64EncryptedKey;

@end

@implementation Recipient

+ (instancetype)withHexEncoding:(NSString *)hexEncoding
                   encryptedKey:(NSString *)rawBase64EncryptedKey {
    Recipient *rpt = [Recipient new];
    rpt.hexEncoding = hexEncoding;
    rpt.rawBase64EncryptedKey = rawBase64EncryptedKey;
    
    return rpt;
}

@end

@interface AgeObject ()

@property (nonatomic, copy) NSString *type;
@property (nonatomic, strong) NSData *ciphertext;
@property (nonatomic, copy) NSString *rawBase64PublicKey;
@property (nonatomic, strong) NSArray<Recipient *> *recipients;

@end

@implementation AgeObject

+ (instancetype)objectWithType:(NSString *)type
                    ciphertext:(NSData *)ciphertext
                     publicKey:(NSString *)rawBase64PublicKey {
    AgeObject *obj = [AgeObject new];
    obj.type = type;
    obj.ciphertext = ciphertext;
    obj.rawBase64PublicKey = rawBase64PublicKey;
    obj.recipients = [NSArray new];
    
    return obj;
}

- (void)appendHexEncoding:(NSString *)hexEncoding
          andEncryptedKey:(NSString *)rawBase64EncryptedKey {
    NSMutableArray *mutableRecipients = [self.recipients mutableCopy];
    Recipient *rpt = [Recipient withHexEncoding:hexEncoding encryptedKey:rawBase64EncryptedKey];
    [mutableRecipients addObject:rpt];
    
    self.recipients = [mutableRecipients copy];
}

- (NSString *)output {
    NSMutableString *desc = [NSMutableString new];
    for (Recipient *rpt in self.recipients) {
        [desc appendFormat:@"\n-> %@ %@ %@", self.type, rpt.hexEncoding, self.rawBase64PublicKey];
        [desc appendFormat:@"\n%@", rpt.rawBase64EncryptedKey];
    }
    [desc appendString:@"\n---"];
    [desc appendFormat:@"\n%@", self.ciphertext];
    
    return [desc copy];
}

@end
