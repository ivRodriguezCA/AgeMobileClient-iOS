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

#import "NSData+Helper.h"

@implementation NSData (Helper)

#pragma mark - Class Methods

+ (NSData * _Nonnull)randomBytesOfLength:(NSUInteger)length {
    NSMutableData *randomBytes = [NSMutableData dataWithLength:length];
    __unused uint result = SecRandomCopyBytes(kSecRandomDefault, length, randomBytes.mutableBytes);
    
    return [randomBytes copy];
}

#pragma mark - Instance Methods

- (NSString * _Nonnull)rawBase64Encoded {
    return [[self base64EncodedStringWithOptions:0] stringByReplacingOccurrencesOfString:@"=" withString:@""];
}

- (NSString * _Nonnull)firstEightBytesRawBase64Encoded {
    if (self.length < 8) {
        return @"";
    }
    
    NSRange range = NSMakeRange(0, 8);
    NSData *firstEightBytes = [self subdataWithRange:range];
    return [firstEightBytes rawBase64Encoded];
}

@end
