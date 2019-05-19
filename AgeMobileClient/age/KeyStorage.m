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

#import "KeyStorage.h"
#import "X25519Key.h"
#import "NSData+Helper.h"

@interface KeyStorage ()

@property (nonatomic, strong) NSDictionary<NSString *, X25519Key *> *keys;

@end

@implementation KeyStorage

- (instancetype)init {
    if (self = [super init]) {
        _keys = [NSDictionary new];
    }
    
    return self;
}

#pragma mark - <KeyStorageProtocol>

// This is temporary, we'll store these on disk.
- (void)storeX25519Key:(X25519Key *)key {
    NSMutableDictionary *mutableKyes = [self.keys mutableCopy];
    [mutableKyes setObject:key forKey:[key.publicKey firstEightBytesHexEncoded]];
    self.keys = [mutableKyes copy];
}

- (X25519Key * _Nullable)retrieveX25519KeyWithHexEncoded:(NSString *)hexEncoded {
    return self.keys[hexEncoded];
}

@end
