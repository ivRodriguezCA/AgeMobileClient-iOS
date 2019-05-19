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

#import <XCTest/XCTest.h>
#import "STREAMCryptor.h"
#import "NSData+Helper.h"

@interface STREAMCryptorSpec : XCTestCase

@property (nonatomic, strong) STREAMCryptor *subject;

@end

@implementation STREAMCryptorSpec

- (void)setUp {
    self.subject = [STREAMCryptor new];
}

- (void)tearDown {
    self.subject = nil;
}

- (void)testThatItEncrypts {
    NSData *message = [@"Hello!" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *key = [NSData randomBytesOfLength:32];
    NSData *ciphertext =  [self.subject encryptData:message key:key isLastBlock:YES];
    
    XCTAssertNotNil(ciphertext);
}

- (void)testThatItDecryptsCorrectly {
    STREAMCryptor *cryptor = [STREAMCryptor new];
    NSData *message = [@"Hello!" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *key = [NSData randomBytesOfLength:32];
    NSData *ciphertext = [cryptor encryptData:message key:key isLastBlock:YES];
    
    NSData *plaintext = [self.subject decryptData:ciphertext key:key isLastBlock:YES];
    NSString *plaintextString = [[NSString alloc] initWithData:plaintext encoding:NSUTF8StringEncoding];
    
    XCTAssertEqualObjects(@"Hello!", plaintextString);
}

@end
