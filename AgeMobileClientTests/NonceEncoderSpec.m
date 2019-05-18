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
#import "NonceEncoder.h"

@interface NonceEncoderSpec : XCTestCase

@property (nonatomic, strong) NonceEncoder *subject;

@end

@implementation NonceEncoderSpec

- (void)setUp {
    self.subject = [NonceEncoder new];
}

- (void)tearDown {
    self.subject = nil;
}

- (void)testThatItGeneratesNextNonce {
   NSData *nonce = [self.subject nextIsLastBlock:0];
    
    XCTAssertNotNil(nonce);
}

- (void)testThatItThrowsSTREAMFinished {
    [self.subject nextIsLastBlock:0];
    [self.subject nextIsLastBlock:1];

    XCTAssertThrows([self.subject nextIsLastBlock:0], @"STREAMFinished");
}

- (void)testThatItReturnsTheCounterInBigEndian {
    [self.subject nextIsLastBlock:0];
    NSData *nonce = [self.subject nextIsLastBlock:0];
    
    XCTAssertEqualObjects([self dataToString:nonce], @"000000000000000000000100");
}

// Helper funciton taken from https://stackoverflow.com/a/9084784
- (NSString *)dataToString:(NSData *)data {
    const unsigned char *dataBuffer = (const unsigned char *)data.bytes;
    if (!dataBuffer) {
        return [NSString string];
    }
    
    NSUInteger dataLength  = data.length;
    NSMutableString *hexString  = [NSMutableString stringWithCapacity:(dataLength * 2)];
    
    for (NSUInteger i = 0; i < dataLength; ++i) {
        [hexString appendString:[NSString stringWithFormat:@"%02lx", (unsigned long)dataBuffer[i]]];
    }
    
    return [NSString stringWithString:hexString];
}

@end
