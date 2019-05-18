//
//  NonceEncoderSpec.m
//  AgeMobileClientTests
//
//  Created by Ivan Rodriguez on 2019-05-18.
//  Copyright © 2019 Ivan Rodriguez. All rights reserved.
//

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
