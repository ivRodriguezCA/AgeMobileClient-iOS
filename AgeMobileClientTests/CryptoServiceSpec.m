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
#import "CryptoService.h"
#import "CiphertextObject.h"

@interface CryptoServiceSpec : XCTestCase

@property (nonatomic, strong) CryptoService *subject;

@end

@implementation CryptoServiceSpec

- (void)setUp {
    self.subject = [CryptoService new];
}

- (void)tearDown {
    self.subject = nil;
}

- (void)testThatItEncryptsData {
    NSData *data = [@"super secret message" dataUsingEncoding:NSUTF8StringEncoding];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"Waiting for encryption block."];
    
    [self.subject encryptData:data completion:^(CiphertextObject * _Nonnull ciphertext) {
        XCTAssertNotNil(ciphertext.key);
        XCTAssertNotNil(ciphertext.ciphertext);
        [expectation fulfill];
    }];
    
    [self waitForExpectationsWithTimeout:10.0 handler:^(NSError *error) {
        if (error) {
            XCTFail(@"Failed to wait for encryption block with error: %@", error);
        }
    }];
}

- (void)testThatItDecryptsData {
    NSData *data = [@"super secret message" dataUsingEncoding:NSUTF8StringEncoding];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"Waiting for decryption block."];
    
    [self.subject encryptData:data completion:^(CiphertextObject * _Nonnull ciphertext) {
        [self.subject decryptData:data key:ciphertext.key completion:^(NSData * _Nullable plaintext, NSError * _Nullable error) {
            NSString *plaintextString = [[NSString alloc] initWithData:plaintext encoding:NSUTF8StringEncoding];
            XCTAssertNil(error);
            XCTAssertEqualObjects(@"super secret message", plaintextString);
            [expectation fulfill];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:10.0 handler:^(NSError *error) {
        if (error) {
            XCTFail(@"Failed to wait for decryption block with error: %@", error);
        }
    }];
}

@end
