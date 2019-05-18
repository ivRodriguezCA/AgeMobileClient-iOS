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
#import "X25519Key.h"

@interface X25519KeySpec : XCTestCase

@end

@implementation X25519KeySpec

- (void)testThatItCreatesX25519Keys {
    X25519Key *key = [X25519Key new];
    
    XCTAssertNotNil(key.publicKey);
    XCTAssertNotNil(key.privateKey);
    XCTAssertEqual([key keyLength], 32);
    XCTAssertEqualObjects(key.typeString, @"X25519");
    XCTAssertNotNil([key publicKeySHA256]);
}

- (void)testThatItComputesTheCorrectSharedSecret {
    X25519Key *alice = [X25519Key new];
    X25519Key *bob = [X25519Key new];
    
    NSData *aliceSharedSecret = [alice sharedSecretWithPublicKey:bob.publicKey];
    NSData *bobSharedSecret = [bob sharedSecretWithPublicKey:alice.publicKey];
    
    XCTAssertEqualObjects(aliceSharedSecret, bobSharedSecret);
}

- (void)testCreatingKeyFromStoredKey {
    X25519Key *key = [X25519Key new];
    NSString *storedKey = [key description];
    
    X25519Key *restoredKey = [[X25519Key alloc] initFromDisk:storedKey];
    
    XCTAssertEqualObjects(key, restoredKey);
}

@end
