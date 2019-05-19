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
#import "Age.h"
#import "X25519Key.h"
#import "AgeObject.h"
#import "KeyStorageProtocol.h"
#import "NSData+Helper.h"

@interface KeyStorageMock : NSObject <KeyStorageProtocol>
@end
@interface KeyStorageMock ()
@property (nonatomic, strong) NSDictionary<NSString *, X25519Key *> *keys;
@end
@implementation KeyStorageMock
- (instancetype)init {
    if (self = [super init]) {
        _keys = [NSDictionary new];
    }
    return self;
}
- (void)storeX25519Key:(X25519Key *)key {
    NSMutableDictionary *mutableKyes = [self.keys mutableCopy];
    [mutableKyes setObject:key forKey:[key.publicKey firstEightBytesHexEncoded]];
    self.keys = [mutableKyes copy];
}
- (X25519Key * _Nullable)retrieveX25519KeyWithHexEncoded:(NSString *)hexEncoded {
    return self.keys[hexEncoded];
}
@end


@interface AgeSpec : XCTestCase

@property (nonatomic, strong) Age *subject;
@property (nonatomic, strong) KeyStorageMock *keyStorage;

@end

@implementation AgeSpec

- (void)setUp {
    self.subject = [Age new];
    self.keyStorage = [KeyStorageMock new];
}

- (void)tearDown {
    self.subject = nil;
    self.keyStorage = nil;
}

- (void)testThatItEncryptsWithX25519Keys {
    X25519Key *alice = [X25519Key new];
    X25519Key *bob = [X25519Key new];
    NSData *data = [@"super secret message" dataUsingEncoding:NSUTF8StringEncoding];

    XCTestExpectation *expectation = [self expectationWithDescription:@"Waiting for encryption block."];
    
    [self.subject X25519_encryptData:data
                          publicKeys:@[bob.publicKey]
                           X25519Key:alice completion:^(AgeObject *ageObject) {
                               NSMutableString *output = [[ageObject output] mutableCopy];
                               NSUInteger recipients = [output replaceOccurrencesOfString:@"-> X25519"
                                                       withString:@"-> X25519"
                                                          options:NSLiteralSearch
                                                            range:NSMakeRange(0, output.length)];
                               XCTAssertEqual(recipients, 1);
                               [expectation fulfill];
                           }];
    
    [self waitForExpectationsWithTimeout:10.0 handler:^(NSError *error) {
        if (error) {
            XCTFail(@"Failed to wait for encryption block with error: %@", error);
        }
    }];
}

- (void)testThatItEncryptsWithX25519KeysForMultipleRecipients {
    X25519Key *alice = [X25519Key new];
    X25519Key *bob = [X25519Key new];
    X25519Key *charles = [X25519Key new];
    NSData *data = [@"super secret message" dataUsingEncoding:NSUTF8StringEncoding];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"Waiting for encryption block."];
    
    [self.subject X25519_encryptData:data
                          publicKeys:@[bob.publicKey, charles.publicKey]
                           X25519Key:alice completion:^(AgeObject *ageObject) {
                               NSMutableString *output = [[ageObject output] mutableCopy];
                               NSUInteger recipients = [output replaceOccurrencesOfString:@"-> X25519"
                                                                               withString:@"-> X25519"
                                                                                  options:NSLiteralSearch
                                                                                    range:NSMakeRange(0, output.length)];
                               XCTAssertEqual(recipients, 2);
                                [expectation fulfill];
                           }];
    
    [self waitForExpectationsWithTimeout:10.0 handler:^(NSError *error) {
        if (error) {
            XCTFail(@"Failed to wait for encryption block with error: %@", error);
        }
    }];
}

- (void)testThatItCanDecryptThePayload {
    X25519Key *alice = [X25519Key new];
    X25519Key *bob = [X25519Key new];
    Age *sender = [Age new];
    NSData *data = [@"super secret message" dataUsingEncoding:NSUTF8StringEncoding];
    [self.keyStorage storeX25519Key:bob];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"Waiting for decryption block."];
    
    NSLog(@"\n");
    NSLog(@"Alice's Pulblic Key Raw: %@", alice.publicKey);
    NSLog(@"Alice's Pulblic Key RawBas64Encoded: %@", [alice.publicKey rawBase64Encoded]);
    NSLog(@"\n");
    
    [sender X25519_encryptData:data
                    publicKeys:@[bob.publicKey]
                     X25519Key:alice completion:^(AgeObject *ageObject) {
                         NSString *rawInput = [ageObject output];
                         [self.subject X25519_decryptFromRawInput:rawInput
                                                       keyStorage:self.keyStorage
                                                       completion:^(NSData * _Nullable plaintext, NSError * _Nullable error) {
                                                           XCTAssertNil(error);
                                                           NSString *plaintextString = [[NSString alloc] initWithData:plaintext encoding:NSUTF8StringEncoding];
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
