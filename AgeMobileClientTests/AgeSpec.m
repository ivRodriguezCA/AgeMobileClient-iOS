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

@interface AgeSpec : XCTestCase

@property (nonatomic, strong) Age *subject;

@end

@implementation AgeSpec

- (void)setUp {
    self.subject = [Age new];
}

- (void)tearDown {
    self.subject = nil;
}

- (void)testThatItEncryptsWithX25519Keys {
    X25519Key *alice = [X25519Key new];
    X25519Key *bob = [X25519Key new];
    NSData *data = [@"super secret message" dataUsingEncoding:NSUTF8StringEncoding];

    [self.subject X25519_encryptData:data
                          publicKeys:@[bob.publicKey]
                           X25519Key:alice completion:^(AgeObject *ageObject) {
                               NSMutableString *output = [[ageObject output] mutableCopy];
                               NSUInteger recipients = [output replaceOccurrencesOfString:@"-> X25519"
                                                       withString:@"-> X25519"
                                                          options:NSLiteralSearch
                                                            range:NSMakeRange(0, output.length)];
                               XCTAssertEqual(recipients, 1);
                           }];
}

- (void)testThatItEncryptsWithX25519KeysForMultipleRecipients {
    X25519Key *alice = [X25519Key new];
    X25519Key *bob = [X25519Key new];
    X25519Key *charles = [X25519Key new];
    NSData *data = [@"super secret message" dataUsingEncoding:NSUTF8StringEncoding];
    
    [self.subject X25519_encryptData:data
                          publicKeys:@[bob.publicKey, charles.publicKey]
                           X25519Key:alice completion:^(AgeObject *ageObject) {
                               NSMutableString *output = [[ageObject output] mutableCopy];
                               NSUInteger recipients = [output replaceOccurrencesOfString:@"-> X25519"
                                                                               withString:@"-> X25519"
                                                                                  options:NSLiteralSearch
                                                                                    range:NSMakeRange(0, output.length)];
                               XCTAssertEqual(recipients, 2);
                           }];
}

@end
