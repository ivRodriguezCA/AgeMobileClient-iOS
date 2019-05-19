//
//  AgeSpec.m
//  AgeMobileClientTests
//
//  Created by Ivan Rodriguez on 2019-05-18.
//  Copyright © 2019 Ivan Rodriguez. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "Age.h"

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

- (void)testExample {
}

@end
