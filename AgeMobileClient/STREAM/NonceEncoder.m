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

#import "NonceEncoder.h"

// STREAM flag indicating it's the last block (otherwise it's 0).
static NSUInteger kLastBlockFlag = 1;

// STREAM nonce size in bytes.
static NSUInteger kNonceSize = 11;

// STREAM max counter value (11 bytes).
#define kMaxConterValue powl(2.0, 88.0)

@interface NonceEncoder ()

@property (nonatomic, assign) int64_t counter;
@property (nonatomic, assign) NSUInteger lastBlock;

@end

@implementation NonceEncoder

// Added constructor because I like it.
- (instancetype)init {
    if (self = [super init]) {
        _counter = 0;
        _lastBlock = 0;
    }
    
    return self;
}

- (NSData *)nextIsLastBlock:(NSUInteger)isLastBlock {
    if (self.lastBlock == kLastBlockFlag) {
        @throw [NSException exceptionWithName:@"STREAMFinished"
                                       reason:@"STREAM is already finished." userInfo:nil];
    }
    
    self.lastBlock = isLastBlock;
    
    int64_t realCounter = isBigEndianSystem() ? self.counter : CFSwapInt64(self.counter);
    NSData *counterData = [NSData dataWithBytes:&realCounter length:sizeof(realCounter)];
    
    // int64_t size should never be grater than kNonceSize,
    // but just to be safe. 🙂
    NSInteger nonceSize = kNonceSize - counterData.length;
    if (nonceSize < 0) {
        nonceSize = 0;
    }
    
    // Create empty data for the leading zeroes of the nonce.
    NSMutableData *nonce = [NSMutableData dataWithLength:nonceSize];
    
    // Append the big endian counter.
    [nonce appendData:counterData];
    
    // Append 1 byte representing the end block flag.
    NSUInteger lastBlock = self.lastBlock;
    NSData *endBlockFlagData = [NSData dataWithBytes:&lastBlock length:1];
    [nonce appendData:endBlockFlagData];
    
    // Increment block counter for next iteration
    self.counter++;
    
    if (self.counter >= kMaxConterValue) {
        @throw [NSException exceptionWithName:@"STREAMCounterERror"
                                       reason:@"STREAM counter overflow." userInfo:nil];
    }
    
    return [nonce copy];
}

int isBigEndianSystem() {
    unsigned int i = 1;
    char *c = (char*)&i;
    if (*c) return 0;
    
    return 1;
}

@end
