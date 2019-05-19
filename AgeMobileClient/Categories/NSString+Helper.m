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

#import "NSString+Helper.h"

@implementation NSString (Helper)

#pragma mark - Instance Methods

// Apple requires Base64 strings to be padded 🤷🏻‍♂️
// Even though the RFC http://www.faqs.org/rfcs/rfc4648.html
// on section 3.2 says that it's not required
- (NSData *)dataFromRawBase64Encoded {
    NSUInteger paddedLength = self.length + (self.length % 3);
    NSString *paddedString = [self stringByPaddingToLength:paddedLength withString:@"=" startingAtIndex:0];
    paddedString = [paddedString stringByReplacingOccurrencesOfString:@"_" withString:@"/"];
    paddedString = [paddedString stringByReplacingOccurrencesOfString:@"-" withString:@"+"];
    return [[NSData alloc] initWithBase64EncodedString:paddedString options:0];
}

@end
