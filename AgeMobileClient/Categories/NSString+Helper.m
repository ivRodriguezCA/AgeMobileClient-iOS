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
    NSString *base64EncodedString = [self stringByReplacingOccurrencesOfString:@"_" withString:@"/"];
    base64EncodedString = [base64EncodedString stringByReplacingOccurrencesOfString:@"-" withString:@"+"];
    switch (base64EncodedString.length % 4) {
        case 2:
            base64EncodedString = [base64EncodedString stringByAppendingString:@"=="];
            break;
        case 3:
            base64EncodedString = [base64EncodedString stringByAppendingString:@"="];
            break;
        default:
            break;
    }
    
//    return [base64EncodedString dataFromBase64String];
    return [[NSData alloc] initWithBase64EncodedString:base64EncodedString
                                               options:NSDataBase64DecodingIgnoreUnknownCharacters];
}

// Taken from https://stackoverflow.com/a/45708574
- (NSData *)dataFromHexString {
    NSString *string = self;
    if([string length] % 2 == 1){
        string = [@"0" stringByAppendingString:string];
    }
    
    const char *chars = [string UTF8String];
    int i = 0, len = (int)[string length];
    
    NSMutableData *data = [NSMutableData dataWithCapacity:len / 2];
    char byteChars[3] = {'\0','\0','\0'};
    unsigned long wholeByte;
    
    while (i < len) {
        byteChars[0] = chars[i++];
        byteChars[1] = chars[i++];
        wholeByte = strtoul(byteChars, NULL, 16);
        [data appendBytes:&wholeByte length:1];
    }
    return data;
}

@end
