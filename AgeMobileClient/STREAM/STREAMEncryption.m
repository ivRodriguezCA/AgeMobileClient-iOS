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

#import "STREAMEncryption.h"
#include "sodium.h"

@implementation STREAMEncryption

- (NSData * _Nullable)encryptData:(NSData *)plaintextData additionalData:(NSData * _Nullable)additionalData {
    unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
    unsigned char key[crypto_aead_chacha20poly1305_KEYBYTES];
    unsigned char ciphertext[plaintextData.length + crypto_aead_chacha20poly1305_ABYTES];
    unsigned long long ciphertext_len;
    
    crypto_aead_chacha20poly1305_keygen(key);
    randombytes_buf(nonce, sizeof nonce);
    
    crypto_aead_chacha20poly1305_encrypt(ciphertext, &ciphertext_len,
                                         plaintextData.bytes, plaintextData.length,
                                         additionalData.bytes, additionalData.length,
                                         /* nsec= */ NULL, nonce, key);
    
    return [NSData dataWithBytes:ciphertext length:ciphertext_len];
}

//- (NSData * _Nullable)decryptData:(NSData *)ciphertext additionalData:(NSData * _Nullable)additionalData key:(NSData *)key {
//    unsigned char decrypted[ciphertext.length];
//    unsigned long long decrypted_len;
//    if (crypto_aead_chacha20poly1305_decrypt(decrypted, &decrypted_len,
//                                             /* nsec= */ NULL,
//                                             ciphertext.bytes, ciphertext.length,
//                                             additionalData.bytes,
//                                             additionalData.length,
//                                             nonce, key) != 0) {
//        /* message forged! */
//    }
//    NSData *m = [NSData dataWithBytes:decrypted length:plaintextData.length];
//    NSString *s = [[NSString alloc] initWithData:m encoding:NSUTF8StringEncoding];
//    NSLog(@"Decrypted %@", s);
//}

@end
