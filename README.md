# node-secure-stream

This is a module that is designed to help use asymmetric encryption over
streams. Even though there are modules that support RSA widely, they can't
handle large files (where large means about >2k). The recommended solution
to this is to make a random key, encrypt that using RSA, and then use the
random key to encrypt the rest of the data using AES256.

This module does that, essentially over a stream. There is a little more to
it than that, but not much. Streams written in are secure, and can only
be decrypted by the matching private key. 

There are other modules that do this, but their dependencies are broken, not
cleanly at the top level either.

## API

Very similar to `hybrid-rsa-stream`

For encryption:

    var SecureStreams = require('node-secure-stream');
    var fs = require('fs');
    var public_key = fs.readFileSync(__dirname + '/files/public');

    var enc = new SecureStreams.Encrypter({public_key: public_key})
    process.stdin.pipe(enc).pipe(process.stdout);

For decryption:

    var SecureStreams = require('node-secure-stream');
    var fs = require('fs');
    var private_key = fs.readFileSync(__dirname + '/files/private');

    var dec = new SecureStreams.Decrypter({key: private_key});
    process.stdin.pipe(dec).pipe(process.stdout);

## Data transmitted

Essentially the same as `hybrid-rsa-stream`, kind of

 * asymmetric ciphertext length (UInt16BE, 2 bytes)]
 * asymmetric ciphertext, i.e., algorithm, key, iv, only key encrypted
 * symmetric ciphertext, i.e., encrypted data


## License

Copyright (c) 2017. Stuart Watt.

Licensed under the MIT License.
