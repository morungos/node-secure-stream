# node-secure-stream

![test workflow](https://github.com/morungos/node-secure-stream/actions/workflows/main.yml/badge.svg)

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

Very similar to [`hybrid-rsa-stream`](https://www.npmjs.com/package/hybrid-rsa-stream)

For encryption:

    const SecureStreams = require('node-secure-stream');
    const fs = require('fs');
    const public_key = fs.readFileSync(__dirname + '/files/public');

    const enc = new SecureStreams.Encrypter({public_key: public_key})
    process.stdin.pipe(enc).pipe(process.stdout);

or, to use a private key for encryption:

    const SecureStreams = require('node-secure-stream');
    const fs = require('fs');
    const private_key = fs.readFileSync(__dirname + '/files/private');

    const enc = new SecureStreams.Encrypter({private_key: private_key})
    process.stdin.pipe(enc).pipe(process.stdout);


For decryption:

    const SecureStreams = require('node-secure-stream');
    const fs = require('fs');
    const private_key = fs.readFileSync(__dirname + '/files/private');

    const dec = new SecureStreams.Decrypter({private_key: private_key});
    process.stdin.pipe(dec).pipe(process.stdout);

or, to use a public key for decryption:

    const SecureStreams = require('node-secure-stream');
    const fs = require('fs');
    const public_key = fs.readFileSync(__dirname + '/files/public');

    const dec = new SecureStreams.Decrypter({public_key: public_key});
    process.stdin.pipe(dec).pipe(process.stdout);


## Data transmitted

Essentially the same as `hybrid-rsa-stream`, kind of

 * asymmetric ciphertext length (UInt16BE, 2 bytes)]
 * asymmetric ciphertext, i.e., algorithm, key, iv, only key encrypted
 * symmetric ciphertext, i.e., encrypted data


## License

Copyright (c) 2017-2021. Stuart Watt.

Licensed under the MIT License.
