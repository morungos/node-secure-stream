# node-secure-stream

This is a module that is designed to help use asymmetric encryption over
streams. Even though there are modules that support RSA widely, they can't
handle large files (where large means about >2k). The recommended solution
to this is to make a random key, encrypt that using RSA, and then use the
random key to encrypt the rest of the data using AES256.

This module does that, essentially over a stream.

There are other modules that do this, but their dependencies are broken, not
simply at the top level either.

## API

Exactly the same as `hybrid-rsa-stream`

For encryption:

    var crypter = require('node-secure-stream');
    var fs = require('fs');
    var pubkey = fs.readFileSync(__dirname + '/files/public');

    var enc = crypter.encrypt(pubkey, { encoding: 'base64' });
    process.stdin.pipe(enc).pipe(process.stdout);

For decryption:

    var hybrid = require('node-secure-stream');
    var fs = require('fs');
    var privkey = fs.readFileSync(__dirname + '/files/private');

    var dec = crypter.decrypt(privkey, { encoding: 'base64' });
    process.stdin.pipe(dec).pipe(process.stdout);

## Data transmitted

Essentially the same as `hybrid-rsa-stream`, kind of

 * asymmetric ciphertext length (UInt16BE, 2 bytes)]
 * asymmetric ciphertext, i.e., key, iv
 * symmetric ciphertext, i.e., encrypted data
