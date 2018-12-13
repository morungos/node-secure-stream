/*
 * decaffeinate suggestions:
 * DS102: Remove unnecessary code created because of implicit returns
 * DS207: Consider shorter variations of null checks
 * Full docs: https://github.com/decaffeinate/decaffeinate/blob/master/docs/suggestions.md
 */
const crypto = require('crypto');

const { Transform } = require('stream');

class Encrypter extends Transform {

  constructor(options) {
    super(options);

    this.header_written = false;
    this.algorithm = options.algorithm;
    if (this.algorithm == null) {
      this.algorithm = 'AES-256-CBC';
    }
    this.key_length = options.key_length;
    if (this.key_length == null) {
      this.key_length = 256;
    }
    this.public_key = options.public_key;
    this.key = options.key;

    if (!this.public_key) {
      throw new Error("Missing public key");
    }
  }


  getRandomBytes(length) {
    return crypto.randomBytes(length);
  }


  initialize() {
    const self  = this;
    const keys = this.getRandomBytes(16 + (this.key_length/8));
    const iv = keys.slice(0, 16);
    const key = keys.slice(16);
    // logger.debug "KEY", key
    // logger.debug "IV", iv

    // Make a regular cipher object. This handles the writing of all
    // subsequent data.
    // logger.debug "initialize createCipheriv", @algorithm, key, iv
    this.cipher = crypto.createCipheriv(this.algorithm, key, iv);
    this.cipher.on('data', buffer =>
      // logger.debug 'cipher data', buffer
      self.push(buffer)
    );
    this.cipher.on('error', error => logger.debug('cipher error', error));

    // Now, we need to manage the RSA handling of the AES key.
    const encrypted_key = crypto.publicEncrypt(this.public_key, key);

    const header = Buffer.alloc(4096);
    let index = 0;
    index = header.writeInt16LE(0, index);
    index = header.writeInt16LE(this.algorithm.length, index);
    index = index + header.write(this.algorithm, index, 'latin1');
    index = header.writeInt16LE(encrypted_key.length, index);
    header.fill(encrypted_key, index, index + encrypted_key.length);
    index = index + encrypted_key.length;
    index = header.writeInt16LE(iv.length, index);
    header.fill(iv, index, index + iv.length);
    index = index + iv.length;

    // Write the count back
    header.writeInt16LE(index, 0);

    this.push(header.slice(0, index));
    this.header_written = true;
  }


  _transform(chunk, encoding, callback) {
    let result;
    if (!this.header_written) {
      // We've not written a header yet, so we make one and then send it
      // to the output.

      this.initialize();
    }

    // logger.debug "Encrypter _write", chunk, encoding
    this.cipher.write(chunk, encoding, () =>
      // logger.debug "Encrypter write cipher result", result
      callback()
    );
  }


  _flush(callback) {
    // logger.debug "Encrypter _flush"
    this.cipher.end(() =>
      // logger.debug "Encrypter _flush complete"
      callback()
    );
  }
}



class Decrypter extends Transform {

  constructor(options) {
    super(options);
    this.header_complete = false;
    this.key = options.key;
    this.header = Buffer.alloc(4096);
    this.header_size = 0;
    this.header_index = 0;
  }


  unpackHeader() {
    const self = this;
    let index = 0;
    this.header_size = this.header.readInt16LE(index);
    // logger.debug "unpackHeader @header_size", @header_size
    index = index + 2;
    const algorithm_size = this.header.readInt16LE(index);
    // logger.debug "unpackHeader algorithm_size", algorithm_size
    index = index + 2;
    this.algorithm = this.header.slice(index, index + algorithm_size).toString('latin1');
    // logger.debug "unpackHeader @algorithm", @algorithm
    index = index + algorithm_size;
    const encrypted_key_size = this.header.readInt16LE(index);
    // logger.debug "unpackHeader encrypted_key_size", encrypted_key_size
    index = index + 2;
    const encrypted_key = this.header.slice(index, index + encrypted_key_size);
    // logger.debug "unpackHeader encrypted_key", encrypted_key
    index = index + encrypted_key_size;
    const iv_size = this.header.readInt16LE(index);
    // logger.debug "unpackHeader iv_size", iv_size
    index = index + 2;
    this.iv = this.header.slice(index, index + iv_size);
    // logger.debug "unpackHeader @iv", @iv
    index = index + iv_size;

    //# Now, let's decrypted the key, and build a decryption cipher
    this.key = crypto.privateDecrypt(this.key, encrypted_key);
    // logger.debug "unpackHeader decrypted", encrypted_key, 'to', @key

    //# And here's the new cipher
    // logger.debug "unpackHeader createDecipheriv", @algorithm, @key, @iv
    this.cipher = crypto.createDecipheriv(this.algorithm, this.key, this.iv);
    this.cipher.on('data', buffer =>
      // logger.debug 'cipher data', buffer
      self.push(buffer)
    );
    this.cipher.on('error', error => logger.debug('cipher error', error));

    // logger.debug "unpackHeader done"
    this.header_complete = true;
  }


  _transform(chunk, encoding, callback) {
    let result;
    chunk = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
    // logger.debug "Got chunk", chunk, encoding

    if (!this.header_complete) {
      this.header.fill(chunk, this.header_index);
      this.header_index = this.header_index + chunk.length;
      // logger.debug "Added chunk", @header_index, chunk

      if (this.header_index >= 2) {
        this.header_size = this.header.readInt16LE(0);
        // logger.debug "Worked out @header_size", @header_size
      } else {
        callback();
        return;
      }

      if ((this.header_size == null) || (this.header_index < this.header_size)) {
        callback();
        return;
      }

      // logger.debug 'XXXX', @header_size, @header_index, chunk.length

      const header_buffer = this.header.slice(0, this.header_size);
      chunk = chunk.slice(chunk.length - (this.header_index - this.header_size));

      this.header = header_buffer;
      this.unpackHeader();
    }

      // logger.debug "Remaining", chunk, chunk.length

      //# We might well have a bit of chunk left over, so if we do, let's
      //# chop if off and run it through the cipher. This isn't just a block
      //# after 4096, it depends on the header block size.

    this.cipher.write(chunk, encoding, () => callback());
  }


  _flush(callback) {
    return this.cipher.end(() => callback());
  }
}



module.exports = {
  Encrypter,
  Decrypter
};
