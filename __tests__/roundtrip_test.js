/*
 * decaffeinate suggestions:
 * DS102: Remove unnecessary code created because of implicit returns
 * Full docs: https://github.com/decaffeinate/decaffeinate/blob/master/docs/suggestions.md
 */
const fs = require('fs');

const StringToStream = require('./blocked-string-to-stream');
const concat = require('concat-stream');

const SecureStreams = require('../lib/index.js');

describe('SecureStreams', function() {

  const public_key = fs.readFileSync('__tests__/data/testkey.pub', "utf8");
  const private_key = fs.readFileSync('__tests__/data/testkey.pem', "utf8");

  it('should securely roundtrip a short string, public to private', function(done) {
    const input = 'your text here';
    const input_stream = StringToStream([input]);
    const enc = new SecureStreams.Encrypter({public_key});
    const dec = new SecureStreams.Decrypter({private_key: private_key});
    return input_stream.pipe(enc).pipe(dec).pipe(concat(function(data) {
      expect(data).toBeDefined();
      expect(data.toString()).toEqual(input);
      return done();
    })
    );
  });

  it('should securely roundtrip a UTF8 string, public to private', function(done) {
    const input = 'your \u201ctext\u201d here';
    const input_stream = StringToStream([input]);
    const enc = new SecureStreams.Encrypter({public_key});
    const dec = new SecureStreams.Decrypter({private_key});
    return input_stream.pipe(enc).pipe(dec).pipe(concat(function(data) {
      expect(data).toBeDefined();
      expect(data.toString()).toEqual(input);
      return done();
    })
    );
  });

  it('should securely roundtrip a file, public to private', function(done) {
    const buffer = fs.readFileSync('./__tests__/data/darwin-sm.png');
    const input_stream = StringToStream([buffer]);
    const enc = new SecureStreams.Encrypter({public_key});
    const dec = new SecureStreams.Decrypter({private_key});
    return input_stream.pipe(enc).pipe(dec).pipe(concat(function(data) {
      expect(data).toBeDefined();
      expect(data.toString('hex')).toEqual(buffer.toString('hex'));
      return done();
    })
    );
  });

  it('should securely roundtrip a short string, private to public', function(done) {
    const input = 'your text here';
    const input_stream = StringToStream([input]);
    const enc = new SecureStreams.Encrypter({private_key});
    const dec = new SecureStreams.Decrypter({public_key});
    return input_stream.pipe(enc).pipe(dec).pipe(concat(function(data) {
      expect(data).toBeDefined();
      expect(data.toString()).toEqual(input);
      return done();
    })
    );
  });

  it('should securely roundtrip a UTF8 string, private to public', function(done) {
    const input = 'your \u201ctext\u201d here';
    const input_stream = StringToStream([input]);
    const enc = new SecureStreams.Encrypter({private_key});
    const dec = new SecureStreams.Decrypter({public_key});
    return input_stream.pipe(enc).pipe(dec).pipe(concat(function(data) {
      expect(data).toBeDefined();
      expect(data.toString()).toEqual(input);
      return done();
    })
    );
  });

  it('should securely roundtrip a file, private to public', function(done) {
    const buffer = fs.readFileSync('./__tests__/data/darwin-sm.png');
    const input_stream = StringToStream([buffer]);
    const enc = new SecureStreams.Encrypter({private_key});
    const dec = new SecureStreams.Decrypter({public_key});
    return input_stream.pipe(enc).pipe(dec).pipe(concat(function(data) {
      expect(data).toBeDefined();
      expect(data.toString('hex')).toEqual(buffer.toString('hex'));
      return done();
    })
    );
  });

});
