/*
 * decaffeinate suggestions:
 * DS102: Remove unnecessary code created because of implicit returns
 * Full docs: https://github.com/decaffeinate/decaffeinate/blob/master/docs/suggestions.md
 */
const fs = require('fs');

const StringToStream = require('./blocked-string-to-stream');
const concat = require('concat-stream');

const public_key = fs.readFileSync('__tests__/data/testkey.pub', "utf8");

const SecureStreams = require('../lib/index.js');

const fixed_bytes = Buffer.from([0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
                                 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
                                 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
                                 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
                                 0x61, 0x62, 0x63, 0x64, 0x65, 0x46, 0x67, 0x68,
                                 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70]);

describe('SecureStreams.Encrypter', () => {


  it('should encrypt a small string', function(done) {

    const input_string = 'your text here';
    const input = StringToStream([input_string]);

    const enc = new SecureStreams.Encrypter({public_key});
    enc.getRandomBytes = () => fixed_bytes;

    input.pipe(enc).pipe(concat(function(data) {
      expect(data.toString('hex')).toBeDefined();

      //# Check the last block, with the clamped random key and IV
      expect(data.slice(data.length - 16).toString('hex')).toEqual('1121ebe4d7ae4aab810d123acfc15109');
      done();
    }));
  })

});
