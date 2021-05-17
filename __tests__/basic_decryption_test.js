/*
 * decaffeinate suggestions:
 * DS102: Remove unnecessary code created because of implicit returns
 * Full docs: https://github.com/decaffeinate/decaffeinate/blob/master/docs/suggestions.md
 */
const fs = require('fs');

const StringToStream = require('./blocked-string-to-stream');
const concat = require('concat-stream');

const SecureStreams = require('../lib/index.js');

describe('SecureStreams.Decrypter', function() {

  const private_key = fs.readFileSync('__tests__/data/testkey.pem', "utf8");

  it('should decrypt a small string in multiple blocks', function(done) {

    const input = StringToStream([
      Buffer.from("a3", 'hex'),
      Buffer.from("00", 'hex'),
      Buffer.from("0b004145532d3235362d43424380007ce29782259b0a6d82bf56359ea2", 'hex'),
      Buffer.from("ecbe6d770062afaaaf08eb661bdfb86d335e3c3da1480d4e968e13a7d150cc", 'hex'),
      Buffer.from("6fefea6de870950df53392ae2f359e27792312e4ce40cd41be30d6a50522c8", 'hex'),
      Buffer.from("2036a843f8da6cdcb78f6202d9e2e2c419e779dc2ed8e751d98e6d42312ec3", 'hex'),
      Buffer.from("43167a0ce1b08da1b6b136e09d93c92cf3c2b247b010004142434445464748", 'hex'),
      Buffer.from("494a4b4c4d4e4f501121ebe4d7ae4aab810d123acfc15109", 'hex')
    ]);

    const dec = new SecureStreams.Decrypter({private_key: private_key});

    return input.pipe(dec).pipe(concat(function(data) {
      expect(data.toString('utf8')).toEqual('your text here');
      return done();
    })
    );
  });


  it('should decrypt a small string in a single large block', function(done) {

    const input = StringToStream([
      Buffer.from("a3000b004145532d3235362d43424380007ce29782259b0a6d82bf56359ea2ecbe6d770062afaaaf08eb661bdfb86d335e3c3da1480d4e968e13a7d150cc6fefea6de870950df53392ae2f359e27792312e4ce40cd41be30d6a50522c82036a843f8da6cdcb78f6202d9e2e2c419e779dc2ed8e751d98e6d42312ec343167a0ce1b08da1b6b136e09d93c92cf3c2b247b010004142434445464748494a4b4c4d4e4f501121ebe4d7ae4aab810d123acfc15109", 'hex')
    ]);

    const dec = new SecureStreams.Decrypter({private_key: private_key});

    return input.pipe(dec).pipe(concat(function(data) {
      expect(data.toString('utf8')).toEqual('your text here');
      return done();
    })
    );
  });
});
