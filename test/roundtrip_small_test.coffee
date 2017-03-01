chai = require('chai')
expect = chai.expect

fs = require('fs')

StringToStream = require('./blocked-string-to-stream')
concat = require('concat-stream')

SecureStreams = require('../src/index.coffee')

describe 'SecureStreams', () ->

  public_key = fs.readFileSync('test/testkey.pub', "utf8")
  private_key = fs.readFileSync('test/testkey.pem', "utf8")

  testString = (input, done) ->
    input_stream = StringToStream([input])
    enc = new SecureStreams.Encrypter({public_key: public_key})
    dec = new SecureStreams.Decrypter({key: private_key})
    input_stream.pipe(enc).pipe(dec).pipe concat (data) ->
      expect(data).to.exist
      expect(data.toString()).to.equal(input)
      done()

  it 'should securely roundtrip a short string', (done) ->
    testString('your text here', done)

  it 'should securely roundtrip a UTF8 string', (done) ->
    testString('your \u201ctext\u201d here', done)
