chai = require('chai')
expect = chai.expect

fs = require('fs')

StringToStream = require('./blocked-string-to-stream')
concat = require('concat-stream')

SecureStreams = require('../src/index.coffee')

describe 'SecureStreams', () ->

  public_key = fs.readFileSync('test/testkey.pub', "utf8")
  private_key = fs.readFileSync('test/testkey.pem', "utf8")

  it 'should securely roundtrip a short string', (done) ->
    input = 'your text here'
    input_stream = StringToStream([input])
    enc = new SecureStreams.Encrypter({public_key: public_key})
    dec = new SecureStreams.Decrypter({key: private_key})
    input_stream.pipe(enc).pipe(dec).pipe concat (data) ->
      expect(data).to.exist
      expect(data.toString()).to.equal(input)
      done()

  it 'should securely roundtrip a UTF8 string', (done) ->
    input = 'your \u201ctext\u201d here'
    input_stream = StringToStream([input])
    enc = new SecureStreams.Encrypter({public_key: public_key})
    dec = new SecureStreams.Decrypter({key: private_key})
    input_stream.pipe(enc).pipe(dec).pipe concat (data) ->
      expect(data).to.exist
      expect(data.toString()).to.equal(input)
      done()

  it 'should securely roundtrip a file', (done) ->
    buffer = fs.readFileSync('./test/darwin-sm.png')
    input_stream = StringToStream([buffer])
    enc = new SecureStreams.Encrypter({public_key: public_key})
    dec = new SecureStreams.Decrypter({key: private_key})
    input_stream.pipe(enc).pipe(dec).pipe concat (data) ->
      expect(data).to.exist
      expect(data.toString('hex')).to.equal(buffer.toString('hex'))
      done()
