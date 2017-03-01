fs = require('fs')

StringToStream = require('string-to-stream')
concat = require('concat-stream')

log4js = require('log4js')
log4js.configure({appenders: [{type: "console"}], levels: {"[all]" : "DEBUG"}})

logger = log4js.getLogger 'test/basic_encryption_test'

public_key = fs.readFileSync('test/testkey.pub', "utf8")

SecureStreams = require('../src/index.coffee')

input_string = 'your text here'

# input_string = "1234567890"
# for i in [1..12]
#   input_string += input_string + input_string

console.log "Input length", input_string.length

input = StringToStream(input_string)

enc = new SecureStreams.Encrypter({public_key: public_key})
enc.getRandomBytes = () ->
  Buffer.from([0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
               0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
               0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
               0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
               0x61, 0x62, 0x63, 0x64, 0x65, 0x46, 0x67, 0x68,
               0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70])
enc.on 'data', (e) ->
  console.log "Encoding", e
enc.on 'close', (e) ->
  console.log "close", e
enc.on 'finish', (e) ->
  console.log "finish", e
enc.on 'drain', (e) ->
  console.log "drain", e


input.pipe(enc).pipe concat (data) ->
  logger.info(data.toString('hex'))
