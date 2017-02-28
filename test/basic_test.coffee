fs = require('fs')

StringtoStream = require('string-to-stream')
concat = require('concat-stream')

log4js = require('log4js')
log4js.configure({appenders: [{type: "console"}], levels: {"[all]" : "DEBUG"}})

logger = log4js.getLogger 'test/basic_test'

public_key = fs.readFileSync('test/testkey.pub', "utf8")

SecureStreams = require('../src/index.coffee')
WriteableStringStream = require('./writable-string-stream')

input = StringtoStream('your text here')

enc = new SecureStreams.Encrypter({public_key: public_key})
enc.on 'data', (e) ->
  console.log "Encoding", e
enc.on 'close', (e) ->
  console.log "close", e
enc.on 'finish', (e) ->
  console.log "finish", e
enc.on 'drain', (e) ->
  console.log "drain", e


StringtoStream('hi there').pipe(enc).pipe concat (data) -> logger.info(data)
