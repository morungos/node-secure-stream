fs = require('fs')

StringToStream = require('string-to-stream')
concat = require('concat-stream')

log4js = require('log4js')
log4js.configure({appenders: [{type: "console"}], levels: {"[all]" : "DEBUG"}})

logger = log4js.getLogger 'test/basic_test'

private_key = fs.readFileSync('test/testkey.pem', "utf8")

SecureStreams = require('../src/index.coffee')

input_string = """
a3000b004145532d3235362d43424380007ce29782259b0a6d82bf56359ea2ecbe6d770062afaaaf08eb661bdfb86d335e3c3da1480d4e968e13a7d150cc6fefea6de870950df53392ae2f359e27792312e4ce40cd41be30d6a50522c82036a843f8da6cdcb78f6202d9e2e2c419e779dc2ed8e751d98e6d42312ec343167a0ce1b08da1b6b136e09d93c92cf3c2b247b010004142434445464748494a4b4c4d4e4f501121ebe4d7ae4aab810d123acfc15109
"""

input_string = input_string.trim()

input = StringToStream(Buffer.from(input_string, 'hex'))

dec = new SecureStreams.Decrypter({key: private_key})
dec.on 'data', (e) ->
  console.log "Encoding", e
dec.on 'close', (e) ->
  console.log "close", e
dec.on 'finish', (e) ->
  console.log "finish", e
dec.on 'drain', (e) ->
  console.log "drain", e

input.pipe(dec).pipe concat (data) ->
  logger.info(data.toString())
