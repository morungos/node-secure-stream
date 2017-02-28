Writable = require('stream').Writable

class StringStream extends Writable

  constructor: (options) ->
    super(options)
    @chunks = []
    @size = 0

  _write: (chunk, enc, cb) ->
    console.log 'StringStream _write()', chunk
    buffer = if Buffer.isBuffer(chunk) then chunk else Buffer.from(chunk, enc)
    @chunks.push buffer
    @size = @size + buffer.length
    cb()

  get: (encoding) ->
    console.log "StringStream get()"
    output = Buffer.alloc(@size)
    index = 0
    for buffer in @chunks
      console.log 'x', buffer, index
      output.fill buffer, index
      index = index + buffer.length

    output


module.exports = StringStream
