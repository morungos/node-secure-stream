crypto = require('crypto')

Transform = require('stream').Transform

class Encrypter extends Transform

  constructor: (options) ->
    super(options)
    @header_written = false
    @algorithm = options.algorithm
    @algorithm ?= 'AES-256-CBC'
    @key_length = options.key_length
    @key_length ?= 256
    @key = options.key


  initialize: () ->
    self  = @
    keys = crypto.randomBytes(16 + @key_length/8)
    iv = keys.slice(0, 16)
    key = keys.slice(16)

    @cipher = crypto.createCipheriv(@algorithm, key, iv)
    @cipher.on 'data', (buffer) ->
      console.log 'cipher data', buffer
      self.push buffer
    @cipher.on 'error', (error) ->
      console.log 'cipher error', error
    @cipher.on 'end', () ->
      console.log 'cipher end'

    header = Buffer.alloc(4096)
    index = 0
    index = header.writeInt16LE(0, index)
    index = index + header.write("<header #{@algorithm}>", index, 'utf8')

    ## Write the count back
    header.writeInt16LE(index, 0)

    @push header.slice(0, index)
    @header_written = true
    console.log "Cipher initialized"


  _transform: (chunk, encoding, callback) ->
    if ! @header_written
      ## We've not written a header yet, so we make one and then send it
      ## to the output.

      @initialize()

    console.log "Encrypter _write", chunk, encoding
    result = @cipher.write chunk, encoding, () ->
      console.log "Encrypter write cipher result", result
      callback()


  _flush: (callback) ->
    console.log "Encrypter _flush"
    @cipher.end () ->
      console.log "Encrypter _flush complete"
      callback()


class Decrypter extends Transform

  constructor: (options) ->
    super(options)
    @header_read = false
    @algorithm = options.algorithm
    @algorithm ?= 'AES-256-CBC'
    @key = options.key

  _transform: (chunk, encoding, callback) ->
    chunk = Buffer.from(chunk, encoding)
    @push chunk
    callback()


module.exports =
  Encrypter: Encrypter
  Decrypter: Decrypter
