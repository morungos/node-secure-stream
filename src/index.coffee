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
    @public_key = options.public_key
    @key = options.key

    if !@public_key
      throw new Error("Missing public key")


  getRandomBytes: (length) ->
    crypto.randomBytes(length)


  initialize: () ->
    self  = @
    keys = @getRandomBytes(16 + @key_length/8)
    iv = keys.slice(0, 16)
    key = keys.slice(16)

    ## Make a regular cipher object. This handles the writing of all
    ## subsequent data.
    @cipher = crypto.createCipheriv(@algorithm, key, iv)
    @cipher.on 'data', (buffer) ->
      console.log 'cipher data', buffer
      self.push buffer
    @cipher.on 'error', (error) ->
      console.log 'cipher error', error

    ## Now, we need to manage the RSA handling of the AES key.
    encrypted_key = crypto.publicEncrypt(@public_key, key)

    header = Buffer.alloc(4096)
    index = 0
    index = header.writeInt16LE(0, index)
    index = header.writeInt16LE(@algorithm.length, index)
    index = index + header.write(@algorithm, index, 'latin1')
    index = header.writeInt16LE(encrypted_key.length, index)
    header.fill(encrypted_key, index, index + encrypted_key.length)
    index = index + encrypted_key.length
    index = header.writeInt16LE(iv.length, index)
    header.fill(iv, index, index + iv.length)
    index = index + iv.length

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
