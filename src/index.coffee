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
    console.log "KEY", key
    console.log "IV", iv

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
    @key = options.key
    @header = Buffer.alloc(4096)
    @header_size = 0


  unpackHeader: () ->
    index = 0
    @header_size = @header.readInt16LE(index)
    index = index + 2
    algorithm_size = @header.readInt16LE(index)
    index = index + 2
    @algorithm = @header.slice(index, index + algorithm_size).toString('latin1')
    index = index + algorithm_size
    encrypted_key_size = @header.readInt16LE(index)
    encrypted_key = @header.slice(index, index + encrypted_key_size)
    index = index + encrypted_key_size
    iv_size = @header.readInt16LE(index)
    @iv = @header.slice(index, index + iv_size)

    ## Now, let's decrypted the key, and build a decryption cipher
    @key = crypto.privateDecrypt(@key, encrypted_key)

    ## And here's the new cipher
    @cipher = crypto.createCipheriv(@algorithm, key, iv)
    @cipher.on 'data', (buffer) ->
      console.log 'cipher data', buffer
      self.push buffer
    @cipher.on 'error', (error) ->
      console.log 'cipher error', error


  _transform: (chunk, encoding, callback) ->
    chunk = if Buffer.isBuffer(chunk) then chunk else Buffer.from(chunk, encoding)
    if ! @header_read

      @header.fill(chunk, @header_index)
      @header_index = @header_index + chunk.length
      unpackHeader()

      ## We might well have a bit of chunk left over, so if we do, let's
      ## chop if off and run it through the cipher. This isn't just a block
      ## after 4096, it depends on the header block size.


    @push chunk
    callback()


  _flush: (callback) ->
    console.log "Encrypter _flush"
    @cipher.end () ->
      console.log "Encrypter _flush complete"
      callback()







module.exports =
  Encrypter: Encrypter
  Decrypter: Decrypter
