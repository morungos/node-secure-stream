crypto = require('crypto')

Transform = require('stream').Transform

# log4js = require('log4js')
# logger = log4js.getLogger 'node-secure-stream'

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
    # logger.debug "KEY", key
    # logger.debug "IV", iv

    ## Make a regular cipher object. This handles the writing of all
    ## subsequent data.
    # logger.debug "initialize createCipheriv", @algorithm, key, iv
    @cipher = crypto.createCipheriv(@algorithm, key, iv)
    @cipher.on 'data', (buffer) ->
      # logger.debug 'cipher data', buffer
      self.push buffer
    @cipher.on 'error', (error) ->
      logger.debug 'cipher error', error

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
    # logger.debug "Cipher initialized"


  _transform: (chunk, encoding, callback) ->
    if ! @header_written
      ## We've not written a header yet, so we make one and then send it
      ## to the output.

      @initialize()

    # logger.debug "Encrypter _write", chunk, encoding
    result = @cipher.write chunk, encoding, () ->
      # logger.debug "Encrypter write cipher result", result
      callback()


  _flush: (callback) ->
    # logger.debug "Encrypter _flush"
    @cipher.end () ->
      # logger.debug "Encrypter _flush complete"
      callback()



class Decrypter extends Transform

  constructor: (options) ->
    super(options)
    @header_complete = false
    @key = options.key
    @header = Buffer.alloc(4096)
    @header_size = 0
    @header_index = 0


  unpackHeader: () ->
    self = @
    index = 0
    @header_size = @header.readInt16LE(index)
    # logger.debug "unpackHeader @header_size", @header_size
    index = index + 2
    algorithm_size = @header.readInt16LE(index)
    # logger.debug "unpackHeader algorithm_size", algorithm_size
    index = index + 2
    @algorithm = @header.slice(index, index + algorithm_size).toString('latin1')
    # logger.debug "unpackHeader @algorithm", @algorithm
    index = index + algorithm_size
    encrypted_key_size = @header.readInt16LE(index)
    # logger.debug "unpackHeader encrypted_key_size", encrypted_key_size
    index = index + 2
    encrypted_key = @header.slice(index, index + encrypted_key_size)
    # logger.debug "unpackHeader encrypted_key", encrypted_key
    index = index + encrypted_key_size
    iv_size = @header.readInt16LE(index)
    # logger.debug "unpackHeader iv_size", iv_size
    index = index + 2
    @iv = @header.slice(index, index + iv_size)
    # logger.debug "unpackHeader @iv", @iv
    index = index + iv_size

    ## Now, let's decrypted the key, and build a decryption cipher
    @key = crypto.privateDecrypt(@key, encrypted_key)
    # logger.debug "unpackHeader decrypted", encrypted_key, 'to', @key

    ## And here's the new cipher
    # logger.debug "unpackHeader createDecipheriv", @algorithm, @key, @iv
    @cipher = crypto.createDecipheriv(@algorithm, @key, @iv)
    @cipher.on 'data', (buffer) ->
      # logger.debug 'cipher data', buffer
      self.push buffer
    @cipher.on 'error', (error) ->
      logger.debug 'cipher error', error

    # logger.debug "unpackHeader done"
    @header_complete = true


  _transform: (chunk, encoding, callback) ->
    chunk = if Buffer.isBuffer(chunk) then chunk else Buffer.from(chunk, encoding)
    # logger.debug "Got chunk", chunk, encoding

    if ! @header_complete
      @header.fill(chunk, @header_index)
      @header_index = @header_index + chunk.length
      # logger.debug "Added chunk", @header_index, chunk

      if @header_index >= 2
        @header_size = @header.readInt16LE(0)
        # logger.debug "Worked out @header_size", @header_size
      else
        return callback()

      if !@header_size? || @header_index < @header_size
        return callback()

      # logger.debug 'XXXX', @header_size, @header_index, chunk.length

      header_buffer = @header.slice(0, @header_size)
      chunk = chunk.slice(chunk.length - (@header_index - @header_size))

      @header = header_buffer
      @unpackHeader()

      # logger.debug "Remaining", chunk, chunk.length

      ## We might well have a bit of chunk left over, so if we do, let's
      ## chop if off and run it through the cipher. This isn't just a block
      ## after 4096, it depends on the header block size.

    result = @cipher.write chunk, encoding, () ->
      # logger.debug "Decrypter write cipher result", result
      callback()


  _flush: (callback) ->
    # logger.debug "Decrypter _flush"
    @cipher.end () ->
      # logger.debug "Decrypter _flush complete"
      callback()



module.exports =
  Encrypter: Encrypter
  Decrypter: Decrypter
