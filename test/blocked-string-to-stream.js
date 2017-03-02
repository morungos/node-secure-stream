module.exports = BlockedStringStream

var inherits = require('inherits')
var stream = require('readable-stream')

inherits(BlockedStringStream, stream.Readable)

function BlockedStringStream (strings) {
  if (!(this instanceof BlockedStringStream)) return new BlockedStringStream(strings)
  stream.Readable.call(this)
  this._strings = strings
}

BlockedStringStream.prototype._read = function () {
  if (!this.ended) {
    var self = this
    function sendBlock() {
      process.nextTick(function () {
        var first = self._strings.shift()
        if (typeof first != 'undefined') {
          self.push(new Buffer(first))
          sendBlock();
        } else {
          self.push(null)
          this.ended = true
        }
      })
    }
    sendBlock()
  }
}
