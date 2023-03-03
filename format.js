const bipf = require('bipf')
const bfe = require('ssb-bfe')
const SSBURI = require('ssb-uri2')
const varint = require('fast-varint')
const ssbKeys = require('ssb-keys')
const base64Url = require('base64-url')
const makeContentHash = require('./content-hash')
const {
  validate,
  validateBatch,
  validateSync,
  validateBatchSync,
} = require('./validation')
const { getMsgId } = require('./get-msg-id')

function _base64ToBuffer(str) {
  var i = str.indexOf('.')
  return Buffer.from(str.substring(0, i), 'base64')
}

const BIPF_TAG_SIZE = 3
const BIPF_TAG_MASK = 7
const BIPF_STRING_TYPE = 0b000

const name = 'minibutt-v1'
const encodings = ['js', 'bipf']

function getFeedId(nativeMsg) {
  const [metadata] = bipf.decode(nativeMsg)
  const [authorBuf, type] = bipf.decode(metadata)

  return `ssb:feed/minibutt-v1/${base64Url.encode(authorBuf)}/${type}`
}

function getSequence(nativeMsg) {
  throw new Error('a minibutt message does not have a sequence')
}

function isNativeMsg(x) {
  if (!Buffer.isBuffer(x)) return false
  if (x.length === 0) return false
  const type = bipf.getEncodedType(x)
  if (type !== bipf.types.array) return false
  // FIXME: better check
  return true
}

function isAuthor(author) {
  if (typeof author !== 'string') return false
  return author.startsWith('ssb:feed/minibutt-v1/') // FIXME: use SSBURI
}

function toPlaintextBuffer(opts) {
  return bipf.allocAndEncode(opts.content)
}

function getMsgHashFromMsgVal(msgVal) {
  const key = msgVal.key
  if (key.startsWith('ssb:message/minibutt-v1/')) {
    const parts = key.split('/')
    return base64Url.unescape(parts[parts.length - 1])
  } else {
    return key
  }
}

function newNativeMsg(opts) {
  if (!opts.type) {
    throw new Error('opts.type is required in minibutt-v1')
  }
  const author = _base64ToBuffer(opts.keys.public)
  const type = opts.type
  const previous = (opts.previous ?? []).map(getMsgHashFromMsgVal)
  const contentBuffer = bipf.allocAndEncode(opts.content)
  const contentHash = makeContentHash(contentBuffer)
  const timestamp = +opts.timestamp

  const metadata = [
    author,
    type,
    previous,
    timestamp,
    contentBuffer.length,
    contentHash,
  ]

  const metadataBIPF = bipf.allocAndEncode(metadata)
  // FIXME: we need ssb-keys to support returning buffer from sign()
  const signature = ssbKeys.sign(opts.keys, opts.hmacKey, metadataBIPF)
  const sigBuf = _base64ToBuffer(signature)

  return bipf.allocAndEncode([metadataBIPF, sigBuf, contentBuffer])
}

function _fromNativeToJSMsg(nativeMsg) {
  const [metadataBIPF, sigBuf, contentBuf] = bipf.decode(nativeMsg)
  const [authorBuf, type, previous, timestamp, contentLength, contentHashBuf] =
    bipf.decode(metadataBIPF)
  const author = `ssb:feed/minibutt-v1/${base64Url.encode(authorBuf)}/${type}`
  const content = bipf.decode(contentBuf)
  const contentHash = contentHashBuf
  const signature = sigBuf
  const msgVal = {
    author,
    type,
    previous,
    timestamp,
    content,
    contentHash,
    signature,
  }
  return msgVal
}

function _fromNativeToBIPFMsg(nativeMsg) {
  const [encodedVal, sigBuf, contentBuf] = bipf.decode(nativeMsg)
  const [authorBuf, type, previous, timestamp, contentLength, contentHashBuf] =
    bipf.decode(metadataBIPF)
  const author = `ssb:feed/minibutt-v1/${base64Url.encode(authorBuf)}/${type}`
  const signature = sigBuf
  bipf.markIdempotent(contentBuf)
  const msgVal = {
    author,
    type,
    previous,
    timestamp,
    content: contentBuf,
    contentHash,
    signature,
  }
  const bipfMsg = bipf.allocAndEncode(msgVal)
  return bipfMsg
}

function fromNativeMsg(nativeMsg, encoding = 'js') {
  if (encoding === 'js') {
    return _fromNativeToJSMsg(nativeMsg)
  } else if (encoding === 'bipf') {
    return _fromNativeToBIPFMsg(nativeMsg)
  } else {
    // prettier-ignore
    throw new Error(`Feed format "${name}" does not support encoding "${encoding}"`)
  }
}

function fromDecryptedNativeMsg(plaintextBuf, nativeMsg, encoding = 'js') {
  if (encoding !== 'js') {
    throw new Error('minibutt-v1 only supports js encoding when decrypting')
  }
  const msgVal = fromNativeMsg(nativeMsg, encoding)
  const content = bipf.decode(plaintextBuf)
  msgVal.content = content
  return msgVal
}

function _toNativeFromJSMsg(msgVal) {
  const author = Buffer.from(
    base64Url.unescape(msgVal.author.split('/')[2]),
    'base64'
  )
  const type = msgVal.type
  const previous = msgVal.previous
  const timestamp = msgVal.timestamp
  const contentBuffer = bipf.allocAndEncode(msgVal.content)
  const contentHash = msgVal.contentHash
  const metadata = [
    author,
    type,
    previous,
    timestamp,
    contentBuffer.length,
    contentHash,
  ]
  const metadataBIPF = bipf.allocAndEncode(metadata)
  const sigBuf = msgVal.signature
  return bipf.allocAndEncode([metadataBIPF, sigBuf, contentBuffer])
}

function _toNativeFromBIPFMsg(buffer) {
  let authorBuffer, type, previous, timestamp
  let contentBuffer, contentLen, contentHash, sigBuf

  const tag = varint.decode(buffer, 0)
  const len = tag >> BIPF_TAG_SIZE

  for (var c = varint.decode.bytes; c < len; ) {
    const keyStart = c
    var keyTag = varint.decode(buffer, keyStart)
    c += varint.decode.bytes
    c += keyTag >> BIPF_TAG_SIZE
    const valueStart = c
    const valueTag = varint.decode(buffer, valueStart)
    const valueLen = varint.decode.bytes + (valueTag >> BIPF_TAG_SIZE)

    const key = bipf.decode(buffer, keyStart)
    if (key === 'author')
      authorBuffer = Buffer.from(
        base64Url.unescape(bipf.decode(buffer, valueStart).split('/')[2]),
        'base64'
      )
    else if (key === 'type') type = bipf.decode(buffer, valueStart)
    else if (key === 'timestamp') timestamp = bipf.decode(buffer, valueStart)
    else if (key === 'previous') previous = bipf.decode(buffer, valueStart)
    else if (key === 'content') {
      if ((valueTag & BIPF_TAG_MASK) === BIPF_STRING_TYPE) {
        contentBuffer = bipf.decode(buffer, valueStart)
        contentLen = _base64ToBuffer(contentBuffer).length
      } else {
        contentBuffer = bipf.pluck(buffer, valueStart)
        contentLen = contentBuffer.length
      }
    } else if (key === 'contentHash')
      contentHash = bipf.decode(buffer, valueStart)
    else if (key === 'signature') sigBuf = bipf.decode(buffer, valueStart)

    c += valueLen
  }

  const value = [
    authorBuffer,
    type,
    previous,
    timestamp,
    contentLen,
    contentHash,
  ]
  const encodedValue = bipf.allocAndEncode(value)
  return bipf.allocAndEncode([encodedValue, sigBuf, contentBuffer])
}

function toNativeMsg(msgVal, encoding = 'js') {
  if (encoding === 'js') {
    return _toNativeFromJSMsg(msgVal)
  } else if (encoding === 'bipf') {
    return _toNativeFromBIPFMsg(msgVal)
  } else {
    // prettier-ignore
    throw new Error(`Feed format "${name}" does not support encoding "${encoding}"`)
  }
}

module.exports = {
  // ssb-feed-format:
  name,
  encodings,
  getFeedId,
  getMsgId,
  getSequence,
  isNativeMsg,
  isAuthor,
  toPlaintextBuffer,
  newNativeMsg,
  fromNativeMsg,
  fromDecryptedNativeMsg,
  toNativeMsg,
  validate,
  validateBatch,

  // Not part of ssb-feed-format API:
  validateSync,
  validateBatchSync,
}
