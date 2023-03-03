const blake3 = require('blake3')
const bfe = require('ssb-bfe')
const bipf = require('bipf')
const base64Url = require('base64-url')

const BUTTWOO_MSG_TF = bfe.toTF('message', 'buttwoo-v1')

function getMsgHash(nativeMsg) {
  const [metadata, signature] = bipf.decode(nativeMsg)
  return blake3.hash(Buffer.concat([metadata, signature])).subarray(0, 16)
}

function getMsgId(nativeMsg) {
  const msgHash = getMsgHash(nativeMsg)
  const [metadata] = bipf.decode(nativeMsg)
  const [authorBuf, type] = bipf.decode(metadata)

  const author = base64Url.encode(authorBuf)
  const msgHash8 = base64Url.encode(msgHash.subarray(0, 8))
  // Fast:
  const msgId = `ssb:message/minibutt-v1/${author}/${type}/${msgHash8}`
  // Proper:
  // const msgId = SSBURI.compose({
  //   type: 'message',
  //   format: 'minibutt-v1',
  //   data,
  // })
  return msgId
}

function getMsgIdBFE(nativeMsg) {
  let data = getMsgHash(nativeMsg)
  return Buffer.concat([BUTTWOO_MSG_TF, data])
}

module.exports = { getMsgId, getMsgIdBFE, getMsgHash }
