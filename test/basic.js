const tape = require('tape')
const ssbKeys = require('ssb-keys')
const bfe = require('ssb-bfe')
const base64Url = require('base64-url')
const bipf = require('bipf')
const mini = require('../format')

// FIXME: used a forked ssb-keys
const keys = ssbKeys.generate(null, 'alice', 'buttwoo-v1')
keys.id = keys.id.replace('buttwoo', 'minibutt')

const authorBFE = Buffer.concat([
  bfe.toTF('feed', 'buttwoo-v1'),
  Buffer.from(keys.public.substring(0, keys.public.indexOf('.')), 'base64'),
])

tape('encode/decode works', function (t) {
  const hmacKey = null
  const content = { text: 'Hello world!' }
  const timestamp = 1652037377204

  const miniMsg1 = mini.newNativeMsg({
    keys,
    content,
    type: 'post',
    previous: null,
    timestamp,
    hmacKey,
  })

  const jsonMsg = {
    key: mini.getMsgId(miniMsg1),
    value: mini.fromNativeMsg(miniMsg1),
    timestamp: Date.now(),
  }
  console.log(jsonMsg)

  const msgHash1 = 'Gx+JIHa2UqA='
  const msgKey1 =
    'ssb:message/minibutt-v1/OAiOTCroL1xFxoCKYaZJDTxhLOHaI1cURm_HSPvEy7s/post/' +
    base64Url.escape(msgHash1)

  t.deepEqual(jsonMsg.key, msgKey1, 'key is correct')
  t.deepEqual(
    jsonMsg.value.author,
    'ssb:feed/minibutt-v1/OAiOTCroL1xFxoCKYaZJDTxhLOHaI1cURm_HSPvEy7s/post',
    'author is correct'
  )
  t.deepEqual(jsonMsg.value.type, 'post', 'correct type')
  t.equals(typeof jsonMsg.value.timestamp, 'number', 'has timestamp')
  t.deepEqual(jsonMsg.value.previous, [], 'correct previous')
  t.deepEqual(jsonMsg.value.content, content, 'content is the same')

  const reconstructedMiniMsg1 = mini.toNativeMsg(jsonMsg.value)
  t.deepEqual(reconstructedMiniMsg1, miniMsg1, 'can reconstruct')

  const content2 = { text: 'Hello butty world!' }

  const miniMsg2 = mini.newNativeMsg({
    keys,
    content: content2,
    type: 'post',
    previous: [{ key: msgKey1, value: jsonMsg.value }],
    timestamp: timestamp + 1,
    hmacKey,
  })

  const jsonMsg2 = {
    key: mini.getMsgId(miniMsg2),
    value: mini.fromNativeMsg(miniMsg2),
    timestamp: Date.now(),
  }
  console.log(jsonMsg2)

  t.deepEqual(
    jsonMsg2.key,
    'ssb:message/minibutt-v1/OAiOTCroL1xFxoCKYaZJDTxhLOHaI1cURm_HSPvEy7s/post/YxNMLT9YBPY',
    'key is correct'
  )
  t.deepEqual(
    jsonMsg2.value.author,
    'ssb:feed/minibutt-v1/OAiOTCroL1xFxoCKYaZJDTxhLOHaI1cURm_HSPvEy7s/post',
    'author is correct'
  )
  t.deepEqual(jsonMsg2.value.type, 'post', 'correct type')
  t.equals(typeof jsonMsg2.value.timestamp, 'number', 'has timestamp')
  t.deepEqual(jsonMsg2.value.previous, [msgHash1], 'correct previous')
  t.deepEqual(jsonMsg2.value.content, content2, 'content is the same')

  // test slow version as well
  const reconstructedButt2msg2 = mini.toNativeMsg(jsonMsg2.value)
  t.deepEqual(reconstructedButt2msg2, miniMsg2, 'can reconstruct')

  t.end()
})

tape('extract author', function (t) {
  const hmacKey = null
  const content = { type: 'post', text: 'Hello world!' }
  const timestamp = 1652037377204

  const miniMsg = mini.newNativeMsg({
    keys,
    content,
    type: 'post',
    previous: null,
    timestamp,
    hmacKey,
  })

  const extractedFeed = mini.getFeedId(miniMsg)
  const expectedFeed =
    'ssb:feed/minibutt-v1/OAiOTCroL1xFxoCKYaZJDTxhLOHaI1cURm_HSPvEy7s/post'
  t.equal(expectedFeed, extractedFeed, 'extracting author works')

  t.end()
})

tape('year 2080', function (t) {
  const hmacKey = null
  const content = { type: 'post', text: 'Hello world!' }
  const timestamp = Date.parse('01 Jan 2080 00:00:00 GMT')

  const miniMsg = mini.newNativeMsg({
    keys,
    content,
    type: 'post',
    previous: null,
    timestamp,
    hmacKey,
  })

  const [encodedVal] = bipf.decode(miniMsg)
  const [authorBFE, type, previous, timestampExtracted] =
    bipf.decode(encodedVal)

  t.equal(timestamp, timestampExtracted, 'timestamps far into the future works')

  t.end()
})

return

tape('validate', (t) => {
  const hmacKey = null
  const timestamp = 1652037377204

  const butt2Msg1 = mini.newNativeMsg({
    keys,
    content: { type: 'post', text: 'Hello world!' },
    previous: null,
    timestamp,
    tag: mini.tags.SSB_FEED,
    hmacKey,
  })

  mini.validate(butt2Msg1, null, hmacKey, (err1) => {
    t.error(err1, 'no error')

    const butt2Msg2 = mini.newNativeMsg({
      keys,
      content: { type: 'post', text: 'Hello butty world!' },
      previous: {
        key: mini.getMsgId(butt2Msg1),
        value: mini.fromNativeMsg(butt2Msg1),
      },
      timestamp: timestamp + 1,
      tag: mini.tags.END_OF_FEED,
      hmacKey,
    })

    mini.validate(butt2Msg2, butt2Msg1, hmacKey, (err2) => {
      t.error(err2, 'no error')

      const butt2Msg3 = mini.newNativeMsg({
        keys,
        content: { type: 'post', text: 'Sneaky world!' },
        previous: {
          key: mini.getMsgId(butt2Msg2),
          value: mini.fromNativeMsg(butt2Msg2),
        },
        timestamp: timestamp + 2,
        tag: mini.tags.SSB_FEED,
        hmacKey,
      })
      mini.validate(butt2Msg3, butt2Msg2, hmacKey, (err3) => {
        t.equal(
          err3.message,
          'invalid message: previous message is a tombstone',
          'cant extend ended feed'
        )
        t.end()
      })
    })
  })
})

tape('validate many', function (t) {
  const N = 4000
  const M = 100
  const hmacKey = null
  const content = { type: 'post', text: 'Hello world!' }
  const timestamp = 1652037377204

  const nativeMsgs = []
  let previous = null
  for (let i = 0; i < N; ++i) {
    const butt2Msg = mini.newNativeMsg({
      keys,
      content,
      previous,
      timestamp: timestamp + i,
      tag: mini.tags.SSB_FEED,
      hmacKey,
    })
    previous = {
      key: mini.getMsgId(butt2Msg),
      value: mini.fromNativeMsg(butt2Msg),
    }
    nativeMsgs.push(butt2Msg)
  }

  let isOk = true
  let err = null

  // validate single all, take time
  const startSingle = new Date()
  for (let i = 0; i < N; ++i) {
    const prevNativeMsg = i === 0 ? null : nativeMsgs[i - 1]
    if ((err = mini.validateSync(nativeMsgs[i], prevNativeMsg, hmacKey))) {
      console.log(err)
      isOk = false
      break
    }
  }
  const singleTime = new Date() - startSingle

  t.equal(isOk, true, 'validateSingle completes in ' + singleTime + ' ms')

  isOk = true
  const startBatch = new Date()
  for (let i = 0; i < N; i += M) {
    const prevNativeMsg = i === 0 ? null : nativeMsgs[i - 1]
    if (
      (err = mini.validateBatchSync(
        nativeMsgs.slice(i, i + M),
        prevNativeMsg,
        hmacKey
      ))
    ) {
      console.log(err)
      isOk = false
      break
    }
  }
  const batchTime = new Date() - startBatch

  t.equal(isOk, true, 'validateBatch completes in ' + batchTime + ' ms')
  t.ok(
    batchTime < singleTime,
    'batch validation is faster than single validation'
  )

  t.end()
})
