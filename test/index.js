const test = require('tape')
const ssbKeys = require('ssb-keys')
const { check } = require('ssb-feed-format')

const format = require('../format')

test('passes ssb-feed-format', (t) => {
  check(
    format,
    () => {
      const keys = ssbKeys.generate(null, 'alice', 'buttwoo-v1')
      keys.id = keys.id.replace('buttwoo', 'minibutt')
      return keys
    },
    { type: 'post' },
    (err) => {
      t.error(err, 'no error')
      if (err) console.log(err)
      t.end()
    }
  )
})
