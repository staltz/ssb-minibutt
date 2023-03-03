const blake3 = require('blake3')

function makeContentHash(contentBuffer) {
  return Buffer.concat([Buffer.from([0]), blake3.hash(contentBuffer)])
}

module.exports = makeContentHash
