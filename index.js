module.exports = function init(ssb) {
  if (ssb.db) ssb.db.installFeedFormat(require('./format'))
}
