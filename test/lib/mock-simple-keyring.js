// based on https://github.com/MetaMask/eth-simple-keyring/blob/master/index.js

var fakeWallet = {
  privKey: '0x123456788890abcdef',
  address: '0xfedcba0987654321',
}
const type = 'Mocked Simple Key Pair'

class MockSimpleKeyring {

  static type () { return type }

  constructor (opts) {
    this.type = type
    this.opts = opts || {}
    this.wallets = []
  }

  serialize () {
    return [ fakeWallet.privKey ]
  }

  deserialize (data) {
    if (!Array.isArray(data)) {
      throw new Error('Simple keychain deserialize requires a privKey array.')
    }
    this.wallets = [ fakeWallet ]
  }

  addAccounts (n = 1) {
    for (var i = 0; i < n; i++) {
      this.wallets.push(fakeWallet)
    }
  }

  getAccounts () {
    return Promise.resolve(this.wallets.map(w => w.address))
  }

}

MockSimpleKeyring.type = type
module.exports = MockSimpleKeyring
