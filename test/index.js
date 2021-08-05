/* global it, describe, beforeEach, afterEach */
const assert = require('assert')
const KeyringController = require('../')
const configManagerGen = require('./lib/mock-config-manager')
const ethUtil = require('ethereumjs-util')
const BN = ethUtil.BN
const sigUtil = require('eth-sig-util')
const normalizeAddress = sigUtil.normalize
const mockEncryptor = require('./lib/mock-encryptor')
const MockSimpleKeyring = require('./lib/mock-simple-keyring')
const sinon = require('sinon')
const Wallet = require('ethereumjs-wallet').default
const argon2 = require('argon2-wasm')

describe('KeyringController', () => {
  let keyringController
  const password = 'password123'
  const seedWords = 'evil saddle unveil lounge behind that zone circle drill pilot fat faint axis file rotate sunset today bus decorate review today minor duck mad'
  const addresses = ['0x410D5D17C59300145ed11E5FB6451F0f4380522b'.toLowerCase()]
  const accounts = []
  // let originalKeystore

  beforeEach(async () => {
    this.sinon = sinon.sandbox.create()
    window.localStorage = {} // Hacking localStorage support into JSDom

    keyringController = new KeyringController({
      configManager: configManagerGen(),
      encryptor: mockEncryptor,
    })

    const newState = await keyringController.createNewVaultAndKeychain(password)
  })

  afterEach(() => {
    // Cleanup mocks
    this.sinon.restore()
  })

  describe('#submitPassword', function () {
    this.timeout(10000)

    it('should not create new keyrings when called in series', async () => {
      await keyringController.createNewVaultAndKeychain(password)
      await keyringController.persistAllKeyrings()

      assert.equal(keyringController.keyrings.length, 1, 'has one keyring')
      await keyringController.submitPassword(password + 'a')
      assert.equal(keyringController.keyrings.length, 1, 'has one keyring')
      await keyringController.submitPassword('testtest')
      assert.equal(keyringController.keyrings.length, 1, 'has one keyring')
    })

    it('unlocks when correct password is submitted', async () => {
      await keyringController.createNewVaultAndKeychain(password)
      await keyringController.persistAllKeyrings()
      const key = keyringController.masterKey
      await keyringController.setLocked()
      assert(!keyringController.masterKey)
      await keyringController.submitPassword(password)
      assert.deepStrictEqual(keyringController.masterKey, key)
    })

    it('does not unlock when wrong password is submitted', async () => {
      await keyringController.createNewVaultAndKeychain(password)
      await keyringController.persistAllKeyrings()
      const key = keyringController.masterKey
      await keyringController.setLocked()
      assert(!keyringController.masterKey)
      await keyringController.submitPassword('wrong password')
      assert.notDeepStrictEqual(keyringController.masterKey, key)
    })

    it('unlocks on retry with correct password', async () => {
      await keyringController.createNewVaultAndKeychain(password)
      await keyringController.persistAllKeyrings()
      const key = keyringController.masterKey
      await keyringController.setLocked()
      assert(!keyringController.masterKey)
      await keyringController.submitPassword('wrong password')
      assert.notDeepStrictEqual(keyringController.masterKey, key)
      await keyringController.submitPassword(password)
      assert.deepStrictEqual(keyringController.masterKey, key)
    })
  })

  describe('#verifyPassword', function () {
    this.timeout(10000)

    it ('should not restore extra keyrings with correct password', async () => {
      await keyringController.createNewVaultAndKeychain(password)
      await keyringController.persistAllKeyrings()
      await keyringController.verifyPassword(password)
      assert.equal(keyringController.keyrings.length, 1, 'has one keyring')
    })
  })

  describe('#createNewVaultAndKeychain', function () {
    this.timeout(10000)

    it('should set a vault on the configManager', async () => {
      keyringController.store.updateState({ vault: null })
      assert(!keyringController.store.getState().vault, 'no previous vault')
      await keyringController.createNewVaultAndKeychain(password)
      const vault = keyringController.store.getState().vault
      assert(vault, 'vault created')
    })

    it('should encrypt keyrings with the correct password each time they are persisted', async () => {
      keyringController.store.updateState({ vault: null })
      assert(!keyringController.store.getState().vault, 'no previous vault')
      await keyringController.createNewVaultAndKeychain(password)
      const vault = keyringController.store.getState().vault
      assert(vault, 'vault created')
      assert(keyringController.salt.length)
      keyringController.encryptor.encrypt.args.forEach(([subkey]) => {
        const TextEncoder = require('util').TextEncoder
        const subkeyEncoded = new TextEncoder('utf-8').encode(subkey)
        assert(subkeyEncoded.length, 32)
      })
    })
  })

  describe('#_getSubkey', () => {
    const salt = 'somesalt123'

    beforeEach(async () => {
      // reset the keyring controller before each test
      keyringController = new KeyringController({
        configManager: configManagerGen(),
        encryptor: mockEncryptor
      })
      keyringController.password = password
      window.localStorage = {}
    })
    it('generates different keys for different infos', async () => {
      const key1 = await keyringController._getSubkey('foo')
      const key2 = await keyringController._getSubkey('bar')
      assert.strictEqual(key1.length, 32)
      assert.strictEqual(key2.length, 32)
      assert.notDeepStrictEqual(key1, key2)
      await keyringController.setLocked()
      keyringController.password = password
      const key3 = await keyringController._getSubkey('bar')
      assert.deepStrictEqual(key2, key3)
    })

    it('generates different keys for different salts', async () => {
      const key1 = await keyringController._getSubkey('foo')
      await keyringController.setLocked()
      keyringController.password = password
      const key2 = await keyringController._getSubkey('foo', salt)
      assert.strictEqual(key1.length, 32)
      assert.strictEqual(key2.length, 32)
      assert.notDeepStrictEqual(key1, key2)
    })

    it('can override default argon params', async () => {
      const key = await keyringController._getSubkey('foo', undefined, {
        mem: 1000,
        time: 2
      })
      assert.strictEqual(key.length, 32)
      assert.deepStrictEqual(keyringController.store.getState().argonParams, {
        mem: 1000,
        time: 2,
        type: argon2.types.Argon2id,
        hashLen: 32
      })
    })

    it('throws if password is empty', async () => {
      assert.rejects(async () => {
        delete keyringController.password
        await keyringController._getSubkey('foo', salt)
      })
    })

    it('produces expected output for non-empty password', async () => {
      const key = await keyringController._getSubkey('foo', salt)
      assert.deepStrictEqual(key, new Uint8Array([
        34,
        108,
        233,
        231,
        120,
        236,
        87,
        212,
        135,
        3,
        146,
        43,
        40,
        54,
        177,
        5,
        38,
        254,
        79,
        219,
        183,
        179,
        9,
        26,
        214,
        233,
        39,
        255,
        3,
        177,
        146,
        169
      ]))
      assert.deepStrictEqual(keyringController.masterKey, {
        encoded: '$argon2id$v=19$m=500000,t=1,p=1$c29tZXNhbHQxMjM$rELp2+qCmIoutAxj0ouvLdyiMTiGvMkUExU8HzPM8q0',
        hashHex: 'ac42e9dbea82988a2eb40c63d28baf2ddca2313886bcc91413153c1f33ccf2ad',
        hash: new Uint8Array([172,66,233,219,234,130,152,138,46,180,12,99,210,139,175,45,220,162,49,56,134,188,201,20,19,21,60,31,51,204,242,173])
      })
      assert.strictEqual(keyringController.salt, salt)
      assert.strictEqual(keyringController.store.getState().salt, salt)
      assert.deepStrictEqual(keyringController.store.getState().argonParams, {
        mem: 500000,
        time: 1,
        type: argon2.types.Argon2id,
        hashLen: 32
      })
    })
  })

  describe('#addNewKeyring', () => {
    it('Simple Key Pair', async () => {
      const privateKey = 'c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3'
      const previousAccounts = await keyringController.getAccounts()
      const keyring = await keyringController.addNewKeyring('Simple Key Pair', [ privateKey ])
      const keyringAccounts = await keyring.getAccounts()
      const expectedKeyringAccounts = ['0x627306090abab3a6e1400e9345bc60c78a8bef57']
      assert.deepEqual(keyringAccounts, expectedKeyringAccounts, 'keyringAccounts match expectation')
      const allAccounts = await keyringController.getAccounts()
      const expectedAllAccounts = previousAccounts.concat(expectedKeyringAccounts)
      assert.deepEqual(allAccounts, expectedAllAccounts, 'allAccounts match expectation')
    })
    it('HD Key Tree', async () => {
      const previousAccounts = await keyringController.getAccounts()
      const keyring = await keyringController.addNewKeyring('HD Key Tree', {
        numberOfAccounts: 1,
        password: 'abcdef'
      })
      const keyringAccounts = await keyring.getAccounts()
      assert.equal(keyringAccounts.length, 1, 'created 1 new account')
      const allAccounts = await keyringController.getAccounts()
      assert.deepEqual(allAccounts.length, 1 + previousAccounts.length,
        'allAccounts match expectation')
    })
    it('Mocked Simple Key Pair (no opts)', async () => {
      keyringController = new KeyringController({
        configManager: configManagerGen(),
        encryptor: mockEncryptor,
        keyringTypes: [MockSimpleKeyring]
      })

      await keyringController.createNewVaultAndKeychain(password)

      const previousKeyrings = await keyringController.getKeyringsByType('Mocked Simple Key Pair')
      assert.equal(previousKeyrings.length, 0, 'no keyrings')

      await keyringController.addNewKeyring('Mocked Simple Key Pair')
      const keyrings = await keyringController.getKeyringsByType('Mocked Simple Key Pair')
      assert.equal(keyrings.length, 1, 'found mocked keyring')
    })
  })

  describe('#restoreKeyring', () => {
    it(`should pass a keyring's serialized data back to the correct type.`, async () => {
      const mockSerialized = {
        type: 'HD Key Tree',
        data: {
          mnemonic: seedWords,
          numberOfAccounts: 1,
          password: 'abc'
        },
      }

      const keyring = await keyringController.restoreKeyring(mockSerialized)
      assert.equal(keyring.wallets.length, 1, 'one wallet restored')
      const accounts = await keyring.getAccounts()
      assert.equal(accounts[0], addresses[0])
    })
  })

  describe('#getAccounts', () => {
    it('returns the result of getAccounts for each keyring', async () => {
      keyringController.keyrings = [
        { async getAccounts () { return [1, 2, 3] } },
        { async getAccounts () { return [4, 5, 6] } },
      ]

      const result = await keyringController.getAccounts()
      assert.deepEqual(result, [1, 2, 3, 4, 5, 6])
    })
  })

  describe('#removeAccount', () => {
    it('removes an account from the corresponding keyring', async () => {
      const account = {
        privateKey: 'c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3',
        publicKey: '0x627306090abab3a6e1400e9345bc60c78a8bef57',
      }

      const accountsBeforeAdding = await keyringController.getAccounts()
      // Add a new keyring with one account
      await keyringController.addNewKeyring('Simple Key Pair', [ account.privateKey ])

      // remove that account that we just added
      await keyringController.removeAccount(account.publicKey)

      // fetch accounts after removal
      const result = await keyringController.getAccounts()
      assert.deepEqual(result, accountsBeforeAdding)
    })

    it('removes the keyring if there are no accounts after removal', async () => {
      const account = {
        privateKey: 'c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3',
        publicKey: '0x627306090abab3a6e1400e9345bc60c78a8bef57',
      }

      const accountsBeforeAdding = await keyringController.getAccounts()
      // Add a new keyring with one account
      await keyringController.addNewKeyring('Simple Key Pair', [ account.privateKey ])
      // We should have 2 keyrings
      assert.equal(keyringController.keyrings.length, 2)
      // remove that account that we just added
      await keyringController.removeAccount(account.publicKey)

      // Check that the previous keyring with only one account
      // was also removed after removing the account
      assert.equal(keyringController.keyrings.length, 1)
    })

  })

  describe('#addGasBuffer', () => {
    it('adds 100k gas buffer to estimates', () => {
      const gas = '0x04ee59' // Actual estimated gas example
      const tooBigOutput = '0x80674f9' // Actual bad output
      const bnGas = new BN(ethUtil.stripHexPrefix(gas), 16)
      const correctBuffer = new BN('100000', 10)
      const correct = bnGas.add(correctBuffer)

      // const tooBig = new BN(tooBigOutput, 16)
      const result = keyringController.addGasBuffer(gas)
      const bnResult = new BN(ethUtil.stripHexPrefix(result), 16)

      assert.equal(result.indexOf('0x'), 0, 'included hex prefix')
      assert(bnResult.gt(bnGas), 'Estimate increased in value.')
      assert.equal(bnResult.sub(bnGas).toString(10), '100000', 'added 100k gas')
      assert.equal(result, '0x' + correct.toString(16), 'Added the right amount')
      assert.notEqual(result, tooBigOutput, 'not that bad estimate')
    })
  })

  describe('#unlockKeyrings', () => {
    it('returns the list of keyrings', async () => {
      await keyringController.setLocked()
      const keyrings = await keyringController.unlockKeyrings(password)
      assert.notStrictEqual(keyrings.length, 0)
      keyrings.forEach(keyring => {
        assert.strictEqual(keyring.wallets.length, 1)
      })
    })
  })

  describe('getAppKeyAddress', () => {
    it('returns the expected app key address', async () => {
      const address = '0x01560cd3bac62cc6d7e6380600d9317363400896'
      const privateKey = '0xb8a9c05beeedb25df85f8d641538cbffedf67216048de9c678ee26260eb91952'
      const keyring = await keyringController.addNewKeyring('Simple Key Pair', [ privateKey ])
      keyring.getAppKeyAddress = sinon.spy()
      keyringController.getKeyringForAccount = sinon.stub().returns(Promise.resolve(keyring))
      const appKeyAddress = await keyringController.getAppKeyAddress(address, 'someapp.origin.io')

      assert(keyringController.getKeyringForAccount.calledOnce)
      assert.equal(keyringController.getKeyringForAccount.getCall(0).args[0], normalizeAddress(address))
      assert(keyring.getAppKeyAddress.calledOnce)
      assert.deepEqual(keyring.getAppKeyAddress.getCall(0).args, [normalizeAddress(address), 'someapp.origin.io'])
    })
  })

  describe('exportAppKeyForAddress', () => {
    it('returns a unique key', async () => {
      const address = '0x01560cd3bac62cc6d7e6380600d9317363400896'
      const privateKey = '0xb8a9c05beeedb25df85f8d641538cbffedf67216048de9c678ee26260eb91952'
      const keyring = await keyringController.addNewKeyring('Simple Key Pair', [ privateKey ])
      const appKeyAddress = await keyringController.getAppKeyAddress(address, 'someapp.origin.io')

      const privateAppKey = await keyringController.exportAppKeyForAddress(address, 'someapp.origin.io')

      const wallet = Wallet.fromPrivateKey(ethUtil.toBuffer('0x' + privateAppKey))
      const recoveredAddress = '0x' + wallet.getAddress().toString('hex')

      assert.equal(recoveredAddress, appKeyAddress, 'Exported the appropriate private key')
      assert.notEqual(privateAppKey, privateKey)
    })
  })

})
