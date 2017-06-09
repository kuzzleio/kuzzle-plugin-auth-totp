const
  base32 = require('thirty-two'),
  crypto = require('crypto'),
  LocalStrategy = require('passport-local').Strategy,
  defaultConfig = {},
  storageMapping = {
    users: {
      properties: {
        key: {
          type: 'keyword'
        },
        token: {
          type: 'keyword'
        },
        token_generated_at: {
          type: 'date'
        }
      }
    }
  };

/**
 * @class AuthenticationPlugin
 */
class AuthenticationPlugin {
  /**
   * @constructor
   */
  constructor () {
    this.context = null;
    this.strategy = null;
    this.repository = null;
  }


  /**
   * @param {object} customConfig
   * @param {KuzzlePluginContext} context
   * @returns {Promise<*>}
   */
  init (customConfig, context) {
    this.config = Object.assign(defaultConfig, customConfig);

    this.context = context;

    return this.context.accessors.storage.bootstrap(storageMapping)
      .then(() => {
        this.initStrategies();
        this.repository = new this.context.constructors.Repository('users');
        return Promise.resolve();
      });
  }

  initStrategies () {
    this.strategies = {
      'totp': {
        config: {
          constructor: LocalStrategy,
          strategyOptions: {
            usernameField: 'token',
            passwordField: 'code'
          },
          authenticateOptions: {},
          fields: ['kuid', 'key']
        },
        methods: {
          create: 'create',
          delete: 'delete',
          exists: 'exists',
          getInfo: 'getInfo',
          update: 'update',
          validate: 'validate',
          verify: 'verify'
        }
      }
    };
  }

  /**
   * @param {KuzzleRequest} request
   * @param {object} credentials
   * @param {string} kuid
   * @param {string} strategy
   * @param {boolean} isUpdate
   * @returns {Promise<boolean>}
   */
  validate () {
    return Promise.resolve(true);
  }

  /**
   * @param {KuzzleRequest} request
   * @param {string} kuid
   * @returns {Promise<boolean>}
   */
  exists (request, kuid) {
    return this.repository.get(kuid)
      .then(credentials => credentials !== null && credentials.key !== undefined);
  }

  /**
   * @param {KuzzleRequest} request
   * @param {object} credentials
   * @param {string} kuid
   * @returns {Promise<object>}
   */
  create (request, credentials, kuid) {
    return this.repository.createOrReplace({
      _id: kuid,
      key: credentials.key || generateKey()
    }, {refresh: 'wait_for'})
      .then(result => {
        return Promise.resolve(result._source);
      });
  }

  /**
   * @param {KuzzleRequest} request
   * @param {object} credentials
   * @param {string} kuid
   * @returns {Promise<object>}
   */
  update (request, credentials, kuid) {
    return this.repository.get(kuid)
      .then(document => {
        if (document === null) {
          return Promise.reject(new this.context.errors.PreconditionError('A strategy does not exist for this user.'));
        }

        return this.repository.update({
          _id: document._id,
          key: credentials.key || generateKey()
        }, {refresh: 'wait_for'})
          .then(() => this.repository.get(document._id));
      });
  }

  /**
   * @param {KuzzleRequest} request
   * @param {string} kuid
   * @returns {Promise<object>}
   */
  delete (request, kuid) {
    return this.repository.get(kuid)
      .then(document => {
        if (document === null) {
          return Promise.reject(new this.context.errors.PreconditionError('A strategy does not exist for this user.'));
        }

        return this.repository.delete(document._id, {refresh: 'wait_for'});
      });
  }

  /**
   * @param {KuzzleRequest} request
   * @param {string} kuid
   * @returns {Promise<object>}
   */
  getInfo (request, kuid) {
    return this.repository.get(kuid)
      .then(document => {
        if (document === null) {
          return Promise.reject(new this.context.errors.PreconditionError('A strategy does not exist for this user.'));
        }

        return Promise.resolve({kuid: document._id});
      });
  }

  /**
   * @param {KuzzleRequest} request
   * @param {string} token
   * @param {string} code
   * @returns {Promise<string|{message: string}>}
   */
  verify (request, token, code) {
    // @TODO
  }
}

/*
 * @returns {string}
 */
function generateKey() {
  return base32.encode(crypto.randomBytes(16)).toString();
}

module.exports = AuthenticationPlugin;
