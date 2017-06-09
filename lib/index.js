const
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
    // @TODO
  }

  /**
   * @param {KuzzleRequest} request
   * @param {object} credentials
   * @param {string} kuid
   * @returns {Promise<object>}
   */
  create (request, credentials, kuid) {
    // @TODO
  }

  /**
   * @param {KuzzleRequest} request
   * @param {object} credentials
   * @param {string} kuid
   * @returns {Promise<object>}
   */
  update (request, credentials, kuid) {
    // @TODO
  }

  /**
   * @param {KuzzleRequest} request
   * @param {string} kuid
   * @returns {Promise<object>}
   */
  delete (request, kuid) {
    // @TODO
  }

  /**
   * @param {KuzzleRequest} request
   * @param {string} kuid
   * @returns {Promise<object>}
   */
  getInfo (request, kuid) {
    // @TODO
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

module.exports = AuthenticationPlugin;
