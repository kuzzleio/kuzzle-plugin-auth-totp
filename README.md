# Plugin Totp Authentication

This plugin is a proof-of-concept for 2Factor authentication to Kuzzle, with TOTP protocol.

# Configuration

The default configuration is:

```json
{
    "window": 6,
    "period": 30,
    "tokenExpirationTime": "300s"
}
```

# Usage


See [Kuzzle API Documentation](http://docs.kuzzle.io/api-documentation/controller-auth/login/) for more details about Kuzzle authentication mechanism.

# How to create a plugin

See [Kuzzle documentation](http://docs.kuzzle.io/plugins-reference/) about plugin for more information about how to create your own plugin.

# About Kuzzle

For UI and linked objects developers, [Kuzzle](https://github.com/kuzzleio/kuzzle) is an open-source solution that handles all the data management
(CRUD, real-time storage, search, high-level features, etc).

[Kuzzle](https://github.com/kuzzleio/kuzzle) features are accessible through a secured API. It can be used through a large choice of protocols such as REST, Websocket or Message Queuing protocols.
