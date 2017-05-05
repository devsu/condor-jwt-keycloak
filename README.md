# condor-jwt-keycloak

This module lets you authenticate GRPC calls using JSON Web Tokens (**JWTs**) created by [Keycloak](http://www.keycloak.org/) in your [Condor](https://github.com/devsu/condor-framework) GRPC services.

[![Build Status](https://travis-ci.org/devsu/condor-jwt-keycloak.svg?branch=master)](https://travis-ci.org/devsu/condor-jwt-keycloak)
[![Coverage Status](https://coveralls.io/repos/github/devsu/condor-jwt-keycloak/badge.svg?branch=master)](https://coveralls.io/github/devsu/condor-jwt-keycloak?branch=master)

**Condor** is a [GRPC Framework for node](https://github.com/devsu/condor-framework).

## Features

This module extends [condor-jwt](https://github.com/devsu/condor-jwt) and offers additional features for integration with keycloak:

- Handles public key rotation retrieval
- Multi-tenancy support, by allowing multiple realms
- Allows live token validation (using introspection)

Currently we only support **OpenID Connect** (not SAML).

## Installation

```bash
npm i --save condor-framework condor-jwt-keycloak
```

## How to use

The JWT middleware decodes and verifies a JsonWebToken passed in the `authorization` header. If the token is valid, `context.token` (by default) will be set with the JSON object decoded to be used by later middleware for authorization and access control.

```js
const Condor = require('condor-framework');
const jwt = require('condor-jwt-keycloak');
const Greeter = require('./greeter');

const options = {
  'url': 'http://localhost:8080/auth',
  'realm': 'master',
};

const app = new Condor()
  .addService('./protos/greeter.proto', 'myapp.Greeter', new Greeter())
  .use(jwt(options))
  // middleware below this line is only reached if JWT token is valid
  .use((context, next) => {
    console.log('valid token found: ', context.token);
    next();
  })
  .start();
```

## Options

Allows all the options as the [condor-jwt](https://github.com/devsu/condor-jwt) module. And also:

| Option            | Description                                                                  | Default |
|-------------------|------------------------------------------------------------------------------|---------|
| url               | The authorization server URL. E.g. `http://localhost:8080/auth`. Required.   |         |
| realm             | The realm name. E.g. `master`. Required unless `allowAnyRealm` is `true`.    |         |
| allowAnyRealm     | Allow to authenticate against any realm in the authorization server.         | false   |
| introspect        | Perform live validation using token instrospection.                          | false   |

If `secretOrPublicKey` is provided, it will be used instead of retrieving the public key from keycloak. (Not recommended).

Additionaly, you can send any option of the [verify](https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback) method of the [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken). Such options will be used to verify the token.

## License and Credits

MIT License. Copyright 2017 

Built by the [GRPC experts](https://devsu.com) at Devsu.
