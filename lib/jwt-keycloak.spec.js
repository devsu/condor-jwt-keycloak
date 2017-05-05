const nock = require('nock');
const Spy = require('jasmine-spy');
const TokenHelper = require('simple-bearer-token-test-helper');
const ContextHelper = require('condor-context-test-helper');
const JWT = require('condor-jwt').JWT;
const JWTKeycloak = require('./jwt-keycloak');

describe('JwtKeycloak', () => {
  let jwtKeycloak, tokenHelper, contextHelper, options, scope, baseUrl,
    url, realm, realmPath, certs, iss, certsPath;

  beforeEach(() => {
    baseUrl = 'http://localhost:8080';
    url = `${baseUrl}/auth`;
    realm = 'demo';
    realmPath = `auth/realms/${realm}`;
    options = {url, realm, 'minTimeBetweenJwksRequests': 0};
    tokenHelper = new TokenHelper();
    iss = `${url}/realms/${realm}`;
    tokenHelper.setupValidToken({'payload': {iss}});
    certs = {'keys': [tokenHelper.jwk]};
    contextHelper = new ContextHelper();
    contextHelper.setupValidContext(tokenHelper.tokenString);
    certsPath = `/${realmPath}/protocol/openid-connect/certs`;
  });

  it('must extend JWT class', () => {
    jwtKeycloak = new JWTKeycloak(options);
    expect(jwtKeycloak instanceof JWT).toBeTruthy();
  });

  describe('constructor()', () => {
    describe('no options', () => {
      it('must fail with error', () => {
        expect(() => {
          jwtKeycloak = new JWTKeycloak();
        }).toThrowError('options.URL and options.realm (or options.allowAnyRealm) are required');
      });
    });

    describe('options.url is not set', () => {
      beforeEach(() => {
        delete options.url;
      });
      it('must fail with error', () => {
        expect(() => {
          jwtKeycloak = new JWTKeycloak(options);
        }).toThrowError('options.URL and options.realm (or options.allowAnyRealm) are required');
      });
    });

    describe('options.realm and options.allowAnyRealm are not set', () => {
      beforeEach(() => {
        delete options.realm;
      });
      it('must fail with error', () => {
        expect(() => {
          jwtKeycloak = new JWTKeycloak(options);
        }).toThrowError('options.URL and options.realm (or options.allowAnyRealm) are required');
      });
    });

    describe('options.realm is not set and options.allowAnyRealm is false', () => {
      beforeEach(() => {
        delete options.realm;
        options.allowAnyRealm = false;
      });
      it('must fail with error', () => {
        expect(() => {
          jwtKeycloak = new JWTKeycloak(options);
        }).toThrowError('options.URL and options.realm (or options.allowAnyRealm) are required');
      });
    });
  });

  describe('getToken()', () => {
    beforeEach(() => {
      nock.cleanAll();
      scope = nock(baseUrl).get(certsPath).reply(200, certs);
    });

    describe('with realm,', () => {
      beforeEach(() => {
        jwtKeycloak = new JWTKeycloak(options);
      });

      runGetTokenTests();

      describe('with correct auth server URL but incorrect realm', () => {
        beforeEach(() => {
          iss = `${url}/realms/another-realm`;
          tokenHelper.setupValidToken({'payload': {iss}});
          certs = {'keys': [tokenHelper.jwk]};
          contextHelper = new ContextHelper();
          contextHelper.setupValidContext(tokenHelper.tokenString);
          const certsPath = '/auth/realms/another-realm/protocol/openid-connect/certs';
          nock.cleanAll();
          scope = nock(baseUrl).get(certsPath).reply(200, certs);
        });
        it('should return null', (done) => {
          Promise.resolve().then(() => {
            return jwtKeycloak.getToken(contextHelper.context);
          }).then((token) => {
            expect(token).toEqual(null);
            done();
          }).catch(done.fail);
        });
      });
    });

    describe('with allowAnyRealm,', () => {
      beforeEach(() => {
        options.allowAnyRealm = true;
        delete options.realm;
        jwtKeycloak = new JWTKeycloak(options);
      });
      runGetTokenTests();
    });

    function runGetTokenTests() {
      it('must get the public keys from the right url', (done) => {
        contextHelper.setupValidContext(tokenHelper.bearerTokenString);
        Promise.resolve().then(() => {
          return jwtKeycloak.getToken(contextHelper.context);
        }).then(() => {
          scope.done();
          done();
        }).catch(done.fail);
      });

      describe('no token', () => {
        beforeEach(() => {
          contextHelper.setupEmptyContext();
        });
        it('must return null or undefined', (done) => {
          Promise.resolve().then(() => {
            return jwtKeycloak.getToken(contextHelper.context);
          }).then((token) => {
            expect(token).toBeFalsy();
            done();
          }).catch(done.fail);
        });
      });

      describe('valid token: with Bearer prefix', () => {
        beforeEach(() => {
          contextHelper.setupValidContext(tokenHelper.bearerTokenString);
        });
        it('must return the token', (done) => {
          Promise.resolve().then(() => {
            return jwtKeycloak.getToken(contextHelper.context);
          }).then((token) => {
            tokenHelper.verifyToken(token);
            done();
          }).catch(done.fail);
        });
      });

      describe('valid token: without Bearer prefix', () => {
        beforeEach(() => {
          contextHelper.setupValidContext(tokenHelper.tokenString);
        });
        it('must return the token', (done) => {
          Promise.resolve().then(() => {
            return jwtKeycloak.getToken(contextHelper.context);
          }).then((token) => {
            tokenHelper.verifyToken(token);
            done();
          }).catch(done.fail);
        });
      });

      describe('invalid token', () => {
        let originalConsoleError;
        beforeEach(() => {
          contextHelper.setupValidContext('invalid token');
          originalConsoleError = console.error;
          console.error = Spy.create();
        });
        afterEach(() => {
          console.error = originalConsoleError;
        });
        it('must return null or undefined', (done) => {
          Promise.resolve().then(() => {
            return jwtKeycloak.getToken(contextHelper.context);
          }).then((token) => {
            expect(token).toBeFalsy();
            done();
          }).catch(done.fail);
        });
      });

      describe('issuer is incorrect', () => {
        // By design we only allow iss that matches keycloak url realms
        // Otherwise a client could create a self-signed token and get access
        beforeEach(() => {
          iss = 'http://invalid-url/auth/realms/whatever';
          tokenHelper.setupValidToken({'payload': {iss}});
          certs = {'keys': [tokenHelper.jwk]};
          contextHelper.setupValidContext(tokenHelper.tokenString);
        });
        it('should return null', (done) => {
          Promise.resolve().then(() => {
            return jwtKeycloak.getToken(contextHelper.context);
          }).then((token) => {
            expect(token).toBeNull();
            done();
          }).catch(done.fail);
        });
      });

      describe('valid keys response', () => {
        it('should keysCache the keys', (done) => {
          // We call twice, but nocked just once, so scope.done should fail if not cached
          Promise.resolve().then(() => {
            return jwtKeycloak.getToken(contextHelper.context);
          }).then(() => {
            return jwtKeycloak.getToken(contextHelper.context);
          }).then(() => {
            scope.done();
            done();
          }).catch(done.fail);
        });
      });

      describe('invalid public keys response,', () => {
        describe('non 200', () => {
          let originalConsoleError;
          beforeEach(() => {
            nock.cleanAll();
            scope = nock(baseUrl).get(certsPath).twice().reply(400, certs);
            originalConsoleError = console.error;
            console.error = Spy.create();
          });

          afterEach(() => {
            console.error = originalConsoleError;
          });

          runInvalidKeysTests();

          it('must log the error', (done) => {
            Promise.resolve().then(() => {
              return jwtKeycloak.getToken(contextHelper.context);
            }).then(() => {
              expect(console.error).toHaveBeenCalledTimes(1);
              expect(console.error).toHaveBeenCalledWith('Error requesting public keys',
                jasmine.any(Error));
              done();
            }).catch(done.fail);
          });
        });

        describe('non json', () => {
          beforeEach(() => {
            nock.cleanAll();
            scope = nock(baseUrl).get(certsPath).twice().reply(200, 'invalid response');
            options.minTimeBetweenJwksRequests = 0;
            jwtKeycloak = new JWTKeycloak(options);
          });
          runInvalidKeysTests();
        });

        describe('json with no keys property', () => {
          beforeEach(() => {
            nock.cleanAll();
            scope = nock(baseUrl).get(certsPath).twice().reply(200, '{}');
          });
          runInvalidKeysTests();
        });

        describe('json with no keys', () => {
          beforeEach(() => {
            nock.cleanAll();
            scope = nock(baseUrl).get(certsPath).twice().reply(200, '{"keys":[]}');
          });
          runInvalidKeysTests();
        });

        function runInvalidKeysTests() {
          it('should return null', (done) => {
            Promise.resolve().then(() => {
              return jwtKeycloak.getToken(contextHelper.context);
            }).then((token) => {
              expect(token).toEqual(null);
              done();
            }).catch(done.fail);
          });
          it('should not cache the keys', (done) => {
            Promise.resolve().then(() => {
              return jwtKeycloak.getToken(contextHelper.context);
            }).then(() => {
              return jwtKeycloak.getToken(contextHelper.context);
            }).then(() => {
              scope.done();
              done();
            }).catch(done.fail);
          });
        }
      });

      describe('kid is not in the keysCache', () => {
        describe('elapsed time is greater than minTimeBetweenJwksRequests', () => {
          beforeEach(() => {
            nock.cleanAll();
            scope = nock(baseUrl).get(certsPath).twice().reply(200, certs);
            options.minTimeBetweenJwksRequests = 0;
            jwtKeycloak = new JWTKeycloak(options);
          });

          it('must request keys', (done) => {
            Promise.resolve().then(() => {
              return jwtKeycloak.getToken(contextHelper.context);
            }).then(() => {
              tokenHelper.setupValidToken({'header': {'kid': 'anotherKid'}, 'payload': {iss}});
              contextHelper.setupValidContext(tokenHelper.bearerTokenString);
              return jwtKeycloak.getToken(contextHelper.context);
            }).then(() => {
              scope.done();
              done();
            }).catch(done.fail);
          });
        });

        describe('elapsed time is lower than minTimeBetweenJwksRequests', () => {
          let originalConsoleWarn;

          beforeEach((done) => {
            originalConsoleWarn = console.warn;
            console.warn = Spy.create();
            options.minTimeBetweenJwksRequests = 1000;
            jwtKeycloak = new JWTKeycloak(options);
            nock.cleanAll();
            scope = nock(baseUrl).get(certsPath).reply(200, certs);
            scope.get(certsPath).reply(() => {
              // should not make a second request
              fail();
            });
            jwtKeycloak.getToken(contextHelper.context).then(done);
          });

          afterEach(() => {
            console.warn = originalConsoleWarn;
          });

          it('must request just once', (done) => {
            Promise.resolve().then(() => {
              tokenHelper.setupValidToken({'header': {'kid': 'anotherKid'}, 'payload': {iss}});
              contextHelper.setupValidContext(tokenHelper.bearerTokenString);
              return jwtKeycloak.getToken(contextHelper.context);
            }).then(() => {
              done();
            }).catch(done.fail);
          });

          it('must log a warning', (done) => {
            Promise.resolve().then(() => {
              tokenHelper.setupValidToken({'header': {'kid': 'anotherKid'}, 'payload': {iss}});
              contextHelper.setupValidContext(tokenHelper.bearerTokenString);
              return jwtKeycloak.getToken(contextHelper.context);
            }).then(() => {
              expect(console.warn).toHaveBeenCalledTimes(1);
              expect(console.warn).toHaveBeenCalledWith(
                'Not enough time elapsed since the last public keys request, blocking the request');
              done();
            }).catch(done.fail);
          });
        });
      });
    }
  });
});
