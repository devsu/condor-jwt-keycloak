const nock = require('nock');
const Spy = require('jasmine-spy');
const TokenHelper = require('simple-bearer-token-test-helper');
const ContextHelper = require('condor-context-test-helper');
const JWT = require('condor-jwt').JWT;
const JWTKeycloak = require('./jwt-keycloak');

describe('JwtKeycloak', () => {
  let jwtKeycloak, tokenHelper, contextHelper, options, scope, baseUrl,
    url, realm, realmPath, certs, iss;

  beforeEach(() => {
    baseUrl = 'http://localhost:8080';
    url = `${baseUrl}/auth`;
    realm = 'demo';
    realmPath = `auth/realms/${realm}`;
    options = {url, realm};
    tokenHelper = new TokenHelper();
    iss = `${url}/realms/${realm}`;
    tokenHelper.setupValidToken({'payload': {iss}});
    certs = {'keys': [tokenHelper.jwk]};
    contextHelper = new ContextHelper();
    contextHelper.setupValidContext(tokenHelper.tokenString);
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
    describe('with realm', () => {
      beforeEach(() => {
        const certsPath = `/${realmPath}/protocol/openid-connect/certs`;
        scope = nock(baseUrl).get(certsPath).reply(200, certs);
        jwtKeycloak = new JWTKeycloak(options);
      });
      it('must get the public key from the right url', (done) => {
        jwtKeycloak.getToken(contextHelper.context, options).then(() => {
          scope.done();
          done();
        });
      });
      describe('no token', () => {
        beforeEach(() => {
          contextHelper.setupEmptyContext();
        });
        it('must return undefined', (done) => {
          jwtKeycloak.getToken(contextHelper.context, options).then((token) => {
            expect(token).toBeUndefined();
            done();
          }).catch(done.fail);
        });
      });
      describe('valid token', () => {
        it('must return the token', (done) => {
          jwtKeycloak.getToken(contextHelper.context, options).then((token) => {
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
        it('must return undefined', (done) => {
          jwtKeycloak.getToken(contextHelper.context, options).then((token) => {
            expect(token).toBeUndefined();
            done();
          }).catch(done.fail);
        });
      });
    });
    describe('with allowAnyRealm', () => {
      beforeEach(() => {
        const certsPath = `/${realmPath}/protocol/openid-connect/certs`;
        scope = nock(baseUrl).get(certsPath).reply(200, certs);
        options.allowAnyRealm = true;
        delete options.realm;
        jwtKeycloak = new JWTKeycloak(options);
      });
      it('must get the public key from the right url', (done) => {
        jwtKeycloak.getToken(contextHelper.context, options).then(() => {
          scope.done();
          done();
        });
      });
      describe('no token', () => {
        beforeEach(() => {
          contextHelper.setupEmptyContext();
        });
        it('must return null', () => {
          const token = jwtKeycloak.getToken(contextHelper.context, options);
          expect(token).toBeNull();
        });
      });
      describe('valid token', () => {
        it('must return the token', (done) => {
          jwtKeycloak.getToken(contextHelper.context, options).then((token) => {
            tokenHelper.verifyToken(token);
            done();
          }).catch(done.fail);
        });
      });
      describe('invalid token', () => {
        beforeEach(() => {
          contextHelper.setupValidContext('invalid token');
        });
        it('must return null', () => {
          const token = jwtKeycloak.getToken(contextHelper.context, options);
          expect(token).toBeNull();
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
        it('should return null', () => {
          const token = jwtKeycloak.getToken(contextHelper.context, options);
          expect(token).toBeNull();
        });
      });
    });
  });
});
