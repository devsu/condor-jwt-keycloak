const proxyquire = require('proxyquire');
const Spy = require('jasmine-spy');
const index = require('./index');
const JWTKeycloak = require('./lib/jwt-keycloak');

describe('module', () => {
  it('should expose jwtKeycloak() method', () => {
    expect(index).toEqual(jasmine.any(Function));
  });

  it('should expose the JWT class', () => {
    expect(index.JWTKeycloak).toEqual(JWTKeycloak);
  });

  describe('jwtkeycloak()', () => {
    let fakeIndex, JWTKeycloakStub, options, middleware, constructorCount;
    beforeEach(() => {
      constructorCount = 0;
      options = {'foo': 'bar'};
      JWTKeycloakStub = class {
        constructor(opt) {
          expect(opt).toEqual(options);
          constructorCount++;
        }
      };
      middleware = Spy.resolve();
      JWTKeycloakStub.prototype.getMiddleware = Spy.returnValue(middleware);
      fakeIndex = proxyquire('./index', {'./lib/jwt-keycloak': JWTKeycloakStub});
    });

    it('should create JWT instance with the options and return its middleware', () => {
      const actualMiddleware = fakeIndex(options);
      expect(constructorCount).toEqual(1);
      expect(actualMiddleware).toEqual(middleware);
    });
  });
});
