const jws = require('jws');
const JWT = require('condor-jwt').JWT;
const request = require('request-promise');
const jwk2pem = require('pem-jwk').jwk2pem;

const errors = {
  'PARAMETERS_REQUIRED': 'options.URL and options.realm (or options.allowAnyRealm) are required',
  'TIME_BETWEEN_JWKS_REQUEST':
    'Not enough time elapsed since the last public keys request, blocking the request',
  'ERROR_REQUESTING_KEYS': 'Error requesting public keys',
};

class JWTKeycloak extends JWT {
  constructor(options) {
    if (!options || !options.url || (!options.realm && !options.allowAnyRealm)) {
      throw new Error(errors.PARAMETERS_REQUIRED);
    }
    const defaultOptions = {'minTimeBetweenJwksRequests': 10000};
    const opt = Object.assign({}, defaultOptions, options);
    super(opt);
    this.publicKeys = {};
    this.lastJWKRequestTime = 0;
  }

  getToken(context) {
    const decoded = this._getDecodedToken(context);
    if (!decoded || !decoded.payload || !decoded.payload.iss) {
      return null;
    }
    if (!this._issuerMatches(decoded.payload.iss)) {
      return null;
    }
    return Promise.resolve().then(() => {
      return this._getPublicKey(decoded.header.kid, decoded.payload.iss);
    }).then((publicKey) => {
      if (!publicKey) {
        return null;
      }
      this.options.secretOrPublicKey = publicKey;
      return super.getToken(context);
    });
  }

  _getPublicKey(kid, issuerUrl) {
    if (this.publicKeys[kid]) {
      return this.publicKeys[kid];
    }
    if (!this._hasElapsedEnoughTimeForJWKRequest()) {
      console.warn(errors.TIME_BETWEEN_JWKS_REQUEST);
      return null;
    }
    this.lastJWKRequestTime = new Date().getTime();
    return this._requestJWKs(issuerUrl).then((jwks) => {
      if (!jwks.keys || !jwks.keys.length) {
        return null;
      }
      this._updatePublicKeys(jwks.keys);
      return this.publicKeys[kid];
    }).catch((e) => {
      console.error(errors.ERROR_REQUESTING_KEYS, e);
      return null;
    });
  }

  _hasElapsedEnoughTimeForJWKRequest() {
    const currentTime = new Date().getTime();
    const minTime = this.lastJWKRequestTime + this.options.minTimeBetweenJwksRequests;
    return currentTime >= minTime;
  }

  _requestJWKs(issuerUrl) {
    const certsUrl = `${issuerUrl}/protocol/openid-connect/certs`;
    const requestOptions = {'json': true};
    return request(certsUrl, requestOptions);
  }

  _updatePublicKeys(keys) {
    this.publicKeys = {};
    keys.forEach((jwk) => {
      this.publicKeys[jwk.kid] = jwk2pem(jwk);
    });
  }

  _getDecodedToken(context) {
    let tokenString = context.metadata.get('authorization')[0];
    if (!tokenString) {
      return null;
    }
    tokenString = tokenString.replace('Bearer ', '');
    return jws.decode(tokenString);
  }

  _issuerMatches(issuerUrl) {
    if (this.options.realm) {
      return issuerUrl === `${this.options.url}/realms/${this.options.realm}`;
    }
    const matcher = new RegExp(`${this.options.url}/realms/(.)+`);
    return Boolean(issuerUrl.match(matcher));
  }
}

module.exports = JWTKeycloak;
