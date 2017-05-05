const jws = require('jws');
const JWT = require('condor-jwt').JWT;
const request = require('request-promise');
const jwk2pem = require('pem-jwk').jwk2pem;

class JWTKeycloak extends JWT {
  constructor(options) {
    if (!options || !options.url || (!options.realm && !options.allowAnyRealm)) {
      throw new Error('options.URL and options.realm (or options.allowAnyRealm) are required');
    }
    super(options);
    this.publicKeys = {};
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
    const certsUrl = `${issuerUrl}/protocol/openid-connect/certs`;
    if (this.publicKeys[kid]) {
      return this.publicKeys[kid];
    }
    const requestOptions = {'json': true};
    return request(certsUrl, requestOptions).then((certs) => {
      if (!certs.keys || !certs.keys.length) {
        return null;
      }
      this.publicKeys = {};
      certs.keys.forEach((jwk) => {
        this.publicKeys[jwk.kid] = jwk2pem(jwk);
      });
      return this.publicKeys[kid];
    }).catch(() => {
      return null;
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
