const jsonwebtoken = require('jsonwebtoken');
const JWT = require('condor-jwt').JWT;
const request = require('request-promise');
const jwk2pem = require('pem-jwk').jwk2pem;

class JWTKeycloak extends JWT {
  constructor(options) {
    if (!options || !options.url || (!options.realm && !options.allowAnyRealm)) {
      throw new Error('options.URL and options.realm (or options.allowAnyRealm) are required');
    }
    super();
  }

  getToken(context, options) {
    const certsUrl = this._getCertsUrl(context, options);
    if (!certsUrl) {
      return null;
    }
    const requestOptions = {'json': true};
    return request(certsUrl, requestOptions).then((certs) => {
      options.secretOrPublicKey = jwk2pem(certs.keys[0]);
      return super.getToken(context, options);
    });
  }

  _getCertsUrl(context, options) {
    if (!options.allowAnyRealm) {
      return `${options.url}/realms/${options.realm}/protocol/openid-connect/certs`;
    }
    let tokenString = context.metadata.get('authorization')[0];
    if (!tokenString) {
      return null;
    }
    tokenString = tokenString.replace('Bearer ', '');
    const decoded = jsonwebtoken.decode(tokenString);
    if (!decoded) {
      return null;
    }
    const issuerUrl = decoded.iss;
    const matcher = new RegExp(`${options.url}/realms/(.)+`);
    if (!issuerUrl.match(matcher)) {
      return null;
    }
    return `${issuerUrl}/protocol/openid-connect/certs`;
  }
}

module.exports = JWTKeycloak;
