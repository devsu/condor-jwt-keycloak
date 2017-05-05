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
    let certsUrl = `${options.url}/realms/${options.realm}/protocol/openid-connect/certs`;
    if (options.allowAnyRealm) {
      const decoded = jsonwebtoken.decode(context.metadata.get('authorization')[0]);
      if (!decoded) {
        return null;
      }
      const issuerUrl = decoded.iss;
      const matcher = new RegExp(`${options.url}/realms/(.)+`);
      if (!issuerUrl.match(matcher)) {
        return null;
      }
      certsUrl = `${issuerUrl}/protocol/openid-connect/certs`;
    }
    const requestOptions = {'json': true};
    return request(certsUrl, requestOptions).then((certs) => {
      options.secretOrPublicKey = jwk2pem(certs.keys[0]);
      return super.getToken(context, options);
    });
  }
}

module.exports = JWTKeycloak;
