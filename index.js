const JWTKeycloak = require('./lib/jwt-keycloak');

exports = module.exports = (options) => {
  return new JWTKeycloak(options).getMiddleware();
};

exports.JWTKeycloak = JWTKeycloak;
