var jwt = require('jsonwebtoken');
var rp = require('request-promise');
var Q = require('q');
var logger = require('winston');

var instance;

var getTokenFromBearer = function getTokenFromBearer(bearerToken) {
  return (typeof bearerToken === 'string' ? bearerToken.replace('Bearer ', '').replace(' ', '') : bearerToken);
};

var AuthTokenUtils = function authToken (opts) {
  var pubKeyUrl;

  if (instance) {
    return instance;
  }

  if (!(this instanceof AuthTokenUtils)) {
    return new AuthTokenUtils(opts);
  }

  if (typeof opts === 'string') {
    pubKeyUrl = opts;
  } else if (opts && opts.publicKeyUrl) {
    pubKeyUrl = opts.publicKeyUrl;
  } else {
    throw new TypeError('wt-lib-auth-token: must be initialised with publicKeyUrl');
  }

  this.pubKeyUrl = pubKeyUrl;
  this.refreshPublicKey();

  instance = this;
};

AuthTokenUtils.prototype.verify = function verify(token) {
  var payload;
  var deferred = Q.defer();

  token = getTokenFromBearer(token);

  var attemptVerification = function (nextStep) {
    try {
      payload = jwt.verify(token, this.publicKey);
      deferred.resolve(payload);
    } catch (e) {
      logger.info(nextStep);
    }
  }.bind(this);

  if (!token) {
    return undefined;
  }

  attemptVerification('Token verification failed. Re-fetching public key.');

  if (!payload) {
    this.refreshPublicKey()
    .finally(function() {
      attemptVerification('Could not verify token');
      if (!payload) {
        deferred.reject('token verification failed');
      }
    }.bind(this));
  }

  return deferred.promise;
};

AuthTokenUtils.prototype.refreshPublicKey = function refreshPublicKey() {
  logger.info('fetching public key');
  return rp(this.pubKeyUrl)
  .then(function (response) {
    this.lastConnectionSuccessful = true;
    this.publicKey = response;
  }.bind(this))
  .catch(function (err) {
    logger.info('Problem connecting to public key server: ', err);
    this.lastConnectionSuccessful = false;
  }.bind(this));
};

AuthTokenUtils.prototype.getBearerToken = function getBearerToken(req) {
  var token = req.header('Authorization');
  return getTokenFromBearer(token);
};

module.exports = AuthTokenUtils;
