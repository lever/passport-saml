var passport = require('passport-strategy');
var util = require('util');
var saml = require('./saml');

function deepCopy(value) {
  if (value && typeof value === 'object') {
    var obj;
    if (Array.isArray(value)) {
      obj = [];
      for (var i = 0; i < value.length; i++) {
        obj.push(deepCopy(value[i]));
      }
    } else {
      obj = {};
      for (var key in value) {
        if (value.hasOwnProperty(key)) {
          obj[key] = deepCopy(value[key]);
        }
      }
    }
    return obj;
  }
  return value;
}

function extend(target, obj) {
  if (obj && typeof obj === 'object') {
    if (Array.isArray(obj)) {
      for (var i = 0; i < obj.length; i++) {
        target[i] = deepCopy(obj[i]);
      }
    } else {
      for (var key in obj) {
        if (obj.hasOwnProperty(key)) {
          target[key] = deepCopy(obj[key]);
        }
      }
    }
  }
  return target;
}

function Strategy (options, verify) {
  if (typeof options === 'function') {
    verify = options;
    options = {};
  }

  if (!verify) {
    throw new Error('SAML authentication strategy requires a verify function');
  }

  this.name = 'saml';

  passport.Strategy.call(this);

  this._verify = verify;
  this._options = options || {};
  this._passReqToCallback = !!options.passReqToCallback;
  this._authnRequestBinding = options.authnRequestBinding || 'HTTP-Redirect';
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function (req, options) {
  var self = this;

  options.samlFallback = options.samlFallback || 'login-request';
  var samlOptions = extend({}, this._options);
  extend(samlOptions, options);
  var _saml = new saml.SAML(samlOptions);

  function validateCallback(err, profile, loggedOut) {
      if (err) {
        return self.error(err);
      }

      if (loggedOut) {
        req.logout();
        if (profile) {
          req.samlLogoutRequest = profile;
          return _saml.getLogoutResponseUrl(req, redirectIfSuccess);
        }
        return self.pass();
      }

      var verified = function (err, user, info) {
        if (err) {
          return self.error(err);
        }

        if (!user) {
          return self.fail(info);
        }

        self.success(user, info);
      };

      if (self._passReqToCallback) {
        self._verify(req, profile, verified);
      } else {
        self._verify(profile, verified);
      }
  }

  function redirectIfSuccess(err, url) {
    if (err) {
      self.error(err);
    } else {
      self.redirect(url);
    }
  }

  if (req.body && req.body.SAMLResponse) {
      _saml.validatePostResponse(req.body, validateCallback);
  } else if (req.body && req.body.SAMLRequest) {
      _saml.validatePostRequest(req.body, validateCallback);
  } else {
    var requestHandler = {
      'login-request': function() {
        if (samlOptions.authnRequestBinding === 'HTTP-POST') {
          _saml.getAuthorizeForm(req, function(err, data) {
            if (err) {
              self.error(err);
            } else {
              var res = req.res;
              res.send(data);
            }
          });
        } else { // Defaults to HTTP-Redirect
          _saml.getAuthorizeUrl(req, redirectIfSuccess);
        }
      }.bind(self),
      'logout-request': function() {
          _saml.getLogoutUrl(req, redirectIfSuccess);
      }.bind(self)
    }[options.samlFallback];

    if (typeof requestHandler !== 'function') {
      return self.fail();
    }

    requestHandler();
  }
};

Strategy.prototype.logout = function(req, callback) {
  this._saml.getLogoutUrl(req, callback);
};

Strategy.prototype.generateServiceProviderMetadata = function( decryptionCert ) {
  return this._saml.generateServiceProviderMetadata( decryptionCert );
};

module.exports = Strategy;
