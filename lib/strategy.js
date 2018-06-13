/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
    , util = require('util');

function Strategy(verify) {
    if (!verify) throw new Error('Token authentication strategy requires a verify function');

    passport.Strategy.call(this);
    this.name = 'token';
    this._verify = verify;
    this._passReqToCallback = null;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
    options = options || {};
    var token = req.query.token;

    if (!token) {
        return this.fail({ message: options.badRequestMessage || 'Missing token' }, 400);
    }

    var self = this;

    function verified(err, user, info) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(info); }
        self.success(user, info);
    }

    try {
        if (self._passReqToCallback) {
            this._verify(req, token, verified);
        } else {
            this._verify(token, verified);
        }
    } catch (ex) {
        return self.error(ex);
    }
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
