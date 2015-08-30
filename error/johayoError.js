/**
 * Created by mayaj on 2015-08-31.
 */
function johayoError (code, error) {
    Error.call(this, error.message);
    Error.captureStackTrace(this, this.constructor);
    this.name = "UnauthorizedError";
    this.message = error.message;
    this.code = code;
    this.status = 401;
    this.inner = error;
}

johayoError.prototype = Object.create(Error.prototype);
johayoError.prototype.constructor = johayoError;

module.exports = johayoError;