/**
 * Created by mayaj on 2015-08-31.
 */
function johayoError (code, error) {
    Error.call(this, error.message);
    this.name = "UnauthorizedError";
    this.message = error.message;
    this.code = code;
    this.status = 401;
}

johayoError.prototype = Object.create(Error.prototype);
johayoError.prototype.constructor = johayoError;

module.exports = johayoError;