/**
 * Created by ���� on 2015-07-16.
 */
var jsonWebToken = require("jsonwebtoken");
var crypto = require("crypto");

/**
 *
 * @type {{tokenSecret: String, jwtSecret: String, userProperty: string, jsonWebTokenOptions: {expiresInSeconds: number, algorithm: string}}}
 */
var jwtOptions = {
    /* ��ū ��ü�� ��ȣ�� Ű */
    tokenSecret: String,
    /* jwt ��ȣȭ Ű */
    jwtSecret: String,
    userProperty: "user",
    /* ��ȣȭ �˰��� */
    jsonWebTokenOptions: {
        /* ����ð� �⺻ 1�ð� */
        expiresInSeconds: 3600,
        algorithm: "HS256"
    }
};

var jwt = module.exports = function(options){
    if (!options || !options.jwtSecret){
        throw new Error("jwt secret should be set");
    }
    else if (!options.tokenSecret){
        throw new Error("token secret should be set");
    }

    jwtOptions.tokenSecret = options.tokenSecret;
    jwtOptions.jwtSecret = options.jwtSecret;
    jwtOptions.userProperty = !options.userProperty ? jwtOptions.userProperty : options.userProperty;
    jwtOptions.jsonWebTokenOptions.algorithm = !options.algorithm ? jwtOptions.jsonWebTokenOptions.algorithm : options.algorithm;
    jwtOptions.jsonWebTokenOptions.expiresInSeconds = !options.expireTime ? jwtOptions.jsonWebTokenOptions.expiresInSeconds : options.expireTime;
    return function (req, res, next){
        next();
    };
};


jwt.encode = function(data){
    var jwtToken = jsonWebToken.sign(data, jwtOptions.jwtSecret, jwtOptions.jsonWebTokenOptions);
    return jwtToken.split(".")[0]+"."+baseEncode(jwtToken.split(".")[1])+"."+jwtToken.split(".")[2];
};

jwt.verify = function(req, res, next){
    var token;
    if(req.headers && req.headers.authorization) {
        var parts = req.headers.authorization.split(" ");
        if (parts.length == 2) {
            var scheme = parts[0];
            var credentials = parts[1];

            if (/^Bearer$/i.test(scheme)) {
                token = credentials;
            } else {
                return err("Format is Authorization: Bearer [token]");
            }
        } else {
            return err("Format is Authorization: Bearer [token]");
        }
    }else {
        return err("No authorization token was found");
    }

    var decodeToken = token.split(".")[0] +"."+ baseDecode(token.split(".")[1]) +"."+ token.split(".")[2];

    jsonWebToken.verify(decodeToken, jwtOptions.jwtSecret, function(error, data){
        if(error){
            err(error.message);
        }

        req[jwtOptions.userProperty] = data;

        next();
    });
};

function err(message) {
    var error = new Error();
    error.status = 401;
    error.message = message;
    throw error;
}

function baseEncode(token){
    var cipher = crypto.createCipher('aes-256-cbc', jwtOptions.tokenSecret);

    /* �������� ��� */
    var encipheredContent = cipher.update(token,'utf8','hex');
    /* ���� �ƿ�ǲ�� hex ���·� ��� �Ѵ�*/
    encipheredContent += cipher.final('hex');
    return encipheredContent;
}

function baseDecode(token){
    var decipher = crypto.createDecipher('aes-256-cbc', jwtOptions.tokenSecret);
    var decipheredPlaintext = decipher.update(token,'hex','utf8');
    decipheredPlaintext += decipher.final('utf8');
    return decipheredPlaintext;
}

