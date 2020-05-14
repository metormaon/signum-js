const authenticationConstraints = {
    hashcash: {
        presence: false
    },
    "hashcash.require": {
        presence: function (value, attribute) {
            return attribute && attribute.hashcash;
        },
        type: "boolean"
    },
    "hashcash.zeroCount": {
        presence: function (value, attribute) {
            return attribute && attribute.hashcash && attribute.hashcash.require;
        },
        numericality: {
            onlyInteger: true,
            greaterThan: 0,
            lessThanOrEqualTo: 50
        }
    },
    "hashcash.serverString": {
        presence: function (value, attribute) {
            return attribute && attribute.hashcash && attribute.hashcash.require;
        }
    },
    csrfToken: {
        presence: false
    },
    "csrfToken.require": {
        presence: function (value, attribute) {
            return attribute && attribute.csrfToken;
        },
        type: "boolean"
    },
    captcha: {
        presence: false
    },
    "captcha.require": {
        presence: function (value, attribute) {
            return attribute && attribute.captcha;
        },
        type: "boolean"
    }
};


const passwordToleranceConstraints = {
    normalizers: {
        presence: false
    },
    "normalizers.lowerCase": {
        presence: false,
        type: "boolean"
    },
    "normalizers.trim": {
        presence: false,
        type: "boolean"
    },
    "normalizers.whitespacesToDash": {
        presence: false,
        type: "boolean"
    },
    "normalizers.digitsToSingleZero": {
        presence: false,
        type: "boolean"
    },
    "normalizers.removePunctuation": {
        presence: false,
        type: "boolean"
    },
    passphraseMinimalLength: {
        presence: true,
        numericality: {
            onlyInteger: true,
            greaterThanOrEqualTo: 20
        }
    }
};

const passwordHashingConstraints = {
    hashCycles: {
        presence: true,
        numericality: {
            onlyInteger: true,
            greaterThanOrEqualTo: 1
        }
    },
    resultLength: {
        presence: true,
        numericality: {
            onlyInteger: true,
            greaterThanOrEqualTo: 20,
            even: true
        }
    },
    saltHashByUsername: {
        presence: false,
        type: "boolean"
    }
};


exports.authenticationConstraints = authenticationConstraints;
exports.passwordToleranceConstraints = passwordToleranceConstraints;
exports.passwordHashingConstraints = passwordHashingConstraints;