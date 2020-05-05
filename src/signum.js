"use strict";

const validate = require("validate.js");
const { loginFetch, generateHashCash, pdkf2 } = require("./utils");
const { PasswordTolerance } = require("./passwordTolerance");
const { loginConstraints, passwordToleranceConstraints, passwordHashingConstraints } = require("./serverInstructions");

class Signum {
    static async executeLogin(username, hashedPasstext, loginUrl, serverInstructions, referer, state, csrfToken = "",
        loginFunction = loginFetch) {
        if (!username) {
            throw new Error("Username is null or empty");
        }

        if (!hashedPasstext) {
            throw new Error("Passtext is null or empty");
        }

        if (!loginUrl) {
            throw new Error("loginUrl is null or empty");
        }

        const invalidLoginUrl = validate.single(loginUrl, { url: { allowLocal: true } });

        if (invalidLoginUrl) {
            throw new Error(
                `Bad loginUrl: ${loginUrl} ${JSON.stringify(invalidLoginUrl)}`
            );
        }

        if (!serverInstructions) {
            throw new Error("serverInstructions is null or empty");
        }

        if (!referer) {
            throw new Error("referer is null or empty");
        }

        if (!state) {
            throw new Error("state is null or empty");
        }

        const invalidServerInstructions = validate(serverInstructions, loginConstraints, { format: "flat" });

        if (invalidServerInstructions) {
            throw new Error(
                `Bad serverInstructions: ${JSON.stringify(invalidServerInstructions)}`
            );
        }

        const headers = {
            'Content-Type': 'application/json;charset=utf-8',
            'X-Username': username,
            'X-hashed-Passtext': hashedPasstext
        };

        if (serverInstructions.hashcash && serverInstructions.hashcash.require) {
            headers['X-Hashcash'] = await generateHashCash(serverInstructions.hashcash.zeroCount,
                serverInstructions.hashcash.serverString);
        }

        if (serverInstructions.csrfToken && serverInstructions.csrfToken.require) {
            if (!csrfToken) {
                throw new Error("csrfToken is null or empty");
            }

            headers['X-Csrf-Token'] = csrfToken;
        }

        return await loginFunction(loginUrl, {
            method: 'POST',
            headers: headers,
            body: {"state": state},
            referrer: referer
        });
    }

    static normalizePassphrase(passphrase, serverInstructions) {
        if (!passphrase) {
            throw new Error("Passphrase is null or empty");
        }

        if (!serverInstructions) {
            throw new Error("serverInstructions is null or empty");
        }

        const invalidServerInstructions = validate(serverInstructions, passwordToleranceConstraints, { format: "flat" });

        if (invalidServerInstructions) {
            throw new Error(
                `Bad serverInstructions: ${JSON.stringify(invalidServerInstructions)}`
            );
        }

        if (serverInstructions.normalizers && passphrase.length >= serverInstructions.passphraseMinimalLength) {
            passphrase = new PasswordTolerance(passphrase, serverInstructions.normalizers).normalize();
        }

        return passphrase;
    }

    static async hashPasstext(passtext, serverInstructions, username = "") {
        let salt = "";

        if (!passtext) {
            throw new Error("Passtext is null or empty");
        }

        if (!serverInstructions) {
            throw new Error("serverInstructions is null or empty");
        }

        const invalidServerInstructions = validate(serverInstructions, passwordHashingConstraints, { format: "flat" });

        if (invalidServerInstructions) {
            throw new Error(
                `Bad serverInstructions: ${JSON.stringify(invalidServerInstructions)}`
            );
        }

        if(serverInstructions.saltHashByUsername) {
            const invalidUsername = validate.single(username, { presence : {allowEmpty: false}, type: "string"});
            if (invalidUsername) {
                throw new Error(
                    `Bad Username: Username ${JSON.stringify(invalidUsername)}`
                );
            }
            salt = username;
        }

        return await pdkf2(passtext, salt, serverInstructions.hashCycles, serverInstructions.resultLength / 2);
    }

}

exports.Signum = Signum;

global.Signum = Signum;
