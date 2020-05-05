"use strict";

const validate = require("validate.js");
const { fetchUrl, generateHashCash, pdkf2 } = require("./utils");
const { PasswordTolerance } = require("./passwordTolerance");
const { authenticationConstraints , passwordToleranceConstraints, passwordHashingConstraints } = require("./serverInstructions");

class Signum {

    static async executeLogin(username, passtext, captcha, loginUrl, serverInstructions, referer, state, csrfToken = "",
        loginFunction = fetchUrl) {

        return await this.processAuthentication(username,
            passtext,
            captcha,
            loginUrl,
            serverInstructions,
            referer,
            state,
            csrfToken,
            loginFunction,
            false);
    }

     static async executeSignup(username, passtext, captcha, signupUrl, serverInstructions, referer, state, csrfToken = "",
        signupFunction = fetchUrl) {

         return await this.processAuthentication(username,
             passtext,
             captcha,
             signupUrl,
             serverInstructions,
             referer,
             state,
             csrfToken,
             signupFunction,
             true);
     }

    static async processAuthentication(username, passtext, captcha, authUrl, serverInstructions, referer, state, csrfToken = "",
        authFunction = fetchUrl, isSignupAuth = false) {

        if (!username) {
            throw new Error("Username is null or empty");
        }

        if (!passtext) {
            throw new Error("Passtext is null or empty");
        }

        if (!captcha) {
            throw new Error("captcha is null or empty");
        }

        if (!authUrl) {
            throw new Error("authUrl is null or empty");
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

        const invalidServerInstructions = validate(serverInstructions, authenticationConstraints, { format: "flat" });

        if (invalidServerInstructions) {
            throw new Error(
                `Bad serverInstructions: ${JSON.stringify(invalidServerInstructions)}`
            );
        }

        // TODO: check strength password if isSignupAuth = true
        const tolerancePassword = this.normalizePassphrase(passtext, serverInstructions.tolerance);
        const hashedPasstext = await this.hashPasstext(tolerancePassword, serverInstructions.hashing, username);

        const headers = {
            'Content-Type': 'application/json;charset=utf-8',
            'X-Username': username,
            'X-hashed-Passtext': hashedPasstext,
            'X-captcha': captcha
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

        return authFunction(authUrl, {
            method: 'POST',
            headers: headers,
            body: state,
            referrer: referer
        });
    }


    static normalizePassphrase(passphrase, serverInstructions) {
        if (!passphrase) {
            throw new Error("Passphrase is null or empty");
        }

        if (!serverInstructions) {
            throw new Error("tolerance serverInstructions is null or empty");
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
            throw new Error("hashing serverInstructions is null or empty");
        }

        const invalidServerInstructions = validate(serverInstructions, passwordHashingConstraints, { format: "flat" });

        if (invalidServerInstructions) {
            throw new Error(
                `Bad serverInstructions: ${JSON.stringify(invalidServerInstructions)}`
            );
        }

        if (serverInstructions.saltHashByUsername) {
            const invalidUsername = validate.single(username, { presence: { allowEmpty: false }, type: "string" });
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
