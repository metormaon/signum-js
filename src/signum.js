const validate = require("validate.js");
const {loginFetch, generateHashCash} = require("./utils");

class Signum {
    /*

    POST
Ensure referrer
Send x-Requested-With: XmlHttpRequest
Ensure Synchronizer Token
Ensure elapsed time
Send hashcash if was requested
Send captcha if was requested



The response may be a proof of work request, or the actual login.



     */

    static constraints = {
        hashcash: {
            presence: false
        },
        "hashcash.require": {
            presence: function(value, attribute){
              return attribute && attribute.hashcash;
            },
            type: "boolean"
        },
        "hashcash.zeroCount": {
            presence: function(value, attribute){
              return attribute && attribute.hashcash && attribute.hashcash.require;
            },
            numericality: {
                onlyInteger: true,
                greaterThan: 0,
                lessThanOrEqualTo: 10
            }
        },
        "hashcash.serverString": {
            presence: function(value, attribute){
              return attribute && attribute.hashcash && attribute.hashcash.require;
            }
        },
        csrfToken: {
            presence: false
        },
        "csrfToken.require": {
            presence: function(value, attribute){
              return attribute && attribute.csrfToken;
            },
            type: "boolean"
        }
    };

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

        const invalidLoginUrl = validate.single(loginUrl, {url: {allowLocal: true}});

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

        const invalidServerInstructions = validate(serverInstructions, Signum.constraints, {format: "flat"});

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
            headers['X-Hashcash'] = generateHashCash(serverInstructions.hashcash.zeroCount,
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
            body: state,
            referrer: referer
        });
    }
}

exports.Signum = Signum;