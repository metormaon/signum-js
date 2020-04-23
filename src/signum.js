const validate = require("validate.js");
const {generateHashCash} = require("./utils");

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
            presence: true
        },
        "hashcash.require": {
            presence: true,
            type: "boolean"
        },
        "hashcash.zeroCount": {
            presence: function(value, attribute, validatorOptions, attributes, globalOptions){
              return attribute && attribute.hashcash && attribute.hashcash.require;
            },
            numericality: {
                onlyInteger: true,
                greaterThan: 0,
                lessThanOrEqualTo: 10
            }
        },
        "hashcash.serverString": {
            presence: function(value, attribute, validatorOptions, attributes, globalOptions){
              return attribute && attribute.hashcash && attribute.hashcash.require;
            }
        }
    };

    static executeLogin(username, hashedPasstext, loginUrl, serverInstructions, csrfToken = "", ) {
        if (!username) {
            throw new Error("Username is null or empty");
        }

        if (!hashedPasstext) {
            throw new Error("Passtext is null or empty");
        }

        if (!loginUrl) {
            throw new Error("loginUrl is null or empty");
        }

        if (!serverInstructions) {
            throw new Error("serverInstructions is null or empty");
        }

        const invalidServerInstructions = validate(serverInstructions, Signum.constraints, {format: "flat"});

        if (invalidServerInstructions) {
            throw new Error(
                `Bad serverInstructions: ${JSON.stringify(invalidServerInstructions)}`
            );
        }

        const headers = {
            'Content-Type': 'application/json;charset=utf-8',
        };

        if (serverInstructions.hashcash.require) {
            headers['x-hashcash'] = generateHashCash(serverInstructions.hashcash.zeroCount,
                serverInstructions.hashcash.serverString);
        }

        const userDetails = {
          username: username,
          hashedPasstext: hashedPasstext
        };

        if (serverInstructions['csrf_token']['require']) {
            headers['x-csrf-token'] = csrfToken;
        }

    //     const response = await fetch(loginUrl, {
    //         method: 'POST',
    //         headers: headers,
    //         body: userDetails
    //     });
    //
    //     const result = await response.json();
    }
}

exports.Signum = Signum;