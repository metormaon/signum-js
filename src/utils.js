const fetch = require("cross-fetch");
const crypto = require("crypto");
const dateFormat = require("dateformat");
const hexToBinary = require('hex-to-binary');

async function getPublicIp() {
    return new Promise((resolve, reject) => {
        fetch("https://api.ipify.org")
            .then((response) => {
                if (response.ok) {
                    resolve(response.text());
                } else {
                    reject('Failed to fetch ip address');
                }
            });
    });
}

async function fetchUrl(url, details) {
    return new Promise((resolve, reject) => {
        fetch(url, details)
            .then((response) => {
                if (response.ok) {
                    resolve(response.json());
                } else {
                    reject(`Failed to fetch ${url}`);
                }
            });
    });
}

async function pdkf2(password, salt, iterations, keylen) {
    return new Promise((resolve, reject) => {
        crypto.pbkdf2(
            password,
            salt,
            iterations,
            keylen,
            'sha512',
            (err, derivedKey) => (err ? reject(err) : resolve(derivedKey.toString('hex')))
        );
    });
}

function btoa(input) {
    return Buffer.from(input).toString('base64');
}

async function generateHashCash(zeroCount, serverString) {
    const ipAddress = await getPublicIp();

    const timestamp = dateFormat(new Date(), "yyyymmdd-HHMMss");

    let header = "";
    let found = false;
    let binaryHash;

    while (!found) {
        const randomString = btoa((Math.floor(Math.random() * Number.MAX_VALUE) + 1).toString());
        let counter = 0;

        while (counter < Number.MAX_VALUE - 1) {
            header = `${zeroCount}:${timestamp}:${ipAddress}:${serverString}:${randomString}:${btoa(counter.toString())}`;

            const hexHash = crypto.createHash('sha1').update(header).digest('hex').toString();

            binaryHash = hexToBinary(hexHash);

            if (binaryHash.startsWith("0".repeat(zeroCount))) {
                found = true;
                break;
            }

            counter++;
        }
    }

    console.log(`Generated header: ${header}`);
    console.log(`Corresponding hash: ${binaryHash}`);

    return header;
}

exports.generateHashCash = generateHashCash;
exports.getPublicIp = getPublicIp;
exports.fetchUrl = fetchUrl;
exports.pdkf2 = pdkf2;