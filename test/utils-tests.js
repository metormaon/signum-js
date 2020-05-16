const {getPublicIp, generateHashCash, stringToBinaryHash} = require("../src/utils");
const hexToBinary = require('hex-to-binary');
const crypto = require("crypto");

const ipRegex = new RegExp (['^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
    '\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'].join(''));

describe("getPublicIp", function () {
    let originalTimeout;

    beforeEach(function() {
        originalTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
        jasmine.DEFAULT_TIMEOUT_INTERVAL = 10000;
    });

    it("should get an ip", async function () {
        expect((await getPublicIp())).toMatch(ipRegex);
    });

    afterEach(function() {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = originalTimeout;
    });
});

describe("generateHashCash", function () {
    let originalTimeout;

    beforeEach(function() {
        originalTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
        jasmine.DEFAULT_TIMEOUT_INTERVAL = 30000;
    });

    for (let count=1; count<=21; count+=5) {
        it(`should generate the correct header for ${count} zeroCount`, async function () {
            await generateHashCash(count, "hello world")
                .then(header => {
                    const [zeros, timestamp, ipAddress, serverString] = header.split(":");

                    expect(zeros).toBe("" + count);

                    const [date, time] = timestamp.split("-");

                    expect(date.match(/^[0-9]+$/).length).toBe(1);
                    expect(time.match(/^[0-9]+$/).length).toBe(1);

                    expect(ipAddress).toMatch(ipRegex);

                    expect(serverString).toEqual("hello world");

                    const hexHash = crypto.createHash('sha1').update(header).digest('hex').toString();

                    const binaryHash = hexToBinary(hexHash);

                    expect(binaryHash.startsWith("0".repeat(count))).toBeTrue();
                });
        });
    }

    afterEach(function() {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = originalTimeout;
    });
});

describe("stringToBinaryHash", function () {
    it("should ", function () {
        expect(stringToBinaryHash(
            "15:20200516-184239:82.81.223.44:G5V-uz1mchswi07fqx0QumL8LO0:MS4zMzczODkzNzkyNzY0MDM0ZSszMDc=:MjIwMQ==")
        ).toEqual("00000000000000011110001100001010011001010111001011111010010111101010111001101011010" +
            "00010111000111010110001010111100011000001101010110100001010001001100111110111");
    });
});

