const {getPublicIp, generateHashCash} = require("../src/utils");
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
