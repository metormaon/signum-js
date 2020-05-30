const {Signum} = require('../src/signum.js');

describe("submitLogin", function() {
    let originalTimeout;

    beforeEach(function() {
        originalTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
        jasmine.DEFAULT_TIMEOUT_INTERVAL = 60000;
    });

    afterEach(function() {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = originalTimeout;
    });

    it("should fail without username", async function () {
        await expectAsync(
            Signum.executeLogin()
        ).toBeRejectedWithError("Username is null or empty");
    });

    it("should fail with empty username", async function () {
        await expectAsync(
            Signum.executeLogin("")
        ).toBeRejectedWithError("Username is null or empty");
    });

    it("should fail without passtext", async function () {
        await expectAsync(
            Signum.executeLogin("joe")
        ).toBeRejectedWithError("Passtext is null or empty");
    });

    it("should fail with empty passtext", async function () {
        await expectAsync(
            Signum.executeLogin("joe", "")
        ).toBeRejectedWithError("Passtext is null or empty");
    });

    it("should fail without loginUrl", async function () {
        await expectAsync(
            Signum.executeLogin("joe", "sdf57fs7")
        ).toBeRejectedWithError("authUrl is null or empty");
    });

    it("should fail with empty loginUrl", async function () {
        await expectAsync(
            Signum.executeLogin("joe", "sdf57fs7", "")
        ).toBeRejectedWithError("authUrl is null or empty");
    });

    it("should fail without serverInstructions", async function () {
        await expectAsync(
            Signum.executeLogin("joe", "sdf57fs7", "http://localhost")
        ).toBeRejectedWithError("serverInstructions is null or empty");
    });

    it("should fail with missing hashcash policy", async function () {
        const serverInstructions = {
            hashcash: {
                require: true
            }
        };

        await expectAsync(
            Signum.executeLogin("joe", "sdf57fs7", "http://localhost",
                serverInstructions, "referer", "state")
        ).toBeRejectedWithError("Bad serverInstructions: [\"Hashcash zero count can't be blank\"," +
            "\"Hashcash server string can't be blank\"]");
    });

    const scenarios = [
        {value: "Josh", error: "is not a number"},
        {value: 1.2, error: "must be an integer"},
        {value: -1, error: "must be greater than 0"},
        {value: 0, error: "must be greater than 0"},
        {value: 60, error: "must be less than or equal to 50"}
    ];

    for (const {value, error} of scenarios) {
        it(`should fail because zeroCount ${error}`, async function () {

            const serverInstructions = {
                hashcash: {
                    require: true,
                    serverString: "hello world",
                    zeroCount: value
                }
            };

            await expectAsync(
                Signum.executeLogin("joe", "sdf57fs7", "http://localhost",
                    serverInstructions, "referer", "state")
            ).toBeRejectedWithError(`Bad serverInstructions: [\"Hashcash zero count ${error}\"]`);
        });
    }

    it("should fail if server string is required but not provided", async function () {
        const serverInstructions = {
            hashcash: {
                require: true,
                zeroCount: 4
            }
        };

        await expectAsync(
            Signum.executeLogin("joe", "sdf57fs7", "http://localhost",
                serverInstructions, "referer", "state")
        ).toBeRejectedWithError("Bad serverInstructions: [\"Hashcash server string can't be blank\"]");
    });

    it("should fail if zero count is required but not provided", async function () {
        const serverInstructions = {
            hashcash: {
                require: true,
                serverString: "hello world",
            }
        };

        await expectAsync(
            Signum.executeLogin("joe", "sdf57fs7", "http://localhost",
                serverInstructions, "referer", "state")
        ).toBeRejectedWithError("Bad serverInstructions: [\"Hashcash zero count can't be blank\"]");
    });

    it("should fail if captcha is mentioned but require is not specified", async function () {
        const serverInstructions = {
            captcha: {}
        };

        await expectAsync(
            Signum.executeLogin("joe", "sdf57fs7",  "http://localhost",
                serverInstructions, "referer", "state")
        ).toBeRejectedWithError("Bad serverInstructions: [\"Captcha require can't be blank\"]");
    });

    it("should fail if csrf token is mentioned but require is not specified", async function () {
        const serverInstructions = {
            csrfToken: {}
        };

        await expectAsync(
            Signum.executeLogin("joe", "sdf57fs7",  "http://localhost",
                serverInstructions, "referer", "state")
        ).toBeRejectedWithError("Bad serverInstructions: [\"Csrf token require can't be blank\"]");
    });

     it("should fail without tolerance serverInstructions", async function () {
        const serverInstructions = {
        };

        await expectAsync(
            Signum.executeLogin("joe", "sdf57fs7","http://localhost",
                serverInstructions, "referer", "state")
        ).toBeRejectedWithError("tolerance serverInstructions is null or empty");
    });

     it("should fail without hashing serverInstructions", async function () {
        const serverInstructions = {
             tolerance: {
                minimumAlphabetPassphrase: 20
            }
        };

        await expectAsync(
            Signum.executeLogin("joe", "sdf57fs7","http://localhost",
                serverInstructions, "referer", "state")
        ).toBeRejectedWithError("hashing serverInstructions is null or empty");
    });

    it("should fail if captcha is required but not provided", async function () {
        const serverInstructions = {
            captcha: {
                require: true
            },
            tolerance: {
                minimumAlphabetPassphrase: 20
            },
            hashing: {
                hashCycles: 3,
                resultLength: 20
            }
        };

        await expectAsync(
            Signum.executeLogin("joe", "sdf57fs7", "http://localhost",
                serverInstructions, "referer", "state")
        ).toBeRejectedWithError("captcha is null or empty");
    });

    it("should fail if csrf token is required but not provided", async function () {
        const serverInstructions = {
            csrfToken: {
                require: true
            },
            tolerance: {
                minimumAlphabetPassphrase: 20
            },
            hashing: {
                hashCycles: 3,
                resultLength: 20
            }
        };

        await expectAsync(
            Signum.executeLogin("joe", "sdf57fs7", "http://localhost",
                serverInstructions, "referer", "state")
        ).toBeRejectedWithError("csrfToken is null or empty");
    });

    async function loginMock(_, request) {
        return request;
    }

    const requestBase = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json;charset=utf-8',
            'X-Username': "joe",
            'X-hashed-Passtext': "3b640263b35f52c731f0"
        },
        body: "{\"state\":\"state\"}",
        referrer: "referer"
    };

    it("should login right without additional policies", async function() {
        const serverInstructions = {
            tolerance: {
                minimumAlphabetPassphrase: 20
            },
            hashing: {
                hashCycles: 3,
                resultLength: 20
            }
        };

        await expectAsync(
            Signum.executeLogin("joe", "sdf57fs7", "http://localhost",
                serverInstructions, "referer", "state", "", "", loginMock)
        ).toBeResolvedTo(requestBase);
    });

    it("should login right with hashcash", async function() {
        const serverInstructions = {
            hashcash: {
                require: true,
                zeroCount: 1,
                serverString: "hello world"
            },
            tolerance: {
                minimumAlphabetPassphrase: 20
            },
            hashing: {
                hashCycles: 3,
                resultLength: 20
            }
        };

        let request = await Signum.executeLogin("joe", "sdf57fs7",  "http://localhost",
                serverInstructions, "referer", "state", "", "", loginMock);

        expect(request.headers["X-Hashcash"]).toMatch(
            /^1:[0-9]{8}-[0-9]{6}:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:hello world:[^:]+:[^:]+$/);

        delete request.headers["X-Hashcash"];

        expect(request).toEqual(requestBase);
    });

    it("should login right with hashcash and csrf token", async function() {
        const serverInstructions = {
            hashcash: {
                require: true,
                zeroCount: 1,
                serverString: "hello world"
            },
            csrfToken: {
                require: true
            },
            tolerance: {
                minimumAlphabetPassphrase: 20
            },
            hashing: {
                hashCycles: 3,
                resultLength: 20
            }
        };

        let request = await Signum.executeLogin("joe", "sdf57fs7", "http://localhost",
                serverInstructions, "referer", "state", "", "df73dfFad54S", loginMock);

        expect(request.headers["X-Hashcash"]).toMatch(
            /^1:[0-9]{8}-[0-9]{6}:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:hello world:[^:]+:[^:]+$/);

        delete request.headers["X-Hashcash"];

        let requestBasePluCsrf = JSON.parse(JSON.stringify(requestBase));
        requestBasePluCsrf.headers["X-Csrf-Token"] = "df73dfFad54S";

        expect(request).toEqual(requestBasePluCsrf);
    });

    it("should login right with hashcash and csrf token and captcha", async function() {
        const serverInstructions = {
            hashcash: {
                require: true,
                zeroCount: 1,
                serverString: "hello world"
            },
            csrfToken: {
                require: true
            },
            captcha: {
                require: true
            },
            tolerance: {
                minimumAlphabetPassphrase: 20
            },
            hashing: {
                hashCycles: 3,
                resultLength: 20
            }
        };

        let request = await Signum.executeLogin("joe", "sdf57fs7", "http://localhost",
                serverInstructions, "referer", "state", "apple", "df73dfFad54S", loginMock);

        expect(request.headers["X-Hashcash"]).toMatch(
            /^1:[0-9]{8}-[0-9]{6}:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:hello world:[^:]+:[^:]+$/);

        delete request.headers["X-Hashcash"];

        let requestBasePluCsrfAndCaptcha = JSON.parse(JSON.stringify(requestBase));
        requestBasePluCsrfAndCaptcha.headers["X-Csrf-Token"] = "df73dfFad54S";
        requestBasePluCsrfAndCaptcha.headers["X-captcha"] = "apple";

        expect(request).toEqual(requestBasePluCsrfAndCaptcha);
    });
});