const {Signum} = require('../src/signum.js');

describe("submitLogin", function() {
    it("should fail without username", function() {
        expect(() =>
            Signum.executeLogin()
        ).toThrowError("Username is null or empty");
    });

    it("should fail with empty username", function() {
        expect(() =>
            Signum.executeLogin("")
        ).toThrowError("Username is null or empty");
    });

    it("should fail without passtext", function() {
        expect(() =>
            Signum.executeLogin("joe")
        ).toThrowError("Passtext is null or empty");
    });

    it("should fail with empty passtext", function() {
        expect(() =>
            Signum.executeLogin("joe", "")
        ).toThrowError("Passtext is null or empty");
    });

    it("should fail without loginUrl", function() {
        expect(() =>
            Signum.executeLogin("joe", "sdf57fs7")
        ).toThrowError("loginUrl is null or empty");
    });

    it("should fail with empty loginUrl", function() {
        expect(() =>
            Signum.executeLogin("joe", "sdf57fs7", "")
        ).toThrowError("loginUrl is null or empty");
    });

    it("should fail without serverInstructions", function() {
        expect(() =>
            Signum.executeLogin("joe", "sdf57fs7", "localhost")
        ).toThrowError("serverInstructions is null or empty");
    });

    it("should fail with missing hashcash policy", function() {
        const serverInstructions = {
            hashcash: {
                require: true
            }
        };

        expect(() =>
            Signum.executeLogin("joe", "sdf57fs7", "localhost", serverInstructions)
        ).toThrowError("Bad serverInstructions: [\"Hashcash zero count can't be blank\"," +
            "\"Hashcash server string can't be blank\"]");
    });

    it("should fail with missing hashcash policy", function() {
        const serverInstructions = {};

        expect(() =>
            Signum.executeLogin("joe", "sdf57fs7", "localhost", serverInstructions)
        ).toThrowError("Bad serverInstructions: [\"Hashcash can't be blank\",\"Hashcash require can't be blank\"]");
    });

    it("should fail with missing hashcash require", function() {
        const serverInstructions = {
            hashcash: {}
        };

        expect(() =>
            Signum.executeLogin("joe", "sdf57fs7", "localhost", serverInstructions)
        ).toThrowError("Bad serverInstructions: [\"Hashcash require can't be blank\"]");
    });

    it("should fail with missing hashcash zero count", function() {
        const serverInstructions = {
            hashcash: {
                require: true
            }
        };

        expect(() =>
            Signum.executeLogin("joe", "sdf57fs7", "localhost", serverInstructions)
        ).toThrowError("Bad serverInstructions: [\"Hashcash zero count can't be blank\",\"Hashcash server string can't be blank\"]");
    });

    const scenarios =  [
        {value: "Josh", error: "is not a number"},
        {value: 1.2, error: "must be an integer"},
        {value: -1, error: "must be greater than 0"},
        {value: 0, error: "must be greater than 0"},
        {value: 60, error: "must be less than or equal to 10"}
    ];

    for (const {value, error} of scenarios) {
        it(`should fail because zeroCount ${error}`, function () {

            const serverInstructions = {
                hashcash: {
                    require: true,
                    serverString: "hello world",
                    zeroCount: value
                }
            };

            expect(() =>
                Signum.executeLogin("joe", "sdf57fs7", "localhost", serverInstructions)
            ).toThrowError(`Bad serverInstructions: [\"Hashcash zero count ${error}\"]`);
        });
    }

    it("should fail if server string is required but not provided", function() {
        const serverInstructions = {
            hashcash: {
                require: true,
                zeroCount: 4
            }
        };

        expect(() =>
            Signum.executeLogin("joe", "sdf57fs7", "localhost", serverInstructions)
        ).toThrowError("Bad serverInstructions: [\"Hashcash server string can't be blank\"]");
    });

    it("should fail if zero count is required but not provided", function() {
        const serverInstructions = {
            hashcash: {
                require: true,
                serverString: "hello world",
            }
        };

        expect(() =>
            Signum.executeLogin("joe", "sdf57fs7", "localhost", serverInstructions)
        ).toThrowError("Bad serverInstructions: [\"Hashcash zero count can't be blank\"]");
    });

    it("should fail if hashcash is required but is empty", function() {
        const serverInstructions = {
            hashcash: {
                require: true,
                zeroCount: 4,
                serverString: "hello world"
            }
        };

        expect(() =>
            Signum.executeLogin("joe", "sdf57fs7", "localhost", serverInstructions,
                "hey jude")
        ).toThrowError("Bad hashcash for policy {\"require\":true,\"zeroCount\":4}: hey jude");
    });






    xit("should fail with missing hashcash policy", function() {
        const serverInstructions = {
            hashcash: {
                require: false
            }
        };

        expect(() =>
            Signum.executeLogin("joe", "sdf57fs7", "localhost", serverInstructions)
        ).toBe(true); //TODO
    });


  // it("should fail with bad loginUrl", function() {
  //   expect(() =>
  //       Signum.executeLogin("joe", "sdf57fs7", "login")
  //   ).toThrowError("Invalid URL: ::");
  // });

});