const { Signum } = require('../src/signum.js');

const passtextStrength = { VERY_WEAK: 1, WEAK: 2, ALMOST_STRONG: 3, STRONG: 4, VERY_STRONG: 5 };

describe("passtextStrength", function () {
    it("should fail without passtext", function () {
        expect(function () {
            Signum.passtextStrength()
        }).toThrowError("Passtext is null or empty");
    });

    it("should fail with empty passtext", function () {
        expect(function () {
            Signum.passtextStrength("")
        }).toThrowError("Passtext is null or empty");
    });

    it("should fail without serverInstructions", function () {
        expect(function () {
            Signum.passtextStrength("sdf57fs7")
        }).toThrowError("passtext strength serverInstructions is null or empty");
    });

    it("should fail missing minimum characters password", function () {
        const passtextStrengthServerInstructions = {
        };

        expect(function () {
            Signum.passtextStrength("sdf57fs7", passtextStrengthServerInstructions)
        }).toThrowError("Bad serverInstructions: [\"Minimum characters password can't be blank\"]");
    });

    const scenariosMinimumCharactersPassword = [
        { value: "Josh", error: "is not a number" },
        { value: 1.2, error: "must be an integer" },
        { value: 7, error: "must be greater than or equal to 8" },
    ];

    for (const { value, error } of scenariosMinimumCharactersPassword) {
        it(`should fail because minimum characters password ${error}`, function () {

            const passtextStrengthServerInstructions = {
                minimumCharactersPassword: value
            };

            expect(function () {
                Signum.passtextStrength("sdf57fs7", passtextStrengthServerInstructions)
            }).toThrowError(`Bad serverInstructions: [\"Minimum characters password ${error}\"]`);
        });
    }

    const scenariosPasstextStrength = [
        {
            password: "A!@23bN",
            expected: passtextStrength.VERY_WEAK
        },
        {
            password: "123456789",
            expected: passtextStrength.WEAK
        },
        {
            password: "aAbCeFJHkk",
            expected: passtextStrength.WEAK
        },
        {
            password: "a23cdefg",
            expected: passtextStrength.ALMOST_STRONG
        },
        {
            password: "a23cdefg!",
            expected: passtextStrength.ALMOST_STRONG
        },
        {
            password: "a23Cdefg",
            expected: passtextStrength.STRONG
        },
        {
            password: "awA@cd!efg",
            expected: passtextStrength.STRONG
        },
        {
            password: "A23C!dEfG",
            expected: passtextStrength.VERY_STRONG
        },
        {
            password: "passphrase passphrase passphrase passphrase passphrase passphrase passphrase passphrase",
            expected: passtextStrength.VERY_STRONG
        },
    ]

    for (const { password, expected } of scenariosPasstextStrength) {
        it(`should return ${expected}`, function () {
            const passtextStrengthServerInstructions = {
                minimumCharactersPassword: 8
            };

            const toleranceServerInstructions = {
                minimumAlphabetPassphrase: 25
            }

            expect(
                Signum.passtextStrength(password, passtextStrengthServerInstructions, toleranceServerInstructions)
            ).toEqual(expected);
        });
    }
});