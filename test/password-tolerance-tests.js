const { Signum } = require('../src/signum.js');

describe("normalizePassphrase", function () {
    it("should fail without passphrase", function () {
        expect(function () {
            Signum.normalizePassphrase()
        }).toThrowError("Passphrase is null or empty");
    });

    it("should fail with empty passphrase", function () {
        expect(function () {
            Signum.normalizePassphrase("")
        }).toThrowError("Passphrase is null or empty");
    });

    it("should fail without serverInstructions", function () {
        expect(function () {
            Signum.normalizePassphrase("sdf57fs7")
        }).toThrowError("tolerance serverInstructions is null or empty");
    });

    it("should fail minimum alphabet passphrase", function () {
        const serverInstructions = {
        };

        expect(function () {
            Signum.normalizePassphrase("sdf57fs7", serverInstructions)
        }).toThrowError("Bad serverInstructions: [\"Minimum alphabet passphrase can't be blank\"]");
    });

    const scenariosMinimumAlphabetPassphrase = [
        { value: "Josh", error: "is not a number" },
        { value: 1.2, error: "must be an integer" },
        { value: 15, error: "must be greater than or equal to 20" },
    ];

    for (const { value, error } of scenariosMinimumAlphabetPassphrase) {
        it(`should fail because minimumAlphabetPassphrase ${error}`, function () {

            const serverInstructions = {
                minimumAlphabetPassphrase: value
            };

            expect(function () {
                Signum.normalizePassphrase("sdf57fs7", serverInstructions)
            }).toThrowError(`Bad serverInstructions: [\"Minimum alphabet passphrase ${error}\"]`);
        });
    }

    it("should fail non boolean normalizer", function () {
        const serverInstructions = {
            normalizers: {
                trim: 1
            },
            minimumAlphabetPassphrase: 20
        };

        expect(function () {
            Signum.normalizePassphrase("sdf57fs7", serverInstructions)
        }).toThrowError("Bad serverInstructions: [\"Normalizers trim must be of type boolean\"]");
    });

    it("should not change the passphrase", function () {
        const serverInstructions = {
            minimumAlphabetPassphrase: 20
        };

        expect(
            Signum.normalizePassphrase("sdf57fs7", serverInstructions)
        ).toEqual('sdf57fs7');
    });

    it("should not change the passphrase", function () {
        const serverInstructions = {
            minimumAlphabetPassphrase: 21,
            normalizers: {   
            }
        };

        expect(
            Signum.normalizePassphrase("    rgtg t124 Krh!@ytjhklmd*lkdii'ne  BC   ", serverInstructions)
        ).toEqual("    rgtg t124 Krh!@ytjhklmd*lkdii'ne  BC   ");
    });

    const scenariosNoramalizers = [
        {
            value: {
                trim: true,
                lowerCase: false,
                whitespacesToDash: true,
                digitsToSingleZero: true,
                removePunctuation: false
            },
            expected: "rgtg-t0-Krh!@ytjhklmd*lkdii'ne-BC"
        },
        {
            value: {
                trim: false,
                lowerCase: true,
                whitespacesToDash: false,
                digitsToSingleZero: false,
                removePunctuation: true
            },
            expected: "    rgtg t124 krhytjhklmdlkdiine  bc   "
        },
        {
            value: {
            },
            expected: "    rgtg t124 Krh!@ytjhklmd*lkdii'ne  BC   "
        }
    ]

    for (const { value, expected } of scenariosNoramalizers) {
        it(`should return ${expected}`, function () {
            const serverInstructions = {
                minimumAlphabetPassphrase: 20,
                normalizers: value
            };

            expect(
                Signum.normalizePassphrase("    rgtg t124 Krh!@ytjhklmd*lkdii'ne  BC   ", serverInstructions)
            ).toEqual(expected);
        });
    }
});