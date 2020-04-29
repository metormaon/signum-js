const { Signum } = require('../src/signum.js');

describe("hashPasstext", function () {
    it("should fail without passtext", async function () {
        await expectAsync(
            Signum.hashPasstext()
        ).toBeRejectedWithError("Passtext is null or empty");
    });

    it("should fail with empty passtext", async function () {
        await expectAsync(
            Signum.hashPasstext("")
        ).toBeRejectedWithError("Passtext is null or empty");
    });

    it("should fail without serverInstructions", async function () {
        await expectAsync(
            Signum.hashPasstext("sdf57fs7")
        ).toBeRejectedWithError("serverInstructions is null or empty");
    });

    it("should fail non string username", async function () {
        const serverInstructions = {
            hashCycles: 3,
            resultLength: 20
        };
        await expectAsync(
            Signum.hashPasstext("sdf57fs7", serverInstructions, true)
        ).toBeRejectedWithError("Bad Username: Username [\"must be of type string\"]");
    });

    const scenariosHashCycles = [
        { value: "Josh", error: "is not a number" },
        { value: 1.2, error: "must be an integer" },
        { value: -1, error: "must be greater than or equal to 1" },
    ];

    for (const { value, error } of scenariosHashCycles) {
        it(`should fail because hashCycles ${error}`, async function () {

            const serverInstructions = {
                hashCycles: value,
                resultLength: 20
            };

            await expectAsync(
                Signum.hashPasstext("sdf57fs7", serverInstructions, "")
            ).toBeRejectedWithError(`Bad serverInstructions: [\"Hash cycles ${error}\"]`);
        });
    }

    const scenariosResultLength = [
        { value: "Josh", error: "is not a number" },
        { value: 1.2, error: "must be an integer" },
        { value: 19, error: "must be greater than or equal to 20" },
    ];

    for (const { value, error } of scenariosResultLength) {
        it(`should fail because resultLength ${error}`, async function () {

            const serverInstructions = {
                hashCycles: 3,
                resultLength: value
            };

            await expectAsync(
                Signum.hashPasstext("sdf57fs7", serverInstructions, "")
            ).toBeRejectedWithError(`Bad serverInstructions: [\"Result length ${error}\"]`);
        });
    }

    it("should hashing right without username", async function () {
        const serverInstructions = {
            hashCycles: 3,
            resultLength: 20
        };

        let hashedPasstext = await Signum.hashPasstext("sdf57fs7", serverInstructions, "");

        expect(hashedPasstext).toEqual("3b640263b35f52c731f0ff71b527817b0080c0cf");
        expect(hashedPasstext.length).toEqual(40);
    });

    it("should hashing right with username", async function () {
        const serverInstructions = {
            hashCycles: 3,
            resultLength: 20
        };

        let hashedPasstext = await Signum.hashPasstext("sdf57fs7", serverInstructions, "joe");

        expect(hashedPasstext).toEqual("9e9181be6987c2d0556c5763312b41924dc8203f");
        expect(hashedPasstext.length).toEqual(40);
    });
});