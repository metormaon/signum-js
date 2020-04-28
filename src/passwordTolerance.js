class PasswordTolerance {
    constructor(passphrase, normalizers) {
        this.passphrase = passphrase;
        this.actualNormalizers = this.buildNormalizers(normalizers);
    }

    normalize() {
        for(let normalizer of this.actualNormalizers) {
            this.passphrase = normalizer.normalize(this.passphrase);
        }

        return this.passphrase;
    }

    buildNormalizers(normalizers) {
        let res = [];

        if(normalizers.lowerCase) {
            res.push(new LowerCaseNormalize());
        }

        if(normalizers.trim) {
            res.push(new TrimNormalize());
        }

        if(normalizers.whitespacesToDash) {
            res.push(new WhitespacesToDashNormalize());
        }

        if(normalizers.digitsToSingleZero) {
            res.push(new DigitsToSingleZeroNormalize());
        }

        if(normalizers.removePunctuation) {
            res.push(new RemovePunctuationNormalize());
        }

        return res;
    }
}

class LowerCaseNormalize {
    normalize(passphrase) {
        return passphrase.toLowerCase();
    }
}

class TrimNormalize {
    normalize(passphrase) {
        return passphrase.trim();
    }
}
class WhitespacesToDashNormalize {
    normalize(passphrase) {
        return passphrase.replace(/\s+/g, '-');
    }
}

class DigitsToSingleZeroNormalize {
    normalize(passphrase) {
        return passphrase.replace(/\d+/g, '0');
    }
}

class RemovePunctuationNormalize {
    normalize(passphrase) {
        return passphrase.replace(/[!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~]/g, '');
    }
}

exports.PasswordTolerance = PasswordTolerance;






