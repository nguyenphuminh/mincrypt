"use strict";

// node keygen           - create keys.json (refuses to clobber an existing one)
// node keygen --force   - overwrite, destroying the old private key
// node keygen --show    - print the existing public key

const path = require("path");
const {
    KEYS_FILE,
    armorKey,
    generateKeys,
    saveKeys,
    keysExist,
    loadKeys,
    say,
    fail,
} = require("./shared");

const name = path.basename(KEYS_FILE);

function report(publicKey) {
    say("");
    say("Your public key - give this to your friend:");
    say("");
    say(armorKey(publicKey));
    say("");
    say("Confirm it over a second channel so nobody can swap it in transit.");
    say("");
}

try {
    const args = process.argv.slice(2);

    if (args.includes("--show")) {
        report(loadKeys().publicKey);
        process.exit(0);
    }

    if (keysExist() && !args.includes("--force")) {
        say(`${name} already exists. Overwriting it destroys your private key and`);
        say("every message already encrypted to you. Pass --force to do it anyway,");
        say("or --show to print the public key you already have.");
        process.exit(1);
    }

    const keys = generateKeys();
    saveKeys(keys);

    say(`Wrote ${name} (mode 600). The private key in it is not encrypted.`);
    report(keys.publicKey);
} catch (err) {
    fail(err);
}
