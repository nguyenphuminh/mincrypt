"use strict";

// Shared helpers for mincrypt.
//
// Crypto: static-static X25519 ECDH -> HKDF-SHA256 -> AES-256-GCM.
// The shared secret requires one of the two private keys, so a successful
// decrypt authenticates the sender as well as hiding the plaintext.
// No forward secrecy: keys are long-term, so compromising a private key
// exposes every past message encrypted to or from it.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const readline = require("readline");

const VERSION = 1;
const KEYS_FILE = path.join(__dirname, "keys.json");
const CONTACT_FILE = path.join(__dirname, "contact.json");
const WRAP = 64;

const MESSAGE_LABEL = "MINCRYPT MESSAGE";
const KEY_LABEL = "MINCRYPT PUBLIC KEY";
const MESSAGE_BEGIN = beginLine(MESSAGE_LABEL);
const MESSAGE_END = endLine(MESSAGE_LABEL);
const KEY_BEGIN = beginLine(KEY_LABEL);
const KEY_END = endLine(KEY_LABEL);

// Matches any armor delimiter, so stray ones can be stripped from pasted input.
const DELIMITER = /^-{5}(BEGIN|END) .*-{5}$/;

// DER prefixes for raw 32-byte X25519 keys, so we can store/paste short keys
// instead of PEM blocks.
const SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");
const PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");

// ----------------------------------------------------------------------- armor

function beginLine(label) {
    return `-----BEGIN ${label}-----`;
}

function endLine(label) {
    return `-----END ${label}-----`;
}

function armor(body, label) {
    return [beginLine(label), body, endLine(label)].join("\n");
}

function dearmor(text, label) {
    const lines = String(text).split(/\r?\n/);
    const start = lines.findIndex((line) => line.trim() === beginLine(label));
    const stop = lines.findIndex((line) => line.trim() === endLine(label));
    if (start === -1 || stop === -1 || stop < start) {
        throw new Error(`could not find the BEGIN/END lines for a ${label.toLowerCase()}`);
    }
    return lines.slice(start + 1, stop).join("").replace(/\s+/g, "");
}

// ---------------------------------------------------------------- key formats

function toPublicKey(raw) {
    if (raw.length !== 32) throw new Error("public key must be 32 bytes");
    return crypto.createPublicKey({
        key: Buffer.concat([SPKI_PREFIX, raw]),
        format: "der",
        type: "spki",
    });
}

function toPrivateKey(raw) {
    if (raw.length !== 32) throw new Error("private key must be 32 bytes");
    return crypto.createPrivateKey({
        key: Buffer.concat([PKCS8_PREFIX, raw]),
        format: "der",
        type: "pkcs8",
    });
}

function rawPublic(key) {
    return Buffer.from(key.export({ format: "der", type: "spki" }).subarray(-32));
}

function rawPrivate(key) {
    return Buffer.from(key.export({ format: "der", type: "pkcs8" }).subarray(-32));
}

function encodeKey(raw) {
    return raw.toString("base64url");
}

// The armored body is exactly the bare encoding, so either form pastes in.
function armorKey(raw) {
    return armor(encodeKey(raw), KEY_LABEL);
}

// Accepts an armored block, a bare base64url line, or either spread over
// several lines by a chat client that wrapped it.
function decodeKey(text) {
    const cleaned = String(text)
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line && !DELIMITER.test(line))
        .join("")
        .replace(/\s+/g, "");

    if (!cleaned) throw new Error("no key given");
    if (!/^[A-Za-z0-9\-_+/=]+$/.test(cleaned)) {
        throw new Error("key contains characters that are not base64");
    }
    const raw = Buffer.from(cleaned, "base64url");
    if (raw.length !== 32) {
        throw new Error(`expected a 32-byte key, got ${raw.length} bytes`);
    }
    return raw;
}

// ---------------------------------------------------------------- key storage

function generateKeys() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");
    return { publicKey: rawPublic(publicKey), privateKey: rawPrivate(privateKey) };
}

function saveKeys({ publicKey, privateKey }) {
    const body = JSON.stringify(
        {
            version: VERSION,
            algorithm: "x25519",
            publicKey: encodeKey(publicKey),
            privateKey: encodeKey(privateKey),
        },
        null,
        4,
    );
    fs.writeFileSync(KEYS_FILE, body + "\n", { mode: 0o600 });
}

function keysExist() {
    return fs.existsSync(KEYS_FILE);
}

function contactsExist() {
    return fs.existsSync(CONTACT_FILE);
}

function saveContact(contact, contactPub) {
    if (!contactsExist()) {
        let cbody = {
            version: VERSION,
            algorithm: "x25519",
            
        };
        cbody[contact] = contactPub
        const body = JSON.stringify(
            cbody,
            null,
            4,
        );
        fs.writeFileSync(CONTACT_FILE, body + "\n", { mode: 0o600 });
    } else {
        let cbody = JSON.parse(fs.readFileSync(CONTACT_FILE, "utf8"));
        cbody[contact] = contactPub
        const body = JSON.stringify(
            cbody,
            null,
            4,
        );
        fs.writeFileSync(CONTACT_FILE, body + "\n", { mode: 0o600 });
    }
}

function loadContact(contact) {
    if (!keysExist()) {
        throw new Error(`no ${path.basename(CONTACT_FILE)} found`);
    }
    let parsed;
    try {
        parsed = JSON.parse(fs.readFileSync(CONTACT_FILE, "utf8"));
    } catch (err) {
        throw new Error(`could not read ${path.basename(KEYS_FILE)}: ${err.message}`);
    }
    if (!parsed[contact]) {
        throw new Error(`${path.basename(CONTACT_FILE)} has no such contact`);
    }
    return parsed[contact]
}

function loadKeys() {
    if (!keysExist()) {
        throw new Error(`no ${path.basename(KEYS_FILE)} found - run "node keygen" first`);
    }
    let parsed;
    try {
        parsed = JSON.parse(fs.readFileSync(KEYS_FILE, "utf8"));
    } catch (err) {
        throw new Error(`could not read ${path.basename(KEYS_FILE)}: ${err.message}`);
    }
    if (!parsed.publicKey || !parsed.privateKey) {
        throw new Error(`${path.basename(KEYS_FILE)} is missing publicKey or privateKey`);
    }
    return {
        publicKey: decodeKey(parsed.publicKey),
        privateKey: decodeKey(parsed.privateKey),
    };
}

// ---------------------------------------------------------------------- crypto

// Binds the version and both identities into the key derivation and the GCM
// AAD, so a message cannot be replayed back at its own sender or reused
// against a different recipient.
function context(senderPublic, recipientPublic) {
    return Buffer.concat([Buffer.from([VERSION]), senderPublic, recipientPublic]);
}

function agree(privateKey, publicKey) {
    const secret = crypto.diffieHellman({
        privateKey: toPrivateKey(privateKey),
        publicKey: toPublicKey(publicKey),
    });
    // All-zero output means a low-order point was supplied.
    if (secret.every((byte) => byte === 0)) {
        throw new Error("degenerate shared secret - the public key is not usable");
    }
    return secret;
}

function derive(secret, salt, info) {
    const material = Buffer.from(
        crypto.hkdfSync("sha256", secret, salt, info, 44),
    );
    return { key: material.subarray(0, 32), iv: material.subarray(32, 44) };
}

function encryptMessage(keys, recipientPublic, plaintext) {
    const info = context(keys.publicKey, recipientPublic);
    const salt = crypto.randomBytes(16);
    const { key, iv } = derive(agree(keys.privateKey, recipientPublic), salt, info);

    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(info);
    const body = Buffer.concat([
        cipher.update(Buffer.from(plaintext, "utf8")),
        cipher.final(),
    ]);

    const payload = Buffer.concat([
        Buffer.from([VERSION]),
        keys.publicKey,
        salt,
        body,
        cipher.getAuthTag(),
    ]);
    const wrapped = payload.toString("base64").match(new RegExp(`.{1,${WRAP}}`, "g")) || [];
    return armor(wrapped.join("\n"), MESSAGE_LABEL);
}

function decryptMessage(keys, armored) {
    const body = dearmor(armored, MESSAGE_LABEL);
    if (!/^[A-Za-z0-9+/=]*$/.test(body)) {
        throw new Error("message body contains characters that are not base64");
    }
    const payload = Buffer.from(body, "base64");
    if (payload.length < 1 + 32 + 16 + 16) throw new Error("message is truncated");

    const version = payload[0];
    if (version !== VERSION) {
        throw new Error(`unsupported message version ${version}`);
    }

    const senderPublic = payload.subarray(1, 33);
    const salt = payload.subarray(33, 49);
    const cipherBody = payload.subarray(49, payload.length - 16);
    const tag = payload.subarray(payload.length - 16);

    const info = context(senderPublic, keys.publicKey);
    const { key, iv } = derive(agree(keys.privateKey, senderPublic), salt, info);

    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAAD(info);
    decipher.setAuthTag(tag);

    let plaintext;
    try {
        plaintext = Buffer.concat([decipher.update(cipherBody), decipher.final()]);
    } catch {
        throw new Error(
            "authentication failed - wrong recipient, wrong sender key, or the message was altered",
        );
    }
    return { plaintext: plaintext.toString("utf8"), senderPublic };
}

// -------------------------------------------------------------------------- io

// Prompts go to stderr so stdout carries only ciphertext or plaintext and
// stays clean for piping into a file or the clipboard.
function say(text = "") {
    process.stderr.write(text + "\n");
}

// Reads lines and returns null at end of input.
//
// terminal is on for a real tty so readline handles echo and line editing
// itself, writing to stderr and keeping stdout clean for the payload. When
// stdin is a pipe, terminal is off and this behaves like a plain line stream,
// which is what makes end of input work when piping. Ctrl-C closes the reader,
// so the loops in encrypt and decrypt fall out and the process exits.
function lineReader() {
    const interactive = Boolean(process.stdin.isTTY);
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stderr,
        terminal: interactive,
    });

    let closed = false;
    rl.on("close", () => {
        closed = true;
    });
    rl.on("SIGINT", () => {
        process.stderr.write("\n");
        rl.close();
    });

    const iterator = rl[Symbol.asyncIterator]();

    return {
        interactive,
        async next(promptText = "") {
            if (closed) return null;
            if (interactive) {
                rl.setPrompt(promptText);
                rl.prompt();
            } else if (promptText) {
                process.stderr.write(promptText);
            }
            const result = await iterator.next();
            return result.done ? null : result.value;
        },
        close() {
            if (!closed) rl.close();
        },
    };
}

// Reads a public key, accepting an armored block or a single bare line.
// Returns null at end of input.
async function readKey(lines, promptText) {
    for (;;) {
        const first = await lines.next(promptText);
        if (first === null) return null;

        const trimmed = first.trim();
        if (!trimmed) continue;

        let text = trimmed;
        if (trimmed === KEY_BEGIN) {
            const collected = [];
            for (;;) {
                const line = await lines.next();
                if (line === null) return null;
                if (line.trim() === KEY_END) break;
                collected.push(line.trim());
            }
            text = collected.join("");
        }

        try {
            return decodeKey(text);
        } catch (err) {
            say(`  ${err.message} - try again`);
        }
    }
}

function fail(err) {
    say(`\nerror: ${err.message}`);
    process.exit(1);
}

module.exports = {
    VERSION,
    KEYS_FILE,
    MESSAGE_BEGIN,
    MESSAGE_END,
    KEY_BEGIN,
    KEY_END,
    encodeKey,
    decodeKey,
    armorKey,
    generateKeys,
    saveKeys,
    keysExist,
    loadKeys,
    encryptMessage,
    decryptMessage,
    say,
    lineReader,
    readKey,
    fail,
    loadContact,
    saveContact
};
