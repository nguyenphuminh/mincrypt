"use strict";

// node encrypt
//
// Asks for your friend's public key once, then encrypts message after message
// until you stop. Ciphertext goes to stdout, prompts to stderr.

const {
    loadKeys,
    encryptMessage,
    say,
    lineReader,
    readKey,
    fail,
    loadContact,
    saveContact,
    decodeKey,
    encodeKey
} = require("./shared");

async function readMessage(lines) {
    const collected = [];
    for (;;) {
        const line = await lines.next();
        if (line === null) return null;
        if (line.trim() === ".") return collected.join("\n");
        collected.push(line);
    }
}

async function main() {
    const keys = loadKeys();
    const lines = lineReader();
    const args = process.argv.slice(2);
    let recipient;
    if (args.includes("--contact")) {
        recipient = await decodeKey(await loadContact(args[1]))
        say("");
        say(`Loaded ${args[1]}'s contact`);
    } else {
        say("");
        say("Paste your friend's public key - the armored block or just the key line.");
        recipient = await readKey(lines, "> ");
        if (recipient === null) {
            lines.close();
            say("Failed");
            return;
        }
        if (args.includes("--add")) {
            await saveContact(args[1], encodeKey(recipient));
            say(`Added ${args[1]} as contact`)
        }
    }

    for (;;) {
        say("");
        say("Message - finish with a single . on its own line. Ctrl-C to exit.");
        const message = await readMessage(lines);
        if (message === null) break;
        if (!message.trim()) {
            say("  (empty, skipped)");
            continue;
        }

        say("");
        process.stdout.write(encryptMessage(keys, recipient, message) + "\n");
    }

    lines.close();
    say("");
}

main().catch(fail);
