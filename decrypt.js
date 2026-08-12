"use strict";

// node decrypt
//
// Paste an armored block; anything before the BEGIN line is ignored, so you can
// paste a whole chat message around it. Plaintext goes to stdout.

const {
    MESSAGE_BEGIN,
    MESSAGE_END,
    armorKey,
    loadKeys,
    decryptMessage,
    say,
    lineReader,
    fail,
} = require("./shared");

async function readBlock(lines) {
    const collected = [];
    let started = false;
    for (;;) {
        const line = await lines.next();
        if (line === null) return null;
        const trimmed = line.trim();
        if (!started) {
            if (trimmed === MESSAGE_BEGIN) {
                started = true;
                collected.push(trimmed);
            }
            continue;
        }
        collected.push(trimmed);
        if (trimmed === MESSAGE_END) return collected.join("\n");
    }
}

async function main() {
    const keys = loadKeys();
    const lines = lineReader();

    for (;;) {
        say("");
        say("Paste a message, BEGIN line through END line. Ctrl-C to exit.");
        const block = await readBlock(lines);
        if (block === null) break;

        try {
            const { plaintext, senderPublic } = decryptMessage(keys, block);
            say("");
            say("Sent by");
            say(armorKey(senderPublic));
            say("");
            process.stdout.write(plaintext + "\n");
        } catch (err) {
            say("");
            say("error: " + err.message);
        }
    }

    lines.close();
    say("");
}

main().catch(fail);
