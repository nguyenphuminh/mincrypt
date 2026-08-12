## Mincrypt

Mincrypt is a small collection of simple scripts for key generation, encryption, and decryption. Sometimes you want to send encrypted messages but can not use encrypted messengers like Signal and have go through a non-private platform, then Mincrypt helps you encrypt and decrypt messages manually.

It currently utilizes X25519 key agreement, HKDF-SHA256 key derivation, AES-256-GCM authenticated encryption.

## Prerequisites

Just have Node installed and you are set.

## Key generation

You have to generate a pair of keys before proceeding, run:
```sh
node keygen
```

and a pair of private and public keys will be stored into `keys.json`. Share the public key with your friend, hide the private key from everyone.

To view your public key, you can run:
```sh
node keygen --show
```

To generate a new key pair, run:
```sh
node keygen --force
```

## Encryption

Run:
```sh
node encrypt
```

Enter your friend's public key and your messages and it will print out the encrypted versions.

### Add contact

Finding your friend's public key every time you want to send them an encrypted message is exhausting, so you can add them to the contact list and reference them by name later.

To add a person to the contact list, run:
```sh
node encrypt --add <name>
```

To load a person's public key by saved name, run:
```sh
node encrypt --contactlist <name>
```

## Decryption

Run:
```sh
node decrypt
```

Paste your friend's encrypted messages in and it will print out the decrypted versions.

## Copyright and License

Copyright © 2026 Nguyen Phu Minh.

This project is licensed under the MIT License.
