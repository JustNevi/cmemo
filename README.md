# CMEMO

This is an implementation of the [OMEMO](https://xmpp.org/extensions/xep-0384.html) protocol based on [X3DH](https://signal.org/docs/specifications/x3dh/) written in C.

Get to know the main idea of the project: [Main idea](#main-idea)

## Terms

- _Unit_ - user, friend, one side of the conversation.

## Features

### Initialization

Flags: `--init` | `-i`.

```
cmemo -i
```

### Add unit

Flags: `--add` | `-a`.

```
cmemo -a < unit_pub.bl
```

### Note unit

Value here is fingerprint of added unit public bundle.

Flags: `--unit` | `-u`.

```
cmemo -u 6860b33af65db960db48932aef5d512
```

### Request for conversation

To start a conversation, you need to make a request.

You and your interlocutor must agree on a common starting key for the conversation and the ID of the one-time prekey. The key must be 12 characters long and the ID must be from 0 to 99.

For example, the key "NONCEUSERKEY" and the ID "67". They must be written using the ":" symbol:

```
NONCEUSERKEY:67
```

You must save the public ephemeral key when requesting.

Flags: `--request` | `-q`.

```
cmemo -q NONCEUSERKEY:67 -u 6860b33 > /tmp/eph.key
```

### Response for conversation

Flags: `--response` | `-p`.

```
cmemo -p NONCEUSERKEY:67 -u 48dabed < /tmp/eph.key
```

### Send message

Flags: `--send` | `-s`.

```
cmemo -s -u 48dabed < /tmp/msg > /tmp/enmsg
```

### Receive message

Flags: `--receive` | `-r`.

```
cmemo -r -u 6860b33 < /tmp/enmsg > /tmp/demsg
```

### Encoding

Used to indicate that you are receiving or sending encrypted data. Currently used "HEX".

Flags: `--encode` | `-e`.

```
cat "Hello, how are you?" | cmemo -s -u 48dabed -e
# Output: e831361abb5b73d...
```

```
cat "e831361abb5b73d..." cmemo -r -u 6860b33 -e
# Output: Hello, how are you?
```

## Usage

### Example

Create directories for Alice and Bob.

```
mkdir -p /tmp/cmemo/alice
mkdir -p /tmp/cmemo/bob
```

In two shells, we set the `HOME` for `Alias` ​​and `Bob`.

```
export HOME="/tmp/cmemo/alice"
```

```
export HOME="/tmp/cmemo/bob"
```

#### Initializing

Alice/Bob:

```
cmemo -i
```

#### Bundles exchange

Alice:

```
cmemo -a < /tmp/cmemo/bob/.cmemo/public.bl
```

Bob:

```
cmemo -a < /tmp/cmemo/alice/.cmemo/public.bl
```

#### Request/Response

```
Key: ExamleKey_00
ID: 69
```

Alice:

```
cmemo -q ExamleKey_00:69 -u 0bfb608d2 -e > /tmp/cmemo/ep.key
```

Bob:

```
cmemo -p ExamleKey_00:69 -u e2e5a35dcd2 -e < /tmp/cmemo/ep.key
```

#### Send/Receive

Alice:

```
echo "Hello, Bob" | cmemo -s -u 0bfb608d2 > /tmp/cmemo/enmsg
```

Bob:

```
cmemo -r -u e2e5a35dcd2 < /tmp/cmemo/enmsg
# Output: Hello, Bob
```

## Main idea

The main idea of ​​the project is to enable sending end-to-end encrypted messages regardless of the method of transmission. You can easily use it in unencrypted messengers, game chats, radio, and so on. That is, you can write various extensions that can integrate into the chat, track history for any method of communication.

## TODO

- [ ] Add base64 encoding.
- [ ] Clean code.
- [ ] Binding a nickname to unit.
- [ ] Export public bundle.
- [ ] Size-independent initial key.

## Contribution

This is my first project on C. I would be happy for any support and I absolutely accept consideration of any suggestions and improvements.
