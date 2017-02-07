# tacacs-plus

This is a simple TACACS+ library to help with basic encoding and decoding of TACACS+ authentication packets.

More information on TACACS+ can be found here, [https://tools.ietf.org/html/draft-ietf-opsawg-tacacs-05](https://tools.ietf.org/html/draft-ietf-opsawg-tacacs-05).

# Basic Usage

```js
var tacacs = require('tacacs-plus');

// receive or send raw TCP packet (port 49) to a TACACS+ server or client

var decoded = tacacs.decodePacket({ packet: raw_data, secret: 'your_key' });
```

The decoded object, depending on the sequence of packets, should be something along the lines of this.

```json
{
    "header": {
        "majorVersion": 12,
        "minorVersion": 0,
        "versionByte": 193,
        "type": 1,
        "sequenceNumber": 1,
        "flags": 1,
        "is_encrypted": false,
        "is_singleConnect": false,
        "sessionId": 1,
        "length": 34
    },
    "rawData": {
        "type": "Buffer",
        "data": [ ... ]
    },
    "data": {
        "action": 1,
        "privLvl": 0,
        "authenType": 0,
        "authenService": 0,
        "userLen": 9,
        "portLen": 4,
        "remAddrLen": 13,
        "dataLen": 0,
        "user": "your_user_name",
        "port": "tty10",
        "remAddr": "your_location"
    }
}
```

In certain instances, the data element may not be populated if there is an issue with the type of messages or the sequence number. You can manually decode a message body using the decode functions in the library.

----

# Creating a Simple Auth Start

If you are creating a client, to create a simple auth start to send to a server, simply do something along the lines of the following code snippit.

```js
var tacacs = require('tacacs-plus');

// create the auth start body
var authStart = tacacs.createAuthStart({
    action: tacacs.TAC_PLUS_AUTHEN_LOGIN,
    privLvl: tacacs.TAC_PLUS_PRIV_LVL_MAX,
    authenAype: tacacs.TAC_PLUS_AUTHEN_TYPE_ASCII,
    authenAervice: tacacs.TAC_PLUS_AUTHEN_SVC_LOGIN,
    user: 'your_user_name',
    port: 'tty10',
    remAddr: 'your_location',
    data: null
});

// create the tacacs+ header
var header = tacacs.createHeader({
    majorVersion: tacacs.TAC_PLUS_MAJOR_VER,
    minorVersion: tacacs.TAC_PLUS_MINOR_VER_DEFAULT,
    type: tacacs.TAC_PLUS_AUTHEN,
    sequenceNumber: 0x1,
    flags: tacacs.TAC_PLUS_UNENCRYPTED_FLAG,
    sessionId: 0x1,
    length: authStart.length
});

// combine the header and body
var authStartPacket = Buffer.concat([header, authStart]);

// open a connection and send the raw packet via TCP to the server (this example is not using encryption)
```

* All decode processes take Buffers that are then converted to objects. 
* All create processes take objects and return Buffers of data.

----

# Encryption

You can use the ```encodeByteData``` and ```decodeByteData``` functions to encrypt and decrypt data packets.

Using encryption requires a shared secret key as well as cryptographically secure random Session ID values.

```js
var crypto = require('crypto');
var tacacs = require('tacacs-plus');

// Generate a random 32-bit session
var sessionIdBytes = crypto.randomBytes(4);
var sessionId = Math.abs(sessionIdBytes.readInt32BE(0));

// create the auth start body
var authStart = tacacs.createAuthStart({
    action: tacacs.TAC_PLUS_AUTHEN_LOGIN,
    privLvl: tacacs.TAC_PLUS_PRIV_LVL_MAX,
    authenType: tacacs.TAC_PLUS_AUTHEN_TYPE_ASCII,
    authenService: tacacs.TAC_PLUS_AUTHEN_SVC_LOGIN,
    user: 'your_user_name',
    port: 'tty10',
    remAddr: 'your_location',
    data: null
});

var version = tacacs.createVersion(tacacs.TAC_PLUS_MAJOR_VER, tacacs.TAC_PLUS_MINOR_VER_DEFAULT);
var sequenceNumber = 1;
var encryptedAuthStart = tacacs.encodeByteData(sessionId, 'your_key', version, sequenceNumber, authStart);

// create the tacacs+ header
var headerOptions = {
    majorVersion: tacacs.TAC_PLUS_MAJOR_VER,
    minorVersion: tacacs.TAC_PLUS_MINOR_VER_DEFAULT,
    type: tacacs.TAC_PLUS_AUTHEN,
    sequenceNumber: sequenceNumber,
    flags: 0x0, // setting this to zero assumes encryption is being used
    sessionId: sessionId,
    length: authStart.length
}
var header = tacacs.createHeader(headerOptions);

var packetToSend = Buffer.concat([header, encryptedAuthStart]);

// open a connection and send the packet via TCP to the server
```

----

# Sample Communications

Here is a very simple client that sends a auth start packet to a server, then the server responds to the client... this is a very simple "getting started" sample, that requires a lot more development to implement a full workflow, but it illustrates how to start.


```js
var crypto = require('crypto');
var tacacs = require('tacacs-plus');

// SAMPLE SERVER

var server = net.createServer(function (c) {
    console.log('Server: Connection opened.');

    c.on('error', function (err) {
        console.log(err);
    });

    c.on('end', function () {
        console.log('Server: Connection closed.');
    });

    c.on('data', function (data) {
        var replyOptions = {};
        var replyHeader = {
            majorVersion: tacacs.TAC_PLUS_MAJOR_VER,
            minorVersion: tacacs.TAC_PLUS_MINOR_VER_DEFAULT,
            type: tacacs.TAC_PLUS_AUTHEN,
            sequenceNumber: 1,
            flags: 0x0,
            sessionId: 0x0,
            length: 0x0
        };

        console.log('Server: Received ', (data ? data.length : 0), ' bytes.');
        console.log('Server: ' + data.toString('hex'));

        var decodedPacket = tacacs.decodePacket({ packet: data, key: 'your_key' });

        console.log('Server: Decoded TACACS+ request.');
        console.log(JSON.stringify(decodedPacket));

        decodedPacket.header = decodedPacket.header || {};

        var replyHeader = decodedPacket.header;
        replyHeader.sequenceNumber++;
        replyHeader.sessionId = decodedPacket.header.sessionId;

        // build the auth reply (this is all the server should ever send for auth)
        // in this example we will send a get password command (TAC_PLUS_AUTHEN_STATUS_GETPASS)
        var replyOptions = {
            status: tacacs.TAC_PLUS_AUTHEN_STATUS_GETPASS,
            flags: 0x0,
            message: 'Please enter your password: ',
            data: null
        };
        var replyBytes = tacacs.createAuthReply(replyOptions);

        replyHeader.length = replyBytes.length;
        var headerBytes = tacacs.createHeader(replyHeader);
        var encryptedResponse = tacacs.encodeByteData(replyHeader.sessionId, 'your_key', tacacs.createVersion(replyHeader.majorVersion, replyHeader.minorVersion), replyHeader.sequenceNumber, replyBytes);

        replyBytes = Buffer.concat([headerBytes, encryptedResponse]);
        c.write(replyBytes);
    });
});

server.on('error', function (err) {
    console.log('Server: ' + err);
});

server.listen({ port: 49 }, function () {
    console.log('Server: listening...');
});


// SIMPLE CLIENT

var client = net.connect(49, '127.0.0.1', function () {
    console.log('Client connected!');

    // now that we've connected, send the first auth packet

    var sessionIdBytes = crypto.randomBytes(4);
    var sessionId = Math.abs(sessionIdBytes.readInt32BE(0));

    // create the auth start body
    var authStart = tacacs.createAuthStart({
        action: tacacs.TAC_PLUS_AUTHEN_LOGIN,
        privLvl: tacacs.TAC_PLUS_PRIV_LVL_MAX,
        authenType: tacacs.TAC_PLUS_AUTHEN_TYPE_ASCII,
        authenService: tacacs.TAC_PLUS_AUTHEN_SVC_LOGIN,
        user: 'your_user_name',
        port: 'tty10',
        remAddr: 'your_location',
        data: null
    });

    var version = tacacs.createVersion(tacacs.TAC_PLUS_MAJOR_VER, tacacs.TAC_PLUS_MINOR_VER_DEFAULT);
    var sequenceNumber = 1;
    var encryptedAuthStart = tacacs.encodeByteData(sessionId, 'your_key', version, sequenceNumber, authStart);

    // create the tacacs+ header
    var headerOptions = {
        majorVersion: tacacs.TAC_PLUS_MAJOR_VER,
        minorVersion: tacacs.TAC_PLUS_MINOR_VER_DEFAULT,
        type: tacacs.TAC_PLUS_AUTHEN,
        sequenceNumber: sequenceNumber,
        flags: 0x0, // setting this to zero assumes encryption is being used
        sessionId: sessionId,
        length: authStart.length
    }
    var header = tacacs.createHeader(headerOptions);

    var packetToSend = Buffer.concat([header, encryptedAuthStart]);

    // send the auth start packet to the server
    console.log('Client: Sending: ' + packetToSend.length + ' bytes.');
    console.log('Client: ' + packetToSend.toString('hex'));
    client.write(packetToSend);
});

client.on('error', function (err) { console.log(err); });
client.on('data', function (data) {
    if (data) {
        console.log('Client: Received Data: ' + data.toString('hex'));
        // decode response
        var resp = tacacs.decodePacket({ packet: data, key: 'your_key' });
        console.log('Client: Decoded Response: ' + JSON.stringify(resp, null, 2));
    }
    else {
        console.log('Client: No data!');
    }
});

```
