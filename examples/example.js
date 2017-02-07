const net = require('net');
const crypto = require('crypto');
const tacacs = require('../tacacs-plus');

// SAMPLE SERVER

var server = net.createServer(function (c) {
    console.log('Server: Connection opened.');

    c.on('error', function (err) {
        console.log('Server: Error: ' + err);
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
