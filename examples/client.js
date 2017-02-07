const net = require('net');
const crypto = require('crypto');
const tacacs = require('../tacacs-plus');

// SIMPLE CLIENT

var client = net.connect({ port: 49, host: '10.0.0.105' }, function () {
    console.log('Client connected!');

    // now that we've connected, send the first auth packet

    var sessionIdBytes = crypto.randomBytes(4);
    var sessionId = Math.abs(sessionIdBytes.readInt32BE(0));

    console.log('Client: Session Id: ' + sessionId);

    // create the auth start body
    var authStart = tacacs.createAuthStart({
        action: tacacs.TAC_PLUS_AUTHEN_LOGIN,
        privLvl: tacacs.TAC_PLUS_PRIV_LVL_USER,
        authenType: tacacs.TAC_PLUS_AUTHEN_TYPE_ASCII,
        authenService: tacacs.TAC_PLUS_AUTHEN_SVC_LOGIN,
        user: 'user1',
        port: '',
        remAddr: '',
        data: null
    });

    var version = tacacs.createVersion(tacacs.TAC_PLUS_MAJOR_VER, tacacs.TAC_PLUS_MINOR_VER_DEFAULT);
    var sequenceNumber = 1;
    var encryptedAuthStart = tacacs.encodeByteData(sessionId, 'mysharedsecret', version, sequenceNumber, authStart);

    // create the tacacs+ header
    var headerOptions = {
        majorVersion: tacacs.TAC_PLUS_MAJOR_VER,
        minorVersion: tacacs.TAC_PLUS_MINOR_VER_DEFAULT,
        type: tacacs.TAC_PLUS_AUTHEN,
        sequenceNumber: sequenceNumber,
        flags: tacacs.TAC_PLUS_SINGLE_CONNECT_FLAG, // setting this to zero assumes encryption is being used --  | tacacs.TAC_PLUS_UNENCRYPTED_FLAG
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
        var resp = tacacs.decodePacket({ packet: data, key: 'mysharedsecret' });
        console.log('Client: Received Session Id: ' + resp.header.sessionId);
        console.log('Client: Decoded Response: ' + JSON.stringify(resp, null, 2));
    }
    else {
        console.log('Client: No data!');
    }
});
