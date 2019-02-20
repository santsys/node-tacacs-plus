const net = require('net');
const crypto = require('crypto');
const tacacs = require('../tacacs-plus');
const readline = require('readline');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

// SIMPLE CLIENT

// *** Update this to your shared secret ***
const shared_secret = 'mysharedsecret';

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
        user: '',
        port: '',
        remAddr: '',
        data: null
    });

    var version = tacacs.createVersion(tacacs.TAC_PLUS_MAJOR_VER, tacacs.TAC_PLUS_MINOR_VER_DEFAULT);
    var sequenceNumber = 1;
    var encryptedAuthStart = tacacs.encodeByteData(sessionId, shared_secret, version, sequenceNumber, authStart);

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

function promptUser(msg, next) {
    msg = msg || "[Unknown]: ";

    rl.question(msg, function (answer) {
        if (next) {
            next(answer);
        }
    });
}

client.on('error', function (err) { console.log(err); });
client.on('close', function (had_err) {
    console.log('Client: Connection closed' + (had_err ? ' with errors.' : '') + '.');
});
client.on('data', function (data) {
    if (data) {
        console.log('Client: Received Data: ' + data.toString('hex'));
        // decode response
        var resp = tacacs.decodePacket({ packet: data, key: shared_secret });
        
        if (resp) {
            console.log('Client: Received Session Id: ' + resp.header.sessionId);
            //console.log('Client: Decoded Response: ' + JSON.stringify(resp, null, 2));

            if (resp.data.status === tacacs.TAC_PLUS_AUTHEN_STATUS_ERROR) {
                console.log('Client: Authentication error!');
                client.end();
            }
            else if (resp.data.status === tacacs.TAC_PLUS_AUTHEN_STATUS_FAIL) {
                console.log('Client: *** Authentication Failed! ***');
                client.end();
            }
            else if (resp.data.status === tacacs.TAC_PLUS_AUTHEN_STATUS_GETUSER
                || resp.data.status === tacacs.TAC_PLUS_AUTHEN_STATUS_GETPASS) {

                // prompt the user for information
                promptUser(resp.data.message, function (answer) {
                    var newSeq = resp.header.sequenceNumber + 1;

                    var tRespOptions = {
                        flags: 0x00,
                        userMessage: answer,
                        data: null
                    };
                    var tContinue = tacacs.createAuthContinue(tRespOptions);
                    var encryptedContinue = tacacs.encodeByteData(resp.header.sessionId, shared_secret, resp.header.versionByte, newSeq, tContinue);

                    var tRespHeader = {
                        majorVersion: tacacs.TAC_PLUS_MAJOR_VER,
                        minorVersion: tacacs.TAC_PLUS_MINOR_VER_DEFAULT,
                        type: tacacs.TAC_PLUS_AUTHEN,
                        sequenceNumber: newSeq,
                        flags: resp.header.flags,
                        sessionId: resp.header.sessionId,
                        length: encryptedContinue.length
                    }
                    var header = tacacs.createHeader(tRespHeader);

                    var packetToSend = Buffer.concat([header, encryptedContinue]);
                    client.write(packetToSend);
                });
            }
            else if (resp.data.status === tacacs.TAC_PLUS_AUTHEN_STATUS_PASS) {
                console.log('Client: *** User Authenticated ***');
                console.log('Client: ' + JSON.stringify(resp.data, null, 2));
                client.end();
            }
            else {
                console.log('Client: Some other status (' + resp.data.status + ')!');
                var tRespOptions = {
                    flags: tacacs.TAC_PLUS_CONTINUE_FLAG_ABORT,
                    userMessage: null,
                    data: null
                };
                var newSeq = resp.header.sequenceNumber + 1;
                var tContinue = tacacs.createAuthContinue(tRespOptions);
                var encryptedContinue = tacacs.encodeByteData(resp.header.sessionId, shared_secret, resp.header.versionByte, newSeq, tContinue);

                var tRespHeader = {
                    majorVersion: tacacs.TAC_PLUS_MAJOR_VER,
                    minorVersion: tacacs.TAC_PLUS_MINOR_VER_DEFAULT,
                    type: tacacs.TAC_PLUS_AUTHEN,
                    sequenceNumber: newSeq,
                    flags: resp.header.flags,
                    sessionId: resp.header.sessionId,
                    length: encryptedContinue.length
                };
                var header = tacacs.createHeader(tRespHeader);

                var packetToSend = Buffer.concat([header, encryptedContinue]);
                client.write(packetToSend);
                client.end();
            }
        }
    }
    else {
        console.log('Client: No data!');
    }
});
