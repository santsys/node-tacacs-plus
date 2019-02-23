'use strict';

var crypto;
try {
    crypto = require('crypto');
}
catch (err) {
    console.log('Crypto not available.', err);
}

const HEADER_LENGTH = 12;

// major version
exports.TAC_PLUS_MAJOR_VER = 0x0c;

// minor versions
exports.TAC_PLUS_MINOR_VER_DEFAULT = 0x0;
exports.TAC_PLUS_MINOR_VER_ONE = 0x01;

// packet types
exports.TAC_PLUS_AUTHEN = 0x01; // Authentication
exports.TAC_PLUS_AUTHOR = 0x02; // Authorization
exports.TAC_PLUS_ACCT = 0x03; // Accounting

// flags
exports.TAC_PLUS_UNENCRYPTED_FLAG = 0x01;
exports.TAC_PLUS_SINGLE_CONNECT_FLAG = 0x04;

// auth actions
exports.TAC_PLUS_AUTHEN_LOGIN = 0x01;
exports.TAC_PLUS_AUTHEN_CHPASS = 0x02;
exports.TAC_PLUS_AUTHEN_SENDAUTH = 0x04;

// priv level
exports.TAC_PLUS_PRIV_LVL_MAX = 0x0f;
exports.TAC_PLUS_PRIV_LVL_ROOT = 0x0f;
exports.TAC_PLUS_PRIV_LVL_USER = 0x01;
exports.TAC_PLUS_PRIV_LVL_MIN = 0x00;

// auth types
exports.TAC_PLUS_AUTHEN_TYPE_ASCII = 0x01;
exports.TAC_PLUS_AUTHEN_TYPE_PAP = 0x02;
exports.TAC_PLUS_AUTHEN_TYPE_CHAP = 0x03;
exports.TAC_PLUS_AUTHEN_TYPE_ARAP = 0x04;
exports.TAC_PLUS_AUTHEN_TYPE_MSCHAP = 0x05;
exports.TAC_PLUS_AUTHEN_TYPE_MSCHAPV2 = 0x06;

// auth services
exports.TAC_PLUS_AUTHEN_SVC_NONE = 0x00;
exports.TAC_PLUS_AUTHEN_SVC_LOGIN = 0x01;
exports.TAC_PLUS_AUTHEN_SVC_ENABLE = 0x02;
exports.TAC_PLUS_AUTHEN_SVC_PPP = 0x03;
exports.TAC_PLUS_AUTHEN_SVC_ARAP = 0x04;
exports.TAC_PLUS_AUTHEN_SVC_PT = 0x05;
exports.TAC_PLUS_AUTHEN_SVC_RCMD = 0x06;
exports.TAC_PLUS_AUTHEN_SVC_X25 = 0x07;
exports.TAC_PLUS_AUTHEN_SVC_NASI = 0x08;
exports.TAC_PLUS_AUTHEN_SVC_FWPROXY = 0x09;

// auth response status
exports.TAC_PLUS_AUTHEN_STATUS_PASS = 0x01;
exports.TAC_PLUS_AUTHEN_STATUS_FAIL = 0x02;
exports.TAC_PLUS_AUTHEN_STATUS_GETDATA = 0x03;
exports.TAC_PLUS_AUTHEN_STATUS_GETUSER = 0x04;
exports.TAC_PLUS_AUTHEN_STATUS_GETPASS = 0x05;
exports.TAC_PLUS_AUTHEN_STATUS_RESTART = 0x06;
exports.TAC_PLUS_AUTHEN_STATUS_ERROR = 0x07;
exports.TAC_PLUS_AUTHEN_STATUS_FOLLOW = 0x21;

// auth response flags
exports.TAC_PLUS_REPLY_FLAG_NOECHO = 0x01;

// auth continue flags
exports.TAC_PLUS_CONTINUE_FLAG_ABORT = 0x01;

// authorization - authen method
exports.TAC_PLUS_AUTHEN_METH_NOT_SET = 0x00;
exports.TAC_PLUS_AUTHEN_METH_NONE = 0x01;
exports.TAC_PLUS_AUTHEN_METH_KRB5 = 0x02;
exports.TAC_PLUS_AUTHEN_METH_LINE = 0x03;
exports.TAC_PLUS_AUTHEN_METH_ENABLE = 0x04;
exports.TAC_PLUS_AUTHEN_METH_LOCAL = 0x05;
exports.TAC_PLUS_AUTHEN_METH_TACACSPLUS = 0x06;
exports.TAC_PLUS_AUTHEN_METH_GUEST = 0x08;
exports.TAC_PLUS_AUTHEN_METH_RADIUS = 0x10;
exports.TAC_PLUS_AUTHEN_METH_KRB4 = 0x11;
exports.TAC_PLUS_AUTHEN_METH_RCMD = 0x20;

// authorization - authen status
exports.TAC_PLUS_AUTHOR_STATUS_PASS_ADD = 0x01;
exports.TAC_PLUS_AUTHOR_STATUS_PASS_REPL = 0x02;
exports.TAC_PLUS_AUTHOR_STATUS_FAIL = 0x10;
exports.TAC_PLUS_AUTHOR_STATUS_ERROR = 0x11;
exports.TAC_PLUS_AUTHOR_STATUS_FOLLOW = 0x21;

// accounting - flags
exports.TAC_PLUS_ACCT_FLAG_START = 0x02;
exports.TAC_PLUS_ACCT_FLAG_STOP = 0x04;
exports.TAC_PLUS_ACCT_FLAG_WATCHDOG = 0x08;

// accounting - status
exports.TAC_PLUS_ACCT_STATUS_SUCCESS = 0x01;
exports.TAC_PLUS_ACCT_STATUS_ERROR = 0x02;
exports.TAC_PLUS_ACCT_STATUS_FOLLOW = 0x21;

// helpers
function isFlagSet(value, flag) {
    return ((value & flag) == flag);
}

/**
 * Creates a version value using the major and minor versions.
 * @param {any} majorVersion The major version.
 * @param {any} minorVersion The minor version.
 * @returns {Number} Returns a combined version number.
 */
exports.createVersion = function (majorVersion, minorVersion) {
    return ((majorVersion & 0xf) << 4) | (minorVersion & 0xf);
};

/**
 * Splits a version number into major and minor version.
 * @param {any} version The version number
 * @returns {any} An object containing a majorVersion and minorVersion property.
 */
exports.splitVersion = function (version) {
    return {
        majorVersion: ((version >> 4) & 0xf),
        minorVersion: (version & 0xf)
    };
};

/**
 * Creates the data hash used for encryption/decryption.
 * @param {any} session_id The session id.
 * @param {any} key The shared key.
 * @param {any} version The version.
 * @param {any} seq_no The sequence number.
 * @param {Buffer|string} prevHash The previous hash value.
 * @returns {Buffer} A md5 hash.
 */
exports.createDataHashWithPrevHash = function (session_id, key, version, seq_no, prevHash) {
    if (!crypto) {
        throw new Error('Encryption is not supported.');
    }

    var md5 = crypto.createHash('md5');

    var hashBuffer = Buffer.alloc(4 + (key ? key.length : 0) + 1 + 1);
    var offset = 0;
    hashBuffer.writeUInt32BE(session_id, offset);
    offset += 4;
    hashBuffer.write(key || "", offset);
    offset += (key ? key.length : 0);
    hashBuffer.writeUInt8(version, offset);
    offset += 1;
    hashBuffer.writeUInt8(seq_no, offset);
    offset += 1;

    if (prevHash) {
        if (prevHash instanceof Buffer) {
            hashBuffer = Buffer.concat([hashBuffer, prevHash]);
        }
        else {
            var prevHashBuffer = Buffer.from(prevHash, 'hex');
            hashBuffer = Buffer.concat([hashBuffer, prevHash]);
        }
    }

    md5.update(hashBuffer);
    return md5.digest();
};

/**
 * Encodes the buffer of data.
 * @param {any} session_id The session id.
 * @param {any} key The skared key.
 * @param {any} version The version number.
 * @param {any} seq_no The sequence number.
 * @param {any} rawData The raw data to encode.
 * @returns {Buffer} The encoded buffer.
 */
exports.encodeByteData = function (session_id, key, version, seq_no, rawData) {

    var dataLen = rawData.length;
    var bOut = Buffer.alloc(dataLen);

    var prevHash;
    for (var i = 0; i < dataLen; i += 16) {
        var hash = exports.createDataHashWithPrevHash(session_id, key, version, seq_no, prevHash);

        for (var j = 0; j < 16 && dataLen > (i + j); j++) {
            bOut[i + j] = rawData[i + j] ^ hash[j];
        }

        prevHash = hash;
    }

    return bOut;
};

/**
 * Decodes the buffer (encode and decode operations are the same underlying function).
 * @param {any} session_id The session id.
 * @param {any} key The skared key.
 * @param {any} version The version number.
 * @param {any} seq_no The sequence number.
 * @param {any} rawData The raw data to encode.
 * @returns {Buffer} The decoded buffer.
 */
exports.decodeByteData = function (session_id, key, version, seq_no, rawData) {
    return exports.encodeByteData(session_id, key, version, seq_no, rawData);
};

/**
 * Decodes a TACACS+ header.
 * @param {Buffer} rawData A Buffer containing the raw header data.
 * @returns {any} Returns a response object containing a decoded header and rawData buffer containing the remaining body.
 */
exports.decodeHeader = function (rawData) {

    if (!rawData) {
        return null;
    }

    if (!(rawData instanceof Buffer)) {
        throw new Error('decodeHeader requires a Buffer.');
    }

    if (rawData.length < 12) {
        throw new Error('Invalid packet length.');
    }

    var data = rawData;

    // parse out the header
    var detailData = data.slice(0, 4);
    var versionByte = detailData.readUInt8(0);
    var ver = exports.splitVersion(versionByte);

    var majorVersion = ver.majorVersion;
    var minorVersion = ver.minorVersion;
    var type = detailData.readUInt8(1);
    var seq = detailData.readUInt8(2);
    var flags = detailData.readUInt8(3);

    var sessionId = data.slice(4, 8).readUInt32BE(0);
    var length = data.slice(8, 12).readUInt32BE(0);

    var response = {
        header: {
            majorVersion: majorVersion,
            minorVersion: minorVersion,
            versionByte: versionByte,
            type: type,
            sequenceNumber: seq,
            flags: flags,
            is_encrypted: !isFlagSet(flags, exports.TAC_PLUS_UNENCRYPTED_FLAG),
            is_singleConnect: isFlagSet(flags, exports.TAC_PLUS_SINGLE_CONNECT_FLAG),
            sessionId: sessionId,
            length: length
        },
        rawData: (data.length > 0 ? data.slice(12, 12 + length) : null)
    };
    return response;
};

/**
 * Creates a buffer containing a TACACS+ header.
 * @param {any} options The TACACS+ header options to be encoded.
 * @returns {Buffer} A buffer containg an encoded TACACS+ header.
 */
exports.createHeader = function (options) {
    options = options || {
        majorVersion: 0x0,
        minorVersion: 0x0,
        type: 0x0,
        sequenceNumber: 0x1,
        flags: exports.TAC_PLUS_UNENCRYPTED_FLAG,
        sessionId: 0x0,
        length: 0x0
    };

    var data = Buffer.alloc(12);
    data.writeUInt8(exports.createVersion(options.majorVersion, options.minorVersion), 0);
    data.writeUInt8(options.type, 1);
    data.writeUInt8(options.sequenceNumber, 2);
    data.writeUInt8(options.flags, 3);
    data.writeUInt32BE(options.sessionId, 4);
    data.writeUInt32BE(options.length, 8);
    return data;
};

/**
 * Decodes a data packet and handles basic authentication decode routing.
 * @param {any} packetData The packet data to decode.
 * @returns {any} An object containing the decoded data.
 */
exports.decodePacket = function decodePacket(packetData) {

    if (!packetData) {
        packetData = {
            packet: null,
            key: ""
        };
    }
    packetData.key = packetData.key || "";

    var data = packetData.packet;

    // parse out the header
    var response = exports.decodeHeader(data);

    if (!response) {
        throw new Error('Unable to decode header.');
    }

    if (response.rawData) {

        // get the body of the packet
        if (response.header.is_encrypted) {
            if (!crypto) {
                throw new Error('Communication is encrypted, but encryption is not supported.');
            }

            // decode the body
            response.rawData = exports.decodeByteData(response.header.sessionId, packetData.key, response.header.versionByte, response.header.sequenceNumber, response.rawData);
        }

        // parse the response into the object, if we can
        // a lot of this is based on the workflow used in the server implementation
        // so you may have to do this on your own
        if (response.header.type === exports.TAC_PLUS_AUTHEN) {
            var seqModTwo = response.header.sequenceNumber % 2;

            if (response.header.sequenceNumber === 1) {
                response.data = exports.decodeAuthStart(response.rawData, response.header.length);
            }
            else if (seqModTwo === 0) {
                response.data = exports.decodeAuthReply(response.rawData, response.header.length);
            }
            else if (seqModTwo === 1) {
                response.data = exports.decodeAuthContinue(response.rawData, response.header.length);
            }
        }
        else if (response.header.type === exports.TAC_PLUS_AUTHOR) {
            if (response.header.sequenceNumber === 1) {
                response.data = exports.decodeAuthorizationRequest(response.rawData, response.header.length);
            }
            else if (response.header.sequenceNumber === 2) {
                response.data = exports.decodeAuthorizationResponse(response.rawData, response.header.length);
            }
        }
        else if (response.header.type === exports.TAC_PLUS_ACCT) {
            if (response.header.sequenceNumber === 1) {
                response.data = exports.decodeAccountingRequest(response.rawData, response.header.length);
            }
            else if (response.header.sequenceNumber === 2) {
                response.data = exports.decodeAccountingResponse(response.rawData, response.header.length);
            }
        }
    }

    return response;
};

// *** Authentication ***
/**
 * Creates an authentication start buffer.
 * @param {any} options The options to be encoded into an authentication start buffer.
 * @returns {Buffer} A buffer containing the authentication start details.
 */
exports.createAuthStart = function (options) {

    options = options || {
        action: 0,
        privLvl: 0,
        authenType: 0,
        authenService: 0,
        user: "",
        port: "",
        remAddr: "",
        data: null
    };

    options.user = options.user || "";
    options.port = options.port || "";
    options.remAddr = options.remAddr || "";

    var bSize = 8 + options.user.length + options.port.length + options.remAddr.length + (options.data ? options.data.length : 0);
    var buff = Buffer.alloc(bSize);
    var offset = 0;

    buff.writeUInt8(options.action, offset);
    offset += 1;
    buff.writeUInt8(options.privLvl, offset);
    offset += 1;
    buff.writeUInt8(options.authenType, offset);
    offset += 1;
    buff.writeUInt8(options.authenService, offset);
    offset += 1;
    buff.writeUInt8(options.user.length, offset);
    offset += 1;
    buff.writeUInt8(options.port.length, offset);
    offset += 1;
    buff.writeUInt8(options.remAddr.length, offset);
    offset += 1;
    buff.writeUInt8((options.data == null ? 0 : options.data.length), offset);
    offset += 1;

    if (options.user.length > 0) {
        buff.write(options.user, offset);
        offset += options.user.length;
    }

    if (options.port.length > 0) {
        buff.write(options.port, offset);
        offset += options.port.length;
    }

    if (options.remAddr.length > 0) {
        buff.write(options.remAddr, offset);
        offset += options.remAddr.length;
    }

    if (options.data) {
        if (options.data instanceof Buffer) {
            buff = Buffer.concat([buff, options.data]);
        }
        else {
            buff.write(options.data, offset);
        }
        offset += options.data.length;
    }

    return buff;
};

/**
 * Decodes an authentication start message.
 * @param {any} data A buffer containing the authentication start details.
 * @param {any} headerDataLength The length defined in the header for the message.
 * @returns {any} An object containing the decoded information.
 */
exports.decodeAuthStart = function (data, headerDataLength) {
    if (!(data instanceof Buffer)) {
        throw new Error('Data must be a Buffer.');
    }

    if (data.length < 8) {
        throw new Error('Invalid body header length.');
    }

    var response = {
        action: data.readUInt8(0),
        privLvl: data.readUInt8(1),
        authenType: data.readUInt8(2),
        authenService: data.readUInt8(3),
        userLen: data.readUInt8(4),
        portLen: data.readUInt8(5),
        remAddrLen: data.readUInt8(6),
        dataLen: data.readUInt8(7)
    };

    var currentPosition = 8;
    var user;
    var port;
    var remAddr;
    var dataBody;

    if (response.userLen > 0) {
        user = data.slice(currentPosition, currentPosition + response.userLen).toString('utf8');
        currentPosition += response.userLen;
    }

    if (response.portLen > 0) {
        port = data.slice(currentPosition, currentPosition + response.portLen).toString('ascii');
        currentPosition += response.portLen;
    }

    if (response.remAddrLen > 0) {
        remAddr = data.slice(currentPosition, currentPosition + response.remAddrLen).toString('ascii');
        currentPosition += response.remAddrLen;
    }

    if (response.dataLen > 0) {
        dataBody = data.slice(currentPosition, currentPosition + response.dataLen);
        currentPosition += response.dataLen;
    }

    response.user = user;
    response.port = port;
    response.remAddr = remAddr;
    response.data = dataBody;

    if (headerDataLength !== undefined && currentPosition !== headerDataLength) {
        throw new Error('Data length mismatch. If using encryption please verify your keys are correct.');
    }

    return response;
};

/**
 * Creates an authentication reply buffer.
 * @param {any} options The options to be encoded into an auth reply buffer.
 * @returns {Buffer} Returns a buffer containing the authentication reply details.
 */
exports.createAuthReply = function (options) {
    options = options || {
        status: exports.TAC_PLUS_AUTHEN_STATUS_ERROR,
        flags: 0x00,
        message: null,
        data: null
    };

    options.status = options.status || exports.TAC_PLUS_AUTHEN_STATUS_ERROR;
    options.flags = options.flags || 0x00;
    options.message = options.message || null;
    options.data = options.data || null;

    var bSize = 2 + 4 + (options.message ? options.message.length : 0) + (options.data ? options.data.length : 0);
    var resp = Buffer.alloc(bSize);
    resp.writeUInt8(options.status, 0);
    resp.writeUInt8(options.flags, 1);

    var offset = 2;

    if (options.message) {
        resp.writeUInt16BE(options.message.length, offset);
    }
    else {
        resp.writeUInt16BE(0, offset);
    }
    offset += 2;

    if (options.data) {
        resp.writeUInt16BE(options.data.length, offset);
    }
    else {
        resp.writeUInt16BE(0, offset);
    }
    offset += 2;

    if (options.message) {
        resp.write(options.message, offset);
        offset += options.message.length;
    }

    if (options.data) {
        if (options.data instanceof Buffer) {
            resp = Buffer.concat([resp, options.data]);
        }
        else {
            resp.write(options.data, offset);
        }
        offset += options.data.length;
    }

    return resp;
};

/**
 * Decodes an authentication reply message.
 * @param {Buffer} data The raw buffer containing the auth reply.
 * @param {Number} headerDataLength The length specified in the header (used for verification).
 * @returns {any} Returns a decoded auth reply message.
 */
exports.decodeAuthReply = function (data, headerDataLength) {
    if (!(data instanceof Buffer)) {
        throw new Error('Data must be a Buffer.');
    }

    if (data.length < 6) {
        throw new Error('Invalid reply header length.');
    }
    
    var response = {
        status: (data.readUInt8(0) & 0xf),
        flags: (data.readUInt8(1) & 0xf),
        message: null,
        data: null
    };

    var msgLen = data.readUInt16BE(2) || 0;
    var dataLen = data.readUInt16BE(4) || 0;
    var pos = 6;

    if (msgLen > 0) {
        response.message = data.slice(pos, pos + msgLen).toString('ascii')
        pos += msgLen;
    }

    if (dataLen > 0) {
        response.data = data.slice(pos, pos + dataLen).toString('utf8');
        pos += dataLen;
    }

    if (headerDataLength !== undefined && pos !== headerDataLength) {
        throw new Error('Data length mismatch. If using encryption please verify your keys are correct.');
    }

    return response;
};

/**
 * Creates an Authentication Continue buffer.
 * @param {any} options The options to be encoded into the buffer.
 * @returns {Buffer} The Authentication Continue buffer.
 */
exports.createAuthContinue = function (options) {
    options = options || {};

    options.flags = options.flags || 0x00;
    options.userMessage = options.userMessage || null;
    options.data = options.data || null;

    var bSize = 2 + 2 + 1 + (options.userMessage ? options.userMessage.length : 0) + (options.data ? options.data.length : 0);
    var resp = Buffer.alloc(bSize);
    var offset = 0;

    resp.writeInt16BE(options.userMessage ? options.userMessage.length : 0, offset);
    offset += 2;
    resp.writeInt16BE(options.data ? options.data.length : 0, offset);
    offset += 2;

    resp.writeUInt8(options.flags, offset);
    offset += 1;

    if (options.userMessage) {
        resp.write(options.userMessage, offset);
        offset += options.userMessage.length;
    }

    if (options.data) {
        if (options.data instanceof Buffer) {
            resp = Buffer.concat([resp, options.data]);
        }
        else {
            resp.write(options.data, offset);
        }
        offset += options.data.length;
    }

    return resp;
};

/**
 * Decodes an authentication continue buffer.
 * @param {Buffer} data The buffer containing the auth continue data.
 * @param {Number} headerDataLength The length specified in the header (used for verification).
 * @returns {any} Returns a decoded auth continue message.
 */
exports.decodeAuthContinue = function (data, headerDataLength) {
    if (!(data instanceof Buffer)) {
        throw new Error('Data must be a Buffer.');
    }

    if (data.length < 5) {
        throw new Error('Invalid continue header length.');
    }

    var uMsgLen = data.readUInt16BE(0);
    var dataLen = data.readUInt16BE(2);
    var flags = data.readUInt8(4);
    var userMsg = uMsgLen > 0 ? data.slice(5, 5 + uMsgLen).toString('ascii') : null;
    var dataMsg = dataLen > 0 ? data.slice(5 + uMsgLen, 5 + uMsgLen + dataLen).toString('utf8') : null;

    var pos = 5 + uMsgLen + dataLen;
    if (headerDataLength !== undefined && pos !== headerDataLength) {
        throw new Error('Data length mismatch. If using encryption please verify your keys are correct.');
    }

    return {
        userMessageLength: uMsgLen,
        dataLength: dataLen,
        flags: flags,
        userMessage: userMsg,
        data: dataMsg
    };
};

// *** Authorization ***
/**
 * Creates an authorization request buffer.
 * @param {any} options The options for the request.
 * @returns {Buffer} Returns a buffer containing the authorization resquest.
 */
exports.createAuthorizationRequest = function (options) {
    options = options || {
        authenMethod: exports.TAC_PLUS_AUTHEN_METH_NOT_SET,
        privLvl: exports.TAC_PLUS_PRIV_LVL_USER,
        authenType: exports.TAC_PLUS_AUTHEN_TYPE_ASCII,
        authenService: exports.TAC_PLUS_AUTHEN_TYPE_NOT_SET,
        user: '',
        port: '',
        remAddr: '',
        args: []
    };

    if (options.args && !(options.args instanceof Array)) {
        throw new Error('The args should be an array of string values.');
    }

    options.args = options.args || [];
    options.user = options.user || '';
    options.port = options.port || '';
    options.remAddr = options.remAddr || '';

    if (options.args.length > 255) {
        throw new Error('You can not have more than 255 args.');
    }

    var argSize = 0;
    for (var i = 0; i < options.args.length; i++) {
        argSize += (options.args[i].length & 0xff);
    }

    var resp = Buffer.alloc(8 + options.user.length + options.port.length + options.remAddr.length + options.args.length + argSize);
    var offset = 0;

    resp.writeUInt8(options.authenMethod, offset++);
    resp.writeUInt8(options.privLvl, offset++);
    resp.writeUInt8(options.authenType, offset++);
    resp.writeUInt8(options.authenService, offset++);
    resp.writeUInt8(options.user.length, offset++);
    resp.writeUInt8(options.port.length, offset++);
    resp.writeUInt8(options.remAddr.length, offset++);

    if (options.args && options.args.length > 0) {
        resp.writeUInt8((options.args.length & 0xff), offset++);

        for (var i = 0; i < options.args.length; i++) {
            resp.writeUInt8((options.args[i].length & 0xff), offset++);
        }
    }
    else {
        resp.writeUInt8(0, offset++);
    }

    if (options.user.length > 0) {
        resp.write(options.user, offset);
        offset += options.user.length;
    }

    if (options.port.length > 0) {
        resp.write(options.port, offset);
        offset += options.port.length;
    }

    if (options.remAddr.length > 0) {
        resp.write(options.remAddr, offset);
        offset += options.remAddr.length;
    }

    if (options.args && options.args.length > 0) {
        for (var i = 0; i < options.args.length; i++) {
            var value = options.args[i];
            if (value.length > 0xff) {
                value = value.substring(0, 0xff);
            }

            resp.write(value, offset);
            offset += value.length;
        }
    }

    return resp;
};

/**
 * Taks a buffer and decodes it to an authorization request object.
 * @param {Buffer} data A buffer containing the raw authorization request data.
 * @param {Number} headerDataLength The length specified in the header (used for verification).
 * @returns {any} Returns a decoded authorization request object.
 */
exports.decodeAuthorizationRequest = function (data, headerDataLength) {
    var resp = {
        authenMethod: exports.TAC_PLUS_AUTHEN_METH_NOT_SET,
        privLvl: exports.TAC_PLUS_PRIV_LVL_USER,
        authenType: exports.TAC_PLUS_AUTHEN_TYPE_ASCII,
        authenService: exports.TAC_PLUS_AUTHEN_TYPE_NOT_SET,
        user: '',
        port: '',
        remAddr: '',
        args: []
    };

    if (!(data instanceof Buffer)) {
        throw new Error('Data must be a Buffer.');
    }

    if (data.length < 8) {
        throw new Error('Invalid header length.');
    }

    var offset = 0;
    resp.authenMethod = data.readUInt8(offset++);
    resp.privLvl = data.readUInt8(offset++);
    resp.authenType = data.readUInt8(offset++);
    resp.authenService = data.readUInt8(offset++);

    var userLen = data.readUInt8(offset++);
    var portLen = data.readUInt8(offset++);
    var remAddrLen = data.readUInt8(offset++);
    var argCnt = data.readUInt8(offset++);
    var argLens = [];

    if (argCnt > 0) {
        for (var i = 0; i < argCnt; i++) {
            argLens[i] = data.readUInt8(offset++);
        }
    }

    if (userLen > 0) {
        resp.user = data.slice(offset, offset + userLen).toString('ascii');
        offset += userLen;
    }

    if (portLen > 0) {
        resp.port = data.slice(offset, offset + portLen).toString('ascii');
        offset += portLen;
    }

    if (remAddrLen > 0) {
        resp.remAddr = data.slice(offset, offset + remAddrLen).toString('ascii');
        offset += remAddrLen;
    }

    if (argCnt > 0) {
        for (var i = 0; i < argCnt; i++) {
            resp.args[i] = data.slice(offset, offset + argLens[i]).toString('ascii');
            offset += argLens[i];
        }
    }

    if (headerDataLength !== undefined && offset !== headerDataLength) {
        throw new Error('Data length mismatch. If using encryption please verify your keys are correct.');
    }

    return resp;
};

/**
 * Creates an authorization response buffer from a set of options.
 * @param {any} options The options to be converted into a buffer.
 * @returns {Buffer} Returns a buffer containing the authorization response data.
 */
exports.createAuthorizationResponse = function (options) {
    options = options || {
        status: exports.TAC_PLUS_AUTHOR_STATUS_ERROR,
        args: [],
        serverMessage: '',
        data: ''
    };

    options.args = options.args || [];
    options.serverMessage = options.serverMessage || '';
    options.data = options.data || '';

    if (options.args.length > 255) {
        throw new Error('You can not have more than 255 args.');
    }

    var argCount = options.args.length;
    var argLen = 0;
    if (argCount > 0) {
        for (var i = 0; i < argCount; i++) {
            argLen += (options.args[i].length & 0xff);
        }
    }

    var offset = 0;
    var resp = Buffer.alloc(6 + options.serverMessage.length + options.data.length + argCount + argLen);

    resp.writeUInt8(options.status & 0xff, offset++);
    resp.writeUInt8(argCount & 0xff, offset++);
    resp.writeUInt16BE(options.serverMessage.length & 0xffff, offset);
    offset += 2;
    resp.writeUInt16BE(options.data.length & 0xffff, offset);
    offset += 2;

    if (argCount > 0) {
        for (var i = 0; i < argCount; i++) {
            resp.writeUInt8((options.args[i].length & 0xff), offset++);
        }
    }

    if (options.serverMessage.length > 0) {
        if (options.serverMessage.length > 0xffff) {
            options.serverMessage = options.serverMessage.substring(0, 0xffff);
        }
        resp.write(options.serverMessage, offset);
        offset += options.serverMessage.length;
    }

    if (options.data.length > 0) {
        if (options.data.length > 0xffff) {
            options.data = options.data.substring(0, 0xffff);
        }
        resp.write(options.data, offset);
        offset += options.data.length;
    }

    if (argCount > 0) {
        for (var i = 0; i < argCount; i++) {
            var value = options.args[i];
            if (value.length > 0xff) {
                value = value.substring(0, 0xff);
            }
            resp.write(value, offset);
            offset += value.length;
        }
    }

    return resp;
};

/**
 * Taks a buffer and decodes it to an authorization response object.
 * @param {Buffer} data A buffer containing the raw authorization response data.
 * @param {Number} headerDataLength The length specified in the header (used for verification).
 * @returns {any} Returns a decoded authorization response object.
 */
exports.decodeAuthorizationResponse = function (data, headerDataLength) {
    var resp = {
        status: exports.TAC_PLUS_AUTHOR_STATUS_ERROR,
        serverMessage: '',
        data: '',
        args: []
    };

    if (!(data instanceof Buffer)) {
        throw new Error('Data must be a Buffer.');
    }

    if (data.length < 6) {
        throw new Error('Invalid header length.');
    }

    var offset = 0;
    resp.status = data.readUInt8(offset++);
    var argCount = data.readUInt8(offset++);
    var msgLen = data.readUInt16BE(offset);
    offset += 2;
    var dataLen = data.readUInt16BE(offset);
    offset += 2;

    var argLens = [];
    if (argCount > 0) {
        for (var i = 0; i < argCount; i++) {
            argLens[i] = data.readUInt8(offset++);
        }
    }

    if (msgLen > 0) {
        resp.serverMessage = data.slice(offset, offset + msgLen).toString('ascii');
        offset += msgLen;
    }

    if (dataLen > 0) {
        resp.data = data.slice(offset, offset + dataLen).toString('ascii');
        offset += dataLen;
    }

    if (argCount > 0) {
        for (var i = 0; i < argCount; i++) {
            resp.args[i] = data.slice(offset, offset + argLens[i]).toString('ascii');
            offset += argLens[i];
        }
    }

    if (headerDataLength !== undefined && offset !== headerDataLength) {
        throw new Error('Data length mismatch. If using encryption please verify your keys are correct.');
    }

    return resp;
};

/**
 * Creates an accounting request buffer.
 * @param {any} options The options for the request.
 * @returns {Buffer} Returns a buffer containing the accounting resquest.
 */
exports.createAccountingRequest = function (options) {
    options = options || {
        flags: exports.TAC_PLUS_ACCT_FLAG_START,
        authenMethod: exports.TAC_PLUS_AUTHEN_METH_NOT_SET,
        privLvl: exports.TAC_PLUS_PRIV_LVL_USER,
        authenType: exports.TAC_PLUS_AUTHEN_TYPE_ASCII,
        authenService: exports.TAC_PLUS_AUTHEN_TYPE_NOT_SET,
        user: '',
        port: '',
        remAddr: '',
        args: []
    };

    if (options.args && !(options.args instanceof Array)) {
        throw new Error('The args should be an array of string values.');
    }

    options.args = options.args || [];
    options.user = options.user || '';
    options.port = options.port || '';
    options.remAddr = options.remAddr || '';

    if (options.args.length > 255) {
        throw new Error('You can not have more than 255 args.');
    }

    var argSize = 0;
    for (var i = 0; i < options.args.length; i++) {
        argSize += (options.args[i].length & 0xff);
    }

    var resp = Buffer.alloc(9 + options.user.length + options.port.length + options.remAddr.length + options.args.length + argSize);
    var offset = 0;

    resp.writeUInt8(options.flags, offset++);
    resp.writeUInt8(options.authenMethod, offset++);
    resp.writeUInt8(options.privLvl, offset++);
    resp.writeUInt8(options.authenType, offset++);
    resp.writeUInt8(options.authenService, offset++);
    resp.writeUInt8(options.user.length, offset++);
    resp.writeUInt8(options.port.length, offset++);
    resp.writeUInt8(options.remAddr.length, offset++);

    if (options.args && options.args.length > 0) {
        resp.writeUInt8((options.args.length & 0xff), offset++);

        for (var i = 0; i < options.args.length; i++) {
            resp.writeUInt8((options.args[i].length & 0xff), offset++);
        }
    }
    else {
        resp.writeUInt8(0, offset++);
    }

    if (options.user.length > 0) {
        resp.write(options.user, offset);
        offset += options.user.length;
    }

    if (options.port.length > 0) {
        resp.write(options.port, offset);
        offset += options.port.length;
    }

    if (options.remAddr.length > 0) {
        resp.write(options.remAddr, offset);
        offset += options.remAddr.length;
    }

    if (options.args && options.args.length > 0) {
        for (var i = 0; i < options.args.length; i++) {
            var value = options.args[i];
            if (value.length > 0xff) {
                value = value.substring(0, 0xff);
            }

            resp.write(value, offset);
            offset += value.length;
        }
    }

    return resp;
};

/**
 * Taks a buffer and decodes it to an accounting request object.
 * @param {Buffer} data A buffer containing the raw accounting request data.
 * @param {Number} headerDataLength The length specified in the header (used for verification).
 * @returns {any} Returns a decoded accounting request object.
 */
exports.decodeAccountingRequest = function (data, headerDataLength) {
    var resp = {
        flags: exports.TAC_PLUS_ACCT_FLAG_START,
        authenMethod: exports.TAC_PLUS_AUTHEN_METH_NOT_SET,
        privLvl: exports.TAC_PLUS_PRIV_LVL_USER,
        authenType: exports.TAC_PLUS_AUTHEN_TYPE_ASCII,
        authenService: exports.TAC_PLUS_AUTHEN_TYPE_NOT_SET,
        user: '',
        port: '',
        remAddr: '',
        args: []
    };

    if (!(data instanceof Buffer)) {
        throw new Error('Data must be a Buffer.');
    }

    if (data.length < 8) {
        throw new Error('Invalid header length.');
    }

    var offset = 0;
    resp.flags = data.readUInt8(offset++);
    resp.authenMethod = data.readUInt8(offset++);
    resp.privLvl = data.readUInt8(offset++);
    resp.authenType = data.readUInt8(offset++);
    resp.authenService = data.readUInt8(offset++);

    var userLen = data.readUInt8(offset++);
    var portLen = data.readUInt8(offset++);
    var remAddrLen = data.readUInt8(offset++);
    var argCnt = data.readUInt8(offset++);
    var argLens = [];

    if (argCnt > 0) {
        for (var i = 0; i < argCnt; i++) {
            argLens[i] = data.readUInt8(offset++);
        }
    }

    if (userLen > 0) {
        resp.user = data.slice(offset, offset + userLen).toString('ascii');
        offset += userLen;
    }

    if (portLen > 0) {
        resp.port = data.slice(offset, offset + portLen).toString('ascii');
        offset += portLen;
    }

    if (remAddrLen > 0) {
        resp.remAddr = data.slice(offset, offset + remAddrLen).toString('ascii');
        offset += remAddrLen;
    }

    if (argCnt > 0) {
        for (var i = 0; i < argCnt; i++) {
            resp.args[i] = data.slice(offset, offset + argLens[i]).toString('ascii');
            offset += argLens[i];
        }
    }

    if (headerDataLength !== undefined && offset !== headerDataLength) {
        throw new Error('Data length mismatch. If using encryption please verify your keys are correct.');
    }

    return resp;
};


/**
 * Creates an accounting response buffer from a set of options.
 * @param {any} options The options to be converted into a buffer.
 * @returns {Buffer} Returns a buffer containing the accounting response data.
 */
exports.createAccountingResponse = function (options) {
    options = options || {
        status: exports.TAC_PLUS_ACCT_STATUS_ERROR,
        serverMessage: '',
        data: ''
    };

    options.serverMessage = options.serverMessage || '';
    options.data = options.data || '';

    var offset = 0;
    var resp = Buffer.alloc(5 + options.serverMessage.length + options.data.length);

    resp.writeUInt16BE(options.serverMessage.length & 0xffff, offset);
    offset += 2;

    resp.writeUInt16BE(options.data.length & 0xffff, offset);
    offset += 2;

    resp.writeUInt8(options.status & 0xff, offset++);

    if (options.serverMessage.length > 0) {
        if (options.serverMessage.length > 0xffff) {
            options.serverMessage = options.serverMessage.substring(0, 0xffff);
        }
        resp.write(options.serverMessage, offset);
        offset += options.serverMessage.length;
    }

    if (options.data.length > 0) {
        if (options.data.length > 0xffff) {
            options.data = options.data.substring(0, 0xffff);
        }
        resp.write(options.data, offset);
        offset += options.data.length;
    }

    return resp;
};

/**
 * Taks a buffer and decodes it to an accounting response object.
 * @param {Buffer} data A buffer containing the raw accounting response data.
 * @param {Number} headerDataLength The length specified in the header (used for verification).
 * @returns {any} Returns a decoded accounting response object.
 */
exports.decodeAccountingResponse = function (data, headerDataLength) {
    var resp = {
        status: exports.TAC_PLUS_ACCT_STATUS_ERROR,
        serverMessage: '',
        data: ''
    };

    if (!(data instanceof Buffer)) {
        throw new Error('Data must be a Buffer.');
    }

    if (data.length < 5) {
        throw new Error('Invalid header length.');
    }

    var offset = 0;

    var msgLen = data.readUInt16BE(offset);
    offset += 2;
    var dataLen = data.readUInt16BE(offset);
    offset += 2;
    resp.status = data.readUInt8(offset++);

    if (msgLen > 0) {
        resp.serverMessage = data.slice(offset, offset + msgLen).toString('ascii');
        offset += msgLen;
    }

    if (dataLen > 0) {
        resp.data = data.slice(offset, offset + dataLen).toString('ascii');
        offset += dataLen;
    }

    if (headerDataLength !== undefined && offset !== headerDataLength) {
        throw new Error('Data length mismatch. If using encryption please verify your keys are correct.');
    }

    return resp;
};
