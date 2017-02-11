const tacacs = require('../tacacs-plus');


var authorReq = tacacs.createAuthorizationRequest({
    authenMethod: tacacs.TAC_PLUS_AUTHEN_METH_NOT_SET,
    privLvl: tacacs.TAC_PLUS_PRIV_LVL_USER,
    authenType: tacacs.TAC_PLUS_AUTHEN_TYPE_ASCII,
    authenService: tacacs.TAC_PLUS_AUTHEN_TYPE_NOT_SET,
    user: 'user',
    port: 'port',
    remAddr: 'rem addr',
    args: ['test=123', 'test1=456']
});

console.log('Author Request: ' + authorReq.toString('hex'));

var decodedReq = tacacs.decodeAuthorizationRequest(authorReq);

console.log('Author Request: ' + JSON.stringify(decodedReq));

console.log('---------');

var authorResp = tacacs.createAuthorizationResponse({
    status: tacacs.TAC_PLUS_AUTHOR_STATUS_ERROR,
    args: ['test=123', 'test1=456'],
    serverMessage: 'Test Message',
    data: 'Test Data'
});

console.log('Author Response: ' + authorResp.toString('hex'));

var decodedResp = tacacs.decodeAuthorizationResponse(authorResp);

console.log('Author Response: ' + JSON.stringify(decodedResp));
