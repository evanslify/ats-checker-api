const tls = require('tls'),
      fs = require('fs'),
      opensslWrap = require('openssl-wrapper');
const openssl = opensslWrap.exec;

const options = {
    host: 'localhost',
    port: 443,
    ca: [
        fs.readFileSync('./ssl-cert/ssl-cert.pem', 'utf8'),
    ],
};

var connection = tls.connect(443, options, function(socket) {
    // node's TLS is really dumb so we need to check whether
    // it has successfully connected or not :/
    var writeString = 'GET / HTTP/1.0\n\rHost: ' + options.host + ':443\n\r\n\r';
    console.log(connection.getPeerCertificate());
    connection.write(writeString);
    connected(connection);
    // write something so that the connection would be closed.
});

connection.on('error', function(error) {
    connected(false);
});

function connected(stream) {
    // callback function upon connection successful
    var result = {};
    if (!stream) {
        result.connectionStatus = false;
    }
    // go check the ATS conditions!
    result = {
        'connectionStatus': true,
        'authorizeStatus': stream.authorized? true : false,
        'protocolResult': checkProtocol(connection.getProtocol()),
        'cipherResult': checkCipher(connection.getCipher())
    };
    callResponse(result);
}

function checkCipher(cipher) {
    const valid_ciphers = [
        'ECDHE-ECDSA-AES256-GCM-SHA384',
        'ECDHE-ECDSA-AES128-GCM-SHA256',
        'ECDHE-ECDSA-AES256-CBC-SHA384',
        'ECDHE-ECDSA-AES256-CBC-SHA',
        'ECDHE-ECDSA-AES128-CBC-SHA256',
        'ECDHE-ECDSA-AES128-CBC-SHA',
        'ECDHE-RSA-AES256-GCM-SHA384',
        'ECDHE-RSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES256-CBC-SHA384',
        'ECDHE-RSA-AES128-CBC-SHA256',
        'ECDHE-RSA-AES128-CBC-SHA',
        'ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        'ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
        'ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
        'ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
        'ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
        'ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        'ECDHE_RSA_WITH_AES_256_CBC_SHA384',
        'ECDHE_RSA_WITH_AES_128_CBC_SHA256',
        'ECDHE_RSA_WITH_AES_128_CBC_SHA',
    ];
    if (valid_ciphers.indexOf(cipher.name) < 0) {
        console.log('cipher FAIL', cipher.name);
        return cipher.name;
    }
    return true;
}

function checkProtocol(protocol) {
    if (protocol !== 'TLSv1.2') {
        return protocol;
    }
    return true;
}

function callResponse(argument) {
    console.log(argument);
}
