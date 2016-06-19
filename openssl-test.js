const sslinfo = require('sslinfo'),
      lodash = require('lodash');

function checkComplete(result, res) {
    res.send(JSON.stringify(result));
}

function startCheck(host, callbackRes) {
    var callback = checkComplete;
    sslinfo.getServerResults({host: host, port: 443})
    // this is a deffered
    .done(
        function (results) {
            const raw = results.cert.publicKey.n;
            runChecks(results, callback, callbackRes);
        },
        function (error) {
            runChecks(false, callback, callbackRes);
        });
}

function runChecks(results, callback, callbackRes) {
    const success = results ? true : false;
    const tlsStatus = results.ciphers.TLSv1_2_method ? true : false;
    callback({
        'host': results.host,
        'cert': validateCert(results),
        'bits': checkBitLength(results),
        'tlsv1_2': tlsStatus,
        'cipher': tlsStatus ? checkCipherSuite(results) : false,
        'success': Boolean(success)
    }, callbackRes);
}

function validateCert(results) {
    const issuer = results.cert.issuer;
    const subject = results.cert.subject;
    if (lodash.isEqual(issuer, subject)) {
        // console.log('self signed certificate');
        return false;
    } else {
        // console.log('cert OK');
        return true;
    }
}

function checkBitLength(results) {
    const bits = results.cert.publicKey.n.length * 4;
    const method = results.cert.publicKey.algorithm;
    if ((method === 'rsaEncryption' && bits >= 2048) || (method === 'eccEncryption' && bits >= 256)){
        // console.log('length OK');
        return true;
    } else {
        // console.log('insufficent bits');
        return false;
    }
}
function checkCipherSuite(results) {
    const ciphers = results.ciphers.TLSv1_2_method.enabled;
    // if not using TLS 1.2, this would throw err.
    const good_ciphers = [
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
    ];
    if (lodash.intersection(ciphers, good_ciphers).length > 1) {
        // console.log('OK');
        return true;
    } else {
        // console.log('Weak ciphers.');
        return false;
    }
}

module.exports = ({
    startCheck
});
