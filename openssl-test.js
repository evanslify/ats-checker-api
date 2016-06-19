const sslinfo = require('sslinfo'),
      lodash = require('lodash');

sslinfo.getServerResults({host: "localhost", port: 443})
    .done(function (results) {
        // console.log(results);
        var raw = results.cert.publicKey.n;
        validateCert(results);
        checkBitLength(results);
        checkCipherSuite(results);
    },
    function (error) {
        // console.log("Error", {error: error});
    });

function runChecks() {
    var p = new Promise(
        function (resolve, reject) {
            if (resolve) {
                console.log('resolved');
            } else {
                console.log('rejected');
            }
        }
    );
}
function validateCert(results) {
    const issuer = results.cert.issuer;
    const subject = results.cert.subject;
    if (lodash.isEqual(issuer, subject)) {
        console.log('self signed certificate');
    } else {
        console.log('cert OK');
    }
}

function checkBitLength(results) {
    const bits = results.cert.publicKey.n.length * 4;
    const method = results.cert.publicKey.algorithm;
    if ((method === 'rsaEncryption' && bits >= 2048) || (method === 'eccEncryption' && bits >= 256)){
        console.log('length OK');
    } else {
        console.log('insufficent bits');
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
        console.log('OK');
    } else {
        console.log('Weak ciphers.');
    }
}

// convert this to promise!
