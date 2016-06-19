var fs = require('fs');
var https = require('https');
var constants = require('constants');
var express = require('express');
var bodyParser = require('body-parser');
var app = express();
var check = require('./openssl-test.js');


var options = {
    key: fs.readFileSync('./ssl-cert/ssl-key.pem', 'utf8'),
    cert: fs.readFileSync('./ssl-cert/ssl-cert.pem', 'utf8'),
    secureProtocol: 'TLSv1_2_method',
    honorCipherOrder: true
};


app.use(bodyParser.json());
app.post('/atscheck/', function(req, res){
    const target = req.body.url;
    check.startCheck(target, res);
});


var port = 4430;
https.createServer(options, app).listen(port, function(){
    console.log("Express server listening on port " + port);
});

