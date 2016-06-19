var fs = require('fs');
var https = require('https');
var http = require('http');
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
app.get('/', function(req, res){
    res.send('1');
});
app.post('/atscheck/', function(req, res){
    const target = req.body.url;
    check.startCheck(target, res);
});

// heroku says: thou shall not decide which port to use.
var port = process.env.PORT || 4430;
// https.createServer(options, app).listen(port, function(){
    // console.log("Express server listening on port " + port);
// });

const server = http.createServer((req, res) => {
  res.end();
});
server.on('clientError', (err, socket) => {
  socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
});
server.listen(port);
