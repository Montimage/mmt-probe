/**
 * Module dependencies.
 */

var http = require('http');
var path = require('path');
var url = require('url');
var redis = require("redis");
var moment = require('moment');
var io = require('socket.io');
var fs = require('fs');

var publisher = redis.createClient();

var mimeTypes = {
    "html": "text/html",
    "jpeg": "image/jpeg",
    "jpg": "image/jpeg",
    "png": "image/png",
    "js": "text/javascript",
    "css": "text/css"};

/*
 * Context awareness code:
 * Get periodically the CPU and Memory usage and send them on the event bus
 */
var caware = require('./contextawareness');
var caware_pub = redis.createClient();
var period = 1 * 1000; //1 second
setInterval(function() {
    caware.cpu(function(err, data) {
      if( err ) return console.log(err);
      if( data ) {
        caware_pub.publish('context.cpu', JSON.stringify(data));
      }
    });

  }, period
);
//////// End of Context awareness code ////////////

var server = http.createServer(function(req, res) {
    console.log(req.url);
    var uri = url.parse(req.url);
    uri = (uri.pathname).replace(/ml\//g, 'ml');
    console.log(uri);
    var filename = path.join(process.cwd(), 'public/' + uri);
    path.exists(filename, function(exists) {
        if(!exists) {
            console.log("not exists: " + filename);
            res.writeHead(200, {'Content-Type': 'text/plain'});
            res.write('404 Not Found\n');
            res.end();
            return;
        }
        var mimeType = mimeTypes[path.extname(filename).split(".")[1]];
        res.writeHead(200, {'Content-Type':mimeType});

        var fileStream = fs.createReadStream(filename);
        fileStream.pipe(res);

    }); //end path.exists
});

///// End DB update

io = io.listen(server);
io.set('log level', 1); //warning + errors
server.listen(8080);

io.sockets.on('connection', function (client) {
    // Subscribe to Context messages
    var sub = redis.createClient();
    sub.psubscribe('*.verdict');
    sub.psubscribe('context.*');

    sub.on("pmessage", function (pattern, channel, message) {
        if(channel.indexOf('pr') === 0) console.log(message);
        msg = JSON.parse(message);
        client.send(JSON.stringify({channel: channel, data: msg}));
    });

    client.on("message", function (msg) {
    });

    client.on('disconnect', function () {
    });
});

