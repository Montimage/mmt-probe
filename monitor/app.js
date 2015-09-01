/**
 * Module dependencies.
 */

var express = require('express');
var http = require('http');
var path = require('path');
var redis = require("redis");
var moment = require('moment');
var jade = require('jade');
var app = express();
var io = require('socket.io');
var mongodbClient = require('mongodb').MongoClient;

mdb = null;
mongodbClient.connect('mongodb://127.0.0.1:27017/olsrdb',function(err,db){
  if(err) throw err;
  mdb = db;
});

var publisher = redis.createClient();

// all environments
app.set('port', process.env.PORT || 8080);
app.set('views', __dirname + '/views');
app.set('view engine', 'jade');
app.use(express.favicon());
app.use(express.logger('dev'));
app.use(express.bodyParser());
app.use(express.methodOverride());
app.use(app.router);
app.use(express.static(path.join(__dirname, 'public')));

app.get('/mmt-context', function(request, response, next) {
  mdb.collection("context.cpu").find({}).sort({ts: 1}).limit(25).toArray(function( err, doc )
  {
    if (err) return next(err);
    cpu = [];
    for(d in doc) {
      cpu.push([doc[d].ts, 100 - doc[d].data.idle]);
    }
    request.cpu = cpu || [];
    next();
  });
}, function(request, response, next) {
  mdb.collection("context.mem").find({}).sort({ts: 1}).limit(25).toArray(function( err, doc )
  {
    if (err) return next(err);
    mem = [];
    for(d in doc) {
      mem.push([doc[d].ts, (100 * doc[d].data.available/doc[d].data.memtotal)]);
    }
    request.mem = mem || [];
    next();
  });
}, function (request, response) {
  response.render('context', { cpu: request.cpu, mem: request.mem });
});

app.get('/mmt-sec', function(request, response, next) {
  mdb.collection("test.verdict").find({}).sort({ts: 1}).limit(25).toArray(function( err, doc )
  {
    if (err) return next(err);
    request.verdicts = doc || [];
    next();
  });
}, function (request, response) {
  response.render('sec', { verdicts: request.verdicts});
});
///// End DB update

var server = http.createServer(app);
io = io.listen(server);
io.set('log level', 1); //warning + errors
server.listen(app.get('port'));
console.log(io);
console.log(io.sockets);
io.sockets.on('connection', function (client) {
    console.log("Someone connecting...")
    // Subscribe to Context messages
    var sub = redis.createClient();
    sub.psubscribe("context.*");
    sub.psubscribe('*.verdict');
    sub.psubscribe('*');

    sub.on("pmessage", function (pattern, channel, message) {
        console.log(message);
        if(channel.indexOf('pr') === 0) console.log(message);
        msg = JSON.parse(message);
        client.send(JSON.stringify({channel: channel, data: msg}));
    });

    client.on("message", function (msg) {
    });

    client.on('disconnect', function () {
    });
});

