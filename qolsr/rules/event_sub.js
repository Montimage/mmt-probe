var redis = require("redis"),
    client1 = redis.createClient(), client2 = redis.createClient(),
    msg_count = 0;

client1.on("psubscribe", function (channel, count) {
  console.log('mmm');
});

client1.on("pmessage", function (pattern, channel, message) {

//    msg_count += 1;
//    if((msg_count % 1000) === 0)
        console.log(message);
});

//client1.psubscribe("olsr.format");
client1.psubscribe("olsr.hello");
