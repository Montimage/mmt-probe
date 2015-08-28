var mmt = require('mmt-correlator');
var redis = require("redis");

var publisher = redis.createClient();

var neighborbourhood = []; //src, neighbor, + timestamp ?

function update_neighborbourhood_quality (active_state, evt, msg, opts) {
  if (neighborbourhood[msg.data.value.orig] == null)  neighborbourhood[msg.data.value.orig] = [];
  //neighborbourhood[msg.data.value.orig][0] = msg.data.value.timestamp;
 // console.log("Quality");
  //console.log(neighborbourhood[msg.data.value.orig][msg.data.value.neighbor]);
  
  neighborbourhood[msg.data.value.orig][msg.data.value.neighbor] = {};
  neighborbourhood[msg.data.value.orig][msg.data.value.neighbor][1]= msg.data.value.fwd_signal;
  neighborbourhood[msg.data.value.orig][msg.data.value.neighbor][2]= msg.data.value.rcv_signal;
  //console.log(neighborbourhood);
  return;
}
function check_property_quality (active_state, evt, msg, opts) {
	//console.log(msg);
  if(neighborbourhood[msg.data.value.neighbor]!= null && neighborbourhood[msg.data.value.neighbor][msg.data.value.orig][1]!=0 && neighborbourhood[msg.data.value.neighbor][msg.data.value.orig][2]!= 0){
        if(neighborbourhood[msg.data.value.neighbor][msg.data.value.orig][1]!=neighborbourhood[msg.data.value.orig][msg.data.value.neighbor][2] || neighborbourhood[msg.data.value.neighbor][msg.data.value.orig][2]!=neighborbourhood[msg.data.value.orig][msg.data.value.neighbor][1]) 
        {
               MMT.emitVerdict(active_state, evt, msg, {value: false,
                 attributes:{ orig: msg.data.value.orig, neighbor: msg.data.value.neighbor,
                 type: neighborbourhood[msg.data.value.orig][msg.data.value.neighbor],
                 attacker: msg.data.value.orig}});
          console.log("OLSR quality false");
        } else {/*
                MMT.emitVerdict(active_state, evt, msg, {value: true, attributes:{ orig: msg.data.value.orig, neighbor: msg.data.value.neighbor,
                  type: neighborbourhood[msg.data.value.orig][msg.data.value.neighbor],
                  attacker: null}});*/
          console.log("OLSR quality true");
        } 
  }
  return;
}

//jeevan qolsr rules
var efsm = new mmt.EFSM(
{
  id: "Linkqualityspoofing",
  description: "If A and B are neigbors,in stable condition then Forward signal (A)=Reverse signal (B) and Reverse signal (A) = Forward signal (B) ",
  hascontext: true,
  logdata: true,
  onCreation: function() {},
  onDeletion: function() {},
  events: ['olsr.hello'],
  states: [
    {
      id: 'init'
    }
  ], //states MUST start with init!
  transitions: [
    {
      from: 'init',
      to: 'init',
      event: 'olsr.hello',
      conditions: [],
      actions: [{fct: update_neighborbourhood_quality},{fct: check_property_quality}]
    }
  ]
});


//San
setTimeout(function(){ publisher.publish('olsr.hello', JSON.stringify(MMT.attributeJSON(1000, 'olsr.hello',{"timestamp":1000,"orig":"192.168.200.4","neighbor":"192.168.200.3", "type":6,"fwd_signal":10,"rcv_signal":0},'', 'i1'))); }, 1000);
setTimeout(function(){ publisher.publish('olsr.hello', JSON.stringify(MMT.attributeJSON(1000, 'olsr.hello',{"timestamp":1000,"orig":"192.168.200.4","neighbor":"192.168.200.5", "type":6,"fwd_signal":100,"rcv_signal":200},'', 'i1'))); }, 1500);
setTimeout(function(){ publisher.publish('olsr.hello', JSON.stringify(MMT.attributeJSON(2000, 'olsr.hello',{"timestamp":2000,"orig":"192.168.200.5","neighbor":"192.168.200.4", "type":6,"fwd_signal":200,"rcv_signal":100},'','i1'))); }, 2000);

setTimeout(function(){ publisher.publish('olsr.hello', JSON.stringify(MMT.attributeJSON(1000, 'olsr.hello',{"timestamp":1000,"orig":"192.168.200.3","neighbor":"192.168.200.4", "type":6,"fwd_signal":0,"rcv_signal":10},'', 'i1'))); }, 2500);
setTimeout(function(){ publisher.publish('olsr.hello', JSON.stringify(MMT.attributeJSON(1000, 'olsr.hello',{"timestamp":1000,"orig":"192.168.200.5","neighbor":"192.168.200.6", "type":6,"fwd_signal":100,"rcv_signal":200},'', 'i1'))); }, 3000);
setTimeout(function(){ publisher.publish('olsr.hello', JSON.stringify(MMT.attributeJSON(2000, 'olsr.hello',{"timestamp":2000,"orig":"192.168.200.6","neighbor":"192.168.200.5", "type":6,"fwd_signal":400,"rcv_signal":100},'','i1'))); }, 4000);

