var mmt = require('mmt-correlator');
var redis = require("redis");

var publisher = redis.createClient();

var neighborbourhood = []; //src, neighbor, + timestamp ?

function update_neighborbourhood (active_state, evt, msg, opts) {
  if (neighborbourhood[msg.data.value.orig] == null)  neighborbourhood[msg.data.value.orig] = [];
  //neighborbourhood[msg.data.value.orig][0] = msg.data.value.timestamp;
  neighborbourhood[msg.data.value.orig][msg.data.value.neighbor]= msg.data.value.type;// type refers to message type
  //console.log("Here");
  return;
}

function check_property (active_state, evt, msg, opts) {

// console.log(msg);
  if(neighborbourhood[msg.data.value.orig][msg.data.value.neighbor] >5 && neighborbourhood[msg.data.value.neighbor]!= null){
        if(neighborbourhood[msg.data.value.neighbor][msg.data.value.orig]==null ||
          neighborbourhood[msg.data.value.neighbor][msg.data.value.orig] == 0 ||
          neighborbourhood[msg.data.value.neighbor][msg.data.value.orig] == 3) {
               MMT.emitVerdict(active_state, evt, msg, {value: false,
                 attributes:{ orig: msg.data.value.orig, neighbor: msg.data.value.neighbor,
                 type: neighborbourhood[msg.data.value.orig][msg.data.value.neighbor],
                 attacker: msg.data.value.orig}});
          console.log("OLSR false");
        } else {
                MMT.emitVerdict(active_state, evt, msg, {value: true, attributes:{ orig: msg.data.value.orig, neighbor: msg.data.value.neighbor,
                  type: neighborbourhood[msg.data.value.orig][msg.data.value.neighbor],
                  attacker: msg.data.value.orig}});
          console.log("OLSR true");


        }
  }
  return;
}

function check_format (active_state, evt, msg, opts) {
  if(msg.data.value === 1) {
    MMT.emitVerdict(active_state, evt, msg, {value: false,
      attributes:{ attacker: msg.attributes['ip.src']}});
    console.log("FORMAT false");
  } else {

    MMT.emitVerdict(active_state, evt, msg, {value: true,
      attributes:{ }});
    console.log("FORMAT true");
  }
  return;
}

var efsm = new mmt.EFSM(
{
  id: "LinkSpoofing",
  description: "If A declares a SYM/MPR link with B, then B must have been declared a ASYM/SYM/MPR link with A otherwise A is a liar",
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
      actions: [{fct: update_neighborbourhood},{fct: check_property}]
    }
  ]
});

var efsm = new mmt.EFSM(
{
  id: "PacketFormat",
  description: "If A declares a SYM/MPR link with B, then B must have been declared a ASYM/SYM/MPR link with A otherwise A is a liar",
  hascontext: true,
  logdata: true,
  onCreation: function() {},
  onDeletion: function() {},
  events: ['olsr.format'],
  states: [
    {
      id: 'init'
    }
  ], //states MUST start with init!
  transitions: [
    {
      from: 'init',
      to: 'init',
      event: 'olsr.format',
      conditions: [],
      actions: [{fct: check_format}]
    }
  ]
});

//San
setTimeout(function(){ 

	publisher.publish('olsr.hello', JSON.stringify(MMT.attributeJSON(1000, 'olsr.hello', {"timestamp":1000,"orig":"192.168.200.4","neighbor":"192.168.200.3", "type":6}, '', 'i1'))); 
}, 1000);

console.log("send 1");
setTimeout(function(){
console.log("send 2");
 publisher.publish('olsr.hello', JSON.stringify(MMT.attributeJSON(1000, 'olsr.hello',{"timestamp":1000,"orig":"192.168.200.4","neighbor":"192.168.200.5", "type":6},'', 'i1'))); }, 1000);
setTimeout(function(){ 
console.log("send 3");
publisher.publish('olsr.hello', JSON.stringify(MMT.attributeJSON(2000, 'olsr.hello',{"timestamp":2000,"orig":"192.168.200.5","neighbor":"192.168.200.4", "type":6},'', 'i1'))); }, 2000);


