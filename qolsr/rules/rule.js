var mmt = require('mmt-correlator');
var redis = require("redis");

var publisher = redis.createClient();

// MAX number of signal to keep
var MAX_PERIOD = 20;

var LOG_LEVEL = 2;

function show_log (flag,message) {
  if(flag==LOG_LEVEL){
    if(flag==0){
      console.log("INFO: "+message);
    }else if(flag==1){
      console.log("ERROR: "+message);
    }else if(flag==2){
      console.log("DEBUG: "+message);
    }else{
      console.log("UNKNOWN LOG TYPE: "+message);
    }
  }
}
/**
* Neighborhood struct
* - Identify by IP address
* - has the latest value of forward signal
* - has the list of reverse singal
*/ 
function Neighbor (ipaddress) {
  var that = {};
  //IP address
  that.ip = ipaddress;
  //forward signal: latest value
  that.fs=null;
  // reverse signal: list of value
  that.rs=[];
  return that;
}

/**
* update signal value for a neighbor:
* - latest forward signal
* - list of reverse signals
* @data data to update
* @neighbor neighbor who will be updated
*/
function updateSignal(data,neighbor) {
  if(data.neighbor!=neighbor.ip){
    show_log(1,"Wrong ip address");
  }else{
    if(data.fwd_signal) neighbor.fs = data.fwd_signal;
    if(data.rcv_signal) addNewSignal(data.rcv_signal,neighbor.rs);
  }
};

/**
* add new signal to the list - with limitation of size #MAX_PERIOD
*/
function addNewSignal (signal,array) {
  if(array.length==MAX_PERIOD){
    array.shift();
  }
  array.push(signal);
}

/**
* Origin class
* - Each origin presents a node in network
* - Identify by IP address
* - Has a list of neighbors
*/
function Origin (ipaddress) {
  var that ={};
  that.ip = ipaddress;
  that.neighbors=[];
  return that;
}

/**
* Add a neighbor to an origin. If the neighbor already in the list neighbors of origin then just update the signal, otherwise create new neighbor and add to the list
* @data: data of neighbor
* @origin: who will be updated
*/
function addNeighbor(data,origin) {
  if(data.orig!=origin.ip){
    show_log(1,"Wrong origin");
  }else{
    if(!data.neighbor){
      show_log(1,"There isn't any neighbor to add");
    }else{
      var nb = getNeighborByIP(data.neighbor,origin);
      if(nb==null){
        var newNB = new Neighbor(data.neighbor);
        updateSignal(data,newNB);
        origin.neighbors.push(newNB);
      }else{
        updateSignal(data,nb);
      }
    }
  }
};

/**
* Get a neighbor in the list neighbor of an origin by the ip address of neighbor
* @nbIP: neighbor ip address
* @origin: Origin which has the list of neighbor to consider
*/
function getNeighborByIP(nbIP,origin) {
  for(var i=0;i<origin.neighbors.length;i++){
    if(origin.neighbors[i].ip==nbIP) return origin.neighbors[i];
  }
  return null;
};

var listOrigins = [];

/**
* find an origin in the network by IP address
* @ipaddress: IP address of origin
*/
function findOriginByIP (ipaddress) {
  for(var i=0;i<listOrigins.length;i++){
    if(listOrigins[i].ip==ipaddress) return listOrigins[i];
  }
  return null;
}


/**
* Update a neighbor signal
*
*/
function update_neighborbourhood_quality (active_state, evt, msg, opts) {

  var data = msg.data.value;
  var origin = findOriginByIP(data.orig);
  if(!origin){
    origin = new Origin(data.orig);
    addNeighbor(data,origin);
    listOrigins.push(origin);
  }else{
    addNeighbor(data,origin);
  }
  
  return;
}

function getRSignals (origin,nbIP) {
  var neighbor = getNeighborByIP(nbIP,origin);
  if(neighbor){
    return neighbor.rs;
  }
  return null;
}

function check_property_quality (active_state, evt, msg, opts) {

  var origin = findOriginByIP(msg.data.value.orig);
  var neighbor = findOriginByIP(msg.data.value.neighbor);
  if(origin&&neighbor){
    var rss = getRSignals(neighbor,origin.ip);
    var fs = msg.data.value.fwd_signal;
    if(rss){
      for(var i=0;i<rss.length;i++){
        // Quality true
        if(fs == rss[i]){
          show_log(0,"Quality true");
          return;
        }
      }
      // Quality false
      show_log(0,"Quality false\n");
      show_log(2,"origin: "+origin.ip+"\n");
      show_log(2,"neighbor: "+neighbor.ip+"\n");
      show_log(2,"msg:\n");
      show_log(2,JSON.stringify(msg));
      show_log(2,"listOrigins:\n");
      show_log(2,"TEST: \nfs: "+fs+"\n");
      show_log(2,"rss:");
      show_log(2,rss);
      show_log(2,JSON.stringify(listOrigins));
      MMT.emitVerdict(active_state, evt, msg, {value: false,
                 attributes:{ orig: msg.data.value.orig, neighbor: msg.data.value.neighbor,
                 type: msg.data.value.type,
                 attacker: msg.data.value.orig}});
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
// setTimeout(function(){ publisher.publish('olsr.hello', JSON.stringify(MMT.attributeJSON(1000, 'olsr.hello',{"timestamp":1000,"orig":"192.168.200.4","neighbor":"192.168.200.3", "type":6,"fwd_signal":10,"rcv_signal":0},'', 'i1'))); }, 1000);
// setTimeout(function(){ publisher.publish('olsr.hello', JSON.stringify(MMT.attributeJSON(1000, 'olsr.hello',{"timestamp":1000,"orig":"192.168.200.4","neighbor":"192.168.200.5", "type":6,"fwd_signal":100,"rcv_signal":200},'', 'i1'))); }, 1500);
// setTimeout(function(){ publisher.publish('olsr.hello', JSON.stringify(MMT.attributeJSON(2000, 'olsr.hello',{"timestamp":2000,"orig":"192.168.200.5","neighbor":"192.168.200.4", "type":6,"fwd_signal":200,"rcv_signal":500},'','i1'))); }, 2000);

// setTimeout(function(){ publisher.publish('olsr.hello', JSON.stringify(MMT.attributeJSON(1000, 'olsr.hello',{"timestamp":1000,"orig":"192.168.200.3","neighbor":"192.168.200.4", "type":6,"fwd_signal":0,"rcv_signal":10},'', 'i1'))); }, 2500);
// setTimeout(function(){ publisher.publish('olsr.hello', JSON.stringify(MMT.attributeJSON(1000, 'olsr.hello',{"timestamp":1000,"orig":"192.168.200.5","neighbor":"192.168.200.6", "type":6,"fwd_signal":100,"rcv_signal":200},'', 'i1'))); }, 3000);
// setTimeout(function(){ publisher.publish('olsr.hello', JSON.stringify(MMT.attributeJSON(2000, 'olsr.hello',{"timestamp":2000,"orig":"192.168.200.6","neighbor":"192.168.200.5", "type":6,"fwd_signal":400,"rcv_signal":100},'','i1'))); }, 4000);

