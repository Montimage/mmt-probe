(function(){
  
  Event_parser = function(){

//        var eve = an_event(
//        '{"v":"1.0","ts":1407945088840,"type":"verdict","data":{"id":"LinkSpoofing.verdict","value":false,"instance_id":"192.168.200.255"},"attributes":{"orig":"192.168.200.2","neigh
//        , network)
//
//        var eve = an_event(
//        '{"v":"1.0","ts":1407945088840,"type":"verdict","data":{"id":"PacketFormat.verdict","value":false,"instance_id":"192.168.200.255"},"attributes":{"attacker":"192.168.200.2"}}'
//        , network)

//{"v":"1.0",
//"ts":1407945088840,
//"type":"verdict",
//"data":{"id":"LinkSpoofing.verdict","value":false,"instance_id":"192.168.200.255"},
//"attributes":{"orig":"192.168.200.2","neighbor":"192.168.200.5","type":10,"attacker":"192.168.200.2"}}

//{"v":"1.0",
//"ts":1407945088840,
//"type":"verdict",
//"data":{"id":"PacketFormat.verdict","value":false,"instance_id":"192.168.200.255"},
//"attributes":{“attacker":"192.168.200.2"}}

//need to:
//    print id
//    increment number of attackers


    var that = {
      eparse:function(eve, net, attackers){
        var show_event
        e = JSON.parse(eve)
/*
        if(attackers === undefined){
            attackers({ id: "192.168.200.1", value: 0 });
            attackers.push({ id: "192.168.200.2", value: 0 });
            attackers.push({ id: "192.168.200.3", value: 0 });
            attackers.push({ id: "192.168.200.4", value: 0 });
            attackers.push({ id: "192.168.200.5", value: 0 });
        }
*/

        $.each(net.nodes, function(nname, ndata){
//    if origin undefined: change attacker node to red
          if (e.attributes.orig===undefined  && e.attributes.attacker == ndata.label){
              ndata.color = "#db8e3c"
              show_event = "Detection of mal-formed packet possibly sent by a compromised node or attacker\n"
                           + "Attacker:\n    " + e.attributes.attacker
                       + "\n************************************\n"
//             if(attackers[1].id == e.attributes.attacker) attackers[1].value = attackers[1].value + 1
          }
        })
//                   else: change to dotted line (origin-attacker)
        if(e.attributes.orig === undefined){
        }else{
          var o = e.attributes.orig
          var oo = o.split(".")
          var n = e.attributes.neighbor
          var nn = n.split(".")
          var a = e.attributes.attacker
          var aa = a.split(".")

          var or = oo[3]
          var ne = nn[3]
          var at = aa[3]
          var x = net.edges[or][ne]
          var y = net.edges[ne][or]
          var z = net.nodes[at]
          x.dash = 5
          y.dash = 5
          x.color = "#db8e3c"
          y.color = "#db8e3c"
          z.color = "#db8e3c"
          

          show_event = "Declaration of link that does not exist\n"
                       + "Spoofed link between:\n    " + o + "\nand: \n    " + n
                       + "\nAttacker:\n    " + e.attributes.attacker
                       + "\n************************************\n"
//          attackers[e.attributes.attacker] = attackers[e.attributes.attacker] + 1
        }

        return show_event
      }
    }
    
    return that
  }

  

  
})()
