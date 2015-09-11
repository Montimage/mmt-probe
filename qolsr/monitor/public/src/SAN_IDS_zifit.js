//
// SAN_IDS.js
//
// instantiates all the helper classes, sets up the particle system + renderer
// and maintains the canvas/editor splitview
//
  var network;
(function(){
  
  trace = arbor.etc.trace
  objmerge = arbor.etc.objmerge
  objcopy = arbor.etc.objcopy
  var parse = Parseur().parse
  var an_event = Event_parser().eparse
  var attackers = []

  function addLink(attacker, neighbor) {
    n_node = (neighbor.split("."))[3];
    a_node = (attacker.split("."))[3];

    console.log(n_node + ' ---- ' + a_node);
    network.edges[a_node][n_node] = {directed: true, dash: 5, color: "red"};
    network.nodes[a_node].color = "red";
    sys.merge(network);

/*
          show_event = "Declaration of link that does not exist\n"
                       + "Spoofed link between:\n    " + o + "\nand: \n    " + n
                       + "\nAttacker:\n    " + e.attributes.attacker
                       + "\n************************************\n"
*/
  }

  var SANIDS = function(elt){
    var dom = $(elt)

    sys = arbor.ParticleSystem(2600, 512, 0.5)
    sys.renderer = Renderer("#viewport") // our newly created renderer will have its .init() method called shortly by sys...
    sys.screenPadding(20)
    
    var _ed = dom.find('#editor')
    var _code = dom.find('textarea')
    var _canvas = dom.find('#viewport').get(0)
    var _grabber = dom.find('#grabber')
    
    var _updateTimeout = null
    var _current = null // will be the id of the doc if it's been saved before
    var _editing = false // whether to undim the Save menu and prevent navigating away
    var _failures = null
    
    var that = {
      dashboard:Dashboard("#dashboard", sys),
      io:IO("#editor .io"),
      init:function(){
        
        $(window).resize(that.resize)
        that.resize()
        that.updateLayout(Math.max(1, $(window).width()-340))

        _code.keydown(that.typing)
        _grabber.bind('mousedown', that.grabbed)

        $(that.io).bind('get', that.getDoc)
        $(that.io).bind('clear', that.newDoc)
        return that
      },
      
      getDoc:function(e){
        $.getJSON('/library/'+e.id+'.json', function(doc){
            
          // update the system parameters
          if (doc.sys){
            sys.parameters(doc.sys)
            that.dashboard.update()
          }

          // modify the graph in the particle system
          //_code.val(doc.src)
          that.updateGraph()
          that.resize()
          _editing = false
        })
        
      },

      newDoc:function(){
        var lorem = "; some example nodes\nhello {color:red, label:HELLO}\nworld {color:orange}\n\n; some edges\nhello -> world {color:yellow}\nfoo -> bar {weight:5}\nbar -> baz {weight:2}"
        
        _code.val(lorem).focus()
        $.address.value("")
        that.updateGraph()
        that.resize()
        _editing = false
      },

      updateGraph:function(e){
        //var src_txt = _code.val()
        var src_txt = doc.src;
        network = parse(src_txt)

//TODO: subscribe to events
        //var eve = an_event('{"v":"1.0","ts":1407945088840,"type":"verdict","data":{"id":"LinkSpoofing.verdict","value":false,"instance_id":"192.168.200.255"},"attributes":{"orig":"192.168.200.2","neighbor":"192.168.200.5","type":10,"attacker":"192.168.200.2"}}', network)
/*
        var eve = an_event(
'{"v":"1.0","ts":1407945088840,"type":"verdict","data":{"id":"PacketFormat.verdict","value":false,"instance_id":"192.168.200.255"},"attributes":{"attacker":"192.168.200.2"}}'
, network)
*/

//TODO: append incomming events
        //_code.val(eve)
        //addLink("192.168.200.4", "192.168.200.5", network);
        _code.val("<a href='#'>laration</a> of link that does not exist")

        sys.merge(network)
        _updateTimeout = null

      },
      
      resize:function(){        
        var w = $(window).width() - 40
        var x = w - _ed.width()
        that.updateLayout(x)
        sys.renderer.redraw()
      },
      
      updateLayout:function(split){
        var w = dom.width()
        var h = _grabber.height()
        var split = split || _grabber.offset().left
        var splitW = _grabber.width()
        _grabber.css('left',split)

        var edW = w - split
        var edH = h
        _ed.css({width:edW, height:edH})
        if (split > w-20) _ed.hide()
        else _ed.show()

        var canvW = split - splitW
        var canvH = h
        _canvas.width = canvW
        _canvas.height = canvH
        sys.screenSize(canvW, canvH)
                
        _code.css({height:h-20,  width:edW-4, marginLeft:2})
      },
      
      grabbed:function(e){
        $(window).bind('mousemove', that.dragged)
        $(window).bind('mouseup', that.released)
        return false
      },
      dragged:function(e){
        var w = dom.width()
        that.updateLayout(Math.max(10, Math.min(e.pageX-10, w)) )
        sys.renderer.redraw()
        return false
      },
      released:function(e){
        $(window).unbind('mousemove', that.dragged)
        return false
      },
      typing:function(e){
        var c = e.keyCode
        if ($.inArray(c, [37, 38, 39, 40, 16])>=0){
          return
        }
        
        if (!_editing){
          $.address.value("")
        }
        _editing = true
        
        if (_updateTimeout) clearTimeout(_updateTimeout)
        _updateTimeout = setTimeout(that.updateGraph, 900)
      }
    }
    
    return that.init()    
  }


  $(document).ready(function(){
    var mcp = SANIDS("#SAN_IDS")    

    var socket = new io.connect('/');
    var failNb = 0;

    socket.on('connect', function() {
      console.log("Connected");
    });
  
    socket.on('message', function(message){
      var msg = JSON.parse(message);
      if( msg.channel === 'PacketFormat.verdict' && msg.data.data.value === false) {
        id = (msg.data.attributes.attacker).replace(/\./g, '_');
        val = parseInt($('#' + id).text()) + 1;
        $('#' + id).text(val);
      } else if( msg.channel === 'LinkSpoofing.verdict' && msg.data.data.value === false) {
        addLink(msg.data.attributes.attacker, msg.data.attributes.neighbor);
      }else if( msg.channel === 'context.cpu' ) {
        cpuusage = 100 - msg.data.data.idle;
        $('#cpu').text(cpuusage.toFixed(2) + ' %');
      }
    }) ;

    socket.on('disconnect', function() {
      console.log('disconnected');
    });

  })

  
})()
