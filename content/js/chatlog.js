/* chat-log as an array */
function macroExpand(msg) {
    var text = msg;

    var loc = '' + document.location;
    loc = loc.replace('chat.html', 'index_broadcast.html?room=');
    while(text.indexOf('$SUBSCRIBELINK') >= 0) {
        text = text.replace('$SUBSCRIBELINK', loc);
    }
    return text;
}
function appendMessageListElem(destList, m) {
  var e = destList;
  var l = document.createElement('li');
  var a = document.createElement('a');
  var t = document.createTextNode(m);
  var tScroll = document.createElement('table');
  var tScrollRow = document.createElement('tr');
  var tScrollRowElem = document.createElement('td');
  tScroll.style.cssText = 'width:100%; height:100%; table-layout:fixed;';
  tScrollRow.style.cssText = 'height:1em;';
  tScrollRowElem.style.cssText = 'overflow:auto;';
  l.cssText = 'padding-left: 0pt;';
  if(m.indexOf('http') >= 0) {
    var ref = m.substring(m.indexOf('http'), m.length)
    a.href = ref
  }
    
  a.appendChild(t);
  tScrollRowElem.appendChild(a);
  tScrollRow.appendChild(tScrollRowElem);
  tScroll.appendChild(tScrollRow);
  l.appendChild(tScroll);
  
  e.appendChild(l);
  return l;
}

function appendMessagesToUnorderedList(l, array) {
  var i = 0;
  var altcolor = 'lightgrey';
  var bgColor = altcolor;

  while(i < array.length) {
    var offset = 0;
    let maxLen = 1000;
    var str = array[i];

    str = macroExpand(str);

    str = str.replace(/\+/g, ' ');
    while(offset < str.length && str.length > 0) {
      var listElem = appendMessageListElem(l, str.substring(offset, offset+maxLen));
      listElem.scrollIntoView(false);
     
      listElem.style.cssText = 'background-color:'+ bgColor + '; list-style-type:none;';
      offset += maxLen;
    }

    if(bgColor.indexOf(altcolor) == 0) bgColor = 'white';
    else bgColor = altcolor;
    i += 1;
  }
}

var jsChatlogLines = [
%$CHATLOGJSARRAY$%
];

