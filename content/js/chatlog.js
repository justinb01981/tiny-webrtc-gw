/* chat-log as an array */

function appendMessageListElem(destList, m) {
  var e = destList;
  var l = document.createElement('li');

  var t = document.createTextNode(m);

  /*
  var key = '$SUBSCRIBEBUTTON_';
  if(m.indexOf(key) >= 0) {
    btn = document.createElement('button');
    l.appendChild(btn);
    let b = m.indexOf(key) + key.length;
    let s = m.length;

    btn.value = m.substring(b, s);
    m = '';
   
    btn.innerHTML = btn.value;
    btn.onclick = function() {
      window.parent.chatLinkClicked(btn);
    }
    // hidden for now, I broke this
    btn.style.cssText = 'display:none;'
  }
  */
    
  l.appendChild(t);  
  e.appendChild(l);
  return l;
}

function appendMessagesToUnorderedList(l, array) {
  var i = 0;
  var altcolor = 'white';
  var bgColor = altcolor;

  while(i < array.length) {
    var offset = 0;
    let maxLen = 1000;
    var str = array[i];

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

