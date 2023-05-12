/* chat-log as an array */

function appendMessageListElem(destList, m, isLoPriority) {
  var e = destList;
  var l = document.createElement('li');
  var t = isLoPriority ? document.createElement('I') : document.createTextNode(m);

  l.className = isLoPriority ? 'chatListElem': 'chatListElemLow'
  if(isLoPriority)
  {
    let it = document.createTextNode(m);
    t.appendChild(it);
    t = null;
  }

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
    
  if(t != null) l.appendChild(t);  
  e.appendChild(l);
  return l;
}

function appendMessagesToUnorderedList(l, array) {
  var i = 0;

  while(i < array.length) {
    var offset = 0;
    let maxLen = 1000;
    var str = array[i];
    var isItalic = str.indexOf('server:') >= 0;
    var bgColor = 'transparent';
    var textColor = isItalic ? 'darkgrey' : 'white';

    // this prefix must match the one used in main.c so we can color chat-lines by their prefix

    str = str.replace(/\+/g, ' ');
    while(offset < str.length && str.length > 0) {
      var listElem = appendMessageListElem(l, str.substring(offset, offset+maxLen, str.indexOf('server:') >= 0));
      listElem.scrollIntoView(false);
     
     listElem.style.cssText = 'color:' + textColor + '; ' + 'background-color:'+ bgColor + '; list-style-type:none;' + 
      (isItalic ? ' font-style:italic;' : '');
      offset += maxLen;
    }

    i += 1;
  }
}

var jsChatlogLines = [
%$CHATLOGJSARRAY$%
];

