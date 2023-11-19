/* chat-log as an array */

function appendMessageListElem(destList, m, isLoPriority) {
  var e = destList;
  var t = document.createElement('div');
  var l = document.createElement('li');

  l.className = isLoPriority ? 'chatListElem': 'chatListElemLow'

  t.className = 'chatEntry';
  var c = m.split(':')
  var c1 = document.createElement('div');
  var c2 = document.createTextNode(c[1]);

  t.appendChild(c1);
  c1.innerHTML = '<p style=\'color:red\'>'+c[0]+'</p><p style=\'color:gray\'>'+c[1]+'</p>';

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
      if(str.indexOf('server:') != 0) {
        var listElem = appendMessageListElem(l, str.substring(offset, offset+maxLen, str.indexOf('server:') >= 0));
     
        listElem.style.cssText = 'color:' + textColor + '; ' + 'background-color:'+ bgColor + '; list-style-type:none;' + 
        (isItalic ? ' font-style:italic; display:none;' : '');
      }
      offset += maxLen;
    }

    i += 1;
  }
}

var jsChatlogLines = [
%$CHATLOGJSARRAY$%
];

