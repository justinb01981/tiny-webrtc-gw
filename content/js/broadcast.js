// -- variables
var divRoom = null;

var vidChildW = 128;
var vidChildH = 96;

var divVideoHTML = "" + 
"<div id=\"div_$USERNAME_child\">" +
"<td>" +
"<table id=\"table_$USERNAME\" border=0>"+
    "<tr align=top><td>" +
        "<video controls autoplay class='videoChild' id=\"video_$USERNAME_remote\" width="+vidChildW.toString()+" height="+vidChildH.toString()+"></video>" +
    "</td>"+
    "<td>" +
        "<button id=\"btn_$USERNAME_1\" onClick=\"connectVideo(document.getElementById('video_$USERNAME_remote'), joinSDP(), true, '$USERNAME')\">show</button>" +
        "<button id=\"btn_$USERNAME_2\" onClick=\"onBtnMakePresent(this, '$USERNAME');\">presenter-ify</button>" +
        "<button id=\"btn_$USERNAME_3\" onClick=\"onBtnMute(this, '$USERNAME');\">stfu</button>" +
        "<button id=\"btn_$USERNAME_4\" onClick=\"onBtnClose(this, '$USERNAME');\">bye</button>" +
        "<input type=\"checkbox\" id=\"check_$USERNAME\" hidden=true>" +
    "</td></tr>"+
"</table>" +
"</td>" +
"<img hidden=true src='logo.jpg' onLoad='if(addUserLoad) addUserLoad(\"$USERNAME\"); this.hidden=true;'>" +
"</div>" +
"";
var addUserHTML = "<td><table border=1 style='margin:0; padding:0; display:inline-block; border-collapse:collapse;'><tr><td><img src='newUser.jpg'></td></tr><tr><td><button onClick='onBtnAddUser(\"\");'>Add User</button></td></tr></table></td>";
var winPopup = null;
var roomPopup = null;
var winPopupSdp = null;
var winPopupVideoTarget = null;
var winPopupRemoteConnection = null;

class VideoConnection {
  constructor(user, vidElem, videoConnection) {
    this.user = user;
    this.vidElem = vidElem;
    this.connection = videoConnection;
  }
}
var videoConnectionTable = {}

var localStream = null;
var audioSourceN = 0;
var videoSourceN = 0;
var audioSource = null;
var videoSource = null;
var videoSourceLabel = null;
var audioSourceLabel = null;

var localVideo = document.getElementById("localVideo");
var vidElemPrevConnection = null;
var vidPresenter = null;

var joinPopupLast = {connection:null, userName:null, roomName:null, recvOnlyChecked:null, stream:null};

var stoppedStreamLast = null;
var userCounter = 1;
var roomTable = '' + addUserHTML;
var roomTableCols = 1;

var controlHeight = 40;
var mainDivW = 800;
var mainDivH = 600;
var mainDivX = 10;
var mainDivY = 10;

var vidChildX;
var vidChildY;

var connectIframe;
var answerIframe;

var getMediaPromise;

var divPresenterClientWidth = 0;
var divPresenterClientHeight = 0;

var onLoadMedia = function() {
    console.debug("onLoadMedia() ...");
    return getMedia();
}

var addUserLoad = function(name) {
    var check = document.getElementById("check_"+name);
    if(!check.checked) {
        resizeObjectWithID("table_"+name, vidChildX, vidChildY, vidChildW+20, vidChildH+controlHeight);
        vidChildX += vidChildW + 100;
        if(vidChildX >= mainDivW) { 
            vidChildY += vidChildH+20;
            vidChildX = mainDivX;
        }
    }
}

var connectionWarning = false;

var autoJoinRoomDone = false;

// -- functions

function vidChildInit() {
    vidChildX = mainDivX;
    vidChildY = mainDivY + mainDivH;
}

function getSelectAudioDevice() {
    return document.getElementById('selectMicInput');
}

function getSelectVideoDevice() {
    return document.getElementById('selectCamInput');
}

function getSelectedRoom() {
    return document.getElementById('roomName').value;
}

function enumerateMedia() {

    navigator.mediaDevices.enumerateDevices().then( 
        function(sourceInfos) {
            for(var i = 0; i < sourceInfos.length; i++) {
                console.log('mediaDevices('+sourceInfos[i].kind+')['+i+']: ' + sourceInfos[i].label);

                var opt = document.createElement('option');
                opt.text = sourceInfos[i].label;
                opt.value = i;

                if(sourceInfos[i].kind == 'audio' || sourceInfos[i].kind == 'audioinput') {
                    document.getElementById('selectMicInput').add(opt);
                }
                else if(sourceInfos[i].kind == 'video' || sourceInfos[i].kind == 'videoinput') {
                    document.getElementById('selectCamInput').add(opt);
                }
                else {
                    document.getElementById('selectMicInput').add(opt);
                }
            }
        });
}

function getMedia() {

    getMediaPromise = new Promise(function(resolve, reject) {

    //if(localStream && localStream.getTracks()[0].readyState == "live") {
    //    resolve();
    //    return;
    //}

    navigator.mediaDevices.enumerateDevices().then(
        function(sourceInfos) {

            // TODO: if auto-joining then we can't use these ui select elements and have to chooose
            // based on sourceInfos
            var ai = -1;
            var vi = -1;

            var infoIdx = 0;
            for (info in sourceInfos) {
                console.debug('srcInfo[]: '+sourceInfos[info].kind+'');

                if (sourceInfos[info].kind == 'audioinput' && ai < 0) ai = infoIdx;
                if (sourceInfos[info].kind == 'videoinput' && vi < 0) vi = infoIdx;
                infoIdx += 1;
            }

            if(getSelectAudioDevice().selectedIndex >= 0) {
                console.debug("SUCCESS: found select-device form-field overriding default ");

                ai = ai + getSelectAudioDevice().selectedIndex;
                vi = vi + getSelectVideoDevice().selectedIndex;
            }

            getSelectAudioDevice().disabled = true;
            getSelectVideoDevice().disabled = true;

            /*
            for(var i = 0; i < sourceInfos.length; i++) {
                console.log('mediaDevices('+sourceInfos[i].kind+')['+i+']: ' + sourceInfos[i].label);
                if(sourceInfos[i].kind == 'audio' || sourceInfos[i].kind == 'audioinput') {
                    if(audioSourceN == ai) {
                        audioSource = sourceInfos[i].deviceId;
                        audioSourceLabel = sourceInfos[i].label;
                    }
                    ai++;
                }
                else if(sourceInfos[i].kind == 'video' || sourceInfos[i].kind == 'videoinput') {
                    if(videoSourceN == vi) {
                        videoSource = sourceInfos[i].deviceId;
                        videoSourceLabel = sourceInfos[i].label;
                    }
                    vi++;
                }
            }
            */
            audioSource = sourceInfos[ai].deviceId;
            audioSourceLabel = sourceInfos[ai].label;
            videoSource = sourceInfos[vi].deviceId;
            videoSourceLabel = sourceInfos[vi].label;           
            
            var constraints = {
                audio: {
                    deviceId: audioSource
                },
                video: {
                    deviceId: videoSource,
                    width: { min: 640, ideal: 1920 },
                    height: { min: 480, ideal: 1080 } 
                }
            };

            navigator.mediaDevices.getUserMedia(constraints).then(
                function (s) {
                    if(localStream) { 
                        resolve();
                        return;
                    } // hack

                    localStream = s;
                    attachMediaStream(localVideo, localStream);
                    localVideo.controls = true;
                    if(localVideo.startButton) {
                        localVideo.startButton.parentNode.removeChild(localVideo.startButton);
                        localVideo.startButton = null;
                    }
                    resolve();
                    localVideo.play();
                }).catch(
                function(e) {
                    reject();
                    //alert('get media failed\nmaybe try https?\ncamera/mic enabled?\n\n(reload the page after allowing)');
                }
            );
        }).catch(function(e) {
            console.debug('exception in getUserMedia:' + e);
        });
    });

    return getMediaPromise;
}

function broadcastOnLoad() {

    //if(document.cookie == '') {
    //    location = 'login.html';
    //}
    divRoom = document.getElementById("roomDivCursor");

    mainDivW = (document.body.clientWidth / 100) * 80;
    mainDivH = (document.body.clientHeight / 100) * 70;

    //resizeObjectWithID("videoMain", mainDivX, mainDivY, (mainDivW/100)*60, (mainDivH/100)*50);

    vidChildInit();

    //resizeObjectWithID("mainDiv", mainDivX, mainDivY, mainDivW, mainDivH);
    //resizeObjectWithID("mainDivTable", mainDivX, mainDivY, mainDivW, mainDivH);

    var userTotal = 0;
    /*
    i = 0;
    while(i < peerList.length) {
        onBtnAddUser(peerList[i].name);
        i++;
        userTotal++;
    }
    */

    /*
    while(userTotal < 1) {
        onBtnAddUser('');
        userTotal++;
    }
    */
    
    resizeObjectWithID("roomAddButtonDiv", mainDivX, vidChildY+vidChildH/2, 50, 50);

    var userElem = document.getElementById('userName');
    userElem.value = myUsername;
    setLoggedIn();

    parseURLArguments();

    onLoadDone();

    userElem.scrollIntoView();
}

function parseURLArguments() {
    let params = new URLSearchParams(document.location.search.substring(1));
    let room = params.get('joinroom');

    let cam = params.get('camera');

    let frameChild = document.getElementById('connect_iframe');
    let roomField = document.getElementById('roomName');

    if(cam && localStream == null) {
        getCameraCheckbox().checked = true;

        // TODO: this is janky because it duplicates code in the connect_iframe onload
        getMedia().then( function() {
            autoJoinRoomDone = true;
            roomField.value = room;
            frameChild.contentWindow.onJoin();
        });
        return;
    }

    // DO not fall thru to here except from post-getmedia closure
    if(room && !autoJoinRoomDone) {
        console.debug('auto-joining room ' + room);

        // necessary so we don't try and re-join every connect_iframe refresh, just the first page landing
        autoJoinRoomDone = true;

        roomField.value = room;

        frameChild.contentWindow.onJoin();
    }
}

function setLoggedIn() {
    var h = document.getElementById('login');
    if(myUsername.indexOf('nobody') == 0) {
        h = document.getElementById('logout');
        //document.getElementById('userName').style = 'display:none';
    }
    h.style = 'display:none;';
}

function onLeaveRoom(videoElemCaptured) {
    console.debug('onLeaveRoom');

    var elemRemote = videoElemCaptured;
    var elemLocal = document.getElementById('localVideo');

    if(elemRemote != null && elemRemote.closeAction) elemRemote.closeAction(elemRemote);
    if(elemLocal.closeAction) elemLocal.closeAction(elemLocal);

    getSelectAudioDevice().disabled = false;
    getSelectVideoDevice().disabled = false;

    let t = window.parent.videoConnectionTable;
    // TODO: remove all video elements, calling closeAction for each
    for (var v of Object.entries(t)) {
        console.debug('calling vidElem.closeAction');
        videoConnectionTable[v[0]].vidElem.closeAction();
    }

    window.parent.localVideo.srcObject = null;
    // TODO: this works but a ref to the device is lingering somewhere - webcam light doesn tturn off
    window.parent.localStream = null;
}

function logout() {
    location = 'logout.html';
}

function removeCookie() {
    document.cookie = "authCookieJS12242016=%$AUTHCOOKIE$%; expires=Thu, 01 Jan 1970 00:00:01 GMT; path=/";
    alert(myUsername + ' logged out...');
}

function macroHelper(a, b, c) {
    v = a;
   while(1) {
        var o = v;
        v = v.replace(b, c);
        if(o == v) break;
    }
    return v;
}

function rebootLocalVideo(vidElem) {
    if(vidElem.style.cssText.indexOf('none') >= 0) {
        vidElem.style.cssText = '';
    } else {
        vidElem.style.cssText = 'display:none;';
    }
}

// TODO: move this
function videoElemForUser(userName) {
  var result = null;
  let t = window.parent.videoConnectionTable;
  Object.keys(t).forEach(function(key) {
    if(t[key].user == userName) {
      // return video element containing table-row (see popup.js)
      result = t[key].vidElem;
    }
  });

  return result;
}

function joinPopupClose(connection, userName, recvOnlyChecked, roomName) {

    console.debug('joinPopupClose called: ' + connection + '/'+userName + '/'+recvOnlyChecked + '/'+roomName);

    joinPopupLast.connection = connection;
    joinPopupLast.userName = userName;
    joinPopupLast.roomName = roomName;
    joinPopupLast.recvOnlyChecked = recvOnlyChecked;
    joinPopupLast.stream = connection.getRemoteStreams()[0];

    winPopupRemoteConnection = connection;
   
    attachMediaStream(winPopupVideoTarget, winPopupRemoteConnection.getRemoteStreams()[0]);

    videoConnectionTable[winPopupVideoTarget.id] = new VideoConnection(userName, winPopupVideoTarget, winPopupRemoteConnection);

    console.debug('joinPopupClose called3');

    window.parent.joinPopupCloseDone(winPopupVideoTarget);
    winPopupVideoTarget = null;

    console.debug('joinPopupClose called4');

    //window.parent.updateViewersLabelDEPRECATED(window.parent.peersList);
}

function joinIframeOnLoadBroadcast() {
    console.debug('joinIframeOnLoadBroadcast');

    var connIFrameState = window.iframeConnectState;

    var winParent = window.parent;
    var docP = winParent.document;
    var docCForm = answerIframe.document.theform;

    var user = docP.getElementById('userName').value;
    var room = docP.getElementById('roomName').value;
    
    docCForm.my_name.value = user;
    docCForm.room_name.value = room;
    docCForm.peerstream_recv.value = user;
    if(connIFrameState.selectedUser)
    {
        console.debug('a=watch='+connIFrameState.selectedUser);
        docCForm.appendsdp.value += 'a=watch='+connIFrameState.selectedUser+'\n';

        // moved this nulling to iframeOnLoad()
        //window.parent.iframeConnectState.selectedUser = null;
    }

    if(connIFrameState.joinMode == 'watch') {
        docCForm.appendsdp.value += 'a=recvonly\n';
        docCForm.recvonly.checked = true;
    }
    else {
        docCForm.offersdp.value = docCForm.offersdp.value.replace(/a=sendrecv/g, 'a=recvonly');
    }

    joinPopupOnLoad2(answerIframe, window);
}

function joinPopupOnLoad2(win, winSource) {
    win.document.theform.answersdp.value = '';
    win.localStream = winSource.localStream;
    win.remoteVideo = winSource.winPopupVideoTarget;

    win.closeHandler = winSource.joinPopupClose;
    win.remoteConnection = new winSource.RTCPeerConnection(winSource.remoteConnectionStunConfig);
}

function disconnectVideo(vidElem) {
  console.debug('disconnectVideo');

  var entry = videoConnectionTable[vidElem.id];

  if(entry != null)
  {
    var conn = entry.connection;

    if(conn.signalingState != 'closed')
    {
      // TODO: closing conn component streams? 
    }
    conn.close();
    delete videoConnectionTable[vidElem.id];
  }
}

function connectVideoIframe(windowSrc, videoElem, afterOnLoad, afterClose) {

  console.debug('connectVideoIframe in doc: ' + window.parent.document.location);
  window.winPopupVideoTarget = videoElem;
  windowSrc.rtcPopupCreateIframe(afterOnLoad, afterClose);
}

function onBtnMute(btn, userName) {
    var vidSrc = document.getElementById('video_'+userName+'_remote');
    vidSrc.muted = !vidSrc.muted;
    if(vidPresenter == vidSrc) {
        document.getElementById('videoMain').muted = vidSrc.muted;
    }
}

function onBtnMakePresent(btn, userName) {
    var vid = document.getElementById('videoMain');
    var vidSrc = document.getElementById('video_'+userName+'_remote');
    reattachMediaStream(vid, vidSrc);
    vid.play();
    vidPresenter = vidSrc;

    var divPresenter = document.getElementById('thPresenter');
    if(divPresenterClientWidth == 0) divPresenterClientWidth = divPresenter.clientWidth;
    if(divPresenterClientHeight == 0) divPresenterClientHeight = divPresenter.clientHeight;
    vid.width = divPresenterClientWidth;
    vid.height = divPresenterClientHeight;
}

function deleteElementAfter(elem, parentOfElem, ms)
{
   setTimeout(function f() {
       parentOfElem.removeChild(elem);
   }, ms);
}

function unmuteAfter(videlem, ms)
{
   setTimeout(function f() {
       try {
           videlem.muted = false;
           videlem.play();
       }
       catch(exc) {
           console.debug('unmuteAfter: failed with ' + exc);
       }
   }, ms);
}

function prepareVideo(containerTable, labelText)
{
    console.debug('prepareVideo called');

    var table = containerTable;

    var row = document.createElement('tr');
    var col = document.createElement('td');

    var videoContainer = document.createElement('div');
    var videoContainerParent = document.createElement('div');
    var videoElemToAdd = document.createElement('video');
    var labelToAdd = document.createTextNode(labelText);
    var paraToAdd = document.createElement('p');
    var stopButton = document.createElement('button');
    var loadingButton = document.createElement('button');

    paraToAdd.appendChild(labelToAdd);
    paraToAdd.className = 'controlsPara';

    videoContainerParent.className = 'videoContainerDiv';

    stopButton.className = 'stopButton';
    loadingButton.className = 'loadingButton';

    stopButton.onclick = function () {
        let vidElem = videoElemToAdd;

        vidElem.muted = true;
        if(vidElem.closeAction) {
            vidElem.closeAction();
        }

        vidElem.controls = false;
        if(vidElem.srcObject) {
            vidElem.srcObject.getTracks().forEach(track=>track.stop());
            vidElem.srcObject = null;
        }
    }

    loadingButton.appendChild(document.createTextNode('loading... please wait'));
    deleteElementAfter(loadingButton, videoContainer, 5000);

    videoContainerParent.appendChild(videoContainer);
    videoContainer.className = 'videoContainerFake';
    videoContainer.appendChild(paraToAdd);
    videoContainer.appendChild(videoElemToAdd);
    videoContainer.appendChild(loadingButton);
    col.appendChild(videoContainerParent);
    col.className = 'videoCell';
    paraToAdd.appendChild(stopButton);
    row.className = 'videoCellRow';
    row.appendChild(col);

    videoElemToAdd.className = 'videoMain';
    videoElemToAdd.autoplay = true;
    videoElemToAdd.muted = true;
    videoElemToAdd.controls = true;
    videoElemToAdd.setAttribute('playsinline', 'true');
    videoElemToAdd.setAttribute('webkit-playsinline', 'webkit-playsinline');
    videoElemToAdd.id = 'video' + Math.random();
    videoElemToAdd.parentRow = row;
    videoElemToAdd.stopButton = stopButton;
    videoElemToAdd.controlPara = paraToAdd;
    //videoElemToAdd.style.width = (window.document.body.clientWidth - 100);

    // this closeAction will be replaced and called by the replacement (chained)
    videoElemToAdd.closeAction = function f() {
        table.removeChild(row);
    }
    unmuteAfter(videoElemToAdd, 1000);

    table.appendChild(row);

    iframeConnectState.videoElem = videoElemToAdd;

    hideRoomEmptyLabel();

    return row;
}

function prepareVideoPlaceholder(containerTable, labelText) {

    prepareVideo(containerTable, labelText);
    let vidElem = iframeConnectState.videoElem;
    let par = vidElem.parentNode;

    par.removeChild(vidElem);

    var phButton = document.createElement('button');

    phButton.class = 'phButton';
    phButton.appendChild(document.createTextNode('👀'));
    par.appendChild(phButton);
}

function rowForVideo(videoElem)
{
    console.debug('WARN: rowForVideo is dead code and should be removed!');
    return videoElem.parentDiv;
}

function addStartButton(vidElem, button) {
    if(vidElem.controlPara == null) return;
    vidElem.controlPara.appendChild(button);
}

function removeStartButton(vidElem, button) {
    if(vidElem.controlPara == null) return;
    vidElem.controlPara.removeChild(button);
}

function stopSending() {
    s = joinPopupLast.connection.getLocalStreams()[0]
    if (s) {
        stoppedStreamLast = s
        joinPopupLast.connection.removeStream(s)
    }
    else {
        joinPopupLast.connection.addStream(stoppedStreamLast)
    }
}

function channelPost() {
    document.channelForm.submit();
}

function getRoomElem() {
    return document.getElementById('roomName');
}

function getRoom() {
    var e = getRoomElem();
    if(e) {
        return e.value;
    }
    return '';
}

function roomEdited(elemTextArea) {
    var iframeDoc = connectIframe.document;
    var e = iframeDoc.getElementById('joinButton');
    if(e != null) e.disabled = true;
    if(elemTextArea.value.length > 0) {
        if(e != null) e.disabled = false;
        elemTextArea.value = elemTextArea.value.toLowerCase();
    }
}

function startLiveBcast(elemButton) {
    e = getRoomElem();
    connectVideo(document.getElementById('videoMain'), false, e.value);
    
    elemButton.onclick = function() {
        console.debug('Leaving room ' + e.value);
        e.disabled = false
        elemButton.textContent = 'Join';
        elemButton.onclick = function (){
            startLiveBcast(elemButton);
        };
    }
}

function getCameraCheckbox() {
    return document.getElementById('enableVideoCheckbox');
}

function errorSchedule() {
    connectionWarning = true;
    let f = function() {
        if(connectionWarning) {
            alert('warning: media connection failed - confirm audio/video device permissions (or contact the admin)');
        }
    }

    setTimeout(f, 7000);
}

function errorCancel() {
    console.debug('errorCancel: found us');
    connectionWarning = false;
}
