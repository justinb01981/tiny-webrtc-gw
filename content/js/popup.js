var remoteConnection = null;
var remoteConnectionOffer = null;
var remoteConnectionAnswer = null;
var remoteConnectionLocalDescription = null;
var remoteVideo = null;
var localConnection = null;
var localStream = null;
var iceCandidate = null;
var iceCandidateID = 0;
var remoteConnectionStunConfig = %$STUNCONFIGJS$%;
var closeHandler = null;
//var stunHost = "%$HOSTNAME$%";
var stunHost = document.location.host;
//var stunPort = "3478";
var stunPort = "%$RTPPORT$%";
//var onLoadDoneAnswerUpload;

function onPeerClick(peername, elem) {
    document.theform.peerstream_recv.value = peername;
    document.theform.appendsdp.value = 'a=watch=' + peername + '\n';
    document.theform.appendsdp.value += 'a=myname=' + document.theform.my_name.value + '\n';
}

function onIceCandidate(event) {
    console.debug("onIceCandidate");

    if (event.candidate && iceCandidate == null) {
        //var c = event.candidate;
        var c = {};
        console.debug("onIceCandidate.event.candidate:"+JSON.stringify(event.candidate));

        //iceCandidate = event.candidate;
        if(remoteConnectionStunConfig == null) {
            //c.candidate = "candidate:" + iceCandidateID++ + " 1 UDP " + 1234+iceCandidateID + " " + stunHost + " " + stunPort + " typ host";
            c.candidate = "%$RTCICECANDIDATE$%";
            c.sdpMid = event.candidate.sdpMid;
            c.sdpMLineIndex = event.candidate.sdpMLineIndex;
            // JB: removed this to avoid exception "unknown ICE Ufrag" with firefox
            //c.usernameFragment = event.candidate.usernameFragment;

            //alert(c.candidate);
            console.debug("onIceCandidate:"+JSON.stringify(c.candidate));
        }
        //alert('iceCandidate:' + c.candidate);
        remoteConnection.addIceCandidate(
            new RTCIceCandidate(c)).then(
                _ => {
                    console.debug("onIceCandidate.then");
                    iceCandidate = event.candidate;
                }).catch(
                e => {
                    console.debug("error in addIceCandidate: " + e);
                    iceCandidate = null;
                });
    }
}

function onConnect() {
    //var servers = {"iceServers": [{"url": "stun:"+stunHost+":"+stunPort}]};
    var servers = null;
    //remoteConnection = new RTCPeerConnection(servers);

    // TODO: reorder this so that form can submit SDP prior to STUN/ICE starting
    remoteConnection.onicecandidate = onIceCandidate;

    remoteConnection.onaddstream = function(e) {
        //alert('onAddStream' + e.stream);
        console.debug('remoteConnection.ontrack');
    };

    /* optionally set local description (send) */
    if(!document.theform.recvonly.checked) {
        //remoteConnection.addStream(localStream);

        localStream.getTracks().forEach(track => remoteConnection.addTrack(track, localStream));
    }

    remoteConnectionOffer = new RTCSessionDescription({type: 'offer', sdp: document.theform.offersdp.value});

    remoteConnection.setRemoteDescription(remoteConnectionOffer).then(
        function () {
            console.debug('setRemoteScription.then');

            remoteConnection.createAnswer({'mandatory': {'OfferToReceiveAudio': true, 'OfferToReceiveVideo': true}}).then(
                function (answer) {
                    remoteConnectionAnswer = answer;
                    document.theform.answersdp.value = answer.sdp;
                    doSubmit();

                    // moved remoteConnection.setLocalDescription() to broadcastStart()

                }).catch( function (err) { alert('createAnswer fail:'+err); });
        }).catch(
            function (err) {
                alert('setRemoteDescription fail: '+err);
            }
        );

    //localConnection = new RTCPeerConnection(servers);

}

function broadcastStart(onSuccess, onFailure) {
    var remoteStream = remoteConnection.getRemoteStreams()[0];

    remoteConnection.setLocalDescription(remoteConnectionAnswer).then(
        function () {
            console.debug('remoteConnection.setLocalDescription');
            if(remoteStream == null) {
                console.debug('remoteConnection has no streams (sendonly?)');
                onSuccess();
                return;
            }
            //attachMediaStream(remoteVideo, remoteConnection.getRemoteStreams()[0]);
            //remoteStream.getTracks().forEach(track => remoteConnection.addTrack(track, remoteStream));
            onSuccess();
        }).catch(
            function (err) {
            console.debug('remoteConnection.setLocalDescription error:'+err);
            onFailure();
        }
    );
}

function doSubmit() {
    var appsdp = document.theform.appendsdp;
    var myname = document.theform.my_name;
    if(appsdp.value.indexOf('a=watch=') < 0) {
        console.debug('no a=watch found, adding one');
        appsdp.value += 'a=watch=' + myname.value;
    }
    document.finalform.answersdp.value = document.theform.answersdp.value + '\n' + document.theform.appendsdp.value;
    document.finalform.target = 'iframe_submit';
    document.finalform.submit();
}

function iframeOnLoad() {
    broadcastStart(
        function() {
            let user = window.parent.iframeConnectState.selectedUser;
            window.parent.iframeConnectState.selectedUser = null;

            closeHandler(remoteConnection, user, document.theform.recvonly.checked, document.theform.room_name.value);
        },
        function() {
            alert('broadcastStart failed');
        }
    );
}

function rtcPopupCreate(handlerOpen, handlerClose, recvOnly, watchUser) {
    var randomNum = Math.ceil(Math.random() % 10 * 1000);
    var w = window.open('answer_upload.html?name='+watchUser, 'sdp_answer_upload' + randomNum, '');
    popupRecvOnly = recvOnly;
    //w.document.body.onload = handlerOpen1;
    onLoadDoneAnswerUpload = handlerOpen;
    closeHandler = handlerClose;

    return w;
}

function rtcPopupCreateIframe(handlerOpen, handlerClose) {
    document.location = 'answer_upload.html';
    popupRecvOnly = false;
    //w.document.body.onload = handlerOpen1;
    console.debug('rtcPopupCreateIframe');
    parent.onLoadDoneAnswerUpload = handlerOpen;
    closeHandler = handlerClose;
}

function roomlistPopupCreate(roomName) {
    var w = window.open('room.html?room='+roomName, 'room' + roomName, 'width=250,height=300');
}

function resizeObjectWithID(idName, x, y, w, h) {
    var d = document.getElementById(idName);
    if(d) { 
        d.style.cssText = 'position:fixed; top:'+y.toString()+'px; left:'+x.toString()+'px; width:'+w.toString()+'px; height:'+h.toString()+'px;';
    }
}

function attachMediaStream(vidElem, vidStream)
{
    // TODO: have single function for building vidElem and sibling nodes as rows in the table instead of splitting in multiple JS files

    var cssButton = 'width:32px; height:32px; position:relative; top:-60px; left:150px; background-position:center; background-repeat:no-repeat;';
    if(vidElem.srcObject != null) {
        console.debug('attachMediaStream: video element srcObject != null, ignoring');
        return;
    }

    vidElem.srcObject = vidStream;

    var startButton = document.createElement('button');

    startButton.vidElem = vidElem;

    startButton.onclick = function() {
        if(vidElem.muted) {
            vidElem.controls = true;
            vidElem.muted = false;
                vidElem.startButton.style.cssText = cssButton + ' background-image:url(/content/img/stop.png); z-index:1;';
            }
            else {
                vidElem.muted = true;
                if(vidElem.closeAction) {
                    vidElem.closeAction();

                    vidElem.onended = null;
                    console.debug('vidElem.onended');

                    vidElem.controls = false;
                    if(vidElem.srcObject) {
                        // commented this out since it kills local streams and are unrecoverable
                        vidElem.srcObject.getTracks().forEach(track=>track.stop());
                        vidElem.srcObject = null;
                    }
                    //if(vidElem.startButton) return;

                    //vidElem.startButton.onRemove.removeChild(vidElem.startButton)
                    vidElem.parentRow.remove();
                    vidElem.startButton = null;
                }
            }
        }

    vidElem.startButton = startButton;

    startButton.style.cssText = cssButton + ' background-image:url(/content/img/unmute.png); z-index:1;';

    if(vidElem.parentNode) vidElem.parentNode.appendChild(startButton);

    console.debug('attachMediaStream: onloadedmetadata');
}

function prepareVideo(containerTable, labelText)
{
    var table = containerTable;

    var row = window.parent.document.createElement('tr');
    var col = window.parent.document.createElement('td');

    var videoElemToAdd = window.parent.document.createElement('video');
    var labelToAdd = window.parent.document.createTextNode(labelText);
    var paraToAdd = window.parent.document.createElement('p');

    paraToAdd.appendChild(labelToAdd);
    paraToAdd.style.cssText = 'z-index:1; position:relative; top:20px; left:0px; width:100px; background-color:black;';

    
    col.appendChild(paraToAdd);
    col.appendChild(videoElemToAdd);
    row.appendChild(col);

    videoElemToAdd.className = 'videoMain';
    videoElemToAdd.autoplay = true;
    videoElemToAdd.muted = true;
    videoElemToAdd.setAttribute('playsinline', 'true');
    videoElemToAdd.setAttribute('webkit-playsinline', 'webkit-playsinline');
    videoElemToAdd.id = 'video' + window.parent.videoElemIdCounter;
    videoElemToAdd.parentRow = row;

    // TODO: instead of using a counter, use username to identify each videoElem
    window.parent.videoElemIdCounter += 1;

    table.appendChild(row);

    window.parent.iframeConnectState.videoElem = videoElemToAdd;

    return row
}
