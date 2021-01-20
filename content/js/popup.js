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

function rtcPopupCreateIframe(handlerOpen, handlerClose) {
    console.debug('rtcPopupCreateIframe at location:' + document.location);

    closeHandler = handlerClose;

    loc = window.location.href.split("/").pop();
    if(loc != 'index_broadcast.html') {
        document.location = 'answer_upload.html';
        popupRecvOnly = false;
        parent.onLoadDoneAnswerUpload = handlerOpen;
    }
    else {
        handlerOpen();
    }
    console.debug('rtcPopupCreateIframe');
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
        }
        vidElem.play();
        window.parent.removeStartButton(vidElem, startButton);
        vidElem.startButton = null;
    }

    startButton.className = 'playButton';

    window.addStartButton(vidElem, startButton);

    console.debug('attachMediaStream: onloadedmetadata');
}

