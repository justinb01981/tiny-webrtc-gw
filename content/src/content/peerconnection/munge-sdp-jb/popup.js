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
var stunHost = "%$HOSTNAME$%";
//var stunPort = "3478";
var stunPort = "%$RTPPORT$%";
var handlerOpenStage2 = null;
function onPeerClick(peername, elem) {
    document.theform.peerstream_recv.value = peername;
    document.theform.appendsdp.value = 'a=watch=' + peername + '\n';
    document.theform.appendsdp.value += 'a=myname=' + document.theform.my_name.value + '\n';
}
function onIceCandidateOK(c) {
}
function onIceCandidateFail(c) {
}
function onIceCandidate(event) {
    if (event.candidate && iceCandidate == null) {
        var c = event.candidate;
        iceCandidate = c;
        if(remoteConnectionStunConfig == null) {
            //c.candidate = "candidate:" + iceCandidateID++ + " 1 UDP " + 1234+iceCandidateID + " " + stunHost + " " + stunPort + " typ host";
            c.candidate = "%$RTCICECANDIDATE$%";
            //alert(c.candidate);
        }
        //alert('iceCandidate:' + c.candidate);
        remoteConnection.addIceCandidate(
            new RTCIceCandidate(c),
            onIceCandidateOK,
            onIceCandidateFail
        );
    }
}
function onConnect() {
    //var servers = {"iceServers": [{"url": "stun:"+stunHost+":"+stunPort}]};
    var servers = null;
    //remoteConnection = new RTCPeerConnection(servers);

    remoteConnection.onicecandidate = onIceCandidate;

    /* optionally set local description (send) */
    if(!document.theform.recvonly.checked) {
        remoteConnection.addStream(localStream);
    }

    remoteConnection.onaddstream = function(e) {
        //alert('onAddStream' + e.stream);
    };

    remoteConnectionOffer = new RTCSessionDescription({type: 'offer', sdp: document.theform.offersdp.value});
    remoteConnection.setRemoteDescription(
        remoteConnectionOffer,
        (function f1() {
            remoteConnection.createAnswer(
                function (e){
                    //alert('createAnswerOK' + e.sdp);
                    remoteConnectionAnswer = e; document.theform.answersdp.value = e.sdp;
                    remoteConnection.setLocalDescription(
                        remoteConnectionAnswer,
                        function (){
                            //alert('setlocalDescription success');
                            doSubmit();
                        },
                        function(){
                        }
                    );
                },
                (function fail() {alert('fail');}),
                {'mandatory': {'OfferToReceiveAudio': true, 'OfferToReceiveVideo': true}}
            );
        }),
        (function f2() {
            alert('setRemoteDescriptionFail');
        })
    );
    //alert('setRemoteDescription done');

    //localConnection = new RTCPeerConnection(servers);
    attachMediaStream(remoteVideo, remoteConnection.getRemoteStreams()[0]);
}
function doSubmit() {
    document.finalform.answersdp.value = document.theform.answersdp.value + '\n' + document.theform.appendsdp.value;
    document.finalform.submit();
    closeHandler(remoteConnection, document.theform.my_name.value, document.theform.recvonly.checked);
}
function handlerOpen1() {
    handlerOpenStage2();
}
function rtcPopupCreate(handlerOpen, handlerClose, recvOnly, watchUser) {
    var randomNum = Math.ceil(Math.random() % 10 * 1000);
    var w = window.open('answer_upload2.html?args='+watchUser, 'sdp_answer_upload' + randomNum, 'width=250,height=550');
    popupRecvOnly = recvOnly;
    w.document.body.onload = handlerOpen1;
    handlerOpenStage2 = handlerOpen;
    closeHandler = handlerClose;
    return w;
}
function roomlistPopupCreate(roomName) {
    var w = window.open('room.html?args='+roomName, 'room' + roomName, 'width=250,height=550');
}
function resizeObjectWithID(idName, x, y, w, h) {
    var d = document.getElementById(idName);
    d.style.cssText = 'position:fixed; top:'+y.toString()+'px; left:'+x.toString()+'px; width:'+w.toString()+'px; height:'+h.toString()+'px;';
}
