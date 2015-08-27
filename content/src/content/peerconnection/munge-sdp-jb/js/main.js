/*
 *  Copyright (c) 2014 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */

'use strict';

var getMediaButton = document.querySelector('button#getMedia');
var createPeerConnectionButton =
    document.querySelector('button#createPeerConnection');
var createOfferButton = document.querySelector('button#createOffer');
var setOfferButton = document.querySelector('button#setOffer');
var createAnswerButton = document.querySelector('button#createAnswer');
var setAnswerButton = document.querySelector('button#setAnswer');
var joinButton = document.querySelector('button#doJoin');
var joinButton2 = document.querySelector('button#doJoin2');
var joinButton3 = document.querySelector('button#doJoin3');
var hangupButton = document.querySelector('button#hangup');

createPeerConnectionButton.hidden = true;
createOfferButton.hidden = true;
setOfferButton.hidden = true;
createAnswerButton.hidden = true;
setAnswerButton.hidden = true;

getMediaButton.onclick = getMedia;
createPeerConnectionButton.onclick = createPeerConnection;
createOfferButton.onclick = createOffer;
setOfferButton.onclick = setOffer;
createAnswerButton.onclick = createAnswer;
setAnswerButton.onclick = setAnswer;
joinButton.onclick = join;
joinButton2.onclick = createAnswerJoin;
joinButton3.onclick = joinComplete;
hangupButton.onclick = hangup;

//var stunHost = "54.245.225.29";
//var stunHost = "192.168.1.123";
var stunHost = "%$HOSTNAME$%";
var stunPort = "3478";

var offerSdpTextarea = document.querySelector('div#local textarea');
var answerSdpTextarea = document.querySelector('div#remote textarea');

var audioSelect = document.querySelector('select#audioSrc');
var videoSelect = document.querySelector('select#videoSrc');

audioSelect.onchange = videoSelect.onchange = getMedia;

var localVideo = document.querySelector('div#local video');
var remoteVideo = document.querySelector('div#remote video');

var selectSourceDiv = document.querySelector('div#selectSource');

var localPeerConnection;
var remotePeerConnection;
var localStream;
var remoteStream;
var sdpConstraintsSendRecv = {
  'mandatory': {
    'OfferToReceiveAudio': true,
    'OfferToReceiveVideo': true
  }
};
var sdpConstraintsRecvOnly = {
  'mandatory': {
    'OfferToReceiveAudio': true,
    'OfferToReceiveVideo': true,
    'OfferToSendAudio': false,
    'OfferToSendVideo': false
  }
};
var sdpConstraints = sdpConstraintsSendRecv;

getSources();
getMedia();

offerSdpTextarea.disabled = false;
offerSdpTextarea.value = joinSDP();

function joinSDP()
{
var sdpStatic = "v=0\n" + 
"o=mozilla...THIS_IS_SDPARTA-38.0.1 1702670192771025677 0 IN IP4 0.0.0.0\n" + 
"s=-\n" + 
"t=0 0\n" + 
"a=fingerprint:sha-256 5C:FF:65:F6:7E:39:38:E6:CF:49:08:E5:73:2C:93:0E:59:13:24:23:22:37:10:50:6E:F1:9E:4A:45:DB:25:F4\n" + 
"a=group:BUNDLE sdparta_0 sdparta_1\n" + 
"a=ice-options:trickle\n" + 
"a=msid-semantic:WMS *\n" + 
"m=audio 9 RTP/SAVPF 109 9 0 8\n" + 
"c=IN IP4 0.0.0.0\n" + 
"a=sendrecv\n" + 
"a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\n" + 
"a=ice-pwd:230r89wef32jsdsjJlkj23rndasf23rlknas\n" +
"a=ice-ufrag:aaaaaaaa\n" + 
"a=mid:sdparta_0\n" + 
"a=msid:{7e5b1422-7cbe-3649-9897-864febd59342} {6fca7dee-f59d-3c4f-be9c-8dd1092b10e3}\n" + 
"a=rtcp-mux\n" + 
"a=rtpmap:109 opus/48000/2\n" + 
"a=rtpmap:9 G722/8000/1\n" + 
"a=rtpmap:0 PCMU/8000\n" + 
"a=rtpmap:8 PCMA/8000\n" + 
"a=setup:actpass\n" + 
"a=ssrc:744719343 cname:{5f2c7e38-d761-f64c-91f4-682ab07ec727}\n" + 
"m=video 9 RTP/SAVPF 120 126 97\n" + 
"c=IN IP4 0.0.0.0\n" + 
"a=sendrecv\n" + 
/*
"a=fmtp:120 max-fs=12288;max-fr=60\n" + 
*/
"a=fmtp:120 max-fs=450;max-fr=60\n" + 
"a=fmtp:126 profile-level-id=42e01f;level-asymmetry-allowed=1;packetization-mode=1\n" + 
"a=fmtp:97 profile-level-id=42e01f;level-asymmetry-allowed=1\n" + 
"a=ice-pwd:230r89wef32jsdsjJlkj23rndasf23rlknas\n" +
"a=ice-ufrag:aaaaaaaa\n" + 
"a=mid:sdparta_1\n" + 
"a=msid:{7e5b1422-7cbe-3649-9897-864febd59342} {f46f496f-30aa-bd40-8746-47bda9150d23}\n" + 
"a=rtcp-fb:120" +
" ccm" + 
/*" fir" +*/
" pli" +
"\n" + 
/*
"a=rtcp-fb:120 nack\n" + 
"a=rtcp-fb:120 nack pli\n" + 
*/
/*
"a=rtcp-fb:120 ccm fir\n" + 
*/
/*
"a=rtcp-fb:126 nack\n" + 
"a=rtcp-fb:126 nack pli\n" + 
*/
"a=rtcp-fb:126 ccm fir\n" + 
/*
"a=rtcp-fb:97 nack\n" + 
"a=rtcp-fb:97 nack pli\n" + 
*/
"a=rtcp-fb:97 ccm fir\n" + 
"a=rtcp-mux\n" + 
"a=rtpmap:120 VP8/90000\n" +
"a=rtpmap:126 H264/90000\n" +
"a=rtpmap:97 H264/90000\n" +
"a=setup:actpass\n" +
"a=ssrc:790737109 cname:{5f2c7e38-d761-f64c-91f4-682ab07ec727}\n"
;
  return sdpStatic;
}

function getSources() {
  if (typeof MediaStreamTrack === 'undefined') {
    alert(
      'This browser does not support MediaStreamTrack.\n\nTry Chrome Canary.');
  } else {
    MediaStreamTrack.getSources(gotSources);
    selectSourceDiv.classList.remove('hidden');
  }
}

function gotSources(sourceInfos) {
  var audioCount = 0;
  var videoCount = 0;
  for (var i = 0; i < sourceInfos.length; i++) {
    var option = document.createElement('option');
    option.value = sourceInfos[i].id;
    option.text = sourceInfos[i].label;
    if (sourceInfos[i].kind === 'audio') {
      audioCount++;
      if (option.text === '') {
        option.text = 'Audio ' + audioCount;
      }
      audioSelect.appendChild(option);
    } else {
      videoCount++;
      if (option.text === '') {
        option.text = 'Video ' + videoCount;
      }
      videoSelect.appendChild(option);
    }
  }
}

function getMedia() {
  getMediaButton.disabled = true;
  createPeerConnectionButton.disabled = false;
  joinButton.disabled = false;

  if (localStream) {
    localVideo.src = null;
    localStream.stop();
  }
  var audioSource = audioSelect.value;
  trace('Selected audio source: ' + audioSource);
  var videoSource = videoSelect.value;
  trace('Selected video source: ' + videoSource);

  var constraints = {
    audio: {
      optional: [{
        sourceId: audioSource
      }]
    },
    video: {
      optional: [{
        sourceId: videoSource
      }]
    }
  };
  trace('Requested local stream');
  getUserMedia(constraints, gotStream, function(e) {
    console.log('navigator.getUserMedia error: ', e);
  });
}

function gotStream(stream) {
  trace('Received local stream');
  // Call the polyfill wrapper to attach the media stream to this element.
  attachMediaStream(localVideo, stream);
  localStream = stream;
  join();
}

function createPeerConnection() {
  createPeerConnectionButton.disabled = true;
  createOfferButton.disabled = false;
  createAnswerButton.disabled = false;
  setOfferButton.disabled = false;
  setAnswerButton.disabled = false;
  hangupButton.disabled = false;
  trace('Starting call');
  var videoTracks = localStream.getVideoTracks();
  var audioTracks = localStream.getAudioTracks();
  if (videoTracks.length > 0) {
    trace('Using video device: ' + videoTracks[0].label);
  }
  if (audioTracks.length > 0) {
    trace('Using audio device: ' + audioTracks[0].label);
  }
  //var servers = null;
  var servers = {"iceServers": [{"url": "stun:"+stunHost+":"+stunPort}]};
  localPeerConnection = new RTCPeerConnection(servers);
  trace('Created local peer connection object localPeerConnection');
  localPeerConnection.onicecandidate = iceCallback1;
  remotePeerConnection = new RTCPeerConnection(servers);
  trace('Created remote peer connection object remotePeerConnection');
  remotePeerConnection.onicecandidate = iceCallback2;
  remotePeerConnection.onaddstream = gotRemoteStream;

  localPeerConnection.addStream(localStream);
  trace('Adding Local Stream to peer connection');
}


/* JOIN */
var offerSDPJoin;
var answerSDPJoin;

function joinIdentityFailed() {
  alert('joinIdentityFailed');
}

function gotDescription1Join(description) {
  alert('offer sdp:\n' + description.sdp);

  offerSdpTextarea.disabled = false;
  offerSdpTextarea.value = description.sdp;

  var sdp = description.sdp;

  sdp = maybeAddLineBreakToEnd(sdp);
  var offer = new RTCSessionDescription({
    type: 'offer',
    sdp: sdp
  });

  remotePeerConnection.setRemoteDescription(offer,
      onSetSessionDescriptionSuccess,
      onSetSessionDescriptionError);

  createAnswerJoin();
}

function joinComplete() {
  var answerElem = winPopup.document.theform.answersdp;
  var answerAppendElem = winPopup.document.theform.appendsdp;
  var myUserElem = winPopup.document.theform.my_name;
  var watchUserElem = winPopup.document.theform.peerstream_recv;
  answerElem.value += answerAppendElem.value;
  var sdpText = maybeAddLineBreakToEnd(answerElem.value);
  var answer = new RTCSessionDescription({
    type: 'answer',
    sdp: sdpText
  });
  winPopup.theform.submit();

  remotePeerConnection.setLocalDescription(answer,
      (function ok() { /*alert('Join successful!\nStreaming as: ' + myUserElem.value + '\nWatching: ' + watchUserElem.value);*/ }),
      onSetSessionDescriptionError);

  attachMediaStream(remoteVideo, remotePeerConnection.getRemoteStreams()[0]);

  hangupButton.disabled = false;
}

var winPopup = null;
var winPopupSdp;
function joinPopupClose() {
    joinComplete();
}
function joinPopupClose2() {
    // fix answer sdp to not stream
    joinComplete();
}
function joinPopupOpen() {
    winPopup.document.theform.answersdp.value = winPopupSdp;
    winPopup.document.theform.button_ok.onclick = joinPopupClose;
    winPopup.document.theform.button_ok_watch.onclick = joinPopupClose2;
    var randomUser = 'user' + Math.ceil(Math.random() % 10 * 1000);
    winPopup.document.theform.my_name.value = randomUser;
    winPopup.document.theform.peerstream_recv.value = randomUser;
}
function winPopupWithSDP(s) {
  winPopup = window.open('answer_upload.html', 'sdp_answer_upload', 'width=300,height=300');
  winPopupSdp = s;
  winPopup.onload = joinPopupOpen;
}

function gotDescription2Join(description) {
  //alert('gotDescription2Join');
  answerSdpTextarea.disabled = false;
  answerSdpTextarea.value = description.sdp;

  var sdpAnswer = answerSdpTextarea.value;

  sdpAnswer = maybeAddLineBreakToEnd(sdpAnswer);
  var answer = new RTCSessionDescription({
    type: 'answer',
    sdp: sdpAnswer
  });

  winPopupWithSDP(sdpAnswer);

  answerSDPJoin = sdpAnswer;
  answerSdpTextarea.value = sdpAnswer;
}

function gotStreamJoinLocal() {
  //alert('gotLocalStreamJoin');
}

function gotStreamJoinRemote(e) {
  //alert('gotRemoteStreamJoin');
  attachMediaStream(remoteVideo, e.stream);
  joinButton2.disabled = false;
}

function createAnswerJoin() {
  remotePeerConnection.onaddstream = gotStreamJoinRemote;

  // Since the 'remote' side has no media stream we need
  // to pass in the right constraints in order for it to
  // accept the incoming offer of audio and video.
  remotePeerConnection.createAnswer(gotDescription2Join,
      onCreateSessionDescriptionError,
      sdpConstraints);

  joinButton3.disabled = false;
}

function join() {
  //var servers = null;
  //var servers = {"iceServers": [{"url": "turn:172.16.130.247:3478", "credential": "webrtc", "username": "justin" }]};
  //var servers = {"iceServers": [{"url": "turn:numb.viagenie.ca", "credential": "justin@domain17.net", "username": "justin@domain17.net", "password": "061781" }]};
  //var servers = {"iceServers": [{"url": "turn:numb.viagenie.ca", "credential": "muazkh", "username": "webrtc@live.com" }]};
  //var servers = {"iceServers": [{"url": "stun:172.16.130.247:3478"}]};
  //var servers = {"iceServers": [{"url": "stun:stun.l.google.com:19302"}]};

  var servers = null;

  remotePeerConnection = new RTCPeerConnection(servers);
  trace('Created remote peer connection object remotePeerConnection');
  remotePeerConnection.onicecandidate = iceCallback1;
  remotePeerConnection.onaddstream = gotStreamJoinLocal;

  remotePeerConnection.addStream(localStream);

  var offer = new RTCSessionDescription({
    type: 'offer',
    sdp: offerSdpTextarea.value
  });

  remotePeerConnection.setRemoteDescription(offer,
      (function() { createAnswerJoin(); }),
      onSetSessionDescriptionError);

  offerSDPJoin = offer.sdp;

  //alert('offer:\n' + offerSDPJoin);

  /*
  var sdp = joinOfferSdp;

  sdp = maybeAddLineBreakToEnd(sdp);
  var offer = new RTCSessionDescription({
    type: 'offer',
    sdp: sdp
  });

  remotePeerConnection.setRemoteDescription(offer,
      onSetSessionDescriptionSuccess,
      onSetSessionDescriptionError);

  */
}

function onSetSessionDescriptionSuccess() {
  trace('Set session description success.');
}

function onSetSessionDescriptionError(error) {
  trace('Failed to set session description: ' + error.toString());
}

// Workaround for crbug/322756.
function maybeAddLineBreakToEnd(sdp) {
  var endWithLineBreak = new RegExp(/\n$/);
  if (!endWithLineBreak.test(sdp)) {
    return sdp + '\n';
  }
  return sdp;
}

function createOffer() {
  localPeerConnection.createOffer(gotDescription1,
      onCreateSessionDescriptionError);
}

function onCreateSessionDescriptionError(error) {
  trace('Failed to create session description: ' + error.toString());
}

function setOffer() {
  var sdp = offerSdpTextarea.value;
  sdp = maybeAddLineBreakToEnd(sdp);
  var offer = new RTCSessionDescription({
    type: 'offer',
    sdp: sdp
  });
  localPeerConnection.setLocalDescription(offer,
      onSetSessionDescriptionSuccess,
      onSetSessionDescriptionError);
  trace('Modified Offer from localPeerConnection \n' + sdp);
  remotePeerConnection.setRemoteDescription(offer,
      onSetSessionDescriptionSuccess,
      onSetSessionDescriptionError);
}

function gotDescription1(description) {
  offerSdpTextarea.disabled = false;
  offerSdpTextarea.value = description.sdp;
}

function createAnswer() {
  // Since the 'remote' side has no media stream we need
  // to pass in the right constraints in order for it to
  // accept the incoming offer of audio and video.
  remotePeerConnection.createAnswer(gotDescription2,
      onCreateSessionDescriptionError,
      sdpConstraints);
}

function setAnswer() {
  var sdp = answerSdpTextarea.value;
  sdp = maybeAddLineBreakToEnd(sdp);
  var answer = new RTCSessionDescription({
    type: 'answer',
    sdp: sdp
  });
  remotePeerConnection.setLocalDescription(answer,
      onSetSessionDescriptionSuccess,
      onSetSessionDescriptionError);
  trace('Modified Answer from remotePeerConnection \n' + sdp);
  localPeerConnection.setRemoteDescription(answer,
      onSetSessionDescriptionSuccess,
      onSetSessionDescriptionError);
}

function gotDescription2(description) {
  answerSdpTextarea.disabled = false;
  answerSdpTextarea.value = description.sdp;
}

function hangup() {
  remoteVideo.src = '';
  trace('Ending call');
  //  localStream.stop();
  localPeerConnection.close();
  remotePeerConnection.close();
  localPeerConnection = null;
  remotePeerConnection = null;
  offerSdpTextarea.disabled = true;
  answerSdpTextarea.disabled = true;
  getMediaButton.disabled = false;
  createPeerConnectionButton.disabled = true;
  createOfferButton.disabled = true;
  setOfferButton.disabled = true;
  createAnswerButton.disabled = true;
  setAnswerButton.disabled = true;
  hangupButton.disabled = true;

  document.refresh();
}

function gotRemoteStream(e) {
  // Call the polyfill wrapper to attach the media stream to this element.
  attachMediaStream(remoteVideo, e.stream);
  trace('Received remote stream');
}

var callback1Candidate = null;
var callback2Candidate = null;
var callback1CandidateID = 0;
var callback2CandidateID = 0;
var callback1CandidateIP = stunHost;
var callback1CandidatePort = stunPort;
var callback2CandidatePort = stunPort;
var candidateRemoteLast;
function iceCallback1(event) {
  if (event.candidate && callback1Candidate == null) {
    trace('Remote ICE candidate (was): ' + event.candidate.candidate);
    var c = event.candidate;
    callback1Candidate = c;
    c.candidate = "candidate:" + callback1CandidateID++ + " 1 UDP " + 1234+callback1CandidateID + " " + callback1CandidateIP + " " + callback1CandidatePort + " typ host";
    candidateRemoteLast = c;
    remotePeerConnection.addIceCandidate(new RTCIceCandidate(c),
        onAddIceCandidateSuccess, onAddIceCandidateError);
    trace('Remote ICE candidate: ' + c.candidate + '\n');
  }
}

function iceCallback2(event) {
  if (event.candidate && callback2Candidate == null) {
    trace('Local ICE candidate (was): ' + event.candidate.candidate);
    var c = event.candidate;
    callback2Candidate = c;
    c.candidate = "candidate:" + callback2CandidateID++ + " 1 UDP " + 1234+callback1CandidateID + " " + callback1CandidateIP + " " + callback2CandidatePort + " typ host";
    localPeerConnection.addIceCandidate(new RTCIceCandidate(c),
        onAddIceCandidateSuccess, onAddIceCandidateError);
    trace('Local ICE candidate: ' + c.candidate + '\n');
  }
}

function onAddIceCandidateSuccess() {
  trace('AddIceCandidate success.');
}

function onAddIceCandidateError(error) {
  trace('Failed to add Ice Candidate: ' + error.toString());
}

