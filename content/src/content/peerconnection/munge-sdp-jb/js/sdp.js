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
" fir" +
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

