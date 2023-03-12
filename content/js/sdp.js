function joinSDP()
{
    var sdpStatic =
        %$SDP_OFFER$%
    ;
    
  console.debug('joinSDP:'+sdpStatic);
  return sdpStatic;
}

