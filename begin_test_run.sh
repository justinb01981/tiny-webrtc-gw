#$!/bin/bash
i=8011;
cat config.txt.tmpl | sed -e "s/\$PORTNUM/$i/";
iptables -t nat -A PREROUTING -s 127.0.0.1 -p tcp --dport 8008 -j REDIRECT --to 8011;
iptables -t nat -A OUTPUT -s 127.0.0.1 -p tcp --dport 8008 -j REDIRECT --to 8011;
make all && gdb -ex run webrtc_gw;
echo done;
