LIB_OPENSSL=./lib
INC_OPENSSL=./boringssl/include
INC_LIBSRTP=./libsrtp/include
INC_LIBSRTP_CFG=./libsrtp
INC_LIBSRTP_CRYPTO=./libsrtp/crypto/include
INC_LIBWS=./ws/cwebsocket/lib
OFFERVP8=0
LDARGS=-static -pthread -lcrypto -lssl -lcrypto -lpthread -lcrypto -lsrtp2 -lm -lrt 
#LDARGS=-lcrypto -lssl -lcrypto -lpthread -lc -lcrypto -lsrtp2 -lm -lpthread -lssl
GPROF_FLAG=-g
BINARY_NAME=webrtc_xcast
MYCLONE="chatlog.`date -I`.txt.bak"

all:
	echo "kidding, edit config.txt first then run make demo; - justin@domain17.net /// holla @ me :-) for help! (make sure you did git checkout --recursive-submodules or git submodule checkout xyz or build fails)";

demo: xcast
	
xcast: lib/libcrypto.a lib/libsrtp2.a lib/libssl.a iplookup_hack.o
# add -pg to profile with gprof
# todo: add visual indicator whether vp8 enabled/disabled ? example sdp offer? next to viewers label?
	gcc -g -v -o ${BINARY_NAME} -DSDP_OFFER_VP8=${OFFERVP8} -DMEMDEBUGHACK=1 -DDTLS_BUILD_WITH_BORINGSSL=1 -I${INC_LIBSRTP} -I${INC_LIBSRTP_CFG} -I${INC_LIBSRTP_CRYPTO} -I${INC_OPENSSL} -I${INC_LIBWS} -L${LIB_OPENSSL} stubs.c main.c util.c tiny_config.c filecache.c iplookup_hack.c ${LDARGS};
#	gcc -v -o webrtc_gw -DDTLS_BUILD_WITH_BORINGSSL=1 -I${INC_LIBSRTP} -I${INC_LIBSRTP_CFG} -I${INC_LIBSRTP_CRYPTO} -I${INC_OPENSSL} -I${INC_LIBWS} -L${LIB_OPENSSL} stubs.c main.c util.c tiny_config.c ws/cwebsocket/lib/*.c ${LDARGS};

lib/libcrypto.a:
	cd boringssl && cmake . && make && cp crypto/libcrypto.a ../lib;
lib/libssl.a:
	cd boringssl && cmake . && make && cp ssl/libssl.a ../lib;
lib/libsrtp2.a:
	cd libsrtp && cmake . && make && cp libsrtp2.a ../lib;

## hope you checked this out submodule (tho not necessary for https)
ssltool: SSLTools

wintermutecfg: preparechat
	echo "handle SIGPIPE nostop" >> ~/.gdbinit && 		\
	echo "handle SIGPIPE noprint" >> ~/.gdbinit && 		\
	echo "set print thread-events off" >> ~/.gdbinit && \
	echo "set confirm off" >> ~/.gdbinit && 			\
	echo "pruning chatlog..."

debug: clean demo wintermutecfg
	gdb -ex "run" ${BINARY_NAME}

preparechat:

	cp chatlog.txt ${MYCLONE} && cat ${MYCLONE} | sed '/server:/d' | grep '.$$' > chatlog.txt;
	cat chatlog.txt;

clean:

	rm ${BINARY_NAME} &

install:

	echo "no";
