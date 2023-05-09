LIB_OPENSSL=./lib
INC_OPENSSL=./boringssl/include
INC_LIBSRTP=./libsrtp/include
INC_LIBSRTP_CFG=./libsrtp
INC_LIBSRTP_CRYPTO=./libsrtp/crypto/include
INC_LIBWS=./ws/cwebsocket/lib
LDARGS=-static -pthread -lcrypto -lssl -lcrypto -lpthread -lcrypto -lsrtp2 -lm -lrt
#LDARGS=-lcrypto -lssl -lcrypto -lpthread -lc -lcrypto -lsrtp2 -lm -lpthread -lssl
GPROF_FLAG=-g

all:
	echo "kidding, edit config.txt first then run make demo; - justin@domain17.net /// holla @ me :-) for help! (make sure you did git checkout --recursive-submodules or git submodule checkout xyz or build fails)";

demo: ./webrtc_gw
	

webrtc_gw: lib/libcrypto.a lib/libsrtp2.a lib/libssl.a
# add -pg to profile with gprof
	gcc -g -v -o webrtc_gw -DMEMDEBUGHACK=1 -DDTLS_BUILD_WITH_BORINGSSL=1 -I${INC_LIBSRTP} -I${INC_LIBSRTP_CFG} -I${INC_LIBSRTP_CRYPTO} -I${INC_OPENSSL} -I${INC_LIBWS} -L${LIB_OPENSSL} stubs.c main.c util.c tiny_config.c filecache.c ws/cwebsocket/lib/*.c ${LDARGS};
#	gcc -v -o webrtc_gw -DDTLS_BUILD_WITH_BORINGSSL=1 -I${INC_LIBSRTP} -I${INC_LIBSRTP_CFG} -I${INC_LIBSRTP_CRYPTO} -I${INC_OPENSSL} -I${INC_LIBWS} -L${LIB_OPENSSL} stubs.c main.c util.c tiny_config.c ws/cwebsocket/lib/*.c ${LDARGS};

lib/libcrypto.a:
	cd boringssl && cmake . && make && cp crypto/libcrypto.a ../lib;
lib/libssl.a:
	cd boringssl && cmake . && make && cp ssl/libssl.a ../lib;
lib/libsrtp2.a:
	cd libsrtp && cmake . && make && cp libsrtp2.a ../lib;

## hope you checked this out submodule (tho not necessary for https)
ssltool: SSLTools

wintermutecfg:
	echo "copying .wintermute file";
	cp .wintermute config.txt;
	echo "handle SIGPIPE nostop" >> ~/.gdbinit && \
	echo "handle SIGPIPE noprint" >> ~/.gdbinit && \
	echo "set print thread-events off" >> ~/.gdbinit && \
	echo "set confirm off" >> ~/.gdbinit;

debug: all wintermutecfg
	gdb -ex "run" webrtc_gw
