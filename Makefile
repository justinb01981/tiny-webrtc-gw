LIB_OPENSSL=./lib
INC_OPENSSL=./include
INC_LIBSRTP=./libsrtp/build/include
INC_LIBWS=./ws/cwebsocket/lib
LDARGS=-static -pthread -lcrypto -lssl -lcrypto -lpthread -lcrypto -lsrtp -lm

all:
	gcc -DDTLS_BUILD_WITH_BORINGSSL=1 -o webrtc_gw -I${INC_LIBSRTP} -I${INC_OPENSSL} -I${INC_LIBWS} -L${LIB_OPENSSL} stubs.c main.c util.c config.c ws/cwebsocket/lib/*.c -g ${LDARGS};
