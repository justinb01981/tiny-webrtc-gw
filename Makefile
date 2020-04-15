LIB_OPENSSL=./lib
INC_OPENSSL=./boringssl/include
INC_LIBSRTP=./libsrtp/include
INC_LIBSRTP_CFG=./libsrtp
INC_LIBSRTP_CRYPTO=./libsrtp/crypto/include
INC_LIBWS=./ws/cwebsocket/lib
LDARGS=-static -pthread -lcrypto -lssl -lcrypto -lpthread -lcrypto -lsrtp2 -lm

all:
	gcc -DDTLS_BUILD_WITH_BORINGSSL=1 -o webrtc_gw -I${INC_LIBSRTP} -I${INC_LIBSRTP_CFG} -I${INC_LIBSRTP_CRYPTO} -I${INC_OPENSSL} -I${INC_LIBWS} -L${LIB_OPENSSL} stubs.c main.c util.c tiny_config.c ws/cwebsocket/lib/*.c -g ${LDARGS};
