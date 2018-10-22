#ifndef __DTLS_H__
#define __DTLS_H__

#include <pthread.h>

#include "peer.h"

#ifdef DTLS_BUILD_WITH_BORINGSSL

#define CRYPTO_malloc(file, line, x) malloc(x)
#define CRYPTO_free(x) free(x)

#ifdef OPENSSL_assert
#undef OPENSSL_assert
#endif

#ifndef OPENSSL_assert
    #define OPENSSL_assert(x)
#endif

#define BIO_new_dgram(x, y) (BIO*)(NULL)

#endif


typedef struct {
    u8 content_type;
    u16 vers;
    u16 epoch;
    u8 seqnum[6];
    u16 len;
    /*char data[1];*/
} ATTR_PACKED dtls_frame;

const unsigned int dtls_frame_head_len = 13;

int dtls_verify_callback (int ok, X509_STORE_CTX *ctx) {
	return 1;
}

#define BUFFER_SIZE          (1<<16)
#define COOKIE_SECRET_LENGTH 16

int verbose = 0;
int veryverbose = 0;
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
int cookie_initialized=0;

struct sockaddr_storage peer_pending;

int verify_cookie(SSL *ssl, unsigned char *cookie, unsigned int cookie_len)
	{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} peer;

	/* If secret isn't initialized yet, the cookie can't be valid */
	if (!cookie_initialized)
		return 0;

	/* Read peer information */
    /*
	(void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);
    */
    memcpy(&peer, &peer_pending, sizeof(peer));

	/* Create buffer with peer's address and port */
	length = 0;
	switch (peer.ss.ss_family) {
		case AF_INET:
			length += sizeof(struct in_addr);
			break;
		case AF_INET6:
			length += sizeof(struct in6_addr);
			break;
		default:
			OPENSSL_assert(0);
			break;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if (buffer == NULL)
		{
		printf("out of memory\n");
		return 0;
		}

	switch (peer.ss.ss_family) {
		case AF_INET:
			memcpy(buffer,
			       &peer.s4.sin_port,
			       sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
			       &peer.s4.sin_addr,
			       sizeof(struct in_addr));
			break;
		case AF_INET6:
			memcpy(buffer,
			       &peer.s6.sin6_port,
			       sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
			       &peer.s6.sin6_addr,
			       sizeof(struct in6_addr));
			break;
		default:
			OPENSSL_assert(0);
			break;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
	     (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
		return 1;

	return 0;
	}

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
	{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} peer;

	/* Initialize a random secret */
	if (!cookie_initialized)
		{
		if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH))
			{
			printf("error setting random cookie secret\n");
			return 0;
			}
		cookie_initialized = 1;
		}

	/* Read peer information */
    /*
	(void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);
    */
    memcpy(&peer, &peer_pending, sizeof(peer));

	/* Create buffer with peer's address and port */
	length = 0;
	switch (peer.ss.ss_family) {
		case AF_INET:
			length += sizeof(struct in_addr);
			break;
		case AF_INET6:
			length += sizeof(struct in6_addr);
			break;
		default:
			OPENSSL_assert(0);
			break;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if (buffer == NULL)
		{
		printf("out of memory\n");
		return 0;
		}

	switch (peer.ss.ss_family) {
		case AF_INET:
			memcpy(buffer,
			       &peer.s4.sin_port,
			       sizeof(in_port_t));
			memcpy(buffer + sizeof(peer.s4.sin_port),
			       &peer.s4.sin_addr,
			       sizeof(struct in_addr));
			break;
		case AF_INET6:
			memcpy(buffer,
			       &peer.s6.sin6_port,
			       sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
			       &peer.s6.sin6_addr,
			       sizeof(struct in6_addr));
			break;
		default:
			OPENSSL_assert(0);
			break;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
	     (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	memcpy(cookie, result, resultlength);
	*cookie_len = resultlength;

	return 1;
}

SSL_CTX* DTLS_ssl_ctx_global = NULL;
unsigned short dtls_listen_port;
void DTLS_init()
{
    time_t tm = time(NULL);

    RAND_seed(&tm, sizeof(tm));
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
}

void DTLS_sock_init(unsigned short listen_port)
{
    dtls_listen_port = listen_port;

    //SSL_CTX *ctx = SSL_CTX_new(DTLSv1_2_server_method());
    SSL_CTX *ctx = SSL_CTX_new(DTLSv1_server_method());

    //SSL_CTX_set_cipher_list(ctx, "ALL:NULL:eNULL:aNULL");
    //SSL_CTX_set_cipher_list(ctx, "TLSv1.2+FIPS:kRSA+FIPS:!eNULL:!aNULL");
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);

    SSL_CTX_set_tlsext_use_srtp(ctx, "SRTP_AES128_CM_SHA1_80");

	if (!SSL_CTX_use_certificate_file(ctx, "certs/server-cert.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no certificate found!");

	if (!SSL_CTX_use_PrivateKey_file(ctx, "certs/server-key.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no private key found!");

	if (!SSL_CTX_check_private_key (ctx))
		printf("\nERROR: invalid private key!");

    SSL_CTX_set_read_ahead(ctx, 1);

	/* Client has to authenticate */
	//SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);

    /*https://code.google.com/p/webrtc/issues/detail?id=4201*/
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, dtls_verify_callback);
    SSL_CTX_set_verify_depth(ctx, 4);
    SSL_CTX_set_cipher_list(ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");

    DTLS_ssl_ctx_global = ctx;
}

void DTLS_uninit()
{
    if(DTLS_ssl_ctx_global)
    {
        SSL_CTX_free(DTLS_ssl_ctx_global);
        DTLS_ssl_ctx_global = NULL;
    }
}

inline static void
SSL_RESULT_CHECK(const char* prefix, SSL* ssl, int r)
{
    char buf[256];
	printf("%s: %s (%d)(r=%d)\n", prefix, ERR_error_string(ERR_get_error(), buf), SSL_get_error(ssl, r), r);
}

inline static void
DTLS_peer_init(peer_session_t* peer)
{
    int timeout_msec = 10;
    SSL *ssl = NULL;
    BIO* bio = NULL;
    int ret = 0;

    peer->dtls.use_membio = 1;

    if(!peer->dtls.ssl)
    {
        struct timeval timeout;
        const int on = 1;
        int timeout_msec = 100;

    	setsockopt(peer->sock, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));
    	setsockopt(peer->sock, SOL_SOCKET, SO_REUSEPORT, (const void*) &on, (socklen_t) sizeof(on));

        bio = BIO_new_dgram(peer->sock, BIO_NOCLOSE);

        ssl = SSL_new(DTLS_ssl_ctx_global);

        if(!peer->dtls.use_membio)
        {
            SSL_set_bio(ssl, bio, bio);

    	    BIO_set_fd(SSL_get_rbio(ssl), peer->sock, BIO_NOCLOSE);

        	//BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &peer->addr);

            //BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL);

		    /* Set and activate timeouts */
        	timeout.tv_sec = 0;
        	timeout.tv_usec = timeout_msec * 1000;
    	    BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
        }
        else
        {
            SSL_set_bio(ssl, BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));
            
            ret = SSL_get_wbio(ssl) == NULL? 1: 0;
            printf("SSL_get_wbio:%d\n", ret);

            ret = BIO_set_nbio(SSL_get_wbio(ssl), 1);
            SSL_RESULT_CHECK("SSL_set_nbio", ssl, ret);

            ret = BIO_set_nbio(SSL_get_rbio(ssl), 1);
            SSL_RESULT_CHECK("SSL_set_nbio", ssl, ret);
        }

        ret = SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
        SSL_RESULT_CHECK("SSL_set_options(COOKIE_EXHCANGE)", ssl, ret);

	    //SSL_CTX_set_cookie_generate_cb(DTLS_ssl_ctx_global, generate_cookie);
    	//SSL_CTX_set_cookie_verify_cb(DTLS_ssl_ctx_global, verify_cookie);

        peer->dtls.ssl = ssl;

        memcpy(&peer_pending, &peer->addr, sizeof(peer->addr));
    }
}

inline static int
DTLS_peer_shutdown(peer_session_t* peer)
{
    if(peer->dtls.ssl == NULL) return -1;

    return SSL_shutdown(peer->dtls.ssl);
}

inline static void
DTLS_peer_uninit(peer_session_t* peer)
{
    if(peer->dtls.ssl)
    {
        SSL_free(peer->dtls.ssl);
        peer->dtls.ssl = NULL;
    }
    peer->dtls.connected = 0;
}

typedef void (*DTLS_read_cb)(u8* buf, unsigned int len);

inline static void
DTLS_accept_read(peer_session_t* peer, DTLS_read_cb cb_read)
{
    int ret = 0;
    int sock = peer->sock;
    int read_retries = 5;
    int timeout_sec = 1;
    SSL *ssl = peer->dtls.ssl;
    BIO* bio = NULL;
    char buf[256];
    struct sockaddr_storage server_addr;
    int retries;

    memset(&server_addr, 0, sizeof(server_addr));

    /*
    if(peer->dtls.state == 0)
    {
        peer->dtls.state = 1;
        return;
    }
    */

    printf("peer DTLS state: %d\n", peer->dtls.state);

    if(peer->dtls.state < 2) peer->dtls.state = 2;

    if(peer->dtls.state == 2)
    {
        int hack = peer->dtls.use_membio;
        if(!hack)
        {
            memcpy(&server_addr, &peer->addr_listen, sizeof(peer->addr_listen));
            //ssl->d1->link_mtu = ssl->d1->mtu = 1500;
            int listen_ret = DTLSv1_listen(ssl, &server_addr);
            if(listen_ret > 0) peer->dtls.state++;
            SSL_RESULT_CHECK("DTLSv1_listen", ssl, listen_ret);
        }
        else
        {
            ssl->d1->listen = 1;
            //ssl->d1->link_mtu = ssl->d1->mtu = 1500;
            peer->dtls.state++;
        }
    }

    if(peer->dtls.state == 3)
    {
        ret = SSL_accept(ssl);
        printf("SSL_accept:%d\n", ret);

        if(ret > 0)
        {
            printf("%s: peer connected\n", __func__);
            peer->dtls.connected = 1;
            peer->dtls.state++;
        }
        else
        {
		    printf("%s (%d)\n", ERR_error_string(ERR_get_error(), buf), SSL_get_error(ssl, ret));
        }
    }

    /* begin reading */
    if(peer->dtls.state == 4)
    {
        int reading = 1;
        while(peer->dtls.connected && reading &&
              !(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN))
        {
            int len = SSL_read(ssl, peer->cleartext.buf + peer->cleartext.len, sizeof(peer->cleartext.buf) - peer->cleartext.len);
            if(len > 0)
            {
                peer->cleartext.len += len;
                printf("peer->cleartext.len=%d\n", peer->cleartext.len);
            }

            switch (SSL_get_error(ssl, len)) {
                case SSL_ERROR_NONE:
                    break;
                case SSL_ERROR_WANT_READ:
                    printf("SSL_ERROR_WANT_READ\n");
                    /* Handle socket timeouts */
                    /*
                    if (BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL)) {
                    }
                    */
                    /* Just try again */
                    reading = 0;
                    break;
                case SSL_ERROR_WANT_WRITE:
                    printf("SSL_ERROR_WANT_WRITE\n");
                    reading = 0;
                    break;
                case SSL_ERROR_ZERO_RETURN:
                    printf("SSL_ERROR_ZERO_RETURN\n");
                    reading = 0;
                    break;
                case SSL_ERROR_SYSCALL:
                    reading = 0;
                    break;
                case SSL_ERROR_SSL:
                    reading = 0;
                    printf("SSL read error: ");
                    printf("%s (%d)\n", ERR_error_string(ERR_get_error(), buf), SSL_get_error(ssl, len));
                    break;
                default:
                    reading = 0;
                    printf("Unexpected error while reading!\n");
                    break;
            }
        }
    }

    printf("%s:%d %s exiting\n", __FILE__, __LINE__, __func__);
}

inline static int
DTLS_connect(peer_session_t* peer, DTLS_read_cb cb_read)
{
    return 0;
}

inline static int
DTLS_write(peer_session_t* peer, u8 *buf, unsigned int len)
{
    int ret = /*SSL_write(peer->dtls.ssl, buf, len);*/ BIO_write(SSL_get_rbio(peer->dtls.ssl), buf, len);
    printf("BIO_write:%d\n", ret);
    return ret;
}

inline static int
DTLS_read(peer_session_t* peer, u8 *buf, unsigned int len)
{
    /*
    char tmp[2048];
    int ret_ssl = SSL_read(peer->dtls.ssl, tmp, sizeof(tmp));
    printf("ret_ssl:%d\n", ret_ssl);
    */

    int ret = /*SSL_read(peer->dtls.ssl, buf, len);*/ BIO_read(SSL_get_wbio(peer->dtls.ssl), buf, len);
    printf("BIO_read:%d\n", ret);

    if(ret < 0 && SSL_get_error(peer->dtls.ssl, ret) == SSL_ERROR_SYSCALL)
    {
        // graceful close
        peer->alive = 0;
    }
    return ret;
}

#endif
