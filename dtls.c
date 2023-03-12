/*
   dtls related code
*/

/*
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define __USE_GNU
#include <sys/socket.h>
#include <netinet/ip.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <time.h>
#include <math.h>
#include <fcntl.h>
#include <pthread.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>

#include "debug.h"
#include "srtp_key_len.h"
#include "srtp_priv.h"
#include "peer.h"
#include "tiny_config.h"

#ifdef DTLS_BUILD_WITH_BORINGSSL

#define CRYPTO_malloc(file, line, x) malloc(x)
#define CRYPTO_free(x) free(x)



#endif

*/
#define OPENSSL_assert(x) assert(x)
#define BIO_new_dgram(x, y) (BIO*)(NULL)

int dtls_verify_callback (int ok, X509_STORE_CTX *ctx) {
	return 1;
}

#define BUFFER_SIZE          (1<<16)
#define COOKIE_SECRET_LENGTH 16

int verbose = 0;
int veryverbose = 0;
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
int cookie_initialized=0;
char dtls_fingerprint_st[128];
char *dtls_fingerprint = dtls_fingerprint_st;

struct sockaddr_storage peer_pending;

void sha256_bytes(unsigned char *bytes, size_t len, char outputBuffer[65])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, bytes, len);
    SHA256_Final(hash, &sha256);
    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 3), "%02X:", hash[i]);
    }
    outputBuffer[strlen(outputBuffer)-1] = '\0';
}

/* end "move this" */

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

static int DTLS_test()
{
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

    DTLS_test();
}

static void str_insert(char* dst, unsigned int off, const char ins)
{
    char t = dst[off];
    for(int d = strlen(dst); d > off; d--) {
        dst[d] = dst[d-1];
    }
    dst[off] = ins;
    printf("str_insert result: %s\n", dst);
}

void DTLS_sock_init(unsigned short listen_port)
{
    dtls_listen_port = listen_port;

    BIO *pkbio = BIO_new(BIO_s_file());

    BIO *mem = BIO_new(BIO_s_mem());

    if (!BIO_read_filename(pkbio, "certs/server-cert.pem")) assert(0);
    X509* x5 = PEM_read_bio_X509(pkbio, NULL, NULL, NULL);
    if(!x5) assert(0);

    SSL_CTX *ctx = SSL_CTX_new(DTLSv1_2_server_method());

    //SSL_CTX_set_cipher_list(ctx, "ALL:NULL:eNULL:aNULL");
    //SSL_CTX_set_cipher_list(ctx, "TLSv1.2+FIPS:kRSA+FIPS:!eNULL:!aNULL");

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);

    // TODO: revisit this and switch statement in main.c srtp init which crashes if you remove it ;-)
    SSL_CTX_set_tlsext_use_srtp(ctx, "SRTP_AES128_CM_SHA1_80");

	//if (!SSL_CTX_use_certificate_file(ctx, "certs/server-cert.pem", SSL_FILETYPE_PEM))
	//	printf("\nERROR: no certificate found!");
    if (!SSL_CTX_use_certificate(ctx, x5))
        printf("\nError: loading certificate");

	if (!SSL_CTX_use_PrivateKey_file(ctx, "certs/server-key.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no private key found!");

    // I give up - no fucking idea how to correctly calculate the hash fingerprint of the x509 cert that agrees with that openssl prints
    // making this a config-file argument for now
    EVP_PKEY* x5key = X509_get_pubkey(x5);
    if (!x5key) assert(0);

    // fingerprint is sha256 of the cert NOT THE PUBLIC KEY
    RSA* rsa = EVP_PKEY_get1_RSA(x5key); // remove?

    if (!i2d_X509_bio(mem, x5)) assert(0);

    // bio now holds DER encoded cert
     
    char *x5der = NULL;
    long hlen = BIO_get_mem_data(mem, &x5der);
    sha256_bytes(x5der, hlen, dtls_fingerprint);

    EVP_PKEY_free(x5key);
    RSA_free(rsa);

    BIO_free(pkbio);
    BIO_free(mem);

    printf("USING FINGERPRINT:\n%s\n", dtls_fingerprint);

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

void
SSL_RESULT_CHECK(const char* prefix, SSL* ssl, int r)
{
    char buf[256];
	printf("%s: %s (%d)(r=%d)\n", prefix, ERR_error_string(ERR_get_error(), buf), SSL_get_error(ssl, r), r);
}

static void
DTLS_flush(struct peer_session_t* peer)
{
    // drain SSL_wbio and send packets
    int r;
    char buf[512];

    r = BIO_read(SSL_get_wbio(peer->dtls.ssl), buf, sizeof(buf));
    printf("DTLS_flush: %d bytes\n", r);
    if(r > 0) peer_send_block(peer, buf, r);
}

void
DTLS_peer_shutdown(struct peer_session_t* peer)
{
    if(peer->dtls.ssl == NULL) return;

    int res = 0;
    int retries = 3;
    while (res >= 0 && retries > 0) {
        res = SSL_shutdown(peer->dtls.ssl);
        //DTLS_flush(peer);
        sleep_msec(20);
        retries--;
    }
}

static int
DTLS_close(struct peer_session_t* peer)
{
    DTLS_peer_shutdown(peer);

    if(peer->dtls.ssl)
    {
        SSL_free(peer->dtls.ssl);
        peer->dtls.ssl = NULL;
    }
    peer->dtls.connected = 0;
}

void
DTLS_peer_uninit(struct peer_session_t* peer)
{
    DTLS_close(peer);
}

typedef void (*DTLS_read_cb)(u8* buf, unsigned int len);

void
DTLS_accept_read(struct peer_session_t* peer, DTLS_read_cb cb_read)
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
            #if !DTLS_BUILD_WITH_BORINGSSL
            int listen_ret = DTLSv1_listen(ssl, &server_addr);
            #else
            int listen_ret = 1;
            #endif
            if(listen_ret > 0) peer->dtls.state++;
            SSL_RESULT_CHECK("DTLSv1_listen", ssl, listen_ret);
        }
        else
        {
            #if !DTLS_BUILD_WITH_BORINGSSL
            ssl->d1->listen = 1;
            #endif
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

int
DTLS_connect(struct peer_session_t* peer, DTLS_read_cb cb_read)
{
    return 0;
}

int
DTLS_write(struct peer_session_t* peer, u8 *buf, unsigned int len)
{
    int ret = /*SSL_write(peer->dtls.ssl, buf, len);*/ BIO_write(SSL_get_rbio(peer->dtls.ssl), buf, len);
    printf("BIO_write:%d\n", ret);
    return ret;
}

int
DTLS_read(struct peer_session_t* peer, u8 *buf, unsigned int len)
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
        peer->time_pkt_last = 0;
    }
    return ret;
}

