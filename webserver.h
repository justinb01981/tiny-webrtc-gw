#ifndef __webserver_h__
#define __webserver_h__

#include "memdebughack.h"
#include "peer.h"
#include "thread.h"
#include <sys/errno.h>
#include "stun_callback.h"
#include "iplookup_hack.h"
#include "macro_expand.h"

/* include websockets */
#define sha1 sha1_
#define assert assert_
#include "websocket.h"
#define sha1_ sha1
#define assert_ assert

#define CHATLOG_SIZE 512000 // js takes up a lot of this space..


#define TMPTRACE \
    printf("TRACE:%d",__FILE__,__LINE__)

extern int listen_port_base;
extern peer_session_t peers[MAX_PEERS];
extern int stun_binding_response_count;
extern char* dtls_fingerprint;

const static unsigned long SPIN_WAIT_USEC = 1000;

static char g_chatlog[CHATLOG_SIZE];

static time_t g_chatlog_ts;

static char* g_sdp;

static pthread_mutex_t webmtx;

char listen_port_str[64];

extern int sdp_prefix_set(const char*);

struct webserver_state {
    char inip[64];
    int running;
    unsigned int peer_idx_next;
    int sock;
};
extern struct webserver_state webserver;

typedef struct {
    int sock;
    pthread_t ws_thread;
    int ws_peeridx;
    int state;
    char websocket_accept_response[512];
    char* pbody;
    char roomname[256];
    char paddinghack[1024];
} webserver_worker_args;

static char *tag_icecandidate = "%$RTCICECANDIDATE$%";
static char *tag_room_ws = "%$ROOMNAME$%";
static char *tag_sdp_offer1 = "%$SDP_OFFER$%";
static char* tag_joinroom_ws = "POST /join/";
static char* tag_msgroom_ws = "POST /message/domain17/";
static char* webserver_staticc;
// static char ufrag_answer_tmp[1024];
static char ufrag_offeranswer_tmp[256];
static int cb_done = 0;

static char webserver_get_localaddr_buf[64];

const char* webserver_get_localaddr() {

    sprintf(webserver_get_localaddr_buf, "%s %u", iplookup_addr, listen_port_base);
    return webserver_get_localaddr_buf;
}

const char*
chatlog_read()
{
    return (const char*) g_chatlog;
}

void
chatlog_ts_update()
{
    g_chatlog_ts = time(NULL);
}

void
chatlog_append(const char* pchatmsg)
{
    size_t appendlen = strlen(pchatmsg);
    //if(appendlen == 0) {
    //    chatlog_ts_update();
    //    return;
    //}
    if(strlen(pchatmsg) >= CHATLOG_SIZE-1) appendlen = (CHATLOG_SIZE-1);
    
    // rotate buffer
    char *pto = g_chatlog, *pfrom = (char*) g_chatlog + ((CHATLOG_SIZE-1) >= strlen(g_chatlog)+appendlen ? 0 : appendlen);
    while(*pfrom)
    {
        if(*pfrom != '\'') *pto = *pfrom;
        pfrom++;
        pto++;
    }

    pfrom = pchatmsg;
    while(*pfrom)
    {
        *pto = *pfrom;
        pto++;
        pfrom++;
    }
    *pto = '\0';
    
    file_append(g_chatlog, strlen(g_chatlog), "chatlog.txt");
    chatlog_ts_update();
}

void
chatlog_reload()
{
    int file_buf_len = 0;
    
    memset(g_chatlog, 0, CHATLOG_SIZE);
    
    char* file_buf = file_read("chatlog.txt", &file_buf_len);
    if(file_buf)
    {
        memcpy(g_chatlog, file_buf, file_buf_len);
        free(file_buf);
    }
}

static void cb_disconnect_first(peer_session_t* p) {
    extern void cb_disconnect(peer_session_t*);

    cb_disconnect(p);

    assert(p->buffer_count == PEER_RECV_BUFFER_COUNT);
}

void cb_begin(peer_session_t* p) {

    printf("peer[%d] we alive now chickenhead!\n", p->id);
    // cxn_start is called by main epoll thread

    extern void cb_disconnect(peer_session_t*);

    p->cb_restart = cb_disconnect_first;
    p->time_pkt_last = get_time_ms();

    p->alive = 1;
}

void
bootstrap_peer_async(peer_session_t* p)
{

    usleep(1000000);
    p->alive = 1;

    printf("bootstrap_peer:\nsdp:\n%s\n", p->sdp.answer);
    int count = 10;
    while(count > 0) 
    {
        while(p->alive && !p->thread_inited) 
        {
            usleep(10000);
            printf("bootstrap_peer_async: awaiting !peers[%d].thread_inited\n", p->id);
        }

        printf("bootstrap_peer_async: peer[%d] alive=%d\n", p->id, p->alive);
        count--;
    }
    //printf("bootstrap_peer_async: aliving..");
    //p->alive = 1;
    printf(".done\n");
}

void setupSTUN(void* voidp) {
    peer_session_t *p = voidp;
    char** sdp = &g_sdp;

    // this is called with peer lock taken and alive=true, careful

    printf("setupSTUN: ICE peer matched....\n");

    // init stun-ice attributes
    strcpy(p->sdp.answer, *sdp);

    // HACK: leaking a buffer here for sdp so it can be shared between threads
    //printf("leaking sdp: %02x\n", *sdp);
    //free(*sdp);
    //*sdp = NULL;

    // mark -- signal/wait for peer to be initialized
    p->time_pkt_last = get_time_ms();
}

peer_session_t* cb_tgtpeer;


void*
webserver_worker(void* p)
{
    int r;
    char *page_buf_welcome = "<html><p>Welcome</p></html>";
    char *page_buf_400 = "<html><button onclick='document.location=\"/index.html\"'>Join conference</button></html>";
    char *page_buf_sdp_uploaded = "<html><button><body onload='window.location=\"content/uploadDone.html\";'>redirecting...</body></html>";
    char *page_buf_redirect_chat = "<html><body onload='window.location=\"content/peersPopup.html\";'>redirecting...</body></html>";
    char *page_buf_redirect_back = "<html><body onload='location=\"/content/chat.html\";'>redirecting...</body></html>";
    char *page_buf_redirect_subscribe = "<html><body onload='location=\"/content/iframe_channel.html\";'>redirecting...</body></html>";
    char *page_buf_slotbusy = "<html><body onload='window.location=\"content/uploadDone.html\";'><p>peer connection resources busy - please try again</p></body></html>";
    char *ok_hdr_ok = "HTTP/1.0 200 OK\r\n", *ok_hdr = ok_hdr_ok;
    char *accepted_hdr = "HTTP/1.0 201 Created\r\n";
    char *fail_hdr = "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n";
    char *content_type_html = "Content-Type: text/html\r\n\r\n";
    char *content_type_sdp = "Content-Type: application/sdp\r\n\r\n";
    char *content_type = content_type_html;
    char* content_length_hdr = "Content-Length: ";
    char *tag_hostname = "%$HOSTNAME$%";
    char *tag_peerdynamicjs = "%$PEERDYNAMICJS$%";
    char *tag_urlargsname = "%$URLARGUMENTSNAME$%";
    char *tag_urlargsroom = "%$URLARGUMENTSROOM$%";
    char *tag_webport = "%$WEBPORT$%";
    char *tag_rtpport = "%$RTPPORT$%";
    char *tag_peerlisthtml = "%$PEERLISTHTML$%";
    char *tag_peerlisthtml_options = "%$PEERLISTHTMLOPTIONS$%";
    char *tag_peerlist_jsarray = "%$PEERLISTJSARRAY$%";
    char *tag_stunconfig_js = "%$STUNCONFIGJS$%";
    char *tag_chatlogvalue = "%$CHATLOGTEXTAREAVALUE$%";
    char *tag_chatlogjs = "%$CHATLOGJSARRAY$%";
    char *tag_chatlogtsvalue = "%$CHATLOGTSVALUE$%";
    char *tag_watchuser = "watch?user=";
    char *tag_login = "login.html";
    char *tag_login_apprtc = "/login/";
    char *tag_logout = "logout.html";
    char *tag_sdp = "%$SDP_OFFER$%";
    char *tag_authcookie = "%$AUTHCOOKIE$%";
    char *tag_dtlsfingerprint = "%$DTLSFINGERPRINT$%";
    char *tag_lobbyimage = "%$LOBBYIMAGEURL$%";
    const size_t buf_size = 4096;
    int use_user_fragment_prefix = 1;
    webserver_worker_args* args = (webserver_worker_args*) p;
    unsigned int content_len = 0;
    char cookie[256], cookieset[256];
    char ws_header_buf[256];
    peer_session_t* peer_found_via_cookie = NULL;
    int peer_broadcast_from_cookie = PEER_IDX_INVALID;
    char stackPaddingHack[2048];
    char* recvbuf = malloc(buf_size*2);
    pthread_t thr_boot;
    pthread_attr_t thread_attrs;


    memset(cookie, 0, sizeof(cookie));

    sprintf(cookieset, "%02x%02x%02x%02x", rand() % 0xff, rand() % 0xff, rand() % 0xff, rand() % 0xff);

    thread_init();

    sprintf(listen_port_str, "%d", peers[webserver.peer_idx_next % MAX_PEERS].port);

    do
    {
        int sock;
        struct sockaddr_in sa;
        socklen_t sa_len;
        int flags = 0;

        memset(&sa, 0, sizeof(sa));
        sa_len = sizeof(sa);

        sock = args->sock;
        if(sock >= 0)
        {
            //printf("%s:%d connection thread (%s:%d)\n", __func__, __LINE__, inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));

            memset(recvbuf, 0, buf_size);

            char *roff = recvbuf;
            unsigned int recv_left = buf_size-1;
            int timed_out = 0;
            int do_shutdown = 1;
            int timeout_ms = 10000;
            while(1)
            {
                /* new request */
                /* TODO: always indicate connection-close by shutting-down immediately */
                if(waitsocket(sock, timeout_ms / 1000, 0) == 0)
                {
                    printf("%s:%d timed out\n", __func__, __LINE__);

                    do_shutdown = 1;
                    timed_out = 1;
                }

                r = recv(sock, roff, recv_left, flags);
                if(r <= 0) break;

                const char *cookietoken;
                char* pcookie;

                cookietoken = "authCookieJS12242016=";
                pcookie = strstr(recvbuf, cookietoken);

                memset(cookie, 0, sizeof(cookie));
                if(pcookie)
                {
                    pcookie += strlen(cookietoken);
                    str_read(pcookie, cookie, ";\r\n\t", sizeof(cookie));
                    strcpy(cookieset, cookie);
                }

                char* pcontent_len = strstr(recvbuf, content_length_hdr);
                if(pcontent_len && content_len == 0)
                {
                    pcontent_len += strlen(content_length_hdr);
                    sscanf(pcontent_len, "%u", &content_len);
                }

                char* phdr_end = strstr(recvbuf, "\r\n\r\n");
                if(phdr_end && content_len == 0) break;

                roff += r; 
                recv_left -= r;

                /* if >= content-length received, break */
                unsigned int body_len = (roff-recvbuf) - (phdr_end-recvbuf) - 4;
                if(content_len > 0 && body_len >= content_len) break;
            }

            if(strlen(recvbuf) > 0)
            {
                char path[buf_size];
                char url_args[1024];
                char *purl = NULL;
                char *pbody = NULL;
                char *phttpheaders = NULL;
                char *pend = NULL;
                char *response = NULL;
                int response_binary = 0;
                unsigned int file_buf_len = 0;
                char *file_buf = NULL;
                int cmd_post = 0;
                char cookie_hdr[256];
                int sidx;
                int i;
                char tmp[256];

                memset(url_args, 0, sizeof(url_args));
                cookie_hdr[0] = '\0';

                purl = recvbuf;

                memdebug_sanity(recvbuf);

                if(strncmp(recvbuf, "GET ", 4) == 0) {
                    purl = recvbuf+4;
                }
                else if(strncmp(recvbuf, "POST ", 5) == 0) {
                    purl = recvbuf+5;
                    cmd_post = 1;
                }
                else {
                    continue;
                }

                response = strdup(page_buf_400);

                memdebug_sanity(response);

                char *e = purl;
                char *pargs = NULL;
                while (e-purl < (sizeof(path)-1) && *e != '\0' && *e != '\r' && *e && *e != '\n' && *e != ' ' && *e != '?') e++;
                if(*e == '?') {
                    char* ptr = url_args;
                    pargs = e+1;
                    while((*pargs >= 'a' && *pargs <= 'z') || (*pargs >= '0' && *pargs <= '9') || (*pargs == '&' || *pargs == '%' || *pargs == '='))
                    {
                        *ptr = *pargs;
                        pargs++;
                        ptr++;
                    }
                    *ptr = '\0';
                }
                *e = '\0';

                memdebug_sanity(recvbuf);

                pbody = e+1;
                while(*pbody == '\r' || *pbody == '\n') pbody++;
                phttpheaders = pbody;
                if(*pbody != '\0')
                {
                    pbody = strstr(pbody, "\r\n\r\n");
                    if(pbody) pbody += 4;
                    else pbody = e+1;
                }

                pend = pbody;
                while(*pend) pend++;

                memdebug_sanity(recvbuf);

                //printf("%s:%d webserver received:\n----------------\n"
                //       "%s\n---------------%s\n"
                //       "---------------\n", __func__, __LINE__,
                //       recvbuf, phttpheaders);

                peer_found_via_cookie = peer_find_by_cookie(cookie);
                //printf("peer_found_via_cookie=%s\n", peer_found_via_cookie!=0? "yes" : "no");

                if(!cmd_post)
                {
                    if(strcmp(purl, "/") == 0) strcpy(path, "index.html");
                    else sprintf(path, "./%s", purl);
                     
                    file_buf = file_read(path, &file_buf_len);

                    //printf("%s:%d webserver GET for file (%s):\n\t%s\n", __func__, __LINE__, file_buf? "": "failed", path);

                    if(!file_buf)
                    {
                        if(file_buf)
                        {
                            free(file_buf);
                            file_buf = NULL;
                        }

                        send(sock, ok_hdr, strlen(ok_hdr), flags);
                        send(sock, content_type_html, strlen(content_type_html), flags);
                        send(sock, page_buf_400, strlen(page_buf_400), flags);
                        timed_out = 1;
                    }
                    else
                    {
                        free(response);
                        response = file_buf;
                        file_buf = NULL;

                        if(strstr(path, ".js")) content_type = "Content-Type: text/javascript\r\n\r\n";
                        else if(strstr(path, ".html")) content_type = content_type_html;
                        else if(strstr(path, ".css")) content_type = "Content-Type: text/css\r\n\r\n";
                        else if(strstr(path, ".jpg")) { response_binary = 1; content_type = "Content-Type: image/jpeg\r\n\r\n"; }
                        else if(strstr(path, ".gif")) { response_binary = 1; content_type = "Content-Type: image/gif\r\n\r\n"; }
                        else if(strstr(path, ".png")) { response_binary = 1; content_type = "Content-Type: image/png\r\n\r\n"; }
                        else if(strstr(path, tag_watchuser)) content_type = content_type_html;
                        else content_type = content_type = "Content-Type: application/octet-stream\r\n\r\n";
                    }

                    if(strstr(purl, tag_login) && strlen(url_args) > 0)
                    {
                        size_t retries = MAX_PEERS;

                        printf("cookie=%s\n", cookie);
                       
                        sidx = webserver.peer_idx_next % MAX_PEERS;
                        webserver.peer_idx_next += 1;

                        PEER_LOCK(sidx);

                        if(peers[sidx].alive)
                        {
                            // full
                            PEER_UNLOCK(sidx);
                            
                            printf("webserver: peers full @ login\n");
                            content_type = content_type_html;
                            response = strdup(page_buf_redirect_back);
                            goto response_override;
                        }

                        printf("peer[%d] logging in\n", sidx);

                        peer_init(&peers[sidx], sidx);

                        peers[sidx].time_pkt_last = get_time_ms();

                        peer_cookie_init(&peers[sidx], cookie);
                        strcpy((char*) &peers[sidx].name, str_read_unsafe(url_args, "name=", 0));
                        /*
                        chatlog_append("login:"); chatlog_append(peers[sidx].name); chatlog_append("\n");
                        */
                        strcat(peers[sidx].http.dynamic_js, "myUsername = '");
                        strcat(peers[sidx].http.dynamic_js, peers[sidx].name);
                        strcat(peers[sidx].http.dynamic_js, "';\n");

                        PEER_UNLOCK(sidx);
                    }

                    if(strstr(purl, tag_logout))
                    {
                        if(peer_found_via_cookie)
                        {
                            peer_session_t* peer_logout = peer_found_via_cookie;

                            /*
                            chatlog_append("logged out:"); chatlog_append(peer_found_via_cookie->name); chatlog_append("\n");
                            */

                            PEER_LOCK(peer_logout->id);

                            void web_cb_logout(peer_session_t* p) {
                                printf("cb_logout @ %02x\n", p);

                                p->alive = 0;
                                peer_cookie_init(p, "");
                            }

                            peer_logout->cb_restart = web_cb_logout;
                            peer_logout->init_needed = 1;
                            PEER_UNLOCK(peer_logout->id);
                            
                            peer_found_via_cookie = NULL;
                        }
                    }

                    /* macros */
                    if(peer_found_via_cookie)
                    {
                        response = macro_str_expand(response, tag_peerdynamicjs, peer_found_via_cookie->http.dynamic_js);
                    }
                    else
                    {
                        response = macro_str_expand(response, tag_peerdynamicjs, PEER_DYNAMIC_JS_EMPTY);
                    }
                    
                    response = macro_str_expand(response, tag_hostname, iplookup_addr);
                    response = macro_str_expand(response, tag_urlargsname, str_read_unsafe_delim(url_args, "name=", 0, "&"));
                    response = macro_str_expand(response, tag_urlargsroom, str_read_unsafe_delim(url_args, "room=", 0, "&"));
                    response = macro_str_expand(response, tag_webport, get_config("webserver_port="));
                    response = macro_str_expand(response, tag_rtpport, listen_port_str);
                    
                    {
                        const char *onClickMethod = "onPeerClick";
                        char peer_list_html[buf_size];
                        memset(peer_list_html, 0, sizeof(peer_list_html));
                        char line[buf_size];
                        int i;
                        int num_peers = 0; 
                        for(i = 0; i < MAX_PEERS; i++)
                        {
                            if(peers[i].alive)
                            {
                                num_peers++;

                                char key_buf[1024];
                                hex_print(key_buf, peers[i].dtls.master_key_salt, 8);
                                sprintf(line, "<input type='checkbox' %s onClick='%s(\"%s\", this);'>[%d]:%s (address:%s:%d bytes:%u id:%d master_key:%s)</input><br>\n",
                                        peers[i].recv_only? "disabled": "",
                                        (char*)onClickMethod,
                                        peers[i].name, i, peers[i].name,
                                        inet_ntoa(peers[i].addr.sin_addr),
                                        ntohs(peers[i].addr.sin_port),
                                        peers[i].rtp_buffered_total,
                                        peers[i].id,
                                        key_buf);
                                strncat(peer_list_html, line, sizeof(peer_list_html)-strlen(peer_list_html)-1);
                            }
                        }                       
                        response = macro_str_expand(response, tag_peerlisthtml, peer_list_html);
                    }

                    if(strstr(response, tag_peerlisthtml_options))
                    {
                        char peer_list_html[buf_size];
                        char line[buf_size];
                        int peer_list_html_free = buf_size-1;
                        int num_peers = 0;

                        memset(peer_list_html, 0, sizeof(peer_list_html));
                        memset(line, 0, sizeof(line));

                        for(i = 0; i < MAX_PEERS; i++)
                        {
                            if(peers[i].alive)
                            {
                                num_peers++;

                                char key_buf[1024];
                                hex_print(key_buf, peers[i].dtls.master_key_salt, 8);
                                sprintf(line, "<option value=\"%s\">%s (%s:%d)</option>\n", peers[i].name, peers[i].name, inet_ntoa(peers[i].addr.sin_addr), ntohs(peers[i].addr.sin_port));
                                
                                if(strlen(line) >= sizeof(peer_list_html)-strlen(peer_list_html)) break;

                                strcat(peer_list_html, line);
                                peer_list_html_free -= strlen(line);
                            }
                        }                       
                        response = macro_str_expand(response, tag_peerlisthtml_options, peer_list_html);
                    }

                    if(strstr(response, tag_peerlist_jsarray))
                    {
                        char peer_list_html[buf_size];
                        int peer_list_html_free = buf_size-16;
                        char line[buf_size];
                        int num_peers = 0;
                        int first_entry = 1;

                        sprintf(peer_list_html, "var peerList = [");

                        for(i = 0; i < MAX_PEERS; i++)
                        {
                            if(peers[i].alive && peers[i].srtp_inited)
                            {
                                num_peers++;

                                char key_buf[1024];
                                char salt_buf[1024];
                                hex_print(key_buf, peers[i].dtls.master_key[0], SRTP_MASTER_KEY_KEY_LEN);
                                hex_print(salt_buf, peers[i].dtls.master_salt[0], SRTP_MASTER_KEY_SALT_LEN);
                                sprintf(line, "%s{'name': '%s', 'id': '%d', 'addr': '%s:%u', 'key': '%s', 'salt': '%s', 'recvonly': %s, 'room': '%s'}",
                                        (first_entry? "": ","), peers[i].name, peers[i].id, inet_ntoa(peers[i].addr.sin_addr), ntohs(peers[i].addr.sin_port),
                                        key_buf, salt_buf, (peers[i].recv_only? "true": "false"), peers[i].roomname);
                                if(peer_list_html_free < strlen(line)) break;
                                strcat(peer_list_html, line);
                                peer_list_html_free -= strlen(line);
                                first_entry = 0;
                            }
                        }
                        strcat(peer_list_html, "];\n");
                        response = macro_str_expand(response, tag_peerlist_jsarray, peer_list_html);
                    }

                    sprintf(tmp, "{ \"iceServers\": [{ \"url\": \"stun:%s:%s\" }] }", iplookup_addr, listen_port_str);
                    response = macro_str_expand(response, tag_stunconfig_js, /*tmp*/ "null");

                    sprintf(tmp, "candidate:1 1 UDP 1234 %s %s typ host generation 0 network-cost 50", iplookup_addr, listen_port_str);
                    response = macro_str_expand(response, tag_icecandidate, tmp);
                
                    response = macro_str_expand(response, tag_chatlogvalue, chatlog_read());

                    if(strstr(response, tag_sdp))
                    {
                        pthread_mutex_lock(&webmtx);

                        // MARK: -- sdp offer created here
                        char* offer = sdp_offer_create();
                        response = macro_str_expand(response, tag_sdp, offer);

                        pthread_mutex_unlock(&webmtx);
                    }

                    if(strstr(response, tag_chatlogjs))
                    {
                        size_t jslen = sizeof(g_chatlog)*4;
                        char* js = malloc(jslen);
                        if(!js) return NULL;
                        char* ptr = g_chatlog;
                        char* wptr = js;


                        // TODO: better separators in chatlog

                        const char* eoltag = "\n";
                        const char* septag = "',\n'";

                        strcpy(wptr, "'"); wptr++;
                        while(*ptr && wptr-js < (jslen-16))
                        {
                            if(strncmp(ptr, eoltag, strlen(eoltag)) == 0) {
                                strcpy(wptr, septag);
                                if(*ptr == eoltag[0]) ptr += strlen(eoltag);
                                else ptr++;
                                wptr += strlen(septag);
                                continue;
                            }
                            else if(*ptr == '\r') { ptr++; continue; }
                            else if(*ptr == '\'') { ptr++; continue; }
                            else {
                                *wptr = *ptr;
                            }
                            ptr ++;
                            wptr ++;
                        }
                        *wptr = '\''; wptr++; *wptr = '\0';
                        
                        response = macro_str_expand(response, tag_chatlogjs, js);
                        free(js);
                    }

                    sprintf(tmp, "%lu", g_chatlog_ts);
                    response = macro_str_expand(response, tag_chatlogtsvalue, tmp);

                    response = macro_str_expand(response, tag_authcookie, cookieset);

                    response = macro_str_expand(response, tag_dtlsfingerprint, dtls_fingerprint);

                    response = macro_str_expand(response, tag_lobbyimage, get_config("lobby_image="));
                }
                else
                {

                    sprintf(path, "./%s", purl);//posturl
                    printf("%s:%d webserver POST for file (content_len:%d):\n\t%s\n", __func__, __LINE__, content_len, purl);

                    char** sdp = &g_sdp;
                    const char* (*ufrag_offerget)(void), (*ufrag_answerget)(void);
                    char* frag;

                    const char* ufrag_offerget_whep(void) {
                        // https://datatracker.ietf.org/doc/html/draft-murillo-whep-03

                        ok_hdr = accepted_hdr;

                        // stuff the uploaded offer as if we had prior created so it will be found during stun

                        strcpy(offer_frag, sdp_read(*sdp, kSDPICEUFRAG));
                        strcpy(offer_pwd, sdp_read(*sdp, kSDPICEPWD));

                        sdp_whep_answer_create(*sdp); // actually an answer reusing offer_table

                        char* g_answer = offer_building_whep;
                        char* myufrag = sdp_offer_table.t.iceufrag; // actually an answer reusing offer_table

                        // change peers init fn
                        peers[sidx].init_sesscb = peer_cb_init_sesh_whepice;

                        strcpy(peers[sidx].sdp.offer, *sdp); // save original offer from client
                        strcpy(peers[sidx].sdp.answer, g_answer);   // save our answer

                        // DONT FORGET ICE PARAMS - stun_ice used temporarily before cxn-worker starts
                        //strcpy(peers[sidx].stun_ice.ufrag_answer, offer_frag);  // TODO: ??? redundant? we are setting ufrag_offer/answer all over !!
                        //strcpy(peers[sidx].stun_ice.answer_pwd, sdp_read(peers[sidx].sdp.offer, kSDPICEPWD));

                        //strcpy(peers[sidx].stun_ice.offer_pwd, sdp_read(peers[sidx].sdp.answer, kSDPICEPWD));

                        // do not copy sdp offer from offer-table to peer yet - STUN happens and does that
                        // breakpoint!
                        return offer_frag;   // return offer:answer (here whep is offer, we answer)
                    }

                    const char* ufrag_offerget_pbody(void) {
                        // here offer is previously already created by a GET for /sdp.js
                        ok_hdr = ok_hdr_ok;

                        strcpy(peers[sidx].sdp.answer, *sdp); // save original offer and use as answer
                        strcpy(peers[sidx].sdp.offer, sdp_offer_table.t.offer);

                        return sdp_offer_table.t.iceufrag;  // return offer:answer (here we extended offer, *sdp is answer)
                    }

                    int sdp_upload_parse(void) {
                        // create temp file, decode, rename for worker thread to pick up/read and remove
                        sdp = &g_sdp;

                        *sdp = strdup(pbody);

                        memdebug_sanity(*sdp);
                        *sdp = sdp_decode(*sdp);

                        // anonymous+watching-only peers use new slot
                        if(peer_found_via_cookie && strstr(*sdp, "a=recvonly") != NULL)
                        {
                            assert(0); // peer_found_via is dead code
                            peer_broadcast_from_cookie = peer_found_via_cookie->id;
                            peer_found_via_cookie = NULL;
                        }

                        sidx = webserver.peer_idx_next % MAX_PEERS;
                        webserver.peer_idx_next += 1;

                        PEER_LOCK(sidx);

                        if(peers[sidx].alive)
                        {
                            PEER_UNLOCK(sidx);

                            printf("webserver: peers full @ /upload (sdp) \n");
                            content_type = content_type_html;
                            response = strdup(page_buf_400);
                            return -1;
                        }

                        // dont copy things to the peer prior to this!!!!
                        peer_init(&peers[sidx], sidx);
                        peers[sidx].broadcastingID = peer_broadcast_from_cookie;

                        // CALLING CREATE-OFFER HERE or create-answer (whep) in ufrag_offerget()
                        char *offeranswermaybe = ufrag_offerget();  // see ufrag_offerget_whep

                        // still LOCKED!
                        return 0;
                    }


                    void cb_begin(peer_session_t* p) {

                        printf("peer[%d] we alive now chickenhead!\n", p->id);
                        // cxn_start is called by main epoll thread

                        // next time this peer restarts we are terminating (state)
                        extern void cb_disconnect(peer_session_t*);

                        p->time_pkt_last = get_time_ms();
                        p->alive = 1;
                        p->cb_restart = cb_disconnect;

                        cb_done = 1;
                    }


                    void stun_config_peer(void) {
                        // --
                        peer_session_t* p = &peers[sidx];

                        // TODO: to support non-bundled connections create a 2nd thread here with above stun/sdp fields cloned

                        // -- using init_needed here to signal
                        p->cb_restart = cb_begin;

                        // await??
                        p->init_needed = 1;
                        PEER_UNLOCK(p->id);

                        // TODO: signal connection_w23orker thread that it may continue running
                        // (right now it just sleeps)
                        do {
                            sleep_msec(10); // wait for thread to call cb_done
                        } while(!cb_done);

                        // copy more from offer-table to peer? (leaving work in connection_worker) to parse from sdp -- but this copy has to happen for stun matching prior
                        // NOOOOO dont change shit here while it is being asynchronously modified

                        // todo: send peer a stun bind request here

                        printf("stun_config_peer: userfrag: %s:%s\n", p->stun_ice.ufrag_offer, p->stun_ice.ufrag_answer);
                    }

                    // parse uri
                    printf("purl=%s\n", purl);

                    if(strcmp(purl, "/"FILENAME_SDP_WHEP_OFFER) == 0)
                    {
                        ufrag_offerget = ufrag_offerget_whep;
                        if(sdp_upload_parse() != 0) goto response_override;
                        // at this point the sdp-offer table should contain the offer SDP text OBS uploaded

                        free(response);
                        response = malloc(strlen(page_buf_sdp_uploaded) + 2048);
                        strcpy(response, peers[sidx].sdp.answer);

                        content_type = content_type_sdp;

                        // our SDP answer is stuffed into the sdp offer table...and will be copied to peerX when stun matches
                        stun_config_peer();



                        goto response_override;
                    }
                    // handle SDP-answer upload
                    else if(strcmp(purl, "/"FILENAME_SDP_ANSWER) == 0)
                    {
                        ufrag_offerget = ufrag_offerget_pbody;
                        if(sdp_upload_parse() != 0) goto response_override;

                        // find original SDP offer and decode SDP answer and init stun_ice attributes
                        /*
                        if(peer_found_via_cookie) // OR WHEP RESPONSE
                        {
                            assert(0);  // TODO: REMOVE ME dead code to be removed

                            strcpy(ufrag_offeranswer_tmp, peer_found_via_cookie->stun_ice.ufrag_offer);
                            
                            sidx = PEER_INDEX(peer_found_via_cookie);

                            if(sidx == webserver.peer_idx_next) webserver.peer_idx_next += 1;

                            PEER_LOCK(sidx);
                        }
                        */

                        // setupSTUN moved from here - can't live on the stack now

                        printf("requesting peer[%d] restart\n", sidx);

                        free(response);
                        response = malloc(strlen(page_buf_sdp_uploaded) + 2048);
                        response[0] = '\0'; strcat(response, page_buf_sdp_uploaded);
                        content_type = content_type_html;

                        // TODO: there may be some benefit to having a separate monitor thread
                        // during setup "bootstrapping"
                        //pthread_attr_init(&thread_attrs);
                        //pthread_attr_setdetachstate(&thread_attrs, PTHREAD_CREATE_DETACHED);
                        //pthread_create(&thr_boot, &thread_attrs, bootstrap_peer_async, &peers[sidx]);

                        printf("webserver peer[%d] got SDP:\n%s\n", sidx, *sdp);

                        stun_config_peer();

                        goto response_override;
                    }
                    else if(strcmp(purl, "/chatmsg") == 0)
                    {
                        char *pchatmsg = pbody;

                        if(strncmp(pchatmsg, "msg=", 4)==0) pchatmsg += 4;
                        pchatmsg = sdp_decode(strdup(pchatmsg));
                      
                        chatlog_append(pchatmsg);
                        
                        free(response);
                        response = strdup(page_buf_redirect_back);
                        content_type = content_type_html;
                        goto response_override;
                    }
                    else if(strcmp(purl, "/subscribe") == 0)
                    {
                        peer_session_t* ps = peer_found_via_cookie;
                        unsigned int newChannel = 0;
                        char *p = pbody;
                        const char* subscribeKey = "subscriptionID=";
                        if(ps && strncmp(p, subscribeKey, strlen(subscribeKey)) == 0)
                        {
                            p += strlen(subscribeKey);
                            sscanf(p, "%u", &newChannel);
                            if(newChannel >= 0 && newChannel <= MAX_PEERS) {
                                ps->subscriptionID = peers[newChannel].id;
                            }
                        } 
                    }

                    free(response);
                    response = strdup(page_buf_redirect_subscribe);
                    content_type = content_type_html;
                }

                response_override:
                if(response && !timed_out)
                {
                    char *hdr = ok_hdr;
                    char clen_hdr[256];

                    r = send(sock, hdr, strlen(hdr), flags);
                    r = send(sock, cookie_hdr, strlen(cookie_hdr), flags);

                    // all headers prior to content-length (which contains \r\n\r\n and terminates headers)
                    sprintf(clen_hdr, "Content-Length: %lu\r\nETag: \"wutang4eva\"\r\nLocation: %s\r\n%s",
                            response_binary? file_buf_len: strlen(response),
                            purl, // location
                            content_type
                            );
                    r = send(sock, clen_hdr, strlen(clen_hdr), flags);
                    r = send(sock, response, response_binary? file_buf_len: strlen(response), flags);
                }

                if(do_shutdown)
                {
                    /* indicate to close cxn when done */
                    shutdown(sock, SHUT_WR);
                }
    
                if(response)
                {
                    free(response);
                    response = NULL;
                }
            }

            if(!do_shutdown) continue;

            close(sock);
        }
    } while(0);

    free(args);
    free(recvbuf);

    //printf("%s:%d exiting\n", __func__, __LINE__);
    return NULL;
}

void webserver_init()
{
    webserver.running = 1;
    webserver.peer_idx_next = 0;

    pthread_mutex_init(&webmtx, NULL);
}

void webserver_deinit(pthread_t thread)
{
    shutdown(webserver.sock, SHUT_RD);
    close(webserver.sock);
    webserver.running = 0;
    pthread_join(thread, NULL);
}

void*
webserver_accept_worker(void* p)
{    
    int backlog = 5;
    pthread_t thread = 0;
    int r;

    thread_init();

    int sock_web = bindsocket(webserver.inip, strToULong(get_config("webserver_port=")), 1);
    webserver.sock = sock_web;

    if(sock_web >= 0)
    {
        r = listen(sock_web, backlog);
    }

    while(webserver.running && sock_web >= 0)
    {
        struct sockaddr sa;
        socklen_t sa_len;
        int sock;
        int flags = 0;
        pthread_attr_t thread_attrs;

        pthread_attr_init(&thread_attrs);
        pthread_attr_setdetachstate(&thread_attrs, PTHREAD_CREATE_DETACHED);

        memset(&sa, 0, sizeof(sa));
        sa_len = sizeof(sa);

        sock = accept(sock_web, (struct sockaddr*) &sa, &sa_len);
        if(sock >= 0)
        {
            webserver_worker_args* args = (webserver_worker_args*) malloc(sizeof(webserver_worker_args) + 128);
            if(args)
            {
                args->ws_thread = 0;
                args->sock = sock;
                if(pthread_create(&thread, &thread_attrs, webserver_worker, args) != 0)
                {
                    printf("creating thread failed (errno=%s)\n", strerror(errno));
                }
            }
        }
    }

    //printf("%s:%d exiting\n", __func__, __LINE__);
}




#endif
