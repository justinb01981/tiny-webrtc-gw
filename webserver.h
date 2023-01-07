#ifndef __webserver_h__
#define __webserver_h__

#include "memdebughack.h"
#include "peer.h"
#include "thread.h"
#include <sys/errno.h>
#include "stun_callback.h"

/* include websockets */
#define sha1 sha1_
#define assert assert_
#include "websocket.h"
#define sha1_ sha1
#define assert_ assert

#define CHATLOG_SIZE 16384

#define TMPTRACE \
    printf("TRACE:%d",__FILE__,__LINE__)

extern int listen_port_base;
extern peer_session_t peers[];
extern int stun_binding_response_count;

const static unsigned long SPIN_WAIT_USEC = 1000;

static char g_chatlog[CHATLOG_SIZE];

static time_t g_chatlog_ts;

static char* g_sdp;

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


char*
macro_str_expand(char* buf, const char* tag, const char* replace)
{
    char* ret = buf;
    while(1)
    {
        ret = buf;

        /* macros */
        char *pmac = strstr(buf, tag);
        int expandlen = strlen(replace);
        if(pmac)
        {
            size_t realloc_len = strlen(buf) + expandlen + 1;
            char* tmp = malloc(realloc_len);
            if(tmp)
            {
                memset(tmp, 0, realloc_len);
                ret = tmp;

                strncpy(ret, buf, pmac - buf);
                pmac += strlen(tag);
                strcat(ret, replace);
                strcat(ret, pmac);
                free(buf);
                buf = ret;
                continue;
            }
        }
        break;
    }
    return ret;
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
    if(strlen(pchatmsg) >= CHATLOG_SIZE-1) appendlen = (CHATLOG_SIZE-1);
    
    char *pto = g_chatlog, *pfrom = (char*) g_chatlog + ((CHATLOG_SIZE-1) >= strlen(g_chatlog)+appendlen ? 0 : appendlen);
    while(*pfrom)
    {
        *pto = *pfrom;
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
    
    file_write2(g_chatlog, strlen(g_chatlog), "chatlog.txt");
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
    char *ok_hdr = "HTTP/1.0 200 OK\r\n";
    char *content_type = "";
    char *fail_hdr = "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n";
    char *content_type_html = "Content-Type: text/html\r\n\r\n";
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
    const size_t buf_size = 4096;
    int use_user_fragment_prefix = 1;
    webserver_worker_args* args = (webserver_worker_args*) p;
    unsigned int content_len = 0;
    char listen_port_str[64];
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

    int peer_idx_next = webserver.peer_idx_next % MAX_PEERS; // incremented later

    sprintf(listen_port_str, "%d", peers[peer_idx_next].port);

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
                    sprintf(path, "./%s", purl);
                     
                    file_buf = file_read(path, &file_buf_len);

                    //printf("%s:%d webserver GET for file (%s):\n\t%s\n", __func__, __LINE__, file_buf? "": "failed", path);

                    if(!file_buf || strcmp(purl, "/") == 0)
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

                        if(strstr(purl, ".js")) content_type = "Content-Type: text/javascript\r\n\r\n";
                        else if(strstr(purl, ".html")) content_type = content_type_html;
                        else if(strstr(purl, ".css")) content_type = "Content-Type: text/css\r\n\r\n";
                        else if(strstr(purl, ".jpg")) { response_binary = 1; content_type = "Content-Type: image/jpeg\r\n\r\n"; }
                        else if(strstr(purl, ".gif")) { response_binary = 1; content_type = "Content-Type: image/gif\r\n\r\n"; }
                        else if(strstr(purl, ".png")) { response_binary = 1; content_type = "Content-Type: image/png\r\n\r\n"; }
                        else if(strstr(purl, tag_watchuser)) content_type = content_type_html;
                        else content_type = content_type = "Content-Type: application/octet-stream\r\n\r\n";
                    }

                    if(strstr(purl, tag_login) && strlen(url_args) > 0)
                    {
                        printf("cookie=%s\n", cookie);
                       
                        sidx = webserver.peer_idx_next % MAX_PEERS;
                        webserver.peer_idx_next += 1;

                        PEER_LOCK(sidx);

                        if(peers[sidx].alive)
                        {
                            PEER_UNLOCK(sidx);
                            break;
                        }

                        printf("peer[%d] logging in\n", sidx);

                        peer_init(&peers[sidx], sidx);

                        peers[sidx].time_pkt_last = time(NULL);

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

                            peer_logout->restart_done = 0;
                            peer_logout->restart_needed = 1;
                            while(!peer_logout->restart_done)
                            {
                                PEER_UNLOCK(peer_logout->id);
                                usleep(SPIN_WAIT_USEC);
                                PEER_LOCK(peer_logout->id);
                            }
                            peer_logout->alive = 0;
                            peer_logout->restart_needed = 0;
                            peer_init(peer_logout, PEER_INDEX(peer_logout));
                            peer_cookie_init(peer_logout, "");
                            
                            peer_found_via_cookie = NULL;

                            PEER_UNLOCK(peer_logout->id);
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
                    
                    response = macro_str_expand(response, tag_hostname, get_config("udpserver_addr="));
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
                            if(peers[i].alive)
                            {
                                printf("%s:%d: %s\n", __FILE__, __LINE__, peers[i].name);

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

                    sprintf(tmp, "{ \"iceServers\": [{ \"url\": \"stun:%s:%s\" }] }", get_config("udpserver_addr="), listen_port_str);
                    response = macro_str_expand(response, tag_stunconfig_js, /*tmp*/ "null");

                    sprintf(tmp, "candidate:1 1 UDP 1234 %s %s typ host generation 0 network-cost 50", get_config("udpserver_addr="), listen_port_str);
                    response = macro_str_expand(response, tag_icecandidate, tmp);
                
                    response = macro_str_expand(response, tag_chatlogvalue, chatlog_read());

                    if(strstr(response, tag_sdp))
                    {
                        char* offer = sdp_offer_create(peer_found_via_cookie);
                        response = macro_str_expand(response, tag_sdp, offer);
                    }

                    if(strstr(response, tag_chatlogjs))
                    {
                        size_t jslen = sizeof(g_chatlog)*4;
                        char* js = malloc(jslen);
                        if(!js) return NULL;
                        char* ptr = g_chatlog;
                        char* wptr = js;
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
                }
                else
                {
                    sprintf(path, "./%s", purl);

                    //printf("%s:%d webserver POST for file (content_len:%d):\n\t%s\n", __func__, __LINE__, content_len, purl);

                    // handle SDP-answer upload
                    if(strcmp(purl, "/"FILENAME_SDP_ANSWER) == 0)
                    {
                        // create temp file, decode, rename for worker thread to pick up/read and remove
                        char tmp[256];
                        static char ufrag_offer_tmp[256];
                        char** sdp = &g_sdp;

                        *sdp = strdup(pbody);

                        memdebug_sanity(*sdp);

                        *sdp = sdp_decode(*sdp);

                        const static char* ufrag_answer = NULL;
                        ufrag_answer = sdp_read(*sdp, "a=ice-ufrag:");
                        
                        // anonymous+watching-only peers use new slot
                        if(peer_found_via_cookie && strstr(*sdp, "a=recvonly") != NULL)
                        {
                            peer_broadcast_from_cookie = peer_found_via_cookie->id;
                            peer_found_via_cookie = NULL;
                        }

                        // find original SDP offer and decode SDP answer and init stun_ice attributes
                        if(peer_found_via_cookie)
                        {
                            if(strlen(peer_found_via_cookie->stun_ice.ufrag_offer) <= 0)
                            {
                                printf("peer found, but no offer found for ice_ufrag\n");
                                
                                goto response_override;
                            }
                            
                            strcpy(ufrag_offer_tmp, peer_found_via_cookie->stun_ice.ufrag_offer);
                            
                            sidx = PEER_INDEX(peer_found_via_cookie);

                            if(sidx == webserver.peer_idx_next) webserver.peer_idx_next += 1;
                        }
                        else
                        {
                            sidx = webserver.peer_idx_next % MAX_PEERS;
                            webserver.peer_idx_next += 1;

                            peer_init(&peers[sidx], sidx);
                            peers[sidx].broadcastingID = peer_broadcast_from_cookie;
                            
                            strcpy(ufrag_offer_tmp, sdp_offer_table.t.iceufrag);
                            printf("ufrag_offer_tmp:%s\n", ufrag_offer_tmp);
                        }

                        printf("webserver got SDP:\n%s\n", *sdp);

                        strcpy(peers[sidx].sdp.answer, *sdp);

                        void setupSTUN(void* voidp) {
                            peer_session_t *p = voidp;
                            // this is called with peer lock taken and alive=true, careful

                            printf("setupSTUN: ....\n");

                            // init stun-ice attributes
                            strcpy(p->stun_ice.ufrag_answer, ufrag_answer);
                            strcat(ufrag_offer_tmp, ":");
                            strcat(ufrag_offer_tmp, ufrag_answer);
                            strcpy(p->stun_ice.ufrag_offer, ufrag_offer_tmp);

                            printf("setupSTUN.ufrag_offer_tmp:%s\n", ufrag_offer_tmp);
                            strcpy(p->sdp.offer, sdp_offer_find(/*p->stun_ice.ufrag_offer*/ ufrag_offer_tmp, ufrag_answer));
                            strcpy(p->sdp.answer, *sdp);

                            // HACK: leaking a buffer here for sdp so it can be shared between threads
                            //printf("leaking sdp: %02x\n", *sdp);
                            //free(*sdp);
                            //*sdp = NULL;

                            // mark -- signal/wait for peer to be initialized
                            p->time_pkt_last = time(NULL);
                        }

                        printf("requesting peer[%d] restart: stun_ice.user-name answer/offer: %s:%s\n",
                            sidx, peers[sidx].stun_ice.ufrag_answer, peers[sidx].stun_ice.ufrag_offer);

                        free(response);
                        //response = strdup(page_buf_sdp_uploaded);
                        response = malloc(strlen(page_buf_sdp_uploaded) + 2048);
                        response[0] = '\0'; strcat(response, page_buf_sdp_uploaded);
                        content_type = content_type_html;

                        //pthread_attr_init(&thread_attrs);
                        //pthread_attr_setdetachstate(&thread_attrs, PTHREAD_CREATE_DETACHED);
                        //pthread_create(&thr_boot, &thread_attrs, bootstrap_peer_async, &peers[sidx]);

                        peers[sidx].cxn_start = setupSTUN;
                        peers[sidx].restart_done = 0;
                        /*
                        while(!peers[sidx].restart_done) {
                            PEER_LOCK(sidx);
                            // don't set alive here - happens when STUN pkt
                            peers[sidx].restart_needed = 1;
                            PEER_UNLOCK(sidx);
                            printf("restart_done: waiting...\n");
                            sleep_msec(20);
                        }
                        */

                        peers[sidx].restart_done = 0;
                        peers[sidx].restart_needed = 1;
                        sleep_msec(100);
                        assert(peers[sidx].restart_done);
                        peers[sidx].restart_needed = 0;
                        peers[sidx].restart_done = 0;

                        char offerid[256];
                        sprintf(offerid, "%s:%s", peers[sidx].stun_ice.ufrag_offer, peers[sidx].stun_ice.ufrag_answer);

                        printf("peers[sidx].stun_ice.ufrag_offer: %s\n", /*peers[sidx].stun_ice.ufrag_offer*/ufrag_offer_tmp); 
                        strcpy(peers[sidx].sdp.offer, sdp_offer_find(ufrag_offer_tmp/*peers[sidx].stun_ice.ufrag_offer*/, ufrag_answer));
                        printf("found offer:%s\n", peers[sidx].sdp.offer);

                        peers[sidx].restart_done = 0;
                        peers[sidx].alive = 1;
                        // cxn_start is called by main epoll thread

                        printf("...done\n");

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
                    sprintf(clen_hdr, "Content-Length: %lu\r\n", response_binary? file_buf_len: strlen(response));
                    r = send(sock, clen_hdr, strlen(clen_hdr), flags);
                    r = send(sock, content_type, strlen(content_type), flags);
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
