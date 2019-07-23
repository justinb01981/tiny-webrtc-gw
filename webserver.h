#ifndef __webserver_h__
#define __webserver_h__

#include "peer.h"
#include "thread.h"

/* include websockets */
#define sha1 sha1_
#define assert assert_
#include "websocket.h"
#define sha1_ sha1
#define assert_ assert

#define CHATLOG_SIZE 16384

extern int listen_port;
extern peer_session_t peers[];
extern int stun_binding_response_count;

static char g_chatlog[CHATLOG_SIZE];

static time_t g_chatlog_ts;

extern int sdp_prefix_set(const char*);

struct webserver_state {
    char inip[64];
    int running;
    int peer_index_sdp_last;
};
extern struct webserver_state webserver;

enum websocket_state {
    WS_STATE_INITIAL = 1,
    WS_STATE_INITPEER = 2,
    WS_STATE_WRITESDP = 3,
    WS_STATE_JOINROOM = 4,
    WS_STATE_ROOMPOST = 5,
    WS_STATE_READING = 6,
    WS_STATE_EXIT = 7
};

typedef struct {
    int sock;
    pthread_t ws_thread;
    int ws_peeridx;
    int state;
    char websocket_accept_response[512];
    char* pbody;
    char roomname[256];
} webserver_worker_args;

static char *tag_icecandidate = "%$RTCICECANDIDATE$%";
static char *tag_room_ws = "%$ROOMNAME$%";
static char *tag_sdp_offer1 = "%$SDP_OFFER$%";
static char* tag_joinroom_ws = "POST /join/";
static char* tag_msgroom_ws = "POST /message/domain17/";


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
    g_chatlog_ts = time(NULL);
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

static void*
websocket_worker(void* p)
{
    webserver_worker_args* args = (webserver_worker_args*) p;
    struct {
        char* out;
        char* in;
        size_t out_len;
        size_t in_len;
    } ws_buffer;
    const size_t buf_size = 4096;
    int state;
    char* sdp = NULL;
    unsigned int icecandidates[16];
    char room_id_msg[256] = {0};
    int icecandidates_n = 0;

    peer_session_t* peer = NULL;

    thread_init();

    memset(&ws_buffer, 0, sizeof(ws_buffer));

    do
    {
        int sock;
        struct sockaddr_in sa;
        socklen_t sa_len;
        int flags = 0;

        memset(&sa, 0, sizeof(sa));
        sa_len = sizeof(sa);

        sock = args->sock;
        state = args->state;

        if(args->pbody)
        {
            printf("WS POST with body:\n%s\n", args->pbody);
        }

        if(sock >= 0)
        {
            char recvbuf[buf_size];
            char wsdecoded[buf_size];
            char sendbuf[buf_size];
            size_t send_len = 0;

            char value[buf_size];
            int value_len;
            int timeout_ms = 1000;
            int timeout_counter = 10;

            printf("%s:%d websocket connection (%s:%d)\n", __func__, __LINE__, inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));

            memset(recvbuf, 0, sizeof(recvbuf));
            memset(wsdecoded, 0, sizeof(wsdecoded));

            char *roff = recvbuf;
            unsigned int recv_left = sizeof(recvbuf)-1;

            while(state != WS_STATE_EXIT && (!peer || (time(NULL) - peer->time_pkt_last < 10)))
            {
                int r = 0;

                if(state == WS_STATE_READING) {

                    if(waitsocket(sock, timeout_ms / 1000, 0) == 0)
                    {
                        timeout_counter--;
                    }
                    else
                    {
                        timeout_counter = 30;
                        r = recv(sock, roff, recv_left > 0? 1: 0, flags);
                        if(r <= 0 || r > recv_left)
                        {
                            state = WS_STATE_EXIT; 
                            break;
                        }

                        roff += r;
                        recv_left -= r;
                    }
                }

                if(state == WS_STATE_READING && r > 0)
                {
                    uint8_t* decodedbuf = wsdecoded;
                    size_t decodedbuf_len = sizeof(wsdecoded)-1;

                    int frame_type =
                        wsParseInputFrame(recvbuf, roff-recvbuf,
                                          &decodedbuf, &decodedbuf_len);
                    switch(frame_type)
                    {
                    case WS_INCOMPLETE_FRAME:
                        // keep reading
                        continue;

                    case WS_TEXT_FRAME:
                        printf("websocket msg<-:\n%s\n", decodedbuf);
                        {
                             value_len = str_read_from_key("\\\"candidate\\\" : \\\"", decodedbuf, value, "\\", buf_size-1, 0);
                             while(value_len > 0 && icecandidates_n < 16) {
                                 char raddr_buf[64], rport_buf[64], cand_buf[64];
                                 if(str_read_from_key("raddr ", value, raddr_buf, " ", sizeof(raddr_buf)-1, 0) <= 0) break;
                                 if(str_read_from_key("rport ", value, rport_buf, " ", sizeof(rport_buf)-1, 0) <= 0) break;
                                 if(str_read_from_key("candidate:", value, cand_buf, " ", sizeof(cand_buf)-1, 0) <= 0) break;

                                 icecandidates[icecandidates_n++] = atoi(cand_buf);
                                 break;
                            }

                            value_len = str_read_from_key("\\\"sdp\\\":\\\"", decodedbuf, value, "\\\"", buf_size-1, 0);
                            if(value_len > 0)
                            {
                                sdp = strdup(decodedbuf);
                                if(sdp) sdp = str_replace_nested_escapes(sdp);
 
                                state = WS_STATE_INITPEER;
                            }

                            value_len = str_read_from_key("\"cmd\" : \"register\"", decodedbuf, value, "}", buf_size-1, 0);
                            if(value_len > 0)
                            {
                                value_len = str_read_from_key("\"roomid\" : \"", value, room_id_msg, "\"", sizeof(room_id_msg)-1, 0);
                            }
                        }

                    default:
                        roff = recvbuf;
                        recv_left = sizeof(recvbuf)-1;
                        memset(recvbuf, 0, sizeof(recvbuf));
                    }
                }

                if(state == WS_STATE_INITPEER)
                {
                    state = WS_STATE_READING;

                    int p;
                    for(p = 0; p < MAX_PEERS; p++)
                    {
                        if(!peers[p].alive)
                        {
                            peer = &peers[p];
                            break;
                        }
                    }
                 
                    if(peer)
                    {
                        peer_init(peer, PEER_INDEX(peer));

                        const char* sdp_offer_pending = sdp_offer_create_apprtc(peer);
                    
                        char* offersdp = strdup(sdp_offer_pending);
                        
                        if(offersdp) offersdp = str_replace_nested_escapes(offersdp);
                        
                        strcpy(peer->sdp.offer, offersdp);

                        strcpy(peer->stun_ice.ufrag_offer, sdp_read(offersdp, "a=ice-ufrag:"));

                        free(offersdp);

                        if(sdp)
                        {
                            char *psep = strchr(room_id_msg, '@');
                            *psep = '\0'; psep++;
                            sprintf(peer->sdp.answer, "a=myname=%s\r\na=watch=%s\r\n%s", room_id_msg, psep, sdp);
                            peer->stun_ice.controller = 0;
                            if(icecandidates_n > 0) peer->stun_ice.candidate_id = icecandidates[icecandidates_n-1];

                            free(sdp);
                            sdp = NULL;
                        }

                        // mark -- wait for peer to be initialized
                        peer->alive = 1;
                        peer->restart_needed = 1;

                        while(!peer->restart_done) usleep(1000);
                        peer->alive = 1;
                        peer->time_pkt_last = time(NULL);

                        peer->restart_needed = 0;
                    }
                }

                if(state == WS_STATE_INITIAL || state == WS_STATE_JOINROOM || state == WS_STATE_WRITESDP | state == WS_STATE_ROOMPOST)
                {
                    if(state == WS_STATE_INITIAL) {
                        
                        sprintf(sendbuf, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", args->websocket_accept_response);
                        send_len = strlen(sendbuf);
                        state = WS_STATE_READING;
                    }
                    else if(state == WS_STATE_JOINROOM) {
                        chatlog_append("appRTC joining\n");
                       
                        int file_buf_len = 0;
                        char* file_buf = file_read("content/apprtc/init.txt", &file_buf_len);

                        if(file_buf_len > 0)
                        {
                            char stuncandidate_js[256];
                            char* response = strdup(file_buf);
                            sprintf(stuncandidate_js, "candidate:1 1 UDP 1234 %s "
                                "%d typ host",
                                get_config("udpserver_addr="), listen_port);
                            response = macro_str_expand(response,
                                    tag_icecandidate, stuncandidate_js);

                            response = macro_str_expand(response, tag_room_ws, args->roomname);

                            sprintf(sendbuf, "HTTP/1.0 200 OK\r\nContent-Length: %lu\r\nContent-Type: text/plain\r\n\r\n%s",
                                    strlen(response), response);
                            send_len = strlen(sendbuf);
                            free(response);
                            free(file_buf);
                        }
                        state = WS_STATE_EXIT;
                    }
                    else if(state == WS_STATE_ROOMPOST) {
                        sdp = strdup(args->pbody);
                        if(sdp) sdp = str_replace_nested_escapes(sdp);

                        state = WS_STATE_INITPEER;
                    }
                    else if(state == WS_STATE_WRITESDP) {
                        int file_buf_len = 0;
                        char* file_buf = file_read("content/apprtc/offer.txt", &file_buf_len);
                        
                        if(file_buf_len > 0) {
                            strcpy(sendbuf, file_buf);
                            send_len = file_buf_len;
                            free(file_buf);
                        }

                        state = WS_STATE_READING;
                    }
                }

                if(send_len > 0) {
                    printf("websocket msg->:\n%s\n", sendbuf);
                    send(sock, sendbuf, send_len, 0);
                }
                send_len = 0;
            }

            printf("websocket_worker shutting down\n");
            shutdown(sock, SHUT_WR);
            close(sock);
            sock = -1;
        }
    }
    while(0);

    if(sdp) free(sdp);

    if(args) {
        if(args->pbody) free(args->pbody);
        free(args);
    }

    return NULL;
}


static void*
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

    memset(cookie, 0, sizeof(cookie));

    sprintf(cookieset, "%02x%02x%02x%02x", rand() % 0xff, rand() % 0xff, rand() % 0xff, rand() % 0xff);

    thread_init();

    sprintf(listen_port_str, "%d", listen_port);

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
            char recvbuf[buf_size];

            //printf("%s:%d connection (%s:%d)\n", __func__, __LINE__, inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));

            memset(recvbuf, 0, sizeof(recvbuf));

            char *roff = recvbuf;
            unsigned int recv_left = sizeof(recvbuf)-1;
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
                int become_ws = 0;
                int i;
                char tmp[256];

                memset(url_args, 0, sizeof(url_args));
                cookie_hdr[0] = '\0';

                purl = recvbuf;
                if(strncmp(recvbuf, "GET ", 4) == 0) {
                    purl = recvbuf+4;
                }
                else if(strncmp(recvbuf, tag_joinroom_ws, strlen(tag_joinroom_ws)) == 0) {
                    char *proomname = purl + strlen(tag_joinroom_ws);
                    str_read(proomname, args->roomname, "\r\n ", sizeof(args->roomname));
                    purl = recvbuf+5;
                    // parse room name
                    args->state = WS_STATE_JOINROOM;
                    become_ws = 1;
                }
                else if(strncmp(recvbuf, tag_msgroom_ws, strlen(tag_msgroom_ws)) == 0) {
                    purl = recvbuf+5;
                    args->state = WS_STATE_ROOMPOST;
                    become_ws = 1;
                }
                else if(strncmp(recvbuf, "POST ", 5) == 0) {
                    purl = recvbuf+5;
                    cmd_post = 1;
                }
                else {
                    continue;
                }

                response = strdup(page_buf_400);

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

                    if(strncmp(purl, "/ws", 3) == 0) { become_ws = 1; args->state = WS_STATE_INITIAL; }

                    if(!file_buf && become_ws)
                    {
                        args->pbody = strdup(pbody);
                        strcpy(args->websocket_accept_response,
                               websocket_accept_header(phttpheaders, ws_header_buf));

                        if(args->state == WS_STATE_INITIAL)
                        {
                             printf("peer[%d] logging in via websocket\n", sidx);
                        }

                        if(!args->ws_thread) pthread_create(&args->ws_thread, NULL, websocket_worker, args);
                        free(response);
                        return NULL;
                    }
                    else if(!file_buf || strcmp(purl, "/") == 0)
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
                        
                        for(sidx = 0; sidx < MAX_PEERS && !peer_found_via_cookie; sidx++) {
                            if(!peers[sidx].alive) {
                                printf("peer[%d] logging in\n", sidx);

                                peer_init(&peers[sidx], sidx);

                                peers[sidx].time_pkt_last = time(NULL);
                                peers[sidx].alive = 1;

                                peer_cookie_init(&peers[sidx], cookie);
                                strcpy((char*) &peers[sidx].name, str_read_unsafe(url_args, "name=", 0));
                                chatlog_append("login:"); chatlog_append(peers[sidx].name); chatlog_append("\n");
                                strcat(peers[sidx].http.dynamic_js, "myUsername = '");
                                strcat(peers[sidx].http.dynamic_js, peers[sidx].name);
                                strcat(peers[sidx].http.dynamic_js, "';\n");
                                break;
                            }
                        }
                    }

                    if(strstr(purl, tag_logout))
                    {
                        if(peer_found_via_cookie)
                        {
                            peer_session_t* peer_logout = peer_found_via_cookie;

                            chatlog_append("logged out:"); chatlog_append(peer_found_via_cookie->name); chatlog_append("\n");

                            peer_logout->restart_needed = 1;
                            while(!peer_logout->restart_done) usleep(1000);
                            peer_logout->alive = 0;
                            peer_logout->restart_needed = 0;
                            peer_init(peer_logout, PEER_INDEX(peer_logout));
                            peer_cookie_init(peer_logout, "");
                            
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
                                
                                if(strlen(line) > peer_list_html) break;

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
                        response = macro_str_expand(response, tag_sdp, sdp_offer_create(peer_found_via_cookie));
                    }

                    if(strstr(response, tag_chatlogjs))
                    {
                        size_t jslen = sizeof(g_chatlog)*4;
                        char* js = malloc(jslen);
                        if(!js) return;
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
                        /* create temp file, decode, rename for worker thread to pick up/read and remove */
                        char tmp[256], ufrag_offer_tmp[256];
                        char* sdp = strdup(pbody);
                        
                        sdp = sdp_decode(sdp);
                        
                        const char* ufrag_answer = sdp_read(sdp, "a=ice-ufrag:");
                        
                        // anonymous+watching-only peers use new slot
                        if(peer_found_via_cookie && strstr(sdp, "a=recvonly") != NULL)
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
                                
                                free(sdp);
                                goto response_override;
                            }
                            
                            strcpy(ufrag_offer_tmp, peer_found_via_cookie->stun_ice.ufrag_offer);
                            
                            sidx = PEER_INDEX(peer_found_via_cookie);
                        }
                        else
                        {
                            sidx = 0;
                            while(sidx < MAX_PEERS)
                            {
                                if(!peers[sidx].alive) break;
                                sidx++;
                            }
                            
                            if(sidx >= MAX_PEERS)
                            {
                                free(sdp);
                                goto response_override;
                            }
                            
                            peer_init(&peers[sidx], sidx);
                            peers[sidx].broadcastingID = peer_broadcast_from_cookie;
                            
                            strcpy(ufrag_offer_tmp, sdp_offer_table.t[(sdp_offer_table.next-1) % MAX_PEERS].iceufrag);
                        }

                        sprintf(tmp, "webserver: new SDP answer for peer %d\n", sidx);
                        chatlog_append(tmp);

                        // mark -- signal/wait for peer to be initialized
                        peers[sidx].time_pkt_last = time(NULL);
                        peers[sidx].alive = 1;
                        peers[sidx].restart_needed = 1;

                        while(!peers[sidx].restart_done) usleep(10000);
                        peers[sidx].alive = 1;
                        
                        // init stun-ice attributes
                        strcpy(peers[sidx].stun_ice.ufrag_answer, ufrag_answer);
                        strcpy(peers[sidx].stun_ice.ufrag_offer, ufrag_offer_tmp);
                        strcpy(peers[sidx].sdp.offer, sdp_offer_find(peers[sidx].stun_ice.ufrag_offer, ufrag_answer));
                        strcpy(peers[sidx].sdp.answer, sdp);
                        
                        strcpy(peers[sidx].name, str_read_unsafe(sdp, "a=myname=", 0));
                        strcpy(peers[sidx].roomname, str_read_unsafe(sdp, "a=room=", 0));

                        webserver.peer_index_sdp_last = sidx;

                        printf("peer restarted (stun_ice.user-name answer/offer: %s:%s)\n", peers[sidx].stun_ice.ufrag_answer, peers[sidx].stun_ice.ufrag_offer);
                        
                        peers[sidx].restart_needed = 0;
                        
                        free(sdp);

                        free(response);
                        response = strdup(page_buf_sdp_uploaded);
                        content_type = content_type_html;
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

    printf("%s:%d exiting\n", __func__, __LINE__);
    return NULL;
}

void webserver_init()
{
    webserver.peer_index_sdp_last = -1;
    webserver.running = 1;
}

void*
webserver_accept_worker(void* p)
{    
    int backlog = 5;
    pthread_t thread;

    thread_init();

    int sock_web = bindsocket(webserver.inip, strToInt(get_config("webserver_port=")), 1);

    printf("%s:%d starting (sock_web=%d)\n", __func__, __LINE__, sock_web);

    if(sock_web >= 0)
    {
        int r = listen(sock_web, backlog);
    }
    
    while(webserver.running && sock_web >= 0)
    {
        struct sockaddr sa;
        socklen_t sa_len;
        int sock;
        int flags = 0;
        pthread_attr_t thread_attrs;

        memset(&thread_attrs, 0, sizeof(thread_attrs));
        pthread_attr_setdetachstate(&thread_attrs, 1);

        memset(&sa, 0, sizeof(sa));
        sa_len = sizeof(sa);

        sock = accept(sock_web, (struct sockaddr*) &sa, &sa_len);
        if(sock >= 0)
        {
            webserver_worker_args* args = (webserver_worker_args*) malloc(sizeof(webserver_worker_args));
            if(args)
            {
                args->ws_thread = 0;
                args->sock = sock;

                pthread_create(&thread, &thread_attrs, webserver_worker, args);
            }
        }
    }

    printf("%s:%d exiting\n", __func__, __LINE__);
}



#endif
