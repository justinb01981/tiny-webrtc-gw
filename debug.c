//#include "prototype.h"
#include "peer.h"

void debug_tailnode(peer_buffer_node_t* pb)
{
    assert(pb != NULL);
}

void debug_headresetnull(void* peer_)
{
    peer_session_t* peer = peer_;
    assert(peer->in_buffers_head.next && peer->in_buffers_head.tail, "peer tail node munged");
}
