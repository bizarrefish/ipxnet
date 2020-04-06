/*
 *  Copyright (C) 2002-2009  The DOSBox Team
 *  Copyright (C) 2009-2010  Michał "MasterM" Siejak
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "config.h"
#include <stdlib.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>
#include <string.h>
#include "ipx.h"
#include <libwebsockets.h>
#include <string.h>


Bit8u packetCRC(Bit8u *buffer, Bit16u bufSize) {
    Bit8u tmpCRC = 0;
    Bit16u i;
    for(i=0;i<bufSize;i++) {
        tmpCRC ^= *buffer;
        buffer++;
    }
    return tmpCRC;
}

/* one of these created for each message */

struct msg {
    void *payload; /* is malloc'd */
    size_t len;
};

/* one of these is created for each client connecting to us */

struct per_session_data__wsipx {
    Bit32u ipxNodeNum;

    bool registered;
    struct per_session_data__wsipx *pss_list;
    struct lws *wsi;
    struct lws_ring *ring; /* ringbuffer holding unsent messages */
};

/* one of these is created for each vhost our protocol is used with */

struct per_vhost_data__wsipx {
    struct lws_context *context;
    struct lws_vhost *vhost;
    const struct lws_protocols *protocol;

    struct per_session_data__wsipx *pss_list; /* linked-list of live pss*/
};

/* destroys the message when everyone has had a copy of it */

static void
__wsipx_destroy_message(void *_msg)
{
    struct msg *msg = _msg;

    free(msg->payload);
    msg->payload = NULL;
    msg->len = 0;
}

static int
callback_wsipx(struct lws *wsi, enum lws_callback_reasons reason,
               void *user, void *in, size_t len)
{
    struct per_session_data__wsipx *pss =
        (struct per_session_data__wsipx *)user;
    struct per_vhost_data__wsipx *vhd =
        (struct per_vhost_data__wsipx *)
        lws_protocol_vh_priv_get(lws_get_vhost(wsi),
                                 lws_get_protocol(wsi));
    const struct msg *pmsg;
    struct msg amsg;

    int m;

    /* Big-endian header */
    IPXHeader *tmpHeader = (IPXHeader*)in;

    switch (reason) {
    case LWS_CALLBACK_PROTOCOL_INIT:
        vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
                                          lws_get_protocol(wsi),
                                          sizeof(struct per_vhost_data__wsipx));
        vhd->context = lws_get_context(wsi);
        vhd->protocol = lws_get_protocol(wsi);
        vhd->vhost = lws_get_vhost(wsi);

        break;

    case LWS_CALLBACK_PROTOCOL_DESTROY:
        /* Dunno */
        break;

    case LWS_CALLBACK_ESTABLISHED:
        pss->wsi = wsi;
        pss->registered = false;

        /* This is the counter we allocate nodes from - server node is 9000 */
        static Bit32u ipxNodeCounter = 9001;
        /* TODO: Make this work for over 4 billion nodes(!) */
        pss->ipxNodeNum = ipxNodeCounter++;
        lwsl_user("Client %lu joined\n", pss->ipxNodeNum);
        

        pss->ring = NULL;

        /* Add us to the subscriber list */
        lws_ll_fwd_insert(pss, pss_list, vhd->pss_list);
        break;

    case LWS_CALLBACK_CLOSED:

        lwsl_user("Client %lu left\n", pss->ipxNodeNum);
        
        /* Destroy the client's ring */
        if(pss->ring)
            lws_ring_destroy(pss->ring);

        /* Remove client's session data */
        lws_ll_fwd_remove(struct per_session_data__wsipx, pss_list, pss, vhd->pss_list);

        break;

    case LWS_CALLBACK_SERVER_WRITEABLE:
        /* Send out whatever we have in the ring */

        pmsg = lws_ring_get_element(pss->ring, NULL);
        if (!pmsg)
            break; /* Nothing to do */

        m = lws_write(wsi, ((unsigned char *)pmsg->payload) + LWS_PRE,
                      pmsg->len, LWS_WRITE_BINARY);
        if (m < (int)pmsg->len) {
            lwsl_err("ERROR %d writing to ws socket\n", m);
            return -1;
        }

        /* Now written element - can consume it */
        lws_ring_consume(pss->ring, NULL, NULL, 1);

        /* more to do? */
        if (lws_ring_get_element(pss->ring, NULL))
            /* come back as soon as we can write more */
            lws_callback_on_writable(pss->wsi);

        break;

    case LWS_CALLBACK_RECEIVE:

        if(!pss->registered)
        {
            /* We haven't yet registered - this should be a reg message */

            // Check to see if echo packet
            if(SDLNet_Read16(tmpHeader->dest.socket) == 0x2) {
                // Null destination node means its a server registration packet
                if(tmpHeader->dest.addr.byIP.host == 0x0) {

                    // Register client - send registration packet back

                    /* Create a ring */
                    pss->ring = lws_ring_create(sizeof(struct msg), 8,
                                                __wsipx_destroy_message);

                    /* Make a registration packet */
                    struct {
                        Uint8 pad[LWS_PRE];
                        IPXHeader regHeader;
                    } *msgBuff;

                    /* notice we over-allocate by LWS_PRE */
                    msgBuff = malloc(sizeof(*msgBuff));


                    SDLNet_Write16(0xffff, msgBuff->regHeader.checkSum);
                    SDLNet_Write16(sizeof(msgBuff->regHeader), msgBuff->regHeader.length);

                    /* Dest - Write the node num we allocated */
                    SDLNet_Write32(0, &msgBuff->regHeader.dest.network);
                    msgBuff->regHeader.dest.addr.byIP.host = 0;
                    SDLNet_Write32(pss->ipxNodeNum, 2+msgBuff->regHeader.dest.addr.byNode.node);
                    SDLNet_Write16(0x2, &msgBuff->regHeader.dest.socket);

                    /* Src - Server is Node 9000 */
                    SDLNet_Write32(1, &msgBuff->regHeader.src.network);
                    msgBuff->regHeader.src.addr.byIP.host = 0;
                    SDLNet_Write32(9000, 2+msgBuff->regHeader.src.addr.byNode.node);
                    SDLNet_Write16(0x2, &msgBuff->regHeader.src.socket);
                    msgBuff->regHeader.transControl = 0;

                    /* Put this is in a msg structure */
                    amsg.payload = msgBuff;
                    amsg.len = sizeof(IPXHeader);

                    /* Enqueue the reply */
                    lws_ring_insert(pss->ring, &amsg, 1);
                    lws_callback_on_writable(pss->wsi);

                    pss->registered = true;
                }
                else
                {
                    LOG_MSG("Wat packet?");
                }
            }
        }
        else
        {
            /* Forwarding */
            Bit32u srcNodeNum = SDLNet_Read32(2+tmpHeader->src.addr.byNode.node);
            Bit32u destNodeNum = SDLNet_Read32(2+tmpHeader->dest.addr.byNode.node);

            /* Put message in the appropriate ring */
            lws_start_foreach_llp(struct per_session_data__wsipx **, ppss, vhd->pss_list) {


                if(!(*ppss)->registered)
                {
                    /* Don't route to unregistered clients */
                    continue;
                }

                bool send = false;
                if(destNodeNum == 0xffffffff)
                {
                    /* broadcast */
                    send = ((*ppss)->ipxNodeNum != srcNodeNum);
                }
                else
                {
                    /* normal */
                    send = ((*ppss)->ipxNodeNum == destNodeNum);
                }

                if(send)
                {
                    amsg.len = len;
                    /* notice we over-allocate by LWS_PRE */
                    amsg.payload = malloc(LWS_PRE + len);
                    if (!amsg.payload)
                    {
                        lwsl_user("OOM: dropping\n");
                        break;
                    }
                    memcpy((char*)amsg.payload + LWS_PRE, in, len);
                    lws_ring_insert((*ppss)->ring, &amsg, 1);
                    lws_callback_on_writable((*ppss)->wsi);

                    if(destNodeNum != 0xffffffff)
                    {
                        /* Not broadcasting - done */
                        break;
                    }
                }
            } lws_end_foreach_llp(ppss, pss_list);
        }

        break;

    default:
        break;
    }

    
    return 0;
}


#define LWS_PLUGIN_PROTOCOL_WSIPX                   \
    {                                               \
        "lws-wsipx",                                \
            callback_wsipx,                         \
            sizeof(struct per_session_data__wsipx), \
            4096,                                   \
            0, NULL,0                               \
            }



static struct lws_protocols protocols[] = {
	LWS_PLUGIN_PROTOCOL_WSIPX,
	{ NULL, NULL, 0, 0 } /* terminator */
};

static int interrupted;

/* static const struct lws_http_mount mount = { */
/* 	/\* .mount_next *\/		NULL,		/\* linked-list "next" *\/ */
/* 	/\* .mountpoint *\/		"/",		/\* mountpoint URL *\/ */
/* 	/\* .origin *\/			"./mount-origin", /\* serve from dir *\/ */
/* 	/\* .def *\/			"index.html",	/\* default filename *\/ */
/* 	/\* .protocol *\/			NULL, */
/* 	/\* .cgienv *\/			NULL, */
/* 	/\* .extra_mimetypes *\/		NULL, */
/* 	/\* .interpret *\/		NULL, */
/* 	/\* .cgi_timeout *\/		0, */
/* 	/\* .cache_max_age *\/		0, */
/* 	/\* .auth_mask *\/		0, */
/* 	/\* .cache_reusable *\/		0, */
/* 	/\* .cache_revalidate *\/		0, */
/* 	/\* .cache_intermediaries *\/	0, */
/* 	/\* .origin_protocol *\/		LWSMPRO_FILE,	/\* files in a dir *\/ */
/* 	/\* .mountpoint_len *\/		1,		/\* char count *\/ */
/* 	/\* .basic_auth_login_file *\/	NULL, */
/*                       }; */
    

static void sigint_handler(int sig)
{
	interrupted = 1;
}


int log_stdout(const char *fmt, ...)
{
  va_list args;
  int ret;

  time_t timestamp;
  struct tm *t;
  char buffer[50];
      
  time(&timestamp);
  t = localtime(&timestamp);
  sprintf(buffer, "%02d-%02d-%d %02d:%02d:%02d", t->tm_mon+1, t->tm_mday, t->tm_year+1900, t->tm_hour, t->tm_min, t->tm_sec);
            
  va_start(args, fmt);
  printf("[%s] ", buffer);
  ret = vprintf(fmt, args);
  printf("\n");
  va_end(args);
  fflush(stdout);
  return ret;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	const char *p;
	int n = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE
			/* for LLL_ verbosity above NOTICE to be built into lws,
			 * lws must have been configured and built with
			 * -DCMAKE_BUILD_TYPE=DEBUG instead of =RELEASE */
			/* | LLL_INFO */ /* | LLL_PARSER */ /* | LLL_HEADER */
			/* | LLL_EXT */ /* | LLL_CLIENT */ /* | LLL_LATENCY */
			/* | LLL_DEBUG */;

	signal(SIGINT, sigint_handler);

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("Starting wsipx router\n");

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.port = 9001;
	info.mounts = NULL;//&mount;
	info.protocols = protocols;
	info.options =
		LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

	lws_context_destroy(context);

	return 0;
}
