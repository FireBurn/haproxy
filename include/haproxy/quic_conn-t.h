/*
 * include/haproxy/quic_conn-t.h
 *
 * Copyright 2019 HAProxy Technologies, Frederic Lecaille <flecaille@haproxy.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_QUIC_CONN_T_H
#define _HAPROXY_QUIC_CONN_T_H

#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <sys/socket.h>

#include <haproxy/cbuf-t.h>
#include <haproxy/list.h>

#include <haproxy/openssl-compat.h>
#include <haproxy/mux_quic-t.h>
#include <haproxy/quic_cc-t.h>
#include <haproxy/quic_frame-t.h>
#include <haproxy/quic_loss-t.h>
#include <haproxy/quic_stats-t.h>
#include <haproxy/quic_tls-t.h>
#include <haproxy/quic_tp-t.h>
#include <haproxy/task.h>

#include <import/ebtree-t.h>

typedef unsigned long long ull;

#define QUIC_PROTOCOL_VERSION_DRAFT_29   0xff00001d /* draft-29 */
#define QUIC_PROTOCOL_VERSION_1          0x00000001 /* V1 */
#define QUIC_PROTOCOL_VERSION_2_DRAFT    0x709a50c4 /* V2 draft */

#define QUIC_INITIAL_IPV4_MTU      1252 /* (bytes) */
#define QUIC_INITIAL_IPV6_MTU      1232

/* The minimum length of Initial packets. */
#define QUIC_INITIAL_PACKET_MINLEN 1200

/* Lengths of the QUIC CIDs generated by the haproxy implementation. */
#define QUIC_HAP_CID_LEN               8

/* Common definitions for short and long QUIC packet headers. */
/* QUIC connection ID maximum length for version 1. */
#define QUIC_CID_MAXLEN               20 /* bytes */
/* QUIC original destination connection ID minial length */
#define QUIC_ODCID_MINLEN              8 /* bytes */
/*
 * All QUIC packets with long headers are made of at least (in bytes):
 * flags(1), version(4), DCID length(1), DCID(0..20), SCID length(1), SCID(0..20)
 */
#define QUIC_LONG_PACKET_MINLEN            7
/* DCID offset from beginning of a long packet */
#define QUIC_LONG_PACKET_DCID_OFF         (1 + sizeof(uint32_t))
/*
 * All QUIC packets with short headers are made of at least (in bytes):
 * flags(1), DCID(0..20)
 */
#define QUIC_SHORT_PACKET_MINLEN           1
/* DCID offset from beginning of a short packet */
#define QUIC_SHORT_PACKET_DCID_OFF         1

/* Byte 0 of QUIC packets. */
#define QUIC_PACKET_LONG_HEADER_BIT  0x80 /* Long header format if set, short if not. */
#define QUIC_PACKET_FIXED_BIT        0x40 /* Must always be set for all the headers. */

/* Tokens formats */
/* Format for Retry tokens sent by a QUIC server */
#define QUIC_TOKEN_FMT_RETRY 0x9c
/* Format for token sent for new connections after a Retry token was sent */
#define  QUIC_TOKEN_FMT_NEW  0xb7
/* Salt length used to derive retry token secret */
#define QUIC_RETRY_TOKEN_SALTLEN       16 /* bytes */
/* Retry token duration */
#define QUIC_RETRY_DURATION_MS      10000
/* Default Retry threshold */
#define QUIC_DFLT_RETRY_THRESHOLD     100 /* in connection openings */

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+
 * |1|1|T|T|X|X|X|X|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Version (32)                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | DCID Len (8)  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |               Destination Connection ID (0..160)            ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | SCID Len (8)  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Source Connection ID (0..160)               ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                      Long Header Packet Format
 */

/* Two bits (T) for QUIC packet types. */
#define QUIC_PACKET_TYPE_BITMASK     0x03
#define QUIC_PACKET_TYPE_SHIFT       4

enum quic_pkt_type {
	QUIC_PACKET_TYPE_INITIAL,
	QUIC_PACKET_TYPE_0RTT,
	QUIC_PACKET_TYPE_HANDSHAKE,
	QUIC_PACKET_TYPE_RETRY,
	/*
	 * The following one is not defined by the RFC but we define it for our
	 * own convenience.
	 */
	QUIC_PACKET_TYPE_SHORT,
};

/* Packet number field length. */
#define QUIC_PACKET_PNL_BITMASK      0x03
#define QUIC_PACKET_PN_MAXLEN        4

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+
 * |0|1|S|R|R|K|P|P|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                Destination Connection ID (0..160)           ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     Packet Number (8/16/24/32)              ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     Protected Payload (*)                   ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                      Short Header Packet Format
 */

/* Bit (S) of short header. */
#define QUIC_PACKET_SPIN_BIT         0x20

/* Reserved Bits (R):  The next two bits of byte 0 are reserved.
 * These bits are protected using header protection
 * (see Section 5.4 of [QUIC-TLS]). The value included
 * prior to protection MUST be set to 0. An endpoint MUST treat
 * receipt of a packet that has a non-zero value for these bits,
 * after removing both packet and header protection, as a connection
 * error of type PROTOCOL_VIOLATION. Discarding such a packet after
 * only removing header protection can expose the endpoint to attacks
 * (see Section 9.3 of [QUIC-TLS]).
 */
#define QUIC_PACKET_RESERVED_BITS    0x18 /* (protected) */

#define QUIC_PACKET_KEY_PHASE_BIT    0x04 /* (protected) */

/* The maximum number of QUIC packets stored by the fd I/O handler by QUIC
 * connection. Must be a power of two.
 */
#define QUIC_CONN_MAX_PACKET  64

#define QUIC_STATELESS_RESET_PACKET_HEADER_LEN 5
#define QUIC_STATELESS_RESET_PACKET_MINLEN     (22 + QUIC_HAP_CID_LEN)

#define           QUIC_EV_CONN_NEW       (1ULL << 0)
#define           QUIC_EV_CONN_INIT      (1ULL << 1)
#define           QUIC_EV_CONN_ISEC      (1ULL << 2)
#define           QUIC_EV_CONN_RSEC      (1ULL << 3)
#define           QUIC_EV_CONN_WSEC      (1ULL << 4)
#define           QUIC_EV_CONN_RWSEC     (1ULL << 5)
#define           QUIC_EV_CONN_LPKT      (1ULL << 6)
#define           QUIC_EV_CONN_SPKT      (1ULL << 7)
#define           QUIC_EV_CONN_ENCPKT    (1ULL << 8)
#define           QUIC_EV_CONN_TXPKT     (1ULL << 9)
#define           QUIC_EV_CONN_PAPKT     (1ULL << 10)
#define           QUIC_EV_CONN_PAPKTS    (1ULL << 11)
#define           QUIC_EV_CONN_IO_CB     (1ULL << 12)
#define           QUIC_EV_CONN_RMHP      (1ULL << 13)
#define           QUIC_EV_CONN_PRSHPKT   (1ULL << 14)
#define           QUIC_EV_CONN_PRSAPKT   (1ULL << 15)
#define           QUIC_EV_CONN_PRSFRM    (1ULL << 16)
#define           QUIC_EV_CONN_PRSAFRM   (1ULL << 17)
#define           QUIC_EV_CONN_BFRM      (1ULL << 18)
#define           QUIC_EV_CONN_PHPKTS    (1ULL << 19)
#define           QUIC_EV_CONN_TRMHP     (1ULL << 20)
#define           QUIC_EV_CONN_ELRMHP    (1ULL << 21)
#define           QUIC_EV_CONN_RXPKT     (1ULL << 22)
#define           QUIC_EV_CONN_SSLDATA   (1ULL << 23)
#define           QUIC_EV_CONN_RXCDATA   (1ULL << 24)
#define           QUIC_EV_CONN_ADDDATA   (1ULL << 25)
#define           QUIC_EV_CONN_FFLIGHT   (1ULL << 26)
#define           QUIC_EV_CONN_SSLALERT  (1ULL << 27)
#define           QUIC_EV_CONN_PSTRM     (1ULL << 28)
#define           QUIC_EV_CONN_RTTUPDT   (1ULL << 29)
#define           QUIC_EV_CONN_CC        (1ULL << 30)
#define           QUIC_EV_CONN_SPPKTS    (1ULL << 31)
#define           QUIC_EV_CONN_PKTLOSS   (1ULL << 32)
#define           QUIC_EV_CONN_STIMER    (1ULL << 33)
#define           QUIC_EV_CONN_PTIMER    (1ULL << 34)
#define           QUIC_EV_CONN_SPTO      (1ULL << 35)
#define           QUIC_EV_CONN_BCFRMS    (1ULL << 36)
#define           QUIC_EV_CONN_XPRTSEND  (1ULL << 37)
#define           QUIC_EV_CONN_XPRTRECV  (1ULL << 38)
#define           QUIC_EV_CONN_FREED     (1ULL << 39)
#define           QUIC_EV_CONN_CLOSE     (1ULL << 40)
#define           QUIC_EV_CONN_ACKSTRM   (1ULL << 41)
#define           QUIC_EV_CONN_FRMLIST   (1ULL << 42)
#define           QUIC_EV_STATELESS_RST  (1ULL << 43)
#define           QUIC_EV_TRANSP_PARAMS  (1ULL << 44)
#define           QUIC_EV_CONN_IDLE_TIMER (1ULL << 45)
#define           QUIC_EV_CONN_SUB       (1ULL << 46)
#define           QUIC_EV_CONN_ELEVELSEL (1ULL << 47)
#define           QUIC_EV_CONN_RCV       (1ULL << 48)

/* Similar to kernel min()/max() definitions. */
#define QUIC_MIN(a, b) ({ \
    typeof(a) _a = (a);   \
    typeof(b) _b = (b);   \
    (void) (&_a == &_b);  \
    _a < _b ? _a : _b; })

#define QUIC_MAX(a, b) ({ \
    typeof(a) _a = (a);   \
    typeof(b) _b = (b);   \
    (void) (&_a == &_b);  \
    _a > _b ? _a : _b; })

/* Size of the internal buffer of QUIC TX ring buffers (must be a power of 2) */
#define QUIC_TX_RING_BUFSZ  (1UL << 12)
/* Size of the QUIC RX buffer for the connections */
#define QUIC_CONN_RX_BUFSZ (1UL << 16)

extern struct trace_source trace_quic;
extern struct pool_head *pool_head_quic_tx_ring;
extern struct pool_head *pool_head_quic_rx_packet;
extern struct pool_head *pool_head_quic_tx_packet;
extern struct pool_head *pool_head_quic_frame;
extern struct pool_head *pool_head_quic_dgram;

struct quic_version {
	uint32_t num;
	const unsigned char *initial_salt;
	size_t initial_salt_len;
	const unsigned char *key_label;
	size_t key_label_len;
	const unsigned char *iv_label;
	size_t iv_label_len;
	const unsigned char *hp_label;
	size_t hp_label_len;
	const unsigned char *ku_label;
	size_t ku_label_len;
	/* Retry tag */
	const unsigned char *retry_tag_key;
	const unsigned char *retry_tag_nonce;
};

extern const struct quic_version quic_versions[];
extern const size_t quic_versions_nb;
extern const struct quic_version *preferred_version;

/* QUIC connection id data.
 *
 * This struct is used by ebmb_node structs as last member of flexible arrays.
 * So do not change the order of the member of quic_cid struct.
 * <data> member must be the first one.
 */
struct quic_cid {
	unsigned char data[QUIC_CID_MAXLEN + sizeof(in_port_t) + sizeof(struct in6_addr)];
	unsigned char len; /* size of QUIC CID, excluding possible concatenated address */
	unsigned char addrlen; /* size of port + IP if present in data*/
};

/* QUIC connection id attached to a QUIC connection.
 *
 * This structure is used to match received packets DCIDs with the
 * corresponding QUIC connection.
 */
struct quic_connection_id {
	struct eb64_node seq_num;
	uint64_t retire_prior_to;
	unsigned char stateless_reset_token[QUIC_STATELESS_RESET_TOKEN_LEN];

	struct ebmb_node node; /* node for receiver tree, cid.data as key */
	struct quic_cid cid;   /* CID data */

	struct quic_conn *qc;  /* QUIC connection using this CID */
};

/* Structure to hold a range of ACKs sent in ACK frames. */
struct quic_arng {
	int64_t first;
	int64_t last;
};

/* Structure to hold a range of ACKs to be store as a node in a tree of
 * ACK ranges.
 */
struct quic_arng_node {
	struct eb64_node first;
	uint64_t last;
};

/* Structure to maintain a set of ACK ranges to be used to build ACK frames. */
struct quic_arngs {
	/* ebtree of ACK ranges organized by their first value. */
	struct eb_root root;
	/* The number of ACK ranges is this tree */
	size_t sz;
	/* The number of bytes required to encode this ACK ranges lists. */
	size_t enc_sz;
};

/* Flag the packet number space as having received a packet */
#define QUIC_FL_PKTNS_PKT_RECEIVED  (1UL << 0)
/* Flag the packet number space as requiring an ACK frame to be sent. */
#define QUIC_FL_PKTNS_ACK_REQUIRED  (1UL << 1)
/* Flag the packet number space as needing probing */
#define QUIC_FL_PKTNS_PROBE_NEEDED  (1UL << 2)
/* Flag the packet number space as having received a packet with a new largest
 * packet number, to be acknowledege
 */
#define QUIC_FL_PKTNS_NEW_LARGEST_PN (1UL << 3)

/* The maximum number of dgrams which may be sent upon PTO expirations. */
#define QUIC_MAX_NB_PTO_DGRAMS         2

/* QUIC packet number space */
struct quic_pktns {
	struct {
		/* List of frames to send. */
		struct list frms;
		/* Next packet number to use for transmissions. */
		int64_t next_pn;
		/* The packet which has been sent. */
		struct eb_root pkts;
		/* The time the most recent ack-eliciting packer was sent. */
		unsigned int time_of_last_eliciting;
		/* The time this packet number space has experienced packet loss. */
		unsigned int loss_time;
		/* Boolean to denote if we must send probe packet. */
		unsigned int pto_probe;
		/* In flight bytes for this packet number space. */
		size_t in_flight;
		/* The acknowledgement delay of the packet with the largest packet number */
		uint64_t ack_delay;
	} tx;
	struct {
		/* Largest packet number */
		int64_t largest_pn;
		/* Largest acked sent packet. */
		int64_t largest_acked_pn;
		struct quic_arngs arngs;
		unsigned int nb_aepkts_since_last_ack;
		/* The time the packet with the largest packet number was received */
		uint64_t largest_time_received;
	} rx;
	unsigned int flags;
};

/* QUIC datagram */
struct quic_dgram {
	void *owner;
	unsigned char *buf;
	size_t len;
	unsigned char *dcid;
	size_t dcid_len;
	struct sockaddr_storage saddr;
	struct sockaddr_storage daddr;
	struct quic_conn *qc;

	struct list recv_list; /* elemt to quic_receiver_buf <dgram_list>. */
	struct mt_list handler_list; /* elem to quic_dghdlr <dgrams>. */
};

/* The QUIC packet numbers are 62-bits integers */
#define QUIC_MAX_PACKET_NUM      ((1ULL << 62) - 1)

/* Maximum number of ack-eliciting received packets since the last
 * ACK frame was sent
 */
#define QUIC_MAX_RX_AEPKTS_SINCE_LAST_ACK       2
/* Flag a received packet as being an ack-eliciting packet. */
#define QUIC_FL_RX_PACKET_ACK_ELICITING (1UL << 0)
/* Packet is the first one in the containing datagram. */
#define QUIC_FL_RX_PACKET_DGRAM_FIRST   (1UL << 1)

struct quic_rx_packet {
	struct list list;
	struct list qc_rx_pkt_list;

	/* QUIC version used in packet. */
	const struct quic_version *version;

	unsigned char type;
	/* Initial desctination connection ID. */
	struct quic_cid dcid;
	struct quic_cid scid;
	/* Packet number offset : only valid for Initial/Handshake/0-RTT/1-RTT. */
	size_t pn_offset;
	/* Packet number */
	int64_t pn;
	/* Packet number length */
	uint32_t pnl;
	uint64_t token_len;
	unsigned char *token;
	/* Packet length */
	uint64_t len;
	/* Packet length before decryption */
	uint64_t raw_len;
	/* Additional authenticated data length */
	size_t aad_len;
	unsigned char *data;
	struct eb64_node pn_node;
	volatile unsigned int refcnt;
	/* Source address of this packet. */
	struct sockaddr_storage saddr;
	unsigned int flags;
	unsigned int time_received;
};

/* QUIC datagram handler */
struct quic_dghdlr {
	struct mt_list dgrams;
	struct tasklet *task;
	struct eb_root odcids;
	struct eb_root cids;
};

/* Structure to store enough information about the RX CRYPTO frames. */
struct quic_rx_crypto_frm {
	struct eb64_node offset_node;
	uint64_t len;
	const unsigned char *data;
	struct quic_rx_packet *pkt;
};

/* Flag a sent packet as being an ack-eliciting packet. */
#define QUIC_FL_TX_PACKET_ACK_ELICITING (1UL << 0)
/* Flag a sent packet as containing a PADDING frame. */
#define QUIC_FL_TX_PACKET_PADDING       (1UL << 1)
/* Flag a sent packet as being in flight. */
#define QUIC_FL_TX_PACKET_IN_FLIGHT     (QUIC_FL_TX_PACKET_ACK_ELICITING | QUIC_FL_TX_PACKET_PADDING)
/* Flag a sent packet as containing a CONNECTION_CLOSE frame */
#define QUIC_FL_TX_PACKET_CC            (1UL << 2)
/* Flag a sent packet as containing an ACK frame */
#define QUIC_FL_TX_PACKET_ACK           (1UL << 3)
/* Flag a sent packet as being coalesced to another one in the same datagram */
#define QUIC_FL_TX_PACKET_COALESCED     (1UL << 4)
/* Flag a sent packet as being probing with old data */
#define QUIC_FL_TX_PACKET_PROBE_WITH_OLD_DATA (1UL << 5)

/* Structure to store enough information about TX QUIC packets. */
struct quic_tx_packet {
	/* List entry point. */
	struct list list;
	/* Packet length */
	size_t len;
	/* This is not the packet length but the length of outstanding data
	 * for in flight TX packet.
	 */
	size_t in_flight_len;
	struct eb64_node pn_node;
	/* The list of frames of this packet. */
	struct list frms;
	/* The time this packet was sent (ms). */
	unsigned int time_sent;
	/* Packet number spakce. */
	struct quic_pktns *pktns;
	/* Flags. */
	unsigned int flags;
	/* Reference counter */
	int refcnt;
	/* Next packet in the same datagram */
	struct quic_tx_packet *next;
	/* Previous packet in the same datagram */
	struct quic_tx_packet *prev;
	/* Largest acknowledged packet number if this packet contains an ACK frame */
	int64_t largest_acked_pn;
	unsigned char type;
};

#define QUIC_CRYPTO_BUF_SHIFT  10
#define QUIC_CRYPTO_BUF_MASK   ((1UL << QUIC_CRYPTO_BUF_SHIFT) - 1)
/* The maximum allowed size of CRYPTO data buffer provided by the TLS stack. */
#define QUIC_CRYPTO_BUF_SZ    (1UL << QUIC_CRYPTO_BUF_SHIFT) /* 1 KB */

/* The maximum number of bytes of CRYPTO data in flight during handshakes. */
#define QUIC_CRYPTO_IN_FLIGHT_MAX 4096

/*
 * CRYPTO buffer struct.
 * Such buffers are used to send CRYPTO data.
 */
struct quic_crypto_buf {
	unsigned char data[QUIC_CRYPTO_BUF_SZ];
	size_t sz;
};

/* QUIC buffer structure used to build outgoing packets. */
struct q_buf {
	/* Points to the data in this buffer. */
	unsigned char *area;
	/* Points to the current position to write into this buffer. */
	unsigned char *pos;
	/* Point to the end of this buffer past one. */
	const unsigned char *end;
	/* The number of data bytes in this buffer. */
	size_t data;
	/* The list of packets attached to this buffer which have not been already sent. */
	struct list pkts;
};

/* Crypto data stream (one by encryption level) */
struct quic_cstream {
	struct {
		uint64_t offset;       /* absolute current base offset of ncbuf */
		struct ncbuf ncbuf;    /* receive buffer - can handle out-of-order offset frames */
	} rx;
	struct {
		uint64_t offset;      /* last offset of data ready to be sent */
		uint64_t sent_offset; /* last offset sent by transport layer */
		struct buffer buf;    /* transmit buffer before sending via xprt */
	} tx;

	struct qc_stream_desc *desc;
};

struct quic_enc_level {
	enum ssl_encryption_level_t level;
	struct quic_tls_ctx tls_ctx;
	struct {
		/* The packets received by the listener I/O handler
		   with header protection removed. */
		struct eb_root pkts;
		/* Liste of QUIC packets with protected header. */
		struct list pqpkts;
	} rx;
	struct {
		struct {
			struct quic_crypto_buf **bufs;
			/* The number of element in use in the previous array. */
			size_t nb_buf;
			/* The total size of the CRYPTO data stored in the CRYPTO buffers. */
			size_t sz;
			/* The offset of the CRYPT0 data stream. */
			uint64_t offset;
		} crypto;
	} tx;
	/* Crypto data stream */
	struct quic_cstream *cstream;
	struct quic_pktns *pktns;
};

struct quic_path {
	/* Control congestion. */
	struct quic_cc cc;
	/* Packet loss detection information. */
	struct quic_loss loss;

	/* MTU. */
	size_t mtu;
	/* Congestion window. */
	uint64_t cwnd;
	/* Minimum congestion window. */
	uint64_t min_cwnd;
	/* Prepared data to be sent (in bytes). */
	uint64_t prep_in_flight;
	/* Outstanding data (in bytes). */
	uint64_t in_flight;
	/* Number of in flight ack-eliciting packets. */
	uint64_t ifae_pkts;
};

/* QUIC ring buffer */
struct qring {
	struct cbuf *cbuf;
	struct mt_list mt_list;
};

/* Status of the connection/mux layer. This defines how to handle app data.
 *
 * During a standard quic_conn lifetime it transitions like this :
 * QC_MUX_NULL -> QC_MUX_READY -> QC_MUX_RELEASED
 */
enum qc_mux_state {
	QC_MUX_NULL,     /* not allocated, data should be buffered */
	QC_MUX_READY,    /* allocated, ready to handle data */
	QC_MUX_RELEASED, /* released, data can be dropped */
};

/* The number of buffers for outgoing packets (must be a power of two). */
#define QUIC_CONN_TX_BUFS_NB 8

/* Flags at connection level */
#define QUIC_FL_CONN_ANTI_AMPLIFICATION_REACHED  (1U << 0)
#define QUIC_FL_CONN_IO_CB_WAKEUP                (1U << 1)
#define QUIC_FL_CONN_POST_HANDSHAKE_FRAMES_BUILT (1U << 2)
#define QUIC_FL_CONN_LISTENER                    (1U << 3)
#define QUIC_FL_CONN_ACCEPT_REGISTERED           (1U << 4)
#define QUIC_FL_CONN_TX_MUX_CONTEXT              (1U << 5) /* sending in progress from the MUX layer */
#define QUIC_FL_CONN_IDLE_TIMER_RESTARTED_AFTER_READ (1U << 6)
#define QUIC_FL_CONN_RETRANS_NEEDED              (1U << 7)
#define QUIC_FL_CONN_RETRANS_OLD_DATA            (1U << 8) /* retransmission in progress for probing with already sent data */
#define QUIC_FL_CONN_TLS_ALERT                   (1U << 9)
/* gap here */
#define QUIC_FL_CONN_HALF_OPEN_CNT_DECREMENTED   (1U << 11) /* The half-open connection counter was decremented */
#define QUIC_FL_CONN_HANDSHAKE_SPEED_UP          (1U << 12) /* Handshake speeding up was done */
#define QUIC_FL_CONN_NOTIFY_CLOSE                (1U << 27) /* MUX notified about quic-conn imminent closure (idle-timeout or CONNECTION_CLOSE emission/reception) */
#define QUIC_FL_CONN_EXP_TIMER                   (1U << 28) /* timer has expired, quic-conn can be freed */
#define QUIC_FL_CONN_CLOSING                     (1U << 29)
#define QUIC_FL_CONN_DRAINING                    (1U << 30)
#define QUIC_FL_CONN_IMMEDIATE_CLOSE             (1U << 31)
struct quic_conn {
	const struct quic_version *original_version;
	const struct quic_version *negotiated_version;
	/* Negotiated version Initial TLS context */
	struct quic_tls_ctx negotiated_ictx;
	/* Connection owned socket FD. */
	int fd;
	/* QUIC transport parameters TLS extension */
	int tps_tls_ext;
	/* Thread ID this connection is attached to */
	int tid;
	int state;
	enum qc_mux_state mux_state; /* status of the connection/mux layer */
	struct quic_err err;
	unsigned char enc_params[QUIC_TP_MAX_ENCLEN]; /* encoded QUIC transport parameters */
	size_t enc_params_len;

	/*
	 * Original DCID used by clients on first Initial packets.
	 * <odcid> is concatenated with the socket src address.
	 */
	struct ebmb_node odcid_node;
	struct quic_cid odcid;

	struct quic_cid dcid; /* DCID of our endpoint - not updated when a new DCID is used */
	struct ebmb_node scid_node; /* used only for client side (backend) */
	struct quic_cid scid; /* first SCID of our endpoint - not updated when a new SCID is used */
	struct eb_root cids; /* tree of quic_connection_id - used to match a received packet DCID with a connection */

	struct quic_enc_level els[QUIC_TLS_ENC_LEVEL_MAX];
	struct quic_pktns pktns[QUIC_TLS_PKTNS_MAX];

	struct ssl_sock_ctx *xprt_ctx;

	struct sockaddr_storage local_addr;
	struct sockaddr_storage peer_addr;

	/* Used only to reach the tasklet for the I/O handler from this quic_conn object. */
	struct connection *conn;

	struct {
		/* The remaining frames to send. */
		struct list frms_to_send;

		/* The size of the previous array. */
		size_t nb_buf;
		/* Writer index. */
		int wbuf;
		/* Reader index. */
		int rbuf;
		/* Number of sent bytes. */
		uint64_t bytes;
		/* Number of bytes for prepared packets */
		uint64_t prep_bytes;
		/* Transport parameters sent by the peer */
		struct quic_transport_params params;
		/* Send buffer used to write datagrams. */
		struct buffer buf;
	} tx;
	struct {
		/* Number of received bytes. */
		uint64_t bytes;
		/* Transport parameters the peer will receive */
		struct quic_transport_params params;
		/* RX buffer */
		struct buffer buf;
		struct list pkt_list;
		struct {
			/* Number of open or closed streams */
			uint64_t nb_streams;
		} strms[QCS_MAX_TYPES];
	} rx;
	struct {
		struct quic_tls_kp prv_rx;
		struct quic_tls_kp nxt_rx;
		struct quic_tls_kp nxt_tx;
	} ku;
	unsigned int max_ack_delay;
	unsigned int max_idle_timeout;
	struct quic_path paths[1];
	struct quic_path *path;

	struct listener *li; /* only valid for frontend connections */
	struct mt_list accept_list; /* chaining element used for accept, only valid for frontend connections */

	struct eb_root streams_by_id; /* qc_stream_desc tree */
	int stream_buf_count; /* total count of allocated stream buffers for this connection */

	struct wait_event wait_event;
	struct wait_event *subs;

	/* MUX */
	struct qcc *qcc;
	struct task *timer_task;
	unsigned int timer;
	/* Idle timer task */
	struct task *idle_timer_task;
	unsigned int flags;

	/* When in closing state, number of packet before sending CC */
	unsigned int nb_pkt_for_cc;
	/* When in closing state, number of packet since receiving CC */
	unsigned int nb_pkt_since_cc;

	const struct qcc_app_ops *app_ops;
	struct quic_counters *prx_counters;
};

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_CONN_T_H */
