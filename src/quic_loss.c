#include <import/eb64tree.h>

#include <haproxy/quic_conn-t.h>
#include <haproxy/quic_loss.h>
#include <haproxy/quic_tls.h>

#include <haproxy/atomic.h>
#include <haproxy/list.h>
#include <haproxy/ticks.h>
#include <haproxy/trace.h>

#define TRACE_SOURCE &trace_quic

/* Update <ql> QUIC loss information with new <rtt> measurement and <ack_delay>
 * on ACK frame receipt which MUST be min(ack->ack_delay, max_ack_delay)
 * before the handshake is confirmed.
 */
void quic_loss_srtt_update(struct quic_loss *ql,
                           unsigned int rtt, unsigned int ack_delay,
                           struct quic_conn *qc)
{
	TRACE_ENTER(QUIC_EV_CONN_RTTUPDT, qc);
	TRACE_DEVEL("Loss info update", QUIC_EV_CONN_RTTUPDT, qc, &rtt, &ack_delay, ql);

	ql->latest_rtt = rtt;
	if (!ql->rtt_min) {
		/* No previous measurement. */
		ql->srtt = rtt;
		ql->rtt_var = rtt / 2;
		ql->rtt_min = rtt;
	}
	else {
		int diff;

		ql->rtt_min = QUIC_MIN(rtt, ql->rtt_min);
		/* Specific to QUIC (RTT adjustment). */
		if (ack_delay && rtt >= ql->rtt_min + ack_delay)
			rtt -= ack_delay;
		diff = ql->srtt - rtt;
		if (diff < 0)
			diff = -diff;
		ql->rtt_var = (3 * ql->rtt_var + diff) / 4;
		ql->srtt = (7 * ql->srtt + rtt) / 8;
	}

	TRACE_DEVEL("Loss info update", QUIC_EV_CONN_RTTUPDT, qc,,, ql);
	TRACE_LEAVE(QUIC_EV_CONN_RTTUPDT, qc);
}

/* Returns for <qc> QUIC connection the first packet number space which
 * experienced packet loss, if any or a packet number space with
 * TICK_ETERNITY as packet loss time if not.
 */
struct quic_pktns *quic_loss_pktns(struct quic_conn *qc)
{
	enum quic_tls_pktns i;
	struct quic_pktns *pktns;

	TRACE_ENTER(QUIC_EV_CONN_SPTO, qc);

	pktns = &qc->pktns[QUIC_TLS_PKTNS_INITIAL];
	TRACE_DEVEL("pktns", QUIC_EV_CONN_SPTO, qc, pktns);
	for (i = QUIC_TLS_PKTNS_HANDSHAKE; i < QUIC_TLS_PKTNS_MAX; i++) {
		TRACE_DEVEL("pktns", QUIC_EV_CONN_SPTO, qc, &qc->pktns[i]);
		/* Select a loss time only if it is set: TICK_ETERNITY (0)
		 * means "no loss time", and tick_is_lt(0, T) is true when T
		 * lies in the low half of the tick circle, so an unset loss
		 * time could hide a real one.
		 */
		if (tick_isset(qc->pktns[i].tx.loss_time) &&
		    (!tick_isset(pktns->tx.loss_time) ||
		     tick_is_lt(qc->pktns[i].tx.loss_time, pktns->tx.loss_time)))
			pktns = &qc->pktns[i];
	}

	TRACE_LEAVE(QUIC_EV_CONN_SPTO, qc);

	return pktns;
}

/* Returns for <qc> QUIC connection the first packet number space to
 * arm the PTO for if any or a packet number space with TICK_ETERNITY
 * as PTO value if not.
 */
struct quic_pktns *quic_pto_pktns(struct quic_conn *qc,
                                  int handshake_confirmed,
                                  unsigned int *pto)
{
	int i;
	unsigned int duration, lpto;
	struct quic_loss *ql = &qc->path->loss;
	struct quic_pktns *pktns, *p;

	TRACE_ENTER(QUIC_EV_CONN_SPTO, qc);
	duration =
		ql->srtt +
		(QUIC_MAX(4 * ql->rtt_var, QUIC_TIMER_GRANULARITY) << ql->pto_count);

	/* RFC 9002 6.2.2.1. Before Address Validation
	 *
	 * the client MUST set the PTO timer if the client has not received an
	 * acknowledgment for any of its Handshake packets and the handshake is
	 * not confirmed (see Section 4.1.2 of [QUIC-TLS]), even if there are no
	 * packets in flight.
	 *
	 * TODO implement the above paragraph for QUIC on backend side. Note
	 * that if now_ms is used this function is not reentrant anymore and can
	 * not be used anytime without side-effect (for example after QUIC
	 * connection migration).
	 */

	lpto = TICK_ETERNITY;
	pktns = p = &qc->pktns[QUIC_TLS_PKTNS_INITIAL];

	for (i = QUIC_TLS_PKTNS_INITIAL; i < QUIC_TLS_PKTNS_MAX; i++) {
		unsigned int tmp_pto;

		if (!qc->pktns[i].tx.in_flight)
			continue;

		if (i == QUIC_TLS_PKTNS_01RTT) {
			if (!handshake_confirmed) {
				TRACE_STATE("TX PTO handshake not already confirmed", QUIC_EV_CONN_SPTO, qc);
				pktns = p;
				goto out;
			}

			duration += qc->max_ack_delay << ql->pto_count;
		}

		p = &qc->pktns[i];
		tmp_pto = tick_add(p->tx.time_of_last_eliciting, duration);
		if (!tick_isset(lpto) || tick_is_lt(tmp_pto, lpto)) {
			lpto = tmp_pto;
			pktns = p;
		}
		TRACE_DEVEL("pktns", QUIC_EV_CONN_SPTO, qc, p);
	}

 out:
	if (pto)
		*pto = lpto;
	TRACE_LEAVE(QUIC_EV_CONN_SPTO, qc, pktns, &duration);

	return pktns;
}

/* Look for packet loss from sent packets for <qel> encryption level of a
 * connection with <ctx> as I/O handler context. If remove is true, remove them from
 * their tree if deemed as lost or set the <loss_time> value the packet number
 * space if any not deemed lost.
 * Should be called after having received an ACK frame with newly acknowledged
 * packets or when the the loss detection timer has expired.
 * Always succeeds.
 */
void qc_packet_loss_lookup(struct quic_pktns *pktns, struct quic_conn *qc,
                           struct list *lost_pkts)
{
	struct eb_root *pkts;
	struct eb64_node *node;
	struct quic_loss *ql;
	unsigned int loss_delay;
	uint64_t pktthresh;

	TRACE_ENTER(QUIC_EV_CONN_PKTLOSS, qc, pktns);
	pkts = &pktns->tx.pkts;
	pktns->tx.loss_time = TICK_ETERNITY;
	if (eb_is_empty(pkts))
		goto out;

	ql = &qc->path->loss;
	loss_delay = QUIC_MAX(ql->latest_rtt, ql->srtt);
	loss_delay = QUIC_MAX(loss_delay, MS_TO_TICKS(QUIC_TIMER_GRANULARITY)) *
		QUIC_LOSS_TIME_THRESHOLD_MULTIPLICAND / QUIC_LOSS_TIME_THRESHOLD_DIVISOR;

	node = eb64_first(pkts);

	/* RFC 9002 6.1.1. Packet Threshold
	 * The RECOMMENDED initial value for the packet reordering threshold
	 * (kPacketThreshold) is 3, based on best practices for TCP loss detection
	 * [RFC5681] [RFC6675]. In order to remain similar to TCP, implementations
	 * SHOULD NOT use a packet threshold less than 3; see [RFC5681].

	 * Some networks may exhibit higher degrees of packet reordering, causing a
	 * sender to detect spurious losses. Additionally, packet reordering could be
	 * more common with QUIC than TCP because network elements that could observe
	 * and reorder TCP packets cannot do that for QUIC and also because QUIC
	 * packet numbers are encrypted.
	 */

	/* Dynamic packet reordering threshold calculation depending on the distance
	 * (in packets) between the last transmitted packet and the oldest still in
	 * flight before loss detection.
	 */
	pktthresh = pktns->tx.next_pn - 1 - eb64_entry(node, struct quic_tx_packet, pn_node)->pn_node.key;
	/* Apply a ratio to this threshold and add it to QUIC_LOSS_PACKET_THRESHOLD. */
	pktthresh = pktthresh * global.tune.quic_reorder_ratio / 100 + QUIC_LOSS_PACKET_THRESHOLD;
	while (node) {
		struct quic_tx_packet *pkt;
		int64_t largest_acked_pn;
		unsigned int loss_time_limit, time_sent;
		int reordered;

		pkt = eb64_entry(&node->node, struct quic_tx_packet, pn_node);
		largest_acked_pn = pktns->rx.largest_acked_pn;
		node = eb64_next(node);
		if ((int64_t)pkt->pn_node.key > largest_acked_pn)
			break;

		time_sent = pkt->time_sent;
		loss_time_limit = tick_add(time_sent, loss_delay);

		reordered = (int64_t)largest_acked_pn >= pkt->pn_node.key + pktthresh;
		if (reordered)
			ql->nb_reordered_pkt++;

		if (tick_is_le(loss_time_limit, now_ms) || reordered) {
			eb64_delete(&pkt->pn_node);
			LIST_APPEND(lost_pkts, &pkt->list);
			ql->nb_lost_pkt++;
			HA_ATOMIC_INC(&qc->prx_counters->lost_pkt);
		}
		else {
			if (tick_isset(pktns->tx.loss_time))
				pktns->tx.loss_time = tick_first(pktns->tx.loss_time, loss_time_limit);
			else
				pktns->tx.loss_time = loss_time_limit;
			break;
		}
	}

 out:
	TRACE_LEAVE(QUIC_EV_CONN_PKTLOSS, qc, pktns, lost_pkts);
}
