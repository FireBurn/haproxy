/*
 * Action management functions.
 *
 * Copyright 2017 HAProxy Technologies, Christopher Faulet <cfaulet@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/action.h>
#include <haproxy/api.h>
#include <haproxy/errors.h>
#include <haproxy/list.h>
#include <haproxy/obj_type.h>
#include <haproxy/pool.h>
#include <haproxy/proxy.h>
#include <haproxy/stick_table.h>
#include <haproxy/task.h>
#include <haproxy/tools.h>


/* Check an action ruleset validity. It returns the number of error encountered
 * andd err_code is updated if a warning is emitted.
 */
int check_action_rules(struct list *rules, struct proxy *px, int *err_code)
{
	struct act_rule *rule;
	char *errmsg = NULL;
	int err = 0;

	list_for_each_entry(rule, rules, list) {
		if (rule->check_ptr && !rule->check_ptr(rule, px, &errmsg)) {
			ha_alert("Proxy '%s': %s.\n", px->id, errmsg);
			err++;
		}

		free(errmsg);
		errmsg = NULL;
	}

	return err;
}

/* Find and check the target table used by an action track-sc*. This
 * function should be called during the configuration validity check.
 *
 * The function returns 1 in success case, otherwise, it returns 0 and err is
 * filled.
 */
int check_trk_action(struct act_rule *rule, struct proxy *px, char **err)
{
	struct stktable *target;

	if (rule->arg.trk_ctr.table.n)
		target = stktable_find_by_name(rule->arg.trk_ctr.table.n);
	else
		target = px->table;

	if (!target) {
		memprintf(err, "unable to find table '%s' referenced by track-sc%d",
			  rule->arg.trk_ctr.table.n ?  rule->arg.trk_ctr.table.n : px->id,
			  rule->action);
		return 0;
	}

	if (!stktable_compatible_sample(rule->arg.trk_ctr.expr,  target->type)) {
		memprintf(err, "stick-table '%s' uses a type incompatible with the 'track-sc%d' rule",
			  rule->arg.trk_ctr.table.n ? rule->arg.trk_ctr.table.n : px->id,
			  rule->action);
		return 0;
	}
	else if (target->proxy && (px->bind_proc & ~target->proxy->bind_proc)) {
		memprintf(err, "stick-table '%s' referenced by 'track-sc%d' rule not present on all processes covered by proxy '%s'",
			  target->id, rule->action, px->id);
		return 0;
	}
	else {
		if (!in_proxies_list(target->proxies_list, px)) {
			px->next_stkt_ref = target->proxies_list;
			target->proxies_list = px;
		}
		free(rule->arg.trk_ctr.table.n);
		rule->arg.trk_ctr.table.t = target;
		/* Note: if we decide to enhance the track-sc syntax, we may be
		 * able to pass a list of counters to track and allocate them
		 * right here using stktable_alloc_data_type().
		 */
	}

	if (rule->from == ACT_F_TCP_REQ_CNT && (px->cap & PR_CAP_FE)) {
		if (!px->tcp_req.inspect_delay && !(rule->arg.trk_ctr.expr->fetch->val & SMP_VAL_FE_SES_ACC)) {
			ha_warning("config : %s '%s' : a 'tcp-request content track-sc*' rule explicitly depending on request"
				   " contents without any 'tcp-request inspect-delay' setting."
				   " This means that this rule will randomly find its contents. This can be fixed by"
				   " setting the tcp-request inspect-delay.\n",
				   proxy_type_str(px), px->id);
		}

		/* The following warning is emitted because HTTP multiplexers are able to catch errors
		 * or timeouts at the session level, before instantiating any stream.
		 * Thus the tcp-request content ruleset will not be evaluated in such case. It means,
		 * http_req and http_err counters will not be incremented as expected, even if the tracked
		 * counter does not use the request content. To track invalid requests it should be
		 * performed at the session level using a tcp-request session rule.
		 */
		if (px->mode == PR_MODE_HTTP &&
		    !(rule->arg.trk_ctr.expr->fetch->use & (SMP_USE_L6REQ|SMP_USE_HRQHV|SMP_USE_HRQHP|SMP_USE_HRQBO)) &&
		    (!rule->cond || !(rule->cond->use & (SMP_USE_L6REQ|SMP_USE_HRQHV|SMP_USE_HRQHP|SMP_USE_HRQBO)))) {
			ha_warning("config : %s '%s' : a 'tcp-request content track-sc*' rule not depending on request"
				   " contents for an HTTP frontend should be executed at the session level, using a"
				   " 'tcp-request session' rule (mandatory to track invalid HTTP requests).\n",
				   proxy_type_str(px), px->id);
		}
	}

	return 1;
}

/* check a capture rule. This function should be called during the configuration
 * validity check.
 *
 * The function returns 1 in success case, otherwise, it returns 0 and err is
 * filled.
 */
int check_capture(struct act_rule *rule, struct proxy *px, char **err)
{
	if (rule->from == ACT_F_TCP_REQ_CNT && (px->cap & PR_CAP_FE) && !px->tcp_req.inspect_delay &&
	    !(rule->arg.trk_ctr.expr->fetch->val & SMP_VAL_FE_SES_ACC)) {
		ha_warning("config : %s '%s' : a 'tcp-request capture' rule explicitly depending on request"
			   " contents without any 'tcp-request inspect-delay' setting."
			   " This means that this rule will randomly find its contents. This can be fixed by"
			   " setting the tcp-request inspect-delay.\n",
			   proxy_type_str(px), px->id);
	}

	return 1;
}

int act_resolution_cb(struct dns_requester *requester, struct dns_nameserver *nameserver)
{
	struct stream *stream;

	if (requester->resolution == NULL)
		return 0;

	stream = objt_stream(requester->owner);
	if (stream == NULL)
		return 0;

	task_wakeup(stream->task, TASK_WOKEN_MSG);

	return 0;
}

/*
 * Do resolve error management callback
 * returns:
 *  0 if we can trash answser items.
 *  1 when safely ignored and we must kept answer items
 */
int act_resolution_error_cb(struct dns_requester *requester, int error_code)
{
	struct stream *stream;

	if (requester->resolution == NULL)
		return 0;

	stream = objt_stream(requester->owner);
	if (stream == NULL)
		return 0;

	task_wakeup(stream->task, TASK_WOKEN_MSG);

	return 0;
}

