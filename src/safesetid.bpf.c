// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2020 Google LLC.
 */

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define CAP_OPT_INSETID (1UL << 2)
#define CAP_SETGID           6
#define SIGKILL		 9
#define CAP_SETUID           7

#define BOB_USERID 1003
#define ALICE_USERID 1002
#define MAX_GROUPS 32

typedef union {
	kuid_t uid;
	kgid_t gid;
} kid_t;

enum setid_type {
	UID,
	GID
};

#define INVALID_ID (kid_t){.uid = (kuid_t){ -1 }}

struct group_info *bpf_group_info_acquire(struct group_info *gi) __ksym;
void bpf_group_info_release(struct group_info *gi) __ksym;

struct uid_rules {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_INNER_MAP);
	__uint(max_entries, 10);
	__type(key, int);
	__type(value, kid_t);
} uid_rules SEC(".maps");

struct uid_to_rules_map {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 10);
	__uint(key_size, sizeof(kid_t));
	__array(values, struct uid_rules);
} uid_to_rules_map SEC(".maps") = {
	.values = { [BOB_USERID] = &uid_rules },
};

struct gid_rules {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 10);
	__type(key, int);
	__type(value, kid_t);
} gid_rules SEC(".maps");

struct gid_to_rules_map {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, 10);
	__uint(key_size, sizeof(kid_t));
	__array(values, struct gid_rules);
} gid_to_rules_map SEC(".maps") = {
	.values = { [1003] = &gid_rules },
};

enum sid_policy_type {
	SIDPOL_DEFAULT, /* source ID is unaffected by policy */
	SIDPOL_CONSTRAINED, /* source ID is affected by policy */
	SIDPOL_ALLOWED /* target ID explicitly allowed */
};

static uid_t __kuid_val(kuid_t uid)
{
	return uid.val;
}

static gid_t __kgid_val(kgid_t gid)
{
	return gid.val;
}

static bool uid_eq(kuid_t left, kuid_t right)
{
	return __kuid_val(left) == __kuid_val(right);
}

static bool gid_eq(kgid_t left, kgid_t right)
{
	return __kgid_val(left) == __kgid_val(right);
}
struct callback_ctx {
	kid_t src_id;
	kid_t dst_id;
	enum sid_policy_type policy_type;
};

static  __u64 uid_rule_cb(struct bpf_map *map, __u32 *key,
			      kid_t *dst, struct callback_ctx *ctx)
{
	if (gid_eq(ctx->dst_id.gid, dst->gid)) {
		ctx->policy_type = SIDPOL_ALLOWED;
		return 1; /* found, stop iterating */
	}

	ctx->policy_type = SIDPOL_CONSTRAINED;
	return 0;
}

static __u64 gid_rule_cb(struct bpf_map *map, __u32 *key,
			 kid_t *dst, struct callback_ctx *ctx)
{
	if (gid_eq(ctx->dst_id.gid, dst->gid)) {
		ctx->policy_type = SIDPOL_ALLOWED;
		return 1; /* found, stop iterating */
	}

	ctx->policy_type = SIDPOL_CONSTRAINED;
	return 0;
}

static enum sid_policy_type setid_policy_lookup(kid_t src, kid_t dst, enum setid_type stype)
{
	struct uid_rules *uid_rules;
	struct gid_rules *gid_rules;

	struct callback_ctx ctx = {
		.dst_id = dst,
		.src_id = src,
	};

	if (stype == UID) {
		bpf_printk("looking up uid policy for uid %d\n", src.uid.val);
		uid_rules = bpf_map_lookup_elem(&uid_to_rules_map, &src);
		if (!uid_rules)
			return SIDPOL_DEFAULT;
		bpf_printk("there is a policy for uid %d\n", src.uid.val);
		bpf_for_each_map_elem(uid_rules, uid_rule_cb, &ctx, 0);
		return ctx.policy_type;
	}

	if (stype == GID) {
		bpf_printk("looking up uid policy for gid %d\n", src.gid.val);
		gid_rules = bpf_map_lookup_elem(&gid_to_rules_map, &src);
		if (!gid_rules)
			return SIDPOL_DEFAULT;

		bpf_printk("there is a policy for gid %d\n", src.gid.val);
		bpf_for_each_map_elem(gid_rules, gid_rule_cb, &ctx, 0);
		return ctx.policy_type;
	}

	return SIDPOL_CONSTRAINED;
}

/*
 * Check whether a caller with old credentials @old is allowed to switch to
 * credentials that contain @new_id.
 */
static bool id_permitted_for_cred(const struct cred *old, kid_t new_id, enum setid_type new_type)
{
	bool permitted;

	/* If our old creds already had this ID in it, it's fine. */
	if (new_type == UID) {
		if (uid_eq(new_id.uid, old->uid) || uid_eq(new_id.uid, old->euid) ||
			uid_eq(new_id.uid, old->suid))
			return true;
	} else if (new_type == GID){
		if (gid_eq(new_id.gid, old->gid) || gid_eq(new_id.gid, old->egid) ||
			gid_eq(new_id.gid, old->sgid))
			return true;
	} else /* Error, new_type is an invalid type */
		return false;

	/*
	 * Transitions to new UIDs require a check against the policy of the old
	 * RUID.
	 */
	permitted =
	    setid_policy_lookup((kid_t){.uid = old->uid}, new_id, new_type) != SIDPOL_CONSTRAINED;

	if (!permitted) {
		if (new_type == UID) {
			bpf_printk("UID transition ((%d,%d,%d) -> %d) blocked\n",
				__kuid_val(old->uid), __kuid_val(old->euid),
				__kuid_val(old->suid), __kuid_val(new_id.uid));
		} else if (new_type == GID) {
			bpf_printk("GID transition ((%d,%d,%d) -> %d) blocked\n",
				__kgid_val(old->gid), __kgid_val(old->egid),
				__kgid_val(old->sgid), __kgid_val(new_id.gid));
		} else /* Error, new_type is an invalid type */
			return false;
	}
	return permitted;
}

char _license[] SEC("license") = "GPL";

SEC("lsm/task_fix_setuid")
int BPF_PROG(lsm_setuid, struct cred *new, const struct cred *old, int flags)
{
	/* Do nothing if there are no setuid restrictions for our old RUID. */
	if (setid_policy_lookup((kid_t){.uid = old->uid}, INVALID_ID, UID) == SIDPOL_DEFAULT)
		return 0;

	if (id_permitted_for_cred(old, (kid_t){.uid = new->uid}, UID) &&
	    id_permitted_for_cred(old, (kid_t){.uid = new->euid}, UID) &&
	    id_permitted_for_cred(old, (kid_t){.uid = new->suid}, UID) &&
	    id_permitted_for_cred(old, (kid_t){.uid = new->fsuid}, UID))
		return 0;

	/*
	 * Kill this process to avoid potential security vulnerabilities
	 * that could arise from a missing allowlist entry preventing a
	 * privileged process from dropping to a lesser-privileged one.
	 */
	bpf_send_signal(SIGKILL);
	return 0;
}

SEC("lsm/task_fix_setgid")
int BPF_PROG(lsm_setgid, struct cred *new, const struct cred *old, int flags)
{
	/* Do nothing if there are no setgid restrictions for our old RGID. */
	if (setid_policy_lookup((kid_t){.gid = old->gid}, INVALID_ID, GID) == SIDPOL_DEFAULT)
		return 0;

	if (id_permitted_for_cred(old, (kid_t){.gid = new->gid}, GID) &&
	    id_permitted_for_cred(old, (kid_t){.gid = new->egid}, GID) &&
	    id_permitted_for_cred(old, (kid_t){.gid = new->sgid}, GID) &&
	    id_permitted_for_cred(old, (kid_t){.gid = new->fsgid}, GID))
		return 0;

	/*
	 * Kill this process to avoid potential security vulnerabilities
	 * that could arise from a missing allowlist entry preventing a
	 * privileged process from dropping to a lesser-privileged one.
	 */
	bpf_send_signal(SIGKILL);
	return 0;
}


SEC("lsm/task_fix_setgroups")
int BPF_PROG(lsm_setgroups, struct cred *new, const struct cred *old)
{
	struct group_info *new_group_info;
	int ngroups;
	int i;

	/* Do nothing if there are no setgid restrictions for our old RGID. */
	if (setid_policy_lookup((kid_t){.gid = old->gid}, INVALID_ID, GID) == SIDPOL_DEFAULT)
		return 0;

	if (!new || !new->group_info)
		return -EACCES;

	new_group_info = bpf_group_info_acquire(new->group_info);
	if (!new_group_info)
		return -EACCES;

	for (i = 0; i < MAX_GROUPS; i++) {
		if (i > new_group_info->ngroups)
			break;

		if (!id_permitted_for_cred(old, (kid_t){.gid = new_group_info->gid[i]}, GID)) {
			bpf_group_info_release(new_group_info);
			/*
			 * Kill this process to avoid potential security vulnerabilities
			 * that could arise from a missing allowlist entry preventing a
			 * privileged process from dropping to a lesser-privileged one.
			 */
			bpf_send_signal(SIGKILL);
			return -EACCES;
		}
	}

	bpf_group_info_release(new_group_info);
	return 0;
}

SEC("lsm/capable")
int BPF_PROG(lsm_capable, const struct cred *cred, struct user_namespace *ns,
	     int cap, unsigned int opts)
{
	/* We're only interested in CAP_SETUID and CAP_SETGID. */
	if (cap != CAP_SETUID && cap != CAP_SETGID)
		return 0;

	/*
	 * If CAP_SET{U/G}ID is currently used for a setid or setgroups syscall, we
	 * want to let it go through here; the real security check happens later, in
	 * the task_fix_set{u/g}id or task_fix_setgroups hooks.
	 */
	if ((opts & CAP_OPT_INSETID) != 0)
		return 0;

	switch (cap) {
	case CAP_SETUID:
		/*
		* If no policy applies to this task, allow the use of CAP_SETUID for
		* other purposes.
		*/
		if (setid_policy_lookup((kid_t){.uid = cred->uid}, INVALID_ID, UID) == SIDPOL_DEFAULT)
			return 0;
		/*
		 * Reject use of CAP_SETUID for functionality other than calling
		 * set*uid() (e.g. setting up userns uid mappings).
		 */
		bpf_printk("Operation requires CAP_SETUID, which is not available to UID %u for operations besides approved set*uid transitions\n",
			__kuid_val(cred->uid));
		return -EPERM;
	case CAP_SETGID:
		/*
		* If no policy applies to this task, allow the use of CAP_SETGID for
		* other purposes.
		*/
		if (setid_policy_lookup((kid_t){.gid = cred->gid}, INVALID_ID, GID) == SIDPOL_DEFAULT)
			return 0;
		/*
		 * Reject use of CAP_SETUID for functionality other than calling
		 * set*gid() (e.g. setting up userns gid mappings).
		 */
		bpf_printk("Operation requires CAP_SETGID, which is not available to GID %u for operations besides approved set*gid transitions\n",
			__kgid_val(cred->gid));
		return -EPERM;
	default:
		/* Error, the only capabilities were checking for is CAP_SETUID/GID */
		return 0;
	}
	return 0;
}

