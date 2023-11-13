// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2020 Google LLC.
 */


// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "safesetid.skel.h"

typedef union {
	uid_t uid;
	uid_t gid;
} kid_t;

enum setid_type {
	UID,
	GID
};
struct setid_rule {
	kid_t src_id;
	kid_t dst_id;

	enum setid_type stype;
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct safesetid_bpf *skel;
	int uid_to_rules_fd, uid_rules_fd;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = safesetid_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	int policy_index = 0;
	kid_t dst_id = { 1001 };
	/* This would have been better with a */
	kid_t src_id = { 1003 };

	uid_rules_fd = bpf_map__fd(skel->maps.uid_rules);
	/* Allow 1003 to change to 1001 */
	bpf_map_update_elem(uid_rules_fd, &policy_index, &dst_id, 0);
	uid_to_rules_fd = bpf_map__fd(skel->maps.uid_to_rules_map);
	bpf_map_update_elem(uid_to_rules_fd, &src_id, &uid_rules_fd, 0);

	err =  safesetid_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	for (;;) {
		/* trigger our BPF program */
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	safesetid_bpf__destroy(skel);
	return -err;
}