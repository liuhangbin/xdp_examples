#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_link.h>
#include <signal.h>
#include <net/if.h>
#include <assert.h>

/* In this example we use libbpf-devel and libxdp-devel */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

/* We define the following variables global */
static int ifindex;
struct xdp_program *prog = NULL;

/* This function will remove XDP from the link when program exit */
static void int_exit(int sig)
{
	xdp_program__close(prog);
	exit(0);
}

/* This function will count the per CPU number and print out total
 * dropped packets number and PPS(packets per second).
 */
static void poll_stats(int map_fd, int interval)
{
	int ncpus = libbpf_num_possible_cpus();
	if (ncpus < 0) {
		printf("Error get possible cpus\n");
		return;
	}
	long values[ncpus], prev[ncpus], total_pkts;
	int i, key = 0;

	memset(prev, 0, sizeof(prev));

	while (1) {
		long sum = 0;

		sleep(interval);
		assert(bpf_map_lookup_elem(map_fd, &key, values) == 0);
		for (i = 0; i < ncpus; i++)
			sum += (values[i] - prev[i]);
		if (sum) {
			total_pkts += sum;
			printf("total dropped %10llu, %10llu pkt/s\n",
			       total_pkts, sum / interval);
		}
		memcpy(prev, values, sizeof(values));
	}
}

int main(int argc, char *argv[])
{
	int prog_fd, map_fd, ret;
	struct bpf_object *bpf_obj;

	if (argc != 2) {
		printf("Usage: %s IFNAME\n", argv[0]);
		return 1;
	}

	ifindex = if_nametoindex(argv[1]);
	if (!ifindex) {
		printf("get ifindex from interface name failed\n");
		return 1;
	}

	/* load XDP object by libxdp */
	prog = xdp_program__open_file("xdp_drop_ipv6_count.o", "xdp_drop_ipv6", NULL);
	if (libxdp_get_error(prog)) {
		printf("Error, load xdp prog failed\n");
		return 1;
	}

	/* attach XDP program to interface with skb mode */
	do {
		ret = xdp_program__attach(prog, ifindex, XDP_MODE_SKB, 0);
	} while (ret == -EPERM && !double_rlimit())

	if (ret) {
		printf("Error, Set xdp fd on iface %d failed\n", ifindex);
		return ret;
	}

	/* Find the map fd from bpf object */
	bpf_obj = xdp_program__bpf_obj(prog);
	map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "rxcnt");
	if (map_fd < 0) {
		printf("Error, get map fd from bpf obj failed\n");
		return map_fd;
	}

	/* Remove attached program when program is interrupted or killed */
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	poll_stats(map_fd, 2);

	return 0;
}
