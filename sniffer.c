/****
 * Author: RaphaLK
 * Notes: This is a kernel module for a IPv4 Traffic Packet Sniffer, built using netfilter.
*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

// Tells kernel which packets to intercept, where to intercept within the network stack, 
// and what function to process them.
static struct nf_hook_ops nfho;

// Statistics
static unsigned long tcp_packets = 0;
static unsigned long udp_packets = 0;
static unsigned long tcp_bytes = 0;
static unsigned long udp_bytes = 0;

unsigned int hook_func(void *priv, struct sk_buff *socket_buffer, const struct nf_hook_state *state)
{
	// ip, tcp, and udp headers
	struct iphdr *ip; 
	struct tcphdr *tcp;
	struct udphdr *udp;

	// Nothing in the socket buffer (No Packets)? Just exit the function 
	if (!socket_buffer)
		return NF_ACCEPT;
	
	// No proper IP Header? Leave as well
	ip = ip_hdr(socket_buffer);
	if (!ip)
		return NF_ACCEPT;

	// TCP (IPROTO_TCP == 6)
	if (ip->protocol == IPPROTO_TCP) {
		tcp = tcp_hdr(socket_buffer);
		// Server Address:Ports -> Destination Address:Ports (Kernel Space Logging)
		// HTTP Specific
		if (ntohs(tcp->dest) == 80) {
			printk(KERN_INFO "TCP (HTTP): %pI4:%d -> %pI4:%d\n", 
				&ip->saddr, ntohs(tcp->source), &ip->daddr, ntohs(tcp->dest));
		}
		else {
			printk(KERN_INFO "TCP: %pI4:%d -> %pI4:%d\n", 
				&ip->saddr, ntohs(tcp->source), &ip->daddr, ntohs(tcp->dest));
		}
		// Info tracking
		tcp_packets++;
		tcp_bytes += ntohs(ip->tot_len);
		return NF_ACCEPT;
	}
	else if (ip->protocol == IPPROTO_UDP) {
		udp = udp_hdr(socket_buffer);
		// DNS Specific
		if (ntohs(udp->dest) == 53) {
			printk(KERN_INFO "UDP (DNS): %pI4:%d -> %pI4:%d\n",
				&ip->saddr, ntohs(udp->source), &ip->daddr, ntohs(udp->dest));
		}
		else {
			printk(KERN_INFO "UDP: %pI4:%d -> %pI4:%d\n", 
				&ip->saddr, ntohs(udp->source), &ip->daddr, ntohs(udp->dest));
		}
		udp_packets++;
		udp_bytes += ntohs(ip->tot_len);
		return NF_ACCEPT;
	}

	return NF_DROP;
}

// Expose to /proc interface -- seq_file for kernel to userspace output
static int sniffer_proc_show(struct seq_file *m, void *v) {
	seq_printf(m, "TCP packets: %lu\nUDP packets: %lu\nTCP bytes: %lu\nUDP bytes: %lu\n",
		tcp_packets, udp_packets, tcp_bytes, udp_bytes);
	return 0;
}

static int sniffer_proc_open(struct inode *inode, struct file *file) {
	return single_open(file, sniffer_proc_show, NULL);
}

static const struct proc_ops sniffer_proc_ops = {
	.proc_open = sniffer_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static struct proc_dir_entry *sniffer_proc_entry;

// Module entrypoint
static int __init sniffer_init(void) {
	nfho.hook = hook_func;
	nfho.hooknum = NF_INET_PRE_ROUTING; // Catch packets right after arrival and before routing
	nfho.pf = PF_INET; // IPv4
	nfho.priority = NF_IP_PRI_FIRST; // High priority (First)
	nf_register_net_hook(&init_net, &nfho); // register_hook(default network namespace, netfilter hook)
	sniffer_proc_entry = proc_create("sniffer_stats", 0, NULL, &sniffer_proc_ops);
	printk(KERN_INFO "Packet Sniffer Module Loaded\n\n");
	return 0;
}

// Module exit function
static void __exit sniffer_exit(void) {
	nf_unregister_net_hook(&init_net, &nfho); // unregister the netfilter hook
	printk(KERN_INFO "Packet Sniffer Module Unloaded\n\n");
}

module_init(sniffer_init);
module_exit(sniffer_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("RaphaLK");
MODULE_DESCRIPTION("Netfilter-based packet sniffer, made for fun");
