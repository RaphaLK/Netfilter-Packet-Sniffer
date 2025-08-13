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

// Tells kernel which packets to intercept, where to intercept within the network stack, 
// and what function to process them.
static struct nf_hook_ops nfho;

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
		printk(KERN_INFO "TCP: %pI4:%d -> %pI4:%d\n", 
				&ip->saddr, ntohs(tcp->source), &ip->daddr, ntohs(tcp->dest));
	}
	else if (ip->protocol == IPPROTO_UDP) {
		udp = udp_hdr(socket_buffer);
		printk(KERN_INFO "UDP: %pI4:%d -> %pI4:%d\n", 
				&ip->saddr, ntohs(udp->source), &ip->daddr, ntohs(udp->dest));
	}

	return NF_ACCEPT;

}

// Module entrypoint
static int __init sniffer_init(void) {
	nfho.hook = hook_func;
	nfho.hooknum = NF_INET_PRE_ROUTING; // Catch packets right after arrival and before routing
	nfho.pf = PF_INET; // IPv4
	nfho.priority = NF_IP_PRI_FIRST; // High priority (First)
	nf_register_net_hook(&init_net, &nfho); // register_hook(default network namespace, netfilter hook)
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
