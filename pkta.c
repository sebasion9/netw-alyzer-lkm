#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h> // netfilter hooks
#include <linux/netfilter_ipv4.h> // netfilter for ipv4
#include <linux/ip.h>
#include <linux/tcp.h>

static unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static struct nf_hook_ops nfho;

static struct nf_hook_ops nfho = {
    .hook = hook_func,
    //nfho.hooknum = NF_INET_PRE_ROUTING;
    .hooknum = NF_INET_LOCAL_IN,
    .pf = PF_INET,                           //IPV4 packets
    .priority = NF_IP_PRI_FIRST,             //set to highest priority over all other hook functions
};

static unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header;
    unsigned char *data;
    unsigned int data_len;
    unsigned int buff_len = 32;
    char buff[buff_len + 1];

    if(ip_header->protocol == IPPROTO_TCP) {
        pr_info("TCP Packet\n");
        tcp_header = tcp_hdr(skb);
        pr_info("source port: %u\n", tcp_header->source);
        pr_info("dest port: %u\n", tcp_header->dest);
        data = skb->data;
        data_len = skb->data_len;

        // print data to dbg

    }
    return NF_ACCEPT;
}


static int __init kmod_init(void)
{
    nf_register_net_hook(&init_net, &nfho);
    pr_info("NF module loaded, NF hook registered");
    return 0;
}

static void __exit kmod_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho);
    pr_info("NF module unloaded");
}

module_init(kmod_init);
module_exit(kmod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("sebasion9");
MODULE_DESCRIPTION("packet analyzer");
MODULE_VERSION("0.1");


