/*
 * gre.c - userspace GRE tunnel
 *
 * Copyright (C) 2015 - 2017, Xiaoxiao <i@pxx.io>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

//gdb --args ./gre_server vit2 192.168.29.34 192.168.29.177 192.168.29.1
// 192.168.29.34  -- Raspberry pi
// 192.168.29.177 -- Server
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
//#include <linux/ip.h>

#include <linux/udp.h>


#define ETHER_TYPE	0x0800

typedef struct {
    uint8_t ethdst[6];
    uint8_t ethsrc[6];
    unsigned short ethtype;
} ETHPKTHDR;

static int tun;
static int sock;
static int sock_normal;
static struct sockaddr_in remote;
static struct sockaddr_in remote_pi;
static struct sockaddr_in remote_outside;
static struct sockaddr_ll remote_outside_ll;
struct sockaddr_in local;
struct sockaddr_in local_normal;

uint8_t buf[4096];

static void gre_cb(void);
static void tun_cb(void);
static int tun_new(const char *dev);
static int setnonblock(int fd);
static int runas(const char *user);
static int daemonize(void);

int main(int argc, char **argv)
{
    fd_set readset;

    if (argc != 5)
    {
        printf("usage: %s <tun> remote local\n", argv[0]);
        return EXIT_FAILURE;
    }

    tun = tun_new(argv[1]);
    if (tun < 0)
    {
        printf("failed to init tun device\n");
        return EXIT_FAILURE;
    }

    //sock = socket(AF_INET, SOCK_RAW, IPPROTO_GRE);
    //sock = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE));
    //sock_normal = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    //sock_normal = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE));
    sock_normal = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    sock = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0)
    {
        perror("socket");
        return EXIT_FAILURE;
    }

    struct ifreq if_idx;
    struct ifreq ifopts;	/* set promiscuous mode */

    int sockfd;
    int sockopt;


    local.sin_family = AF_INET;
    local.sin_port = htons(IPPROTO_GRE);
    local.sin_addr.s_addr = inet_addr(argv[3]);

    local_normal.sin_family = AF_INET;
    local_normal.sin_port = htons(IPPROTO_IP);
    local_normal.sin_addr.s_addr = inet_addr(argv[3]);

    if (local.sin_addr.s_addr == INADDR_NONE)
    {
        fprintf(stderr, "bad local address\n");
        return EXIT_FAILURE;
    }
    else
    {
	strncpy(ifopts.ifr_name, "eth0", IFNAMSIZ-1);
	//strncpy(ifopts.ifr_name, argv[1], IFNAMSIZ-1);
	ioctl(sock_normal, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sock_normal, SIOCSIFFLAGS, &ifopts);
       
        if (setsockopt(sock_normal, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1) {
		perror("setsockopt");
		close(sock_normal);
		exit(EXIT_FAILURE);
	}
	/* Bind to device */
	if (setsockopt(sock_normal, SOL_SOCKET, SO_BINDTODEVICE, "eth0", IFNAMSIZ-1) == -1)	{
		perror("SO_BINDTODEVICE");
		close(sock_normal);
		exit(EXIT_FAILURE);
	}

    }

    remote.sin_family = AF_INET;
    //remote.sin_port = htons(IPPROTO_GRE);
    remote.sin_port = htons(IPPROTO_ICMP);
    remote.sin_addr.s_addr = inet_addr(argv[2]);

    remote_pi.sin_family = AF_INET;
    remote_pi.sin_port = htons(IPPROTO_GRE);
    remote_pi.sin_addr.s_addr = inet_addr(argv[2]);

    //remote_outside_ll.sin_family = AF_INET;
    //remote_outside_ll.sin_port = htons(IPPROTO_RAW);
    //remote_outside_ll.sin_addr.s_addr = inet_addr(argv[3]);

            /* Get the index of the interface to send on */
        memset(&if_idx, 0, sizeof(struct ifreq));
        strncpy(if_idx.ifr_name, "eth0", IFNAMSIZ-1);
        if (ioctl(sock_normal, SIOCGIFINDEX, &if_idx) < 0)
            perror("SIOCGIFINDEX");

        /* Index of the network device */
        remote_outside_ll.sll_ifindex = if_idx.ifr_ifindex;
        /* Address length*/
        remote_outside_ll.sll_halen = ETH_ALEN;
#define MY_DEST_MAC0 0x6c;
#define MY_DEST_MAC1 0xdf;
#define MY_DEST_MAC2 0xfb;
#define MY_DEST_MAC3 0x2f;
#define MY_DEST_MAC4 0x20;
#define MY_DEST_MAC5 0x31;
        /* Destination MAC */
        remote_outside_ll.sll_addr[0] = MY_DEST_MAC0;
        remote_outside_ll.sll_addr[1] = MY_DEST_MAC1;
        remote_outside_ll.sll_addr[2] = MY_DEST_MAC2;
        remote_outside_ll.sll_addr[3] = MY_DEST_MAC3;
        remote_outside_ll.sll_addr[4] = MY_DEST_MAC4;
        remote_outside_ll.sll_addr[5] = MY_DEST_MAC5;

    if (remote.sin_addr.s_addr == INADDR_NONE)
    {
        fprintf(stderr, "bad remote address\n");
        return EXIT_FAILURE;
    }

    //setnonblock(sock);
    //setnonblock(sock_normal);
#if 0
  {				/* lets do it the ugly way.. */
    int one = 1;
    const int *val = &one;
    if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
      printf ("Warning: Cannot set HDRINCL!\n");
  }
#endif
    setnonblock(tun);
    runas("nobody");
    //daemonize();

    //int maxfd = (tun > sock ? tun : sock) + 1;
    //int maxfd = (sock_normal > sock ? sock_normal : sock) + 1;
    int maxfd = sock_normal + 1;
    while (1)
    {
        gre_cb();
    }

    return 0;
}

unsigned short csum(unsigned short *tbuf, int nwords)
{
	unsigned long sum;
	for(sum=0; nwords>0; nwords--)
		sum += *tbuf++;
	sum = (sum >> 16) + (sum &0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}

/* One's Complement checksum algorithm */
unsigned short cksum(unsigned short *addr, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*(unsigned char *)(&answer) = *(unsigned char *)w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;

	return (answer);
}

#if 0
/* set ip checksum of a given ip header*/
void compute_ip_checksum(struct iphdr* iphdrp){
  iphdrp->check = 0;
  iphdrp->check = compute_checksum((unsigned short*)iphdrp, iphdrp->ihl<<2);
}
#endif

/* Compute checksum for count bytes starting at addr, using one's complement of one's complement sum*/
static unsigned short compute_checksum(unsigned short *addr, unsigned int count) {
  register unsigned long sum = 0;

    for (int i = 0; i < count; i++)
	    printf ("<%.2x%.2x>", *(addr + i) & 0xff, *(addr + i) >> 8 & 0xff);

  while (count > 1) {
	  printf("%x=", *(addr));
    sum += * addr++;
    count -= 2;
  }
  //if any bytes left, pad the bytes and add
  if(count > 0) {
    sum += ((*addr)&htons(0xFF00));
  }
  //Fold sum to 16 bits: add carrier to result
  while (sum>>16) {
      sum = (sum & 0xffff) + (sum >> 16);
  }
  //one's complement
  printf("checksum = %x\n", sum);
  sum = ~sum;
  printf("checksum = %x\n", sum);
  return ((unsigned short)sum);
}

// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t
checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

uint32_t
computecsum(register unsigned char *s, register int n)
{
	register int crc;
	if (n > 0)
		do {
			crc += *s++ & 0xFF;
		} while (--n > 0);

	return (crc);
}

void print_ip_header(struct iphdr *ip, char *s)
{
    printf("%s\n", s);
    printf("ip->ihl = %d\n", ip->ihl);
    printf("ip->version = %d\n", ip->version);
    printf("ip->tos = %d\n", ip->tos);;
    printf("ip->id = %d\n", ip->id);
    printf("ip->frag_off = %d\n", ip->frag_off);;
    printf("ip->ttl = %d\n", ip->ttl);
    printf("ip->protocol = %d\n", ip->protocol);
    printf("ip->tot_len = %d\n", ntohs(ip->tot_len));
    printf("ip->check = %d\n", ip->check);
}

static void gre_cb(void)
{
	int ehl;
	int ihl;    // IP header length
	int n;
	int ret;
	ETHPKTHDR *e;
    unsigned char *mac;
    unsigned char *mac_src;
    uint8_t write_buf[4096];
    uint8_t w_gre_buf[4096];
    struct iphdr *ip;
    struct ip *ipfull;
    struct icmp *icmp;
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);



    //n = recv(sock, buf, sizeof(buf), 0);
    //n = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
    //n = recv(sock_normal, buf, sizeof(buf), 0);
    memset(buf, 0, sizeof(buf));
    memset(w_gre_buf, 0, sizeof(w_gre_buf));
    n = recvfrom(sock_normal, buf, sizeof(buf), 0, &saddr, (socklen_t *)&saddr_len);

    if (n < 0)
    {
        perror("recv");
        return;
    }
    mac = (ETHPKTHDR *) buf;
    mac_src = (ETHPKTHDR *) (buf + 6);
    if (mac[0] != 0x08 && mac[1] != 0x00 && mac[2] != 0x27 && mac[3] != 0x77 && mac[4] != 0x08 && mac[5] != 0x49)
    {
	    //printf("Not destined to ours\n"); 
	    return;
    }
    //printf("Mac : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    ehl = sizeof(ETHPKTHDR);
    //ihl = 4 * (buf[0] & 0x0f);
    ihl = 4 * (buf[ehl] & 0x0f);
    if (ihl > 60 || ihl < 20)
    {
        printf("IPv4 header too long\n");
        return;
    }
    // check source IPv4 address
    //if (*(uint32_t *)(buf + ehl + 12) != remote.sin_addr.s_addr)
    if (*(uint32_t *)(buf + ehl + 12) != remote_pi.sin_addr.s_addr)
    {
        return;
    }

    // parse GRE header
    if (*(uint16_t *)(buf + ehl + ihl) != 0)
    {
        return;
    }
    uint16_t protocol = ntohs(*(uint16_t *)(buf + ehl + ihl + 2));
    if (protocol != 0x0800)
    {
        return;
    }

    int i, msg_count = 0;
    int len;
    int getlen;
    uint16_t cksumval;
    int32_t temp_ipaddr;
    uint32_t gre_inner_ip;

    memcpy(w_gre_buf, buf, n);
    w_gre_buf[0 + 0] = 0xb8;
    w_gre_buf[1 + 0] = 0x27;
    w_gre_buf[2 + 0] = 0xeb;
    w_gre_buf[3 + 0] = 0x59;
    w_gre_buf[4 + 0] = 0xa0;
    w_gre_buf[5 + 0] = 0x23;

    //08:00:27:77:08:49
    //? (192.168.29.34) at b8:27:eb:59:a0:23 [ether] on eth0
    // reliance.reliance (192.168.29.1) at 6c:df:fb:2f:20:31 [ether] on eth0
    w_gre_buf[6  + 0] = 0x08;
    w_gre_buf[7  + 0] = 0x00;
    w_gre_buf[8  + 0] = 0x27;
    w_gre_buf[9  + 0] = 0x77;
    w_gre_buf[10 + 0] = 0x08;
    w_gre_buf[11 + 0] = 0x49;
    //memcpy(w_gre_buf + ehl, buf + ehl,  ihl + 4);
    /*
    memcpy(write_buf, buf, ehl);
    write_buf[0 + 0] = 0x6c;
    write_buf[1 + 0] = 0xdf;
    write_buf[2 + 0] = 0xfb;
    write_buf[3 + 0] = 0x2f;
    write_buf[4 + 0] = 0x20;
    write_buf[5 + 0] = 0x31;

    //08:00:27:77:08:49
    write_buf[6  + 0] = 0x08;
    write_buf[7  + 0] = 0x00;
    write_buf[8  + 0] = 0x27;
    write_buf[9  + 0] = 0x77;
    write_buf[10 + 0] = 0x08;
    write_buf[11 + 0] = 0x49;
    */

    //memcpy(write_buf + ehl, buf + ehl + ihl + 4, n - ihl - 4);
    memcpy(write_buf, buf + ehl + ihl + 4 + 20, n - ehl - ihl - 4 - 20);

    for (int i = 0; i < n - ehl - ihl - 4; i++)
	    printf ("%.2x-", write_buf[i]);
    printf("\n total len = %d\n", i);
    
    ip = (struct iphdr *) (w_gre_buf + ehl + ihl + 4);

    remote.sin_family = AF_INET;
    //remote.sin_port = htons(IPPROTO_GRE);
    remote.sin_port = htons(0);
    //remote.sin_addr.s_addr = inet_addr("8.8.8.8");
    remote.sin_addr.s_addr = ip->daddr;
    gre_inner_ip = ip->saddr;

    if(sendto(sock, write_buf, n - ehl - ihl - 4 - 20, 0, (struct sockaddr *)&remote, sizeof(struct sockaddr)) != 0)
        perror("sendto");

#if 1
    memset(write_buf, 0, sizeof(write_buf));
    if ((len = recvfrom(sock, write_buf, sizeof(write_buf), 0, (struct sockaddr*)&local, &getlen)) <= 0) 
    { 
	    printf("\nPacket receive failed!\n"); 
    } 
#endif
    len = len - ihl;
    for (int i = 0; i < ihl + len; i++)
	    printf ("%.2x", write_buf[i]);
    printf("\n ICMP reply recv total len = %d %d\n", len + ihl, getlen);

    //memcpy(w_gre_buf + ehl + ihl + 4 + ihl, write_buf, len);
    //
    //memcpy(w_gre_buf + ehl + ihl + 4 + ihl, write_buf + ihl, len);
    memcpy(w_gre_buf + ehl + ihl + 4, write_buf, len + ihl);
#ifdef ORIG
    ip = (struct iphdr *) (w_gre_buf + ehl);
    //ipfull = (struct ip *) (w_gre_buf + ehl);
    ip->saddr = (192) + (168 << 8) + (29 << 16) + (177 << 24);
    ip->daddr = (192 ) + (168 << 8) + (29 << 16) + (34 << 24);
    memcpy(w_gre_buf + ehl + ihl + 4, buf + ehl + ihl + 4,  ihl);
    ip = (struct iphdr *) (w_gre_buf + ehl + ihl + 4);
    //ipfull = (struct ip *) (w_gre_buf + ehl);
    ip->saddr = (8) + (8 << 8) + (8 << 16) + (8 << 24);
    ip->daddr = (192 ) + (168 << 8) + (29 << 16) + (34 << 24);
#else
    //ipfull = (struct ip *) (w_gre_buf + ehl);
    ip = (struct iphdr *) (w_gre_buf + ehl);
    temp_ipaddr = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = temp_ipaddr;
    //memcpy(w_gre_buf + ehl + ihl + 4, buf + ehl + ihl + 4,  ihl);

    ip = (struct iphdr *) (w_gre_buf + ehl + ihl + 4);
    ip->daddr = gre_inner_ip;
    //ip->saddr = temp_ipaddr;
#if 0
    struct sockaddr_in in;
    in.sin_addr.s_addr = ip->daddr; //100.10.10.10
    printf("IP addr %s\n", inet_ntoa(in.sin_addr));
    in.sin_addr.s_addr = ip->saddr; //8.8.8.8
    printf("IP addr %s\n", inet_ntoa(in.sin_addr));
#endif
#endif
    printf("len = %d\n", len);

    ip = (struct iphdr *) (w_gre_buf + ehl + ihl + 4);
print_ip_header(ip, "Inner Header");
#if 1
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    //ip->id = htonl (54321);	//Id of this packet
    ip->frag_off = 0;
    ip->ttl = 254;
    ip->protocol = IPPROTO_ICMP;
#endif
    //ip->tot_len = htons(sizeof (struct iphdr) + sizeof (struct icmphdr) + len);
    ip->tot_len = htons(sizeof (struct iphdr) + len);
printf("Inner ip tot_len = %d\n", ihl + len);
    ip->check = 0;		//Set to 0 before calculating checksum
    cksumval = compute_checksum((unsigned short *)(ip), sizeof(struct iphdr)); // + sizeof(struct icmphdr));
    w_gre_buf[48] = cksumval & 0xff;
    w_gre_buf[49] = cksumval >> 8 & 0xff;

#if 1
    ip = (struct iphdr *) (w_gre_buf + ehl);
printf("\n");
//print_ip_header(ip, "Outer Header");
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    //ip->id = htonl (54321);	//Id of this packet
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_GRE;
#endif

    ip->tot_len = htons(sizeof (struct iphdr) + 4 + sizeof (struct iphdr) + len);
    printf("Outer header %x\n", ip->tot_len);
    ip->check = 0;		//Set to 0 before calculating checksum
    //cksumval = compute_checksum((unsigned short *)(ip), sizeof(struct iphdr)); // + sizeof(struct icmphdr));
    cksumval = compute_checksum((unsigned short *)(ip), sizeof(struct iphdr));// + sizeof(struct icmphdr) + 4 + ihl + len);
printf("Check Sum %.4x\n", cksumval);
    w_gre_buf[24] = cksumval & 0xff;
    w_gre_buf[25] = cksumval >> 8 & 0xff;

print_ip_header(w_gre_buf + ehl + ihl + 4, "Inner Header");
    for (i = 0; i <  ehl + ihl + 4 + ihl + len ; i++)
	    printf ("%.2x", w_gre_buf[i]);
    printf("\n Gre write total len = %d\n", i);
    if (sendto(sock_normal, w_gre_buf, len  + ehl + ihl + 4 + ihl, 0, (struct sockaddr *) &remote_outside_ll, sizeof(struct sockaddr_ll)) != 0)
    {
	    perror("sendto failed");
    }
}

static void tun_cb(void)
{
    int n;

    n = read(tun, buf + 4, sizeof(buf) - 4);
    if (n < 0)
    {
        perror("read");
        return;
    }
    *(uint16_t *)(buf) = 0;
    *(uint16_t *)(buf + 2) = htons(0x0800);
    printf("Hello packet tun_cb %d\n", buf[2]);
    sendto(sock, buf, n + 4, 0, (struct sockaddr *)&remote, sizeof(struct sockaddr));
}

static int tun_new(const char *dev)
{
    struct ifreq ifr;
    int fd, err;
    char cmd[128];

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
    {
        return -1;
    }

    bzero(&ifr, sizeof(struct ifreq));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (*dev != '\0')
    {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    err = ioctl(fd, TUNSETIFF, (void *)&ifr);
    if (err < 0)
    {
        return err;
    }

    sprintf(cmd, "ifconfig %s up", dev);
    system(cmd);
    return fd;
}

static int setnonblock(int fd)
{
    int flags;
    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
    {
        return -1;
    }
    if (-1 == fcntl(fd, F_SETFL, flags | O_NONBLOCK))
    {
        return -1;
    }
    return 0;
}

static int runas(const char *user)
{
    struct passwd *pw_ent = getpwnam(user);

    if (pw_ent != NULL)
    {
        if (setegid(pw_ent->pw_gid) != 0)
        {
            return -1;
        }
        if (seteuid(pw_ent->pw_uid) != 0)
        {
            return -1;
        }
    }

    return 0;
}

static int daemonize(void)
{
    pid_t pid;

    pid = fork();
    if (pid < 0)
    {
        perror("fork");
        return -1;
    }

    if (pid > 0)
    {
        exit(0);
    }

    umask(0);

    if (setsid() < 0)
    {
        perror("setsid");
        return -1;
    }

    return 0;
}
