/* 最终成型双网程序
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sched.h>
//#include <wiringPi.h>

#include <sys/errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/stat.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>

#include <arpa/inet.h>
#include <asm/types.h>

//宏定义
#define LTE 1
#define MESH 0
#define USER "userlist please!"
#define GW "gwlist please!"
#define LTESERIP "192.168.137.2"
#define LTEIPHD "172.1."
#define MESHIPHD "10.24.1."
#define BUFFER_MAX 4096
#define MACLEN 6
#define IPLEN 4
#define CHARIPLEN 16
#define BUFLEN 80
#define PORTLEN 2

#define PORT 21314
#define UDPPORT 10240
#define LTESER 9090
#define RTPORT 10240

#define ETH_LTE  "wwp0s20u2c2"
#define ETH_MESH "wlo1"
#define ETH_CL "eno1"

#define DELAY 5
#define IFLIST_REPLY_BUFFER	8192


#define LEDM    24  //黄
#define LEDL	29  //蓝

//结构体定义
typedef struct nl_req_s {                      //sendmsg 数据结构体
    struct nlmsghdr hdr;
    struct rtgenmsg gen;
}nl_req_t;

struct rt {										//路由信息
    char index;           //1
    bool status;          //1
    bool net;             //1
    char dest[16];        //16
    char gw[16];          //16
};                        //35

struct user {									//用户信息
    char index;									//meshIP索引
    bool status;
    char ip[16];
};

struct LTELIST {
    short int total;
    struct user list[200];
};

struct GWLIST {
    short int total;
    struct user list[42];
};
//全局变量

struct rt rtlist[42];    					//路由信息表
struct GWLIST gwlist;						//自我网关用户表
struct LTELIST ltelist;						//LTE用户活动用户表
int localindex = 0;
int sock_routereload = 0;
bool fgL = false, fgM = false;

//互斥锁
pthread_mutex_t mutexrtlist;
pthread_mutex_t mutexgwlist;
pthread_mutex_t mutexltelist;
pthread_mutex_t mutexsock;

//函数 --每个线程都可以调用
//int initrtcache(struct rt *rtcache) {                    //init rtlist
//    memset(rtcache, 0,sizeof(*rtcache));
//    char ip[16] = {0};
//    int i;
//    for (i = 0; i < 42; i++) {
//        sprintf(ip, "%s%d", MESHIPHD, i);
//        rtcache[i].index = (char)i;
//        strcpy(rtcache[i].dest, ip);
//    }
//    return 0;
//}

void rtnl_print_link(struct nlmsghdr *h) {
    struct ifinfomsg *iface;                                  //网卡信息结构体 后面一般跟上rtattr 结构
    struct rtattr *attribute;									//特定的消息类 （rtnetlink）
    int len;

    iface = NLMSG_DATA(h);
    len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*iface));        //接收的消息 去掉 网卡信息

    /* loop over all attributes for the NEWLINK message */
    for (attribute = IFLA_RTA(iface); RTA_OK(attribute, len); attribute = RTA_NEXT(attribute, len)) {
        switch(attribute->rta_type) {
            case IFLA_IFNAME:
//                printf("Interface %d : %s\n", iface->ifi_index, (char *) RTA_DATA(attribute));
                break;
            default:
                break;
        }
    }
}

void rtnl_print_route(struct nlmsghdr *nlh, struct rt *rtcache) {
    struct  rtmsg *route_entry;  						        //用于接收内核发来的路由消息
    struct  rtattr *route_attribute;



    int     route_attribute_len = 0;
    unsigned int     route_index = 0;							//网卡的索引
    unsigned char    route_netmask = 0;
//    unsigned char    route_protocol = 0;
    char    destination_address[32];
    char    gateway_address[32];

    route_entry = (struct rtmsg *) NLMSG_DATA(nlh);                                 //数据部分 去掉头部

    if (route_entry->rtm_table != RT_TABLE_MAIN)                                    //是否为系统主route表 linux 下有多个路由表
        return;

    route_netmask = route_entry->rtm_dst_len;										//子网掩码
//    route_protocol = route_entry->rtm_protocol;										//协议
    route_attribute = (struct rtattr *) RTM_RTA(route_entry);

    route_attribute_len = RTM_PAYLOAD(nlh);

    for ( ; RTA_OK(route_attribute, route_attribute_len); \
        route_attribute = RTA_NEXT(route_attribute, route_attribute_len)) {

        if (route_attribute->rta_type == RTA_DST) {
            inet_ntop(AF_INET, RTA_DATA(route_attribute), \
                      destination_address, sizeof(destination_address));
        }
        //获取网关
        if (route_attribute->rta_type == RTA_GATEWAY) {                   //跨网段 肯定要过网卡接入的路由器 所以 单网卡只有一个网关
            inet_ntop(AF_INET, RTA_DATA(route_attribute), \
                      gateway_address, sizeof(gateway_address));
        }
        // 获取路由的网卡索引
        if (route_attribute->rta_type == RTA_OIF) {                   //
            route_index = *(unsigned int *)RTA_DATA(route_attribute); \

        }
    }
//    printf("route to destination --> %s/%d proto %d and gateway %s and dev %d\n",
//           destination_address, route_netmask, route_protocol, gateway_address, route_index);

    //只保存MESH网卡主机路由信息
    if((route_netmask == 32) && (route_index == if_nametoindex(ETH_MESH))){
        int tmp = 0;
        int ret = 0;
        if ((ret = inet_pton(AF_INET, destination_address, &tmp)) < 0) {
            perror("inet_pton");
        }
                           //ip最后一个字节 第三个点后面的值
        int rtindex = (tmp>>24)&0xff;
        rtcache[rtindex].index = (char)rtindex;
        rtcache[rtindex].status = true;											  //状态置一 活动的meshIP
        rtcache[rtindex].net = MESH;												  //网络状态是属于mesh网
        memcpy(rtcache[rtindex].gw, gateway_address, sizeof(rtcache[rtindex].gw));  //获取下一跳IP
    }

    return;
}

int getroute(struct rt *rtcache) {
    int fd = 0; 											//socket
    struct sockaddr_nl local;  								        //netlink地址结构
    struct sockaddr_nl kernel;

    struct msghdr rtnl_msg;   								            //sendmsg recvmsg 使用的消息头
    struct iovec io;	     					                             //指向一个缓冲区（内存地址，内存长度）

    nl_req_t req;              									    //nlmsghdr + rtgenmsg
    char reply[IFLIST_REPLY_BUFFER]; 								 //接收使用的buffer

    pid_t pid = getpid();	     								    //pid_t -> int（32）  获取进程pid
    int end = 0;

    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);                                      //netlink套接字

    memset(&local, 0, sizeof(local)); 						              //初始化本地nl 地址结构
    local.nl_family = AF_NETLINK;
    local.nl_pid = pid;
    local.nl_groups = 0;
    socklen_t len = 0;
    len = sizeof(local);
    if (bind(fd, (struct sockaddr *) &local, len) < 0) {                           //绑定local
        perror("bind");
        return -1;
    }

    memset(&rtnl_msg, 0, sizeof(rtnl_msg));
    memset(&kernel, 0, sizeof(kernel));
    memset(&req, 0, sizeof(req));

    kernel.nl_family = AF_NETLINK;										   //内核不需要pid
    kernel.nl_groups = 0;

    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));				//nl头部后面带的msg类型的长度 也可以使用rtmsg
    req.hdr.nlmsg_type = RTM_GETROUTE;											//操作命令
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP; 									//
    req.hdr.nlmsg_seq = 1;
    req.hdr.nlmsg_pid = pid;
    req.gen.rtgen_family = AF_INET;

    io.iov_base = &req;													//sendmsg 指向req
    io.iov_len = req.hdr.nlmsg_len;
    rtnl_msg.msg_iov = &io;
    rtnl_msg.msg_iovlen = 1;
    rtnl_msg.msg_name = &kernel;
    rtnl_msg.msg_namelen = sizeof(kernel);

    sendmsg(fd, (struct msghdr *) &rtnl_msg, 0);                                     //向内核发送msg

    while (!end) {
        int len;
        struct nlmsghdr *msg_ptr;

        struct msghdr rtnl_reply;
        struct iovec io_reply;

        memset(&io_reply, 0, sizeof(io_reply));
        memset(&rtnl_reply, 0, sizeof(rtnl_reply));

        io.iov_base = reply;                                 //指向接收缓冲buffer
        io.iov_len = IFLIST_REPLY_BUFFER;
        rtnl_reply.msg_iov = &io;
        rtnl_reply.msg_iovlen = 1;
        rtnl_reply.msg_name = &kernel;
        rtnl_reply.msg_namelen = sizeof(kernel);

        len = recvmsg(fd, &rtnl_reply, 0); 								      //接收到reply中
        if (len) {
            for (msg_ptr = (struct nlmsghdr *) reply; NLMSG_OK(msg_ptr, len); msg_ptr = NLMSG_NEXT(msg_ptr, len)) {
                //将收到的消息转化成netlink 消息格式
                switch(msg_ptr->nlmsg_type) {
                    case 3:
                        end++;
                        break;
                    case 16:
                        rtnl_print_link(msg_ptr);
                        break;
                    case 24:
                        rtnl_print_route(msg_ptr, rtcache);
                        break;
                    default:
//                        printf("message type %d, length %d\n", msg_ptr->nlmsg_type, msg_ptr->nlmsg_len);
                        break;
                }
            }
        }
    }

    close(fd);
    return 0;
}

int arpGet(char *ifname, char *ipStr, char *mac) {
    if(ifname == NULL || ipStr == NULL) {
        puts("para is null.\n");
        return -1;
    }

    struct arpreq req;
    struct sockaddr_in *sin;
    int ret = 0;
    int sock_fd = 0;

    memset(&req, 0, sizeof(struct arpreq));

    sin = (struct sockaddr_in *)&req.arp_pa;
    sin->sin_family = AF_INET;
    if ((ret = inet_pton(AF_INET, ipStr, &sin->sin_addr.s_addr)) < 0) {
        perror("arpGet_inet_pton");
    }

    //arp_dev长度为[16]，注意越界
    strncpy(req.arp_dev, ifname, 15);

    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock_fd < 0) {
        perror("create socket error");
        return -1;
    }

    ret = ioctl(sock_fd, SIOCGARP, &req);
    if(ret < 0) {
//        perror("ioctl error");
        close(sock_fd);
        return -1;
    }

    unsigned char *hw = (unsigned char *)req.arp_ha.sa_data;
    memcpy(mac, hw, MACLEN);
    close(sock_fd);
    return 0;
}

int eth_ip(char *ethname, char *ip) {            //获取网卡IP
    int sock = 0, fg = 0;
    socklen_t len = 0;
    struct ifreq req;
    char ethip[CHARIPLEN] = {0};

    strncpy(req.ifr_name, ethname, IFNAMSIZ);      //指定网卡名称

    if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("create socket error");
        return 0;
    }
    fg = ioctl(sock, SIOCGIFADDR, &req);      //获取eht IP

    if(fg < 0) {
        perror("get addr error");
        close(sock);
        return 0;
    } else {
        len = sizeof(ethip);
        if (inet_ntop(AF_INET, &((struct sockaddr_in*)&(req.ifr_addr))->sin_addr, ethip, len - 1) == NULL) {
            perror("inet_ntop");
        }

        strcpy(ip, ethip);
        close(sock);
        return 1;
    }
}

int ifproto(char *ipacket) { 				 	  //判断协议 减少网络压力 只接受icmp udp 包 可调整
    int proto = 0;
    char *p;
    p = ipacket + 14 + 9;
    proto = p[0];
    if((proto == IPPROTO_UDP) || (proto == IPPROTO_ICMP)) return 1;
    else return 0;
}

//线程一：客户机数据包处理
void *rawsocket(/*void *arg*/){
    int raw_sock = 0, lte_udp = 0, mesh_udp = 0, len = 0, ret = 0;
    socklen_t slen = 0;
    int tmp_int = 0;
    int index = 0;
//    char tmp_char[CHARIPLEN] = {0};
    char buffer[BUFFER_MAX];
    char ip[CHARIPLEN] = {0};
//    char *ethhead, *iphead,/* *tcphead, *udphead, *icmphead,*/ *p;
    char ethso[MACLEN] = {0};  //source mac
    char ethlo[MACLEN] = {0};  //localeth mac
    //unsigned char ethde[MACLEN] = {0x00,0x0c,0x29,0x16,0x90,0xb0};  //dest mac
    char lteip[CHARIPLEN] = {0};
    char meship[CHARIPLEN] = {0};
//    char destip[20] = {0};
    char sourip[CHARIPLEN] = {0};

    if((raw_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
        perror("create raw_socket error");
        exit(0);
    }

    if((lte_udp = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
        perror("create lte_udp error");
        exit(0);
    }

    if((mesh_udp = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
        perror("create mesh_udp error");
        exit(0);
    }


    struct ifreq ifr;
    struct sockaddr_ll sll;

    memset(&ifr, 0, sizeof(ifr));              //初始化
    memset(&sll, 0, sizeof(sll));

    strncpy(ifr.ifr_name, ETH_CL, IFNAMSIZ);

    if ((ret = ioctl(raw_sock, SIOCGIFINDEX, &ifr)) < 0) {
        perror("SIOCGIFINDEX:");
        exit(0);
    }

    sll.sll_ifindex  = ifr.ifr_ifindex;             //拷贝网卡索引
    sll.sll_family   = PF_PACKET;
    sll.sll_protocol = htons(ETH_P_IP);

    if ((ret == ioctl(raw_sock, SIOCGIFHWADDR, &ifr)) < 0) {
        perror("SIOCGIFHWADDR:");
        exit(0);
    }

    memcpy(ethlo, ifr.ifr_hwaddr.sa_data, MACLEN);	       //获取本机client 网卡mac

    struct sockaddr_in sin;                    // 传输层 套接字地址结构
    memset(&sin,0,sizeof(sin));
    sin.sin_family = AF_INET;               			//配置传输层套接字地址结构
    sin.sin_port = htons(PORT);

    for (;;) {
        ret = recvfrom(raw_sock, buffer, BUFFER_MAX, 0, NULL, NULL);    //获取mac层数据包
        if(ret < 42){
            continue;
        }
        len = (int)buffer[17] + (int)buffer[16] * 256;			//获取ip包长度
        memset(ip, 0, sizeof(ip));
        memset(sourip, 0, sizeof(sourip));
        memcpy(ip, buffer + 14 + 12, IPLEN);   //获取数据包发送端IP 二进制形式 网络序
        sprintf(sourip,"%d.%d.%d.%d",ip[0]&0XFF, ip[1]&0XFF, ip[2]&0XFF, ip[3]&0XFF);  //转化为点分十进制

        if(ifproto(buffer)) {                    //只抓UDP ICMP\n
            memset(ethso, 0, sizeof(ethso));
            if((arpGet(ETH_CL, sourip, ethso)) == 0){
//                puts("get client mac success\n");

                if(memcmp(buffer + MACLEN, ethso, sizeof(ethso)) == 0){      // 判断发送端MAC 是否为 本机ARP缓存中的客户机的MAC

//                    ethhead = buffer;
//                    p = ethhead;
//                    printf("MAC: %.2X:%02X:%02X:%02X:%02X:%02X==>"
//                            "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
//                            p[6]&0XFF, p[7]&0XFF, p[8]&0XFF, p[9]&0XFF, p[10]&0XFF, p[11]&0XFF,
//                            p[0]&0XFF, p[1]&0XFF, p[2]&0XFF,p[3]&0XFF, p[4]&0XFF, p[5]&0XFF);
//                    iphead = ethhead + 14;
//                    p = iphead + 12;
//                    printf("IP: %d.%d.%d.%d => %d.%d.%d.%d\n",
//                            p[0]&0XFF, p[1]&0XFF, p[2]&0XFF, p[3]&0XFF,
//                            p[4]&0XFF, p[5]&0XFF, p[6]&0XFF, p[7]&0XFF);
//                    int proto;
//                    proto = (iphead + 9)[0];
//                    p = iphead + 20;
//                    printf("Protocol: ");
//                    switch(proto){
//                        case IPPROTO_ICMP: printf("ICMP\n");break;
//                        case IPPROTO_IGMP: printf("IGMP\n");break;
//                        case IPPROTO_IPIP: printf("IPIP\n");break;
//                        case IPPROTO_TCP :
//                        case IPPROTO_UDP : printf("%s,", proto == IPPROTO_TCP ? "TCP": "UDP");
//                                           printf("source port: %u,",(p[0]<<8)&0XFF00 |  p[1]&0XFF);
//                                           printf("dest port: %u\n", (p[2]<<8)&0XFF00 |  p[3]&0XFF);
//                                           break;
//                        case IPPROTO_RAW : printf("RAW\n");break;
//                        default:printf("Unkown, please query in include/linux/in.h\n");
//                    }
                    memset(ip, 0, sizeof(ip));
                    memcpy(ip, buffer + 14 + 12 + 4, IPLEN);    //获取目的IP 二进制 网络序
                    tmp_int = ip[3]&0xff;
                    index = 50 - tmp_int / 5 + 2;               //index
//                    //根据目的IP 计算出 MESHIP 和 LTEIP

//                    sprintf(tmp_char,"%d",tmp_int);
//                    strcpy(meship, MESHIPHD);
//                    strcat(meship, tmp_char);                                         //得到MESHIP
//                    strcpy(lteip, LTEIPHD);
//                    strcat(lteip, tmp_char);									      //得到LTEIP

//                    if(eth_ip(ETH_LTE, ip)){                                         //判断LTE是否可用
//                        strcpy(ip,lteip);
//                        printf("%s\n",ip);
//                        sin.sin_addr.s_addr = inet_addr(ip);
//                        if((send0 = sendto(lte_udp, buffer, len+14, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr_in))) < 0){
//                            perror("sendto error");
//                            exit(0);
//                        }
//                    } else {
//                        strcpy(ip,meship);
//                        printf("%s\n",ip);
//                        sin.sin_addr.s_addr = inet_addr(ip);
//                        if((send0 = sendto(mesh_udp, buffer, len+14, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr_in))) < 0){
//                            perror("sendto error");
//                            continue;
//                        } else {
//                            printf("sendto success\n");
//                        }
//                    }
                    if (rtlist[index].status == true) {
                        if (rtlist[index].net == LTE) {                       //如果net为LTE 使用rtlist
                            memset(lteip, 0, sizeof(lteip));
                            memcpy(lteip, rtlist[index].gw, sizeof(rtlist[index].gw) - 1);
//                            if (memcmp(lteip, LTEIPHD, sizeof(LTEIPHD)) == 0) {
//                                //mie deng let
//                            } else {
//                                //mie deng mesh
//                            }
                            if ((ret = inet_pton(AF_INET, lteip, &sin.sin_addr.s_addr)) < 0) {
                                perror("inet_pton");
                            }
                            slen = sizeof(sin);
                            if((ret = sendto(lte_udp, buffer, len+14, 0, (struct sockaddr *)&sin, slen)) < 0){
                                perror("lteudp sendto error");
                                pthread_mutex_lock(&mutexrtlist);
                                rtlist[index].net = MESH;
                                pthread_mutex_unlock(&mutexrtlist);
//                                pthread_mutex_lock(&mutexsock);
//                                shutdown(sock_routereload, SHUT_RDWR);
//                                pthread_mutex_unlock(&mutexsock);
                            } else {
//                                fgM = true;
//                                puts("lteudp sendto success\n");
                            }
                        } else {                //net == mesh   计算出目的ip所在 的手台ip 直接发送给目的手台的meship
                            memset(meship, 0, sizeof(meship));
                            sprintf(meship,"%s%d", MESHIPHD, index);
                            /*strcpy(meship, );
                            strcat(meship, tmp_char);  */                                       //得到MESHIP
                            if ((ret = inet_pton(AF_INET, meship, &sin.sin_addr.s_addr)) < 0) {
                                perror("inet_pton");
                            }
                            slen = sizeof(sin);
                            if((ret = sendto(mesh_udp, buffer, len+14, 0, (struct sockaddr *)&sin, slen)) < 0){
                                perror("meshudp sendto error");
//                                pthread_mutex_lock(&mutexrtlist);
//                                rtlist[index].status = false;
//                                pthread_mutex_unlock(&mutexrtlist);
                            } else {
//                                fgM = true;
//                                puts("meshudp sendto success\n");
                            }
                        }
                    }

                }
            }
        }
//        memset(tmp_char, 0,sizeof(tmp_char));
    }

}

//线程二：MESH 网络数据包处理
void *meshudp(/*void *arg*/) {
    int raw_sock = 0, udp_sock = 0, send_sock = 0, len = 0, ret = 0;
    socklen_t slen = 0;
    int tmp_int = 0, index = 0;
//    char tmp_char[CHARIPLEN] = {0};
    char buffer[BUFFER_MAX] = {0};
    char ip[CHARIPLEN] = {0};
//    char *ethhead, /**iphead, *tcphead, *udphead, *icmphead,*/ *p;
    char ethlo[MACLEN] = {0};  //localeth mac
    char ethde[MACLEN] = {0};  //dest mac

    char destip[CHARIPLEN] = {0};
    char lteip[CHARIPLEN] = {0};
    char meship[CHARIPLEN] = {0};

    if((raw_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
        perror("create raw_socket error");
        exit(0);
    }

    if((udp_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
        perror("create udp_socket error");
        exit(0);
    }

    if((send_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
        perror("create udp_socket error");
        exit(0);
    }

    struct sockaddr_ll sll;              //原始套接字地址结构
    struct sockaddr_in sin;                    // 传输层 套接字地址结构
    struct ifreq req_udp;
    struct ifreq req_raw;                   //网络接口地址
    strncpy(req_raw.ifr_name, ETH_CL, IFNAMSIZ);    //指定外部数据网卡名称
    strncpy(req_udp.ifr_name, ETH_MESH, IFNAMSIZ);    //指定MESH网卡名称

    if(ioctl(raw_sock,SIOCGIFINDEX, &req_raw) < 0) {
        perror("req_raw ioctl error");
        exit(0);
    }

    if(ioctl(udp_sock, SIOCGIFADDR, &req_udp) < 0) {      //获取MESH IP
        perror("req_udp ioctl error");
        exit(0);
    }

    memset(&sll, 0, sizeof(sll));
    memset(&sin, 0, sizeof(sin));
    sll.sll_ifindex = req_raw.ifr_ifindex;
    sll.sll_family = PF_PACKET;
    sll.sll_protocol = htons(ETH_P_IP);

    slen = sizeof(ip);
    if ((inet_ntop(AF_INET, &((struct sockaddr_in*)&(req_udp.ifr_addr))->sin_addr, ip, slen - 1)) == NULL) {
        perror("inet_ntop");
    }
//    puts(ip);
    sin.sin_family = AF_INET;               //配置传输层套接字地址结构
    if ((ret = inet_pton(AF_INET, ip, &sin.sin_addr.s_addr)) < 0) {
        perror("inet_pton");
    }
    sin.sin_port = htons(PORT);

    struct ifreq ifr;
    struct sockaddr_ll soll;

    memset(&ifr, 0, sizeof(ifr));              //初始化
    memset(&soll, 0, sizeof(soll));

    strncpy(ifr.ifr_name, ETH_CL, IFNAMSIZ);

    if ((ret = ioctl(raw_sock, SIOCGIFINDEX, &ifr)) < 0) {
        perror("SIOCGIFINDEX:");
        exit(0);
    }

    soll.sll_ifindex  = ifr.ifr_ifindex;             //拷贝网卡索引
    soll.sll_family   = PF_PACKET;
    soll.sll_protocol = htons(ETH_P_ARP);

    if ((ret = ioctl(raw_sock, SIOCGIFHWADDR, &ifr)) < 0) {
        perror("SIOCGIFHWADDR:");
        exit(0);
    }

    memcpy(ethlo, ifr.ifr_hwaddr.sa_data, MACLEN);	       //获取本机client 网卡mac

    struct sockaddr_in sendin;                         //用于非本机转发  ********************************
    memset(&sendin, 0, sizeof(sendin));
    sendin.sin_family = AF_INET;                           //配置传输层套接字地址结构
    sendin.sin_port = htons(PORT);
    slen = sizeof(sin);
    for (;;) {
        if(bind(udp_sock, (struct sockaddr *)&sin, slen) < 0){    //绑定MESH的ip地址
            perror("bind error");
            sleep(1);
            continue;
        }else{
//            puts("bind success\n");
            break;
        }
    }

    for (;;) {
        //if(recvfrom(udp_sock, buffer, BUFFER_MAX, 0, (struct sockaddr *)&sin, &sin_size) < 0){
        if(recvfrom(udp_sock, buffer, BUFFER_MAX, 0, NULL, NULL) < 0){
            perror("recvfrom");
            continue;
        }
        fgM = true;
        len = (int)buffer[17] + (int)buffer[16] * 256;            //获取ip报文长度
        memset(ip, 0, sizeof(ip));
        memset(destip, 0, sizeof(destip));
        memcpy(ip, buffer + 14 + 12 + 4, IPLEN);    //获取目的IP 二进制 网络序
        sprintf(destip, "%d.%d.%d.%d", ip[0]&0XFF, ip[1]&0XFF, ip[2]&0XFF, ip[3]&0XFF);

        memset(ethde, 0, sizeof(ethde));
        if((arpGet(ETH_CL, destip, ethde)) == 0){        //判断是否为本机 shi
//            ethhead = buffer;
//            p = ethhead;
            memcpy(buffer, ethde, MACLEN);
//            for(i = 0 ; i < MACLEN; i++){     //替换目标mac地址
//                p[i] = ethde[i];
//            }
            memcpy(buffer + MACLEN, ethlo, MACLEN);
//            for(i = 0 ; i < MACLEN; i++){     //替换源mac地址
//                p[i+MACLEN] = ethlo[i];
//            }
//            printf("MAC: %.2X:%02X:%02X:%02X:%02X:%02X==>"
//                    "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
//                    p[6]&n, p[7]&n, p[8]&n, p[9]&n, p[10]&n, p[11]&n,
//                    p[0]&n, p[1]&n, p[2]&n,p[3]&n, p[4]&n, p[5]&n);
//            iphead = ethhead + 14;
//            p = iphead + 12;
//            printf("IP: %d.%d.%d.%d => %d.%d.%d.%d\n",
//                    p[0]&0XFF, p[1]&0XFF, p[2]&0XFF, p[3]&0XFF,
//                    p[4]&0XFF, p[5]&0XFF, p[6]&0XFF, p[7]&0XFF);
//            proto = (iphead + 9)[0];
//            p = iphead + 20;
//            printf("Protocol: ");
//            switch(proto){
//                case IPPROTO_ICMP: printf("ICMP\n");break;
//                case IPPROTO_IGMP: printf("IGMP\n");break;
//                case IPPROTO_IPIP: printf("IPIP\n");break;
//                case IPPROTO_TCP :
//                case IPPROTO_UDP : printf("%s,", proto == IPPROTO_TCP ? "TCP": "UDP");
//                                printf("source port: %u,",(p[0]<<8)&0XFF00 |  p[1]&0XFF);
//                                printf("dest port: %u\n", (p[2]<<8)&0XFF00 | p[3]&0XFF);
//                                break;
//                case IPPROTO_RAW : printf("RAW\n");break;
//                default:printf("Unkown, please query in include/linux/in.h\n");
//            }
            slen = sizeof(sll);
            if((ret = sendto(raw_sock, buffer, 14+len, 0, (struct sockaddr *)&sll, slen)) < 0){
                perror("sendto error");
                continue;
            } else {
//                puts("sendto success\n");
            }
        } else {                                        //非本机  进行转发 *************************************
            tmp_int = ip[3]&0xff;
            index = 50 - tmp_int / 5 + 2;               //index
            if (rtlist[index].status == true) {
                if (rtlist[index].net == LTE) {                       //如果net为LTE 使用rtlist
                    memset(lteip, 0, sizeof(lteip));
                    memcpy(lteip, rtlist[index].gw, sizeof(rtlist[index].gw) - 1);

                    if ((ret = inet_pton(AF_INET, lteip, &sendin.sin_addr.s_addr)) < 0) {
                        perror("inet_pton");
                    }
                    slen = sizeof(sendin);
                    if((ret = sendto(send_sock, buffer, len+14, 0, (struct sockaddr *)&sendin, slen)) < 0){
                        perror("lteudp sendto error");
                        pthread_mutex_lock(&mutexrtlist);
                        rtlist[index].net = MESH;
                        pthread_mutex_unlock(&mutexrtlist);
//                        pthread_mutex_lock(&mutexsock);
//                        shutdown(sock_routereload, SHUT_RDWR);
//                        pthread_mutex_unlock(&mutexsock);
                    } else {
//                        fgM = true;
//                        puts("lteudp sendto success\n");
                    }
                } else {                //net == mesh   计算出目的ip所在 的手台ip 直接发送给目的手台的meship
                    memset(meship, 0, sizeof(meship));
                    sprintf(meship,"%s%d", MESHIPHD, index);

//                    strcpy(meship, );
//                    strcat(meship, tmp_char);                                         //得到MESHIP
                    if ((ret = inet_pton(AF_INET, meship, &sendin.sin_addr.s_addr)) < 0) {
                        perror("inet_pton");
                    }
                    slen = sizeof(sendin);
                    if((ret = sendto(send_sock, buffer, len+14, 0, (struct sockaddr *)&sendin, slen)) < 0){
                        perror("meshudp sendto error");
                    } else {
//                        fgM = true;
//                        puts("meshudp sendto success\n");
                    }
                }
            }
        }
    }
}
//线程三：LTE 网络数据包处理
void *lteudp(/*void *arg*/) {
    int raw_sock = 0, udp_sock = 0, send_sock = 0, len = 0 , ret = 0;
    socklen_t slen = 0;
    int tmp_int, index;
    char buffer[BUFFER_MAX];
    char ip[CHARIPLEN] = {0};
//    char tmp_char[CHARIPLEN] = {0};
//    char *ethhead, /* *iphead, *tcphead, *udphead, *icmphead,*/ *p;
    char ethlo[MACLEN] = {0};  //localeth mac
    char ethde[MACLEN] = {0};  //dest mac

    char destip[CHARIPLEN] = {0};
    char lteip[CHARIPLEN] = {0};
    char meship[CHARIPLEN] = {0};

    if((raw_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("create raw_socket error");
        exit(0);
    }

    if((send_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
        perror("create send_socket error");
        exit(0);
    }

    struct sockaddr_ll sll;              //原始套接字地址结构
    struct sockaddr_in sin;                    // 传输层 套接字地址结构
    //struct ifreq req_udp;
    struct ifreq req_raw;                   //网络接口地址
    memset(&sll,0,sizeof(sll));
    strncpy(req_raw.ifr_name, ETH_CL, IFNAMSIZ);    //指定外部数据网卡名称
    //strncpy(req_udp.ifr_name, "ppp0", IFNAMSIZ);    //指定LTE网卡名称

    if(ioctl(raw_sock,SIOCGIFINDEX, &req_raw) < 0)
        perror("req_raw ioctl error");

    sll.sll_ifindex = req_raw.ifr_ifindex;


    struct ifreq ifr;
    struct sockaddr_ll soll;

    memset(&ifr, 0, sizeof(ifr));              //初始化
    memset(&soll, 0, sizeof(soll));

    strncpy(ifr.ifr_name, ETH_CL, IFNAMSIZ);

    if ((ret = ioctl(raw_sock, SIOCGIFINDEX, &ifr)) < 0) {
        perror("SIOCGIFINDEX:");
        exit(0);
    }

    soll.sll_ifindex  = ifr.ifr_ifindex;             //拷贝网卡索引
    soll.sll_family   = PF_PACKET;
    soll.sll_protocol = htons(ETH_P_ARP);

    if ((ret == ioctl(raw_sock, SIOCGIFHWADDR, &ifr)) < 0) {
        perror("SIOCGIFHWADDR:");
        exit(0);
    }

    memcpy(ethlo, ifr.ifr_hwaddr.sa_data, MACLEN);	       //获取本机client 网卡mac

    struct sockaddr_in sendin;                         //用于非本机转发  ********************************
    memset(&sendin, 0, sizeof(sendin));
    sendin.sin_family = AF_INET;                           //配置传输层套接字地址结构
    sendin.sin_port = htons(PORT);

    for (;;) {

        if(eth_ip(ETH_LTE, ip)) {     									//判断LTE存在

//            puts("LTE enable\n");

            if((udp_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
                perror("create udp_socket error");
                continue;
            }

            memset(&sin,0,sizeof(sin));
            sin.sin_family = AF_INET;							//配置传输层套接字地址结构
            sin.sin_port = htons(PORT);
            if ((ret = inet_pton(AF_INET, ip, &sin.sin_addr.s_addr)) < 0) {   //ip -> sin
                perror("inet_pton");
            }
            slen = sizeof(sin);
            if((bind(udp_sock, (struct sockaddr *)&sin, slen)) < 0){    //绑定LTE的ip地址
                perror("bind error");
                sleep(1);
                close(udp_sock);
                continue;
            }else{
//                puts("bind success\n");
            }
//            if(recv0 = recvfrom(udp_sock, buffer, BUFFER_MAX, 0, (struct sockaddr *)&sin, &sin_size) < 0){

            if((ret = recvfrom(udp_sock, buffer, BUFFER_MAX, 0, NULL, NULL)) < 0){
                perror("Receive Data Failed");
                close(udp_sock);
                continue;
            }
            fgL = true;
            len = (int)buffer[17] + (int)buffer[16] * 256;            //获取ip报文长度

            memset(ip, 0, sizeof(ip));
            memset(destip, 0, sizeof(destip));
            memcpy(ip, buffer + 14 + 12 + 4, IPLEN);    //获取目的IP 二进制 网络序
            sprintf(destip, "%d.%d.%d.%d", ip[0]&0XFF, ip[1]&0XFF, ip[2]&0XFF, ip[3]&0XFF);
            memset(ethde, 0, sizeof(ethde));

            if((arpGet(ETH_CL, destip, ethde)) == 0) {       //判断目的IP是否为本机 *****************************
//                ethhead = buffer;
//                p = ethhead;
//                for(i = 0 ; i < MACLEN; i++){     //替换目标mac地址
//                    p[i] = ethde[i];
//                }
                memcpy(buffer, ethde, MACLEN);
//                for(i = 0 ; i < MACLEN; i++){     //替换源mac地址
//                    p[i+MACLEN] = ethlo[i];
//                }
                memcpy(buffer + MACLEN, ethlo, MACLEN);
//                printf("MAC: %.2X:%02X:%02X:%02X:%02X:%02X==>"
//                        "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
//                        p[6]&n, p[7]&n, p[8]&n, p[9]&n, p[10]&n, p[11]&n,
//                        p[0]&n, p[1]&n, p[2]&n,p[3]&n, p[4]&n, p[5]&n);
//                iphead = ethhead + 14;
//                p = iphead + 12;
//                printf("IP: %d.%d.%d.%d => %d.%d.%d.%d\n",
//                        p[0]&0XFF, p[1]&0XFF, p[2]&0XFF, p[3]&0XFF,
//                        p[4]&0XFF, p[5]&0XFF, p[6]&0XFF, p[7]&0XFF);
//                proto = (iphead + 9)[0];
//                p = iphead + 20;
//                printf("Protocol: ");
//                switch(proto){
//                    case IPPROTO_ICMP: printf("ICMP\n");break;
//                    case IPPROTO_IGMP: printf("IGMP\n");break;
//                    case IPPROTO_IPIP: printf("IPIP\n");break;
//                    case IPPROTO_TCP :
//                    case IPPROTO_UDP : printf("%s,", proto == IPPROTO_TCP ? "TCP": "UDP");
//                                       printf("source port: %u,",(p[0]<<8)&0XFF00 |  p[1]&0XFF);
//                                       printf("dest port: %u\n", (p[2]<<8)&0XFF00 | p[3]&0XFF);
//                                       break;
//                    case IPPROTO_RAW : printf("RAW\n");break;
//                    default:printf("Unkown, please query in include/linux/in.h\n");
//                }
                slen = sizeof(sll);
                if((ret = sendto(raw_sock, buffer, 14+len, 0, (struct sockaddr *)&sll, slen)) < 0){
                    perror("sendto error");
                    continue;
                } else {
//                    puts("sendto success\n");
                }

            } else {                                    //非本机  进行转发 *************************************
                tmp_int = ip[3]&0xff;
                index = 50 - tmp_int / 5 + 2;               //index
                if (rtlist[index].status == true) {
                    if (rtlist[index].net == LTE) {                       //如果net为LTE 使用rtlist
                        memset(lteip, 0, sizeof(lteip));
                        memcpy(lteip, rtlist[index].gw, sizeof(rtlist[index].gw) - 1);

                        if ((ret = inet_pton(AF_INET, lteip, &sendin.sin_addr.s_addr)) < 0) {
                            perror("inet_pton");
                        }
                        slen = sizeof(sendin);

                        if((ret = sendto(send_sock, buffer, len+14, 0, (struct sockaddr *)&sendin, slen)) < 0){
                            perror("lteudp sendto error");
                            pthread_mutex_lock(&mutexrtlist);
                            rtlist[index].net = MESH;
                            pthread_mutex_unlock(&mutexrtlist);
//                            pthread_mutex_lock(&mutexsock);
//                            shutdown(sock_routereload, SHUT_RDWR);
//                            pthread_mutex_unlock(&mutexsock);
                        } else {
//                            fgM = true;
//                            puts("lteudp sendto success\n");
                        }
                    } else {                //net == mesh   计算出目的ip所在 的手台ip 直接发送给目的手台的meship
                        memset(meship, 0, sizeof(meship));
                        sprintf(meship, "%s%d", MESHIPHD, index);

//                        strcpy(meship, MESHIPHD);
//                        strcat(meship, tmp_char);                                         //得到MESHIP
                        if ((ret = inet_pton(AF_INET, meship, &sendin.sin_addr.s_addr)) < 0) {
                            perror("inet_pton");
                        }
                        slen = sizeof(sendin);
                        if((ret = sendto(send_sock, buffer, len+14, 0, (struct sockaddr *)&sendin, slen)) < 0){
                            perror("meshudp sendto error");
                        } else {
//                            fgM = true;
//                            puts("meshudp sendto success\n");
                        }
                    }
                }
            }
            close(udp_sock);
        } else {
//            puts("LTE Device not found\n");
            sleep(1);
        }
    }

}
//线程四：路由接收UDP 并修改路由结构体
void *routegetlte(/*void *arg*/) {
    short int gwlen;
    int ret;
    char ip[CHARIPLEN] = {0};
    struct sockaddr_in addr;																					//UDP地址结构
    addr.sin_family = AF_INET;
    addr.sin_port = htons(RTPORT);																				//路由端口

    int sock;

    char buff[BUFFER_MAX];
    struct sockaddr_in clientAddr;																				//用于保存客户机的地址信息 （端口，地址IP）
    memset(&clientAddr, 0, sizeof(clientAddr));
    socklen_t len = sizeof(clientAddr);
    for (;;) {
        memset(ip, 0, sizeof(ip));
        if (eth_ip(ETH_LTE, ip)) {
            if ((ret = inet_pton(AF_INET, ip, &addr.sin_addr.s_addr)) < 0) {
                perror("inet_pton");
                continue;
            }
            if ( (sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {															//创建UDP套接字
                perror("socket");
                continue;
            }
            if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {												//绑定UDP地址结构
                perror("bind");
                close(sock);
                continue;
            }
            memset(buff, 0, sizeof(buff));																				//初始化
            if ((ret = recvfrom(sock, buff, BUFFER_MAX, 0, (struct sockaddr*)&clientAddr, &len)) < 0) {					//接收消息
                perror("recvfrom");
                close(sock);
                continue;
            }
           if (strcmp(buff, GW) == 0) {																			//判断是否来请求“网关表”的
                gwlen = sizeof(struct user) * gwlist.total + sizeof(gwlist.total);
                memcpy(buff, &gwlist, gwlen);																		//拷贝“网关表”进缓存数组
                len = sizeof(clientAddr);
                ret = sendto(sock, buff, gwlen, 0, (struct sockaddr *)&clientAddr, len); 			//发回 发送端IP的指定端口
                if (ret < 0) {
                    perror("sendto");
                    close(sock);
                    continue;
                }
            }
            close(sock);
        } else {
//            fprintf(stdout, "LTE Device not found\n");
            sleep(1);
        }
    }
    return 0;
}
//线程5：路由接收meshUDP 并修改路由结构体
void *routegetmesh(/*void *arg*/) {
    int i, ret, index;
    int flag = 0;
//    long tmp = 0;
    socklen_t len = 0;
    char ip[CHARIPLEN];
    struct rt rtmesh[42];																						//路由缓存信息
    struct sockaddr_in addr;																					//UDP地址结构
    addr.sin_family = AF_INET;
    addr.sin_port = htons(RTPORT);																				//路由端口

    for (;;) {
        if (eth_ip(ETH_MESH, ip)) {
            if ((ret = inet_pton(AF_INET, ip, &addr.sin_addr.s_addr)) < 0) {
                perror("inet_pton");
                continue;
            }
            break;
        } else {
            sleep(1);
        }
    }

    int sock;
    if ( (sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {															//创建UDP套接字
        perror("socket");
        exit(-1);
    }
    len = sizeof(addr);
    if (bind(sock, (struct sockaddr *)&addr, len) < 0) {												//绑定UDP地址结构
        perror("bind");
        exit(-1);
    }
    char buff[BUFFER_MAX];
    struct sockaddr_in clientAddr;																				//用于保存客户机的地址信息 （端口，地址IP）
    memset(&clientAddr, 0, sizeof(clientAddr));


    for (;;) {
        len = sizeof(clientAddr);
        memset(buff, 0, sizeof(buff));																				//初始化
        if ((ret = recvfrom(sock, buff, BUFFER_MAX, 0, (struct sockaddr*)&clientAddr, &len)) < 0) {					//接收消息
            perror("recvfrom");
            continue;
        }

        memset(ip, 0, sizeof(ip));
        len = sizeof(ip);
        if (inet_ntop(AF_INET, (void *)&clientAddr.sin_addr, ip, len - 1) == NULL) {
            perror("inet_ntop");
        }                                                				//保留客户机MESHIP

        memcpy(&rtmesh, buff, sizeof(rtmesh));                           //拷贝发送来的路由表进路由缓存
        /*if ((ret = inet_pton(AF_INET, ip, &tmp)) < 0) {
            perror("inet_pton");
            continue;
        }*/
        index = (clientAddr.sin_addr.s_addr>>24) & 0xff;                                                                    //保存索引
        pthread_mutex_lock(&mutexrtlist);																									//检查互斥量
        rtlist[index].net = LTE;																				//更新路由信息                                                                                                            //释放互斥量
        for (i = 0; i < 42; i++) {
            if ((rtmesh[i].status != rtlist[i].status) && (rtmesh[i].net == LTE)/* (rtlist[i].net != LTE)*//* && (i != index)*/) {														//遍历路由缓存 检查发来的路由信息中																					//检查互斥量
                rtlist[i].net = LTE;																			//更新路由信息
                rtlist[i].status = true;
                memcpy(rtlist[i].gw, ip, sizeof(ip));															//释放互斥量
            }
        }
        pthread_mutex_unlock(&mutexrtlist);

        flag++;
        if (flag == 100) {
            flag = 0;
            pthread_mutex_lock(&mutexrtlist);
            for (i = 0; i < 42; i++) {
                rtlist[i].status = false;
                rtlist[i].net = MESH;
            }
            getroute(rtlist);
            pthread_mutex_unlock(&mutexrtlist);
        }

    }
    return 0;
}
//线程6：路由genxin
void *routereload(/*void *arg*/) {
    //bianliang
    char ip[CHARIPLEN], buff[BUFFER_MAX];
    struct sockaddr_in addr_ser, addr/*_lte, addr_mesh*/;
    int ret, i, j, k, index, tmp;
    struct timeval nNetTimeout;
    bool flag;
    short int total;
    socklen_t len = 0;

    struct GWLIST getgw; 								//获取到的“网关表”
    struct rt rtcache[42];								//处理时的路由表缓存
    struct GWLIST gwcache;								//本机“网关表”

    int sock = 0;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) <0) {      //创建UDP套接字
        perror("sock_ser");
        exit(0);
    }

    memset(&addr_ser, 0, sizeof(addr_ser));				//初始化
    memset(&addr, 0, sizeof(addr));


    memset(&nNetTimeout, 0, sizeof(nNetTimeout));
    nNetTimeout.tv_sec = 90; //90s
    nNetTimeout.tv_usec = 0;

    if ((setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&nNetTimeout, sizeof(nNetTimeout))) < 0) {     //recvfrom delay
        perror("setsockopt");
    }

    addr_ser.sin_family = AF_INET;								//对UDP地址结构处理  （用于对LTE活动用户请求）
    addr_ser.sin_port = htons(LTESER);							//LTE服务端口

    if ((ret = inet_pton(AF_INET, LTESERIP, &addr_ser.sin_addr.s_addr)) < 0) {             //LTE服务地址
        perror("inet_pton");
    }
    addr.sin_family = AF_INET;									//对UDP地址结构处理  （用于对路由信息的交换）
    addr.sin_port = htons(RTPORT);

    for (;;) {
//        initrtcache(rtcache);												    //初始化路由缓存表
        memset(rtcache, 0,sizeof(rtcache));
        memset(ip, 0, sizeof(ip));
        for (i = 0; i < 42; i++) {
            sprintf(ip, "%s%d", MESHIPHD, i);
            rtcache[i].index = (char)i;
            strcpy(rtcache[i].dest, ip);
        }

        getroute(rtcache);														//获取本机mesh地址

        if (eth_ip(ETH_LTE, ip)) {												//判断LTE是否拨号成功
//            pthread_mutex_lock(&mutexsock);
//            if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) <0) {      //创建UDP套接字
//                perror("sock_ser");
//                pthread_mutex_unlock(&mutexsock);
//                continue;
//            }
//            pthread_mutex_unlock(&mutexsock);
            memset(buff, 0, sizeof(buff));										//初始化 缓存数组
            strcpy(buff, USER);													//复制 LTE活动用户请求
            len = sizeof(addr_ser);
            if( (ret = sendto(sock, buff, strlen(USER) + 1, 0, (struct sockaddr *)&addr_ser, len)) < 0){   //向LTE服务发出请求
                perror("sendto");
//                pthread_mutex_lock(&mutexsock);
//                close(sock);
//                pthread_mutex_unlock(&mutexsock);
                sleep(1);
                continue;
            } else {
//                puts("sendto success");
            }

            memset(buff, 0, sizeof(buff));      								//初始化 缓存
            if( (ret = recvfrom(sock, buff, BUFFER_MAX, 0, NULL, NULL)) < 0) {					//等待LTE服务回复活动用户表
                perror("recvfrom");
//                pthread_mutex_lock(&mutexsock);
//                close(sock_routereload);
//                pthread_mutex_unlock(&mutexsock);
                sleep(1);
                continue;
            } else {
//                puts("recvfrom success");
            }
            pthread_mutex_lock(&mutexltelist);															//检查互斥量
            memset(&ltelist, 0, sizeof(ltelist));								//初始化 LTE活动用户列表
            ltelist.total = *(short int *)buff;									//储存LTE活动用户列表
            memcpy(ltelist.list, buff + sizeof(ltelist.total), sizeof(struct user) * ltelist.total);
            pthread_mutex_unlock(&mutexltelist);																//释放互斥量
            //debug
//            printf("ltetotal:%d\n", ltelist.total);
//            for (i = 0; i < ltelist.total; i++) {
//                if (strcmp(ltelist.list[i].ip, ip) == 0) {
//                    pthread_mutex_lock(&mutexltelist);
//                    ltelist.list[i].status = false;
//                    pthread_mutex_unlock(&mutexltelist);
//                } else {
//                printf("status:%d ; index:%d ; ip:%s\n",(int)ltelist.list[i].status,(int)ltelist.list[i].index, ltelist.list[i].ip);
//                }
//                printf("status:%d ; index:%d ; ip:%s\n",(int)ltelist.list[i].status,(int)ltelist.list[i].index, ltelist.list[i].ip);
//            }
            //debug ********************************** ok
            for (i = 0; i < ltelist.total; i++) {                                     //更新路由缓存
                index = (int)ltelist.list[i].index;
                memcpy(rtcache[index].gw, ltelist.list[i].ip, sizeof(ltelist.list[i].ip) - 1);      	//将LTE活动用户对应的MESHIP用户的下一跳改为LTEIP
                rtcache[index].net = LTE;															//将LTE活动用户所对应的meshIP 状态更改为LTE
                rtcache[index].status = true;       //使得本机route状态也变成了true                                                     //跨子网的时候使用
            }
            //debug ********************************** ok
            total = 0;
            memset(&gwcache, 0, sizeof(gwcache));
            for (i = 0; i < 42; i++) {																	//根据LTE活动用户构造“网关表”
                if ((rtcache[i].status == true) && (rtcache[i].net != LTE) ) {														//判断有效路由信息
                    if ((ret = inet_pton(AF_INET, rtcache[i].gw, &tmp)) < 0) {
                        perror("inet_pton");
                    }
                    index = (tmp>>24) & 0xff;
                    flag = true;
                    for (j = 0; j < ltelist.total; j++) {
                        if ((ltelist.list[j].status == true) && (index == (int)ltelist.list[j].index)) {
                            //除去本机LTEIP                        对比两个索引，找出与LTE活动用户不相同的路由信息
                            //sprintf(cache, "%s%d", MESHIPHD, (int)ltelist.list[j].index);					//找出LTE对应的MESHIP
                            flag = false;
                            break;
                        }
                    }
                    if (flag == true) {
                        gwcache.list[total].index = (char)i;												//构造“网关表”
                        gwcache.list[total].status = true;
                        memcpy(gwcache.list[total].ip ,rtcache[i].dest ,sizeof(rtcache[i].dest) - 1);           //ip为mesh
                        total++;
                    }
                }
            }
            gwcache.total = total;
            pthread_mutex_lock(&mutexgwlist);																				//检查互斥量
            memcpy(&gwlist, &gwcache, sizeof(gwcache));												//拷贝“网关表”
            pthread_mutex_unlock(&mutexgwlist);                        														//释放互斥量
            sleep(2);																				//休眠2秒（避免其他节点没有完成“网关表”）
            //debug
//            printf("gwtotal:%d\n", gwlist.total);
//            for (i = 0; i < gwlist.total; i++) {
//                printf("status:%d ; index:%d ; ip:%s\n",(int)gwlist.list[i].status,(int)gwlist.list[i].index, gwlist.list[i].ip);
//            }
            //debug  ****************************** ok
            len = sizeof(addr);
            for (i = 0; i < ltelist.total; i++) {													//向其他LTE用户请求“网关表”
                if (ltelist.list[i].status == true ) {                                             //除去本机LTEIP
                    if ((ret = inet_pton(AF_INET, ltelist.list[i].ip, &addr.sin_addr.s_addr)) < 0) {
                        perror("inet_pton");
                    }
                    memset(buff, 0, sizeof(buff));
                    strcpy(buff, GW);																	//拷贝 请求信息
                    if (ret = sendto(sock, buff, strlen(GW) + 1, 0, (struct sockaddr *)&addr, len) < 0) {  	//发出请求
                        perror("sendto");
                        sleep(1);
                        continue;
                    } else {
//                        puts("sendto success!\n");
                    }
                    memset(buff, 0, sizeof(buff));
                    if ((ret = recvfrom(sock, buff, BUFFER_MAX, 0, NULL, NULL)) < 0) {                          	//接收对应IP的“网关表”
                        perror("recvfrom");
                        sleep(1);
                        continue;
                    } else {
//                        puts("recvfrom success!\n");
                    }
                                                                                            //保存“网关表”
                    getgw.total = *(short int*)buff;
                    memcpy(getgw.list, buff + sizeof(getgw.total), sizeof(struct user) * getgw.total);							//
                    //debug
//                    printf("getgwtotal:%d\n",getgw.total);
//                    for (k = 0; k < getgw.total; k++) {
//                        printf("index:%d\nip:%s\n", (int)getgw.list[k].index, getgw.list[k].ip);
//                    }
                    //debug
                    for (k = 0; k < getgw.total; k++) {															//查看与本机“网关表”是否有冲突
                        for (j = 0; j < gwlist.total; j++) {
                            if (strcmp(gwlist.list[j].ip, getgw.list[k].ip) == 0) {                                 //mesh ip
                                goto next;																			//如果有冲突 跳过本次请求 进行下一个LTE“网关表”请求
                            }
                        }
                    }
                    for (j = 0; j < getgw.total; j++) {																//如果没有冲突，进行路由更新
                        if ((rtcache[(int)getgw.list[j].index].net != LTE)) { //判断net状态	LTE 表示已经更新过路由 跳过更新！
                            rtcache[(int)getgw.list[j].index].status = true;
                            strcpy(rtcache[(int)getgw.list[j].index].gw, ltelist.list[i].ip);										//（先到先得机制 更新路由 避免重复更新）
                            rtcache[(int)getgw.list[j].index].net = LTE;															//更新时将更新的路由信息 net状体改为LTE
                        }

                    }
next:               continue;
                }
            }

            pthread_mutex_lock(&mutexrtlist);                                                                   //检查互斥量
            for (i = 0; i < 42; i++) {
                if ((rtcache[i].status == rtlist[i].status) && (rtcache[i].net != rtlist[i].net)) {
                    if (rtcache[i].net == LTE) {         //节点LTE加入
                        rtlist[i].net = LTE;
                        memcpy(rtlist[i].gw, rtcache[i].gw, sizeof(rtlist[i].gw) - 1);
                    } else if ((rtlist[i].net == LTE) ) {   //节点LTE离开
                        rtlist[i].net = MESH;
                        memcpy(rtlist[i].gw, rtcache[i].gw, sizeof(rtlist[i].gw) - 1);
                    }
                } else if (rtcache[i].status != rtlist[i].status) {
                    if (rtcache[i].status == true) {         //新节点加入
                        rtlist[i].status = true;
                        rtlist[i].net = rtcache[i].net;
                        memcpy(rtlist[i].gw, rtcache[i].gw, sizeof(rtlist[i].gw) - 1);
                    } else if ((rtlist[i].status == true) && (rtlist[i].net == MESH)) {   //旧节点离开
                        rtlist[i].status = false;
                    }
                }
            }
            pthread_mutex_unlock(&mutexrtlist);                                                                     //释放互斥量

            memcpy(buff, rtlist, sizeof(rtlist));										//拷贝路由表进缓存数组
            len = sizeof(addr);
            for (i = 0; i < gwlist.total; i++) {										//向“网关表”的用户发送路由信息（mesh）
                if ((ret = inet_pton(AF_INET, gwlist.list[i].ip, &addr.sin_addr.s_addr)) < 0) {
                    perror("inet_pton");
                }
                    //mesh ip
                if (ret = sendto(sock, buff, sizeof(rtlist), 0, (struct sockaddr *)&addr, len) < 0) {
                    perror("sendto");
                    sleep(1);
                    continue;
                } else {
//                    puts("sendto success!\n");
                }
            }
//            pthread_mutex_lock(&mutexsock);
//            close(sock);
//            pthread_mutex_unlock(&mutexsock);
        } else {
            //mesh route
            pthread_mutex_lock(&mutexrtlist);                                                                   //检查互斥量
            for (i = 0; i < 42; i++) {
                if (rtcache[i].status != rtlist[i].status) {
                    if (rtcache[i].status == true) {         //新MESH节点加入
                        rtlist[i].status = true;
                        rtlist[i].net = MESH;
                        memcpy(rtlist[i].gw, rtcache[i].gw, sizeof(rtlist[i].gw) - 1);
                    } else if ((rtlist[i].status == true) && (rtlist[i].net == MESH)) {   //旧MESH节点离开
                        rtlist[i].status = false;
                    }
                } else if ((rtlist[i].status == true) && (rtlist[i].net == LTE)) {
                    if (memcmp(rtlist[i].gw, LTEIPHD, sizeof(LTEIPHD)) == 0) {
                        rtlist[i].status = false;
                        rtlist[i].net = MESH;
                    }
                }
            }
            pthread_mutex_unlock(&mutexrtlist);                                                                 //释放互斥量
        }
        //debug
        for (i = 0; i < 42; i++) {
            printf("route :: index: %d ; dest: %s ; gw: %s ; status : %d ;net : %d;\n",(int)rtlist[i].index,
                   rtlist[i].dest, rtlist[i].gw, (int)rtlist[i].status, (int)rtlist[i].net);
        }
        //debug
        sleep(3);
    }
    return 0;
}
//线程7：deng
void *LED(/*void *arg*/) {
//    char ip[CHARIPLEN] = {0};
    for (;;) {
//        if (fgL) {
//            digitalWrite(LEDL, 1);
//            delay(300);
//            digitalWrite(LEDL, 0);
//        } else if (fgM) {
//            digitalWrite(LEDM, 1);
//            delay(300);
//            digitalWrite(LEDM, 0);
//        }
//        fgM = false;
//        fgL = false;
        usleep(300000);
    }
    return 0;
}

//主函数
int main(){
//    wiringPiSetup();                                                              //init gpio
//    pinMode(LEDL, OUTPUT);
//    pinMode(LEDM, OUTPUT);
//    digitalWrite(LEDM, 1);  //设置为高电平


    pthread_t trawsocket, tmeshudp, tlteudp, troutegetlte, troutegetmesh, troutereload, tled;
    pthread_mutex_init(&mutexgwlist, NULL);
    pthread_mutex_init(&mutexltelist, NULL);
    pthread_mutex_init(&mutexrtlist, NULL);

    sleep(5);

//    initrtcache(rtlist);                                                                //init
    memset(rtlist, 0, sizeof(rtlist));
    char ip[16] = {0};
    int i;
    for (i = 0; i < 42; i++) {
        sprintf(ip, "%s%d", MESHIPHD, i);
        rtlist[i].index = (char)i;
        strcpy(rtlist[i].dest, ip);
    }
    getroute(rtlist);
    memset(&gwlist, 0, sizeof(gwlist));
    memset(&ltelist, 0, sizeof(ltelist));

    // 创建线程
    if(pthread_create(&trawsocket, NULL, rawsocket, NULL) == -1){
        puts("fail to create pthread t1");
        exit(1);
    }

    if(pthread_create(&tmeshudp, NULL, meshudp, NULL) == -1){
        puts("fail to create pthread t2");
        exit(1);
    }

    if(pthread_create(&tlteudp, NULL, lteudp, NULL) == -1){
        puts("fail to create pthread t3");
        exit(1);
    }

    if(pthread_create(&troutegetlte, NULL, routegetlte, NULL) == -1){
        puts("fail to create pthread t4");
        exit(1);
    }

    if(pthread_create(&troutegetmesh, NULL, routegetmesh, NULL) == -1){
        puts("fail to create pthread t5");
        exit(1);
    }

    if(pthread_create(&troutereload, NULL, routereload, NULL) == -1){
        puts("fail to create pthread t6");
        exit(1);
    }

    if(pthread_create(&tled, NULL, LED, NULL) == -1){
        puts("fail to create pthread t7");
        exit(1);
    }

    //join thread end
    void * result;
    if(pthread_join(trawsocket, &result) == -1){
        puts("fail to recollect t1");
        exit(1);
    }

    if(pthread_join(tmeshudp, &result) == -1){
        puts("fail to recollect t2");
        exit(1);
    }

    if(pthread_join(tlteudp, &result) == -1){
        puts("fail to recollect t3");
        exit(1);
    }

    if(pthread_join(troutegetlte, &result) == -1){
        puts("fail to recollect t4");
        exit(1);
    }

    if(pthread_join(troutegetmesh, &result) == -1){
        puts("fail to recollect t5");
        exit(1);
    }

    if(pthread_join(troutereload, &result) == -1){
        puts("fail to recollect t6");
        exit(1);
    }

    if(pthread_join(tled, &result) == -1){
        puts("fail to recollect t7");
        exit(1);
    }

    return 0;
}

