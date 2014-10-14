#include <stdio.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdlib.h>
//#include <netdb.h>
//#include <unistd.h>

unsigned int addrSrc;
unsigned int addrDst;
unsigned int portSrc;
unsigned int portDst;
char buffer[8192]; //tamaño maximo para un paquete IP

struct IpHeader {
 unsigned char hl:4, v:4; //hl:
 unsigned char tos;
 unsigned short int len; //longitud del header + data
 unsigned short int id; //id del datagrama
 unsigned short int offset; // flag y offset
 unsigned char ttl; // tiempo de vida
 unsigned char p; // tipo de protocolo
 unsigned short cksum; // checksum
 unsigned int src; // direccion origen
 unsigned int dst; //direccion destino
} *ipHeader;

struct IcmpHeader 
{
    unsigned char type;
    unsigned char code;
    unsigned short cksum;
    unsigned short id;
    unsigned short seq;
} *icmpHeader;


unsigned short checksum (unsigned short *packet, int num_palabras)
{
    unsigned int sum = 0;
    int i;
    for (sum = 0; num_palabras >0; num_palabras--)
        sum += *packet++;    
    sum = (sum >> 16) + (sum & 0xffff);
    return (unsigned short)~sum;
}



void makeIpHeader(struct IpHeader *ip, unsigned int src, unsigned int dst){    
    ip->v  = 4;
    ip->hl = 5;
    ip->tos = 0;
    ip->len = (unsigned int) ( sizeof(struct IpHeader) + sizeof(struct IcmpHeader) );
    ip->id = 0x1000;
    ip->offset = 0;
    ip->ttl = 64;
    ip->cksum = 0;
    ip->p = 1;
    ip->src = src;
    ip->dst = dst;
}

void makeIcmpHeader(struct IcmpHeader * icmp,unsigned char type,unsigned char code, unsigned short id, unsigned short seq){    
    icmp->type = 30;
    icmp->code = code;
    icmp->cksum = 0;
    icmp->id = id;
    icmp->seq = seq;
}

int main(int narg, char *args[]){

    /*if(narg < 5){
        printf("faltan argumentos\n");
        return 1; 
    }*/
    int sizeIP = sizeof(struct IpHeader);
    int sizeICMP = sizeof(struct IcmpHeader);    
    int sid,sent;
    int optval = 1;    
    struct IpHeader* ipHeader = (struct IpHeader*) buffer;
    struct IcmpHeader* icmpHeader = (struct IcmpHeader*) (buffer + sizeIP);
    struct sockaddr_in src, dst;
    
    //creando socket
    if((sid = socket (AF_INET, SOCK_RAW, IPPROTO_RAW))<0){
        printf("%s\n","error en creacion de socket");
        return -1;
    }

    //informando al kernel que nosotros crearemos los paquetes
    if(setsockopt(sid, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int)) < 0){
        printf("error al informar al kernel");
        return -1;        
    }

    addrSrc = inet_addr(args[1]);
    portSrc = atoi(args[2]);
    addrDst = inet_addr(args[3]);
    portDst = atoi(args[4]);

    //creando los headers
    makeIpHeader(ipHeader,addrSrc,addrDst); 
    makeIcmpHeader(icmpHeader,8,0,1,1);

    src.sin_family = AF_INET;    
    src.sin_addr.s_addr = addrSrc;
    src.sin_port = portSrc;  
    dst.sin_family = AF_INET;  
    dst.sin_addr.s_addr = addrDst;
    dst.sin_port = portDst;
    
    //agreagando checksum
    icmpHeader->cksum = checksum((unsigned short *)icmpHeader,sizeICMP/2);
    ipHeader->cksum = checksum((unsigned short *)ipHeader,(sizeIP+sizeICMP)/2);                

    //enviando paquete
    if((sent=sendto(sid, buffer, ipHeader->len , 0, (struct sockaddr *)&dst, sizeof(dst)))<0){
        printf("error a enviar\n");
    }

    while (1) {
     
    if ((sent = recvfrom(sid, buffer, sizeof(ipHeader), 0,
                      (struct sockaddr *) &src, sizeof(src))) < 0) {
      if (errno == EINTR)
        continue;
      perror("ping: recvfrom");
      continue;
    }
    if (sent >= 76) {                   /* ip + icmp */
      if (icmpHeader->type == 0)
        break;
    }
  }

    printf("%d bytes from %s to %s ttl=%d time=%d\n", sent,args[1],args[3],ipHeader->ttl,0);    
    return 0;
}
