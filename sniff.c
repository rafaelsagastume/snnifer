#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

void proc_pacote(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main(int argc, char **argv){

	int i;
	char *disp;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	const u_char *packet;
	struct pcap_pkthdr hdr;
	struct ether_header *eptr;
	struct bpf_program fp;
	bpf_u_int32 maskp;
	bpf_u_int32 netp;

	if(argc != 2){

		fprintf(stdout, "Como usar: %s \"exprecao\"\n", argv[0]);
		return 0;

	}


	disp = pcap_lookupdev(errbuf);

	if(disp == NULL){

		fprintf(stderr, "Erro ao pegar o dispositivo: %s\n", errbuf);

	}

	printf("Dispositivo capturado: %s\n",disp);

	pcap_lookupnet(disp, &netp, &maskp, errbuf);

	descr = pcap_open_live(disp, BUFSIZ, 1, -1, errbuf);

	if(descr == NULL){

		printf("Erro ao capturar a interface: %s \n", errbuf);
		exit(1);

	}

	if(pcap_compile(descr, &fp, argv[1], 0, netp) == -1){

		//fprintf(stderr, "Erro ao chamar pcap_compile\n");
		printf("%s", pcap_geterr(descr));
		exit(1);

	}

	if(pcap_setfilter(descr, &fp) == -1){

		fprintf(stderr, "Erro ao setar o filtro da rede");

	}

	pcap_loop(descr, -1, proc_pacote, NULL);

	return 0;

}

void proc_pacote(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet){

	static int count = 1;
	fprintf(stdout, "%3d, ", count);
	fflush(stdout);
	count++;

}
