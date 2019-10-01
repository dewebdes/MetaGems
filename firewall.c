#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <stdint.h>
#include <limits.h>


void print_byte_as_bits(char val) {
  for (int i = 7; 0 <= i; i--) {
    printf("%c", (val & (1 << i)) ? '1' : '0');
  }
}

void print_bits(char * ty, char * val, unsigned char * bytes, size_t num_bytes) {
  printf("(%*s) %*s = [ ", 15, ty, 16, val);
  for (size_t i = 0; i < num_bytes; i++) {
    print_byte_as_bits(bytes[i]);
    printf(" ");
  }
  printf("]\n");
}

#define SHOW(T,V) do { T x = V; print_bits(#T, #V, (unsigned char*) &x, sizeof(x)); } while(0)


int main(int argc, char **argv) {
	int sock, n;
	char buffer[2048];
	char stak[65536];
	unsigned char *iphead, *ethhead;

	if ( (sock=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP)))<0) {
		perror("socket");
		exit(1);
	}

	while (1) {
		char sentence[65536];
		FILE *fptr;
		fptr = fopen("firelog.txt", "a");
		if(fptr == NULL)
		{
			printf("Error!");
			exit(1);
		}

		printf("----------\n");
		strcpy(sentence, "----------\n");
		n = recvfrom(sock,buffer,65536,0,NULL,NULL);
		printf("%d bytes read\n%s\n",n,buffer);

		int i=0;
		for(i=0;i<=sizeof(buffer)-1;i++){
			SHOW(int, buffer[i]);
			//SHOW(unsigned int, 17);
			//SHOW(long, 17);
			//SHOW(short, 17);
			//SHOW(uint32_t, 17);
			//SHOW(uint16_t, 17*256+18);
			//SHOW(uint16_t, htons(17*256+18));
			//SHOW(void*, &errno);
			//SHOW(unsigned int, 1 << 1);
		}

		sprintf (stak, "%d bytes read\n", n);
		strcat(sentence, stak);

		if (n<42) {
			perror("recvfrom():");
			printf("Incomplete packet (errno is %d)\n", errno);
			close(sock);
			exit(0);
		}

		ethhead = buffer;
		printf("Source MAC address: "
			   "%02x:%02x:%02x:%02x:%02x:%02x\n",
			   ethhead[0],ethhead[1],ethhead[2],
			   ethhead[3],ethhead[4],ethhead[5]);
		sprintf (stak, "Source MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", ethhead[0],ethhead[1],ethhead[2],ethhead[3],ethhead[4],ethhead[5]);
		strcat(sentence, stak);

		printf("Destination MAC address: "
			   "%02x:%02x:%02x:%02x:%02x:%02x\n",
			   ethhead[6],ethhead[7],ethhead[8],
			   ethhead[9],ethhead[10],ethhead[11]);
		sprintf (stak, "Destination MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", ethhead[6],ethhead[7],ethhead[8],ethhead[9],ethhead[10],ethhead[11]);
		strcat(sentence, stak);

		iphead = buffer+14; /* Skip Ethernet header */
		if (*iphead==0x45) { /* Double check for IPv4
				          * and no options present */
			printf("Source host %d.%d.%d.%d\n",
				     iphead[12],iphead[13],
				     iphead[14],iphead[15]);
			sprintf (stak, "Source host %d.%d.%d.%d\n", iphead[12],iphead[13],iphead[14],iphead[15]);
			strcat(sentence, stak);

			printf("Dest host %d.%d.%d.%d\n",
				     iphead[16],iphead[17],
				     iphead[18],iphead[19]);
			sprintf (stak, "Dest host %d.%d.%d.%d\n", iphead[16],iphead[17],iphead[18],iphead[19]);
			strcat(sentence, stak);

			printf("Source,Dest ports %d,%d\n",
				     (iphead[20]<<8)+iphead[21],
				     (iphead[22]<<8)+iphead[23]);
			sprintf (stak, "Source,Dest ports %d,%d\n", (iphead[20]<<8)+iphead[21],(iphead[22]<<8)+iphead[23]);
			strcat(sentence, stak);

			printf("Layer-4 protocol %d\n",iphead[9]);
			sprintf (stak, "Layer-4 protocol %d\n", iphead[9]);
			strcat(sentence, stak);



			fprintf(fptr,"%s", sentence);
			fclose(fptr);

		}
	}

}
