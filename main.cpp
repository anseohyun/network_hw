#include <stddef.h> // for size_t
#include <stdint.h> // for uint8_t
#include <stdio.h> // for printf
#include <arpa/inet.h>

void dump(void* p, size_t n) {
	uint8_t* u8 = static_cast<uint8_t*>(p);
	size_t i = 0;
	while (true) {
		printf("%02X ", *u8++);
		if (++i >= n) break;
		if (i % 8 == 0)
			printf("\n");
	}
	printf("\n");
}


void write_4660() {
	uint16_t port = 4660; // 0x1234
	printf("port number = %d\n", port);
	dump(&port, sizeof(port));
}

uint16_t my_ntohs(uint16_t a)
{
	uint16_t a1 = (a & 0xFF00) >> 8;
	uint16_t a2 = (a & 0xFF00) << 8;
	
	a = a1 | a2;
	return a;	
	
}

void  write_0x1234() {
	uint8_t network_buffer[] = { 0x12, 0x34 };
	uint16_t* p = reinterpret_cast<uint16_t*>(network_buffer);
	uint16_t n = my_ntohs(*p); // TODO
	printf("16 bit number=0x%x\n", n);
}

uint32_t my_ntol(uint32_t a)
{
	uint32_t a1 = (a & 0xFF000000) >> 24;
	uint32_t a2 = (a & 0x00FF0000) >> 8;
	uint32_t a3 = (a & 0x0000FF00) << 8;
	uint32_t a4 = (a & 0x000000FF) << 24;
	
	return (a1|a2|a3|a4);
}

void  write_0x12345678() {
	uint8_t network_buffer[] = { 0x12, 0x34, 0x56, 0x78 };
	uint32_t* p = reinterpret_cast<uint32_t*>(network_buffer);
	uint32_t n = my_ntol(*p); // TODO
	printf("32 bit number=0x%x\n", n);
}

void hw()
{	
	    FILE* fStream1 = fopen("/home/seohyun/gilgil/five-hundred.bin", "rb"); 
	    FILE* fStream2 = fopen("/home/seohyun/gilgil/thousand.bin", "rb"); 
    
	    uint32_t szData1[50] = {0};
	    uint32_t szData2[50] = {0};

	    uint32_t fStream_1 = fread(szData1, sizeof(uint32_t), 50, fStream1);
	    uint32_t fStream_2 = fread(szData2, sizeof(uint32_t), 50, fStream2);

	    for (int i = 0; i < fStream_1; i++) {
		szData1[i] = ntohl(szData1[i]);
	    }

	    for (int i = 0; i < fStream_2; i++) {
		szData2[i] = ntohl(szData2[i]);
	    }

	    printf("%d(%x)+%d(%x)=%d(%x)", szData1[0], szData1[0], szData2[0], szData2[0], szData1[0] + szData2[0], szData1[0] + szData2[0]);

	    fclose(fStream1);
	    fclose(fStream2);
}

int main() {

	hw();	
	//write_4660();
	//write_0x1234();
	//write_0x12345678();
}
