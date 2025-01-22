#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>

#define PCAP_ERRBUF_SIZE 256

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <pcap file>\n", argv[0]);
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr *header;
    const u_char *packet;
    int packet_count = 0;
    int result;

    // Open the pcap file for offline processing
    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open file %s: %s\n", argv[1], errbuf);
        return -1;
    }

    printf("Reading packets from file: %s\n\n", argv[1]);

    // Loop through the packets using pcap_next_ex()
    while ((result = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (result == 0) {
            // Timeout elapsed (not applicable for offline files)
            continue;
        }

        printf("Packet %d:\n", ++packet_count);
        printf("  Timestamp: %ld.%ld seconds\n", header->ts.tv_sec, header->ts.tv_usec);
        printf("  Packet length: %u bytes\n", header->len);

        // Display the first few bytes of the packet data
        printf("  Data (first 16 bytes): ");
        for (int i = 0; i < 16 && i < header->len; i++) {
            printf("%02x ", packet[i]);
        }
        printf("\n\n");
    }

    if (result == -1) {
        fprintf(stderr, "Error reading the pcap file: %s\n", pcap_geterr(handle));
    }

    // Cleanup
    pcap_close(handle);
    printf("Finished reading packets.\n");

    return 0;
}