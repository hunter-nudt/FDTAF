#include "qemu/osdep.h"
#include "shared/fdtaf-types-common.h"
#include <netinet/in.h>
#include "shared/fdtaf-tcpip-parser.h"


int match_http_data(uint8_t *data, uint8_t *url, int *http_head, int *http_len)
{
	uint8_t *data_ptr;
	FrameHeader_t *frame_header;
	IPHeader_t *ip_header;
	TCPHeader_t *tcp_header;
	int ip_len;
	uint8_t ip_proto;
	int http_len_t;
	int http_head_t;
    int i = 0;

	data_ptr = data;
	frame_header = (FrameHeader_t *)malloc(sizeof(FrameHeader_t));
	ip_header = (IPHeader_t *)malloc(sizeof(IPHeader_t));
	tcp_header = (TCPHeader_t *)malloc(sizeof(TCPHeader_t));

	memcpy(frame_header, data_ptr, sizeof(FrameHeader_t));
	data_ptr += sizeof(FrameHeader_t);
	memcpy(ip_header, data_ptr, sizeof(IPHeader_t));
	data_ptr += sizeof(IPHeader_t);
	memcpy(tcp_header, data_ptr, sizeof(TCPHeader_t));
	data_ptr += sizeof(TCPHeader_t);

	ip_proto = ip_header->protocol;
	if(ip_proto != 0x06) {
		return 0;
	}

	ip_len = ntohs(ip_header->total_len);
	http_len_t = ip_len - 40;
	http_head_t = 54;

	while (http_len_t != 0)
	{
		if (data_ptr[0] == 0x4F || data_ptr[0] == 0x48 || 
			data_ptr[0] == 0x43 || data_ptr[0] == 0x47 || 
			data_ptr[0] == 0x50 || data_ptr[0] == 0x44 ||
			data_ptr[0] == 0x54) {
			if (!strncmp((char *)data_ptr, "GET", 3) ||
				!strncmp((char *)data_ptr, "POST", 4) ||
				!strncmp((char *)data_ptr, "HEAD", 4) ||
				!strncmp((char *)data_ptr, "PUT", 3) ||
				!strncmp((char *)data_ptr, "OPTIONS", 7) ||
				!strncmp((char *)data_ptr, "DELETE", 6) ||
				!strncmp((char *)data_ptr, "TRACE", 5) ||
				!strncmp((char *)data_ptr, "CONNECT", 7)) {
				*http_head = http_head_t;
				*http_len = http_len_t;
				while (data_ptr[0] != 0x20) {
					data_ptr++;
				}
				data_ptr++;
				while (data_ptr[i] != 0x20) {
					url[i] = data_ptr[i];
                    i++;
				}
				return 1;
			}
			else {
				data_ptr++;
				http_len_t--;
				http_head_t++;
			}
		}
		else {
			data_ptr++;
			http_len_t--;
			http_head_t++;
		}
	}
	return 0;
}

int match_taint_data(uint8_t *data, int *taint_head, int *taint_len)
{
    uint8_t *data_ptr;
	FrameHeader_t *frame_header;
	IPHeader_t *ip_header;
	TCPHeader_t *tcp_header;
	int ip_len;
	int taint_len_t;
	int taint_head_t;

	data_ptr = data;
	frame_header = (FrameHeader_t *)malloc(sizeof(FrameHeader_t));
	ip_header = (IPHeader_t *)malloc(sizeof(IPHeader_t));
	tcp_header = (TCPHeader_t *)malloc(sizeof(TCPHeader_t));

	memcpy(frame_header, data_ptr, sizeof(FrameHeader_t));
	data_ptr += sizeof(FrameHeader_t);
	memcpy(ip_header, data_ptr, sizeof(IPHeader_t));
	data_ptr += sizeof(IPHeader_t);
	memcpy(tcp_header, data_ptr, sizeof(TCPHeader_t));
	data_ptr += sizeof(TCPHeader_t);

	ip_len = ntohs(ip_header->total_len);
	taint_len_t = ip_len - 40;
	taint_head_t = 54;

    while (taint_len_t != 0)
	{
        if (data_ptr[0] == 0x41 && data_ptr[1] == 0x64) {
            if (!strncmp((char *)data_ptr, "Addr=", 5)) {
                *taint_head = taint_head_t + 5;
				*taint_len = taint_len_t - 5;
                return 1;
            }
            else {
                data_ptr++;
				taint_len_t--;
				taint_head_t++;
            }
        }
        else {
            data_ptr++;
            taint_len_t--;
            taint_head_t++;
        }
    }
    return 0;
}