/*
 * EAP-prov common helper functions (RFC 7170)
 * Copyright (c) 2008-2019, sebastien.boire@huawei.com
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "crypto/sha384.h"
#include "crypto/tls.h"
#include "eap_defs.h"
#include "eap_prov_common.h"




void eap_prov_put_tlv_hdr(struct wpabuf *buf, u16 type, u16 len)
{
	struct prov_tlv_hdr hdr;

	hdr.tlv_type = host_to_be16(type);
	hdr.length = host_to_be16(len);
	
	//wpa_printf(MSG_INFO, "PERSO: size hdr= %d", sizeof(hdr));
	wpabuf_put_data(buf, &hdr, sizeof(hdr));
	
}


void eap_prov_put_tlv(struct wpabuf *buf, u16 type, const void *data, u16 len)
{
	eap_prov_put_tlv_hdr(buf, type, len);
	//wpa_printf(MSG_INFO, "PERSO: size data= %d", len);
	wpabuf_put_data(buf, data, len);
	//wpa_printf(MSG_INFO, "PERSO: data added");
}


void eap_prov_put_tlv_buf(struct wpabuf *buf, u16 type,
			  const struct wpabuf *data)
{
	eap_prov_put_tlv_hdr(buf, type, wpabuf_len(data));
	wpabuf_put_buf(buf, data);
}






int eap_prov_parse_tlv(struct eap_prov_tlv_parse *tlv,
		       int tlv_type, u8 *pos, size_t len)
{
	switch (tlv_type) {
	case PROV_TLV_IDENTITY_TYPE:
		if (len < 2) {
			wpa_printf(MSG_INFO,
				   "EAP-PROV: Too short Identity-Type TLV");
			tlv->result = PROV_STATUS_FAILURE;
			break;
		}
		tlv->identity_type = WPA_GET_BE16(pos);
		wpa_printf(MSG_DEBUG, "EAP-PROV: Identity-Type: %u",
			   tlv->identity_type);
		break;
	case PROV_TLV_RESULT:
		wpa_hexdump(MSG_MSGDUMP, "EAP-PROV: Result TLV", pos, len);
		if (tlv->result) {
			wpa_printf(MSG_INFO,
				   "EAP-PROV: More than one Result TLV in the message");
			tlv->result = PROV_STATUS_FAILURE;
			return -2;
		}
		if (len < 2) {
			wpa_printf(MSG_INFO, "EAP-PROV: Too short Result TLV");
			tlv->result = PROV_STATUS_FAILURE;
			break;
		}
		tlv->result = WPA_GET_BE16(pos);
		if (tlv->result != PROV_STATUS_SUCCESS &&
		    tlv->result != PROV_STATUS_FAILURE) {
			wpa_printf(MSG_INFO, "EAP-PROV: Unknown Result %d",
				   tlv->result);
			tlv->result = PROV_STATUS_FAILURE;
		}
		wpa_printf(MSG_DEBUG, "EAP-PROV: Result: %s",
			   tlv->result == PROV_STATUS_SUCCESS ?
			   "Success" : "Failure");
		break;
	case PROV_TLV_NAK:
		wpa_hexdump(MSG_MSGDUMP, "EAP-PROV: NAK TLV", pos, len);
		if (len < 6) {
			wpa_printf(MSG_INFO, "EAP-PROV: Too short NAK TLV");
			tlv->result = PROV_STATUS_FAILURE;
			break;
		}
		tlv->nak = pos;
		tlv->nak_len = len;
		break;
	case PROV_TLV_ERROR:
		if (len < 4) {
			wpa_printf(MSG_INFO, "EAP-PROV: Too short Error TLV");
			tlv->result = PROV_STATUS_FAILURE;
			break;
		}
		tlv->error_code = WPA_GET_BE32(pos);
		wpa_printf(MSG_DEBUG, "EAP-PROV: Error: %u", tlv->error_code);
		break;
	// case PROV_TLV_EAP_PAYLOAD:
	// 	wpa_hexdump(MSG_MSGDUMP, "EAP-PROV: EAP-Payload TLV",
	// 		    pos, len);
	// 	if (tlv->eap_payload_tlv) {
	// 		wpa_printf(MSG_INFO,
	// 			   "EAP-PROV: More than one EAP-Payload TLV in the message");
	// 		tlv->iresult = PROV_STATUS_FAILURE;
	// 		return -2;
	// 	}
	// 	tlv->eap_payload_tlv = pos;
	// 	tlv->eap_payload_tlv_len = len;
	// 	break;
	case PROV_TLV_VERSION:
		wpa_hexdump(MSG_MSGDUMP, "EAP-PROV: EAP-Version TLV", pos, len);
		tlv->version = WPA_GET_BE16(pos);
		break;
	case PROV_TLV_CONFIG_PAYLOAD:
		wpa_hexdump(MSG_MSGDUMP, "EAP-PROV: EAP-Config-Payload TLV", pos, len);
		if (tlv->eap_payload_tlv) {
			wpa_printf(MSG_INFO,"EAP-PROV: More than one EAP-Config-Payload TLV in the message");
			tlv->iresult = PROV_STATUS_FAILURE;
			return -2;
		}
		tlv->eap_payload_tlv = pos;
		tlv->eap_payload_tlv_len = len;
		break;
	case PROV_TLV_SUCCESS:
		tlv->result = PROV_STATUS_SUCCESS;
		break;
	case PROV_TLV_FAILURE:
		tlv->result = PROV_STATUS_FAILURE;
		break;
	default:
		/* Unknown TLV */
		return -1;
	}

	return 0;
}


const char * eap_prov_tlv_type_str(enum prov_tlv_types type)
{
	switch (type) {
	case PROV_TLV_AUTHORITY_ID:
		return "Authority-ID";
	case PROV_TLV_IDENTITY_TYPE:
		return "Identity-Type";
	case PROV_TLV_RESULT:
		return "Result";
	case PROV_TLV_NAK:
		return "NAK";
	case PROV_TLV_ERROR:
		return "Error";
	case PROV_TLV_CHANNEL_BINDING:
		return "Channel-Binding";
	case PROV_TLV_VENDOR_SPECIFIC:
		return "Vendor-Specific";
	case PROV_TLV_VERSION:
		return "Request-Version";
	case PROV_TLV_CONFIG_PAYLOAD:
		return "EAP-Config-Payload";
	case PROV_TLV_SUCCESS:
		return "EAP-Success";
	case PROV_TLV_FAILURE:
		return "EAP-Failure";
	}

	return "?";
}




struct wpabuf * eap_prov_tlv_set_config_payload()
{
	char message_file_path[]="/home/pi/radius/notification-message/notification-message.txt";
	struct wpabuf *buf;

	/*
	int len=4000;
	buf = wpabuf_alloc(len);
	for(int i=0;i<len;i++)
	{
		wpabuf_put_u8(buf, 6);
	}
	return buf;
	*/


	if(access( message_file_path, F_OK ) == 0  && access( message_file_path, R_OK) == 0)
	{
		FILE *file = fopen(message_file_path, "r");
		fseek(file, 0L, SEEK_END);
		size_t file_size = ftell(file);
		rewind(file);
		if(file_size > 1000)
		{
			buf = wpabuf_alloc(0);
			fclose(file);
			wpa_printf(MSG_ERROR, "The \"message.json\" file is too big!");
		}
		else
		{
			wpa_printf(MSG_DEBUG, "Reading the config message from \"message.json\" file");
			/* add couple of extra bytes to stay safe */
			buf = wpabuf_alloc(file_size + 5);
			fread(buf->buf, file_size, sizeof(char), file);
			fclose(file);
			
			wpa_hexdump_ascii(MSG_DEBUG, "The read content", buf->buf, file_size);
			buf->used = file_size;
				
			wpa_printf(MSG_DEBUG, "\n\nSize of file being sent: %d\n\n", file_size);
			
		}
	}
	else
	{
		buf = wpabuf_alloc(0);
	}
	return buf;
}



int eap_prov_get_nb_tlvs(struct wpabuf *respData)
{
	int nb=0;
	u8 *pos;
	size_t left;
	int len;

	pos = wpabuf_mhead(respData);
	left = wpabuf_len(respData);
	
	//wpa_hexdump(MSG_DEBUG, "\nPERSO: AVPs", pos, left);
	int loc=5;
		
	while(loc<left)
	{
		//start new TLV
		if(left-loc<4)
		{
			wpa_printf(MSG_INFO, "EAP-PROV: Incorrect TLV: too short ERROR");
			return -1;
		}
		loc+=2;
		len=((unsigned char*)pos)[loc]*256+((unsigned char*)pos)[loc+1];
		loc+=2;
		loc+=len;
		//wpa_printf(MSG_INFO, "PERSO: type= %d, len=%d, content=%s", type, len, content_tlv);
		nb+=1;

	}
	return nb;
}

struct eap_prov_tlv * eap_prov_parse_tlvs(struct wpabuf *respData, int nb_tlvs, struct eap_prov_tlv *tlvs)
{
	
	u8 *pos;
	size_t left;
	int index_tlv=0;
	int type, len;
	pos = wpabuf_mhead(respData);
	left = wpabuf_len(respData);
	
	//wpa_hexdump(MSG_DEBUG, "\nPERSO: AVPs", pos, left);
	int loc=5;
		
	while(loc<left && index_tlv<nb_tlvs)
	{
		//start new TLV
		if(left-loc<4)
		{
			wpa_printf(MSG_INFO, "EAP-PROV: Incorrect TLV: too short ERROR");
			return tlvs; //tolerance to malformed tlvs (ne error raised)
		}
		type=((unsigned char*)pos)[loc]*256+((unsigned char*)pos)[loc+1];
		loc+=2;
		len=((unsigned char*)pos)[loc]*256+((unsigned char*)pos)[loc+1];
		loc+=2;
		int content_pos=loc;
		tlvs[index_tlv].buf = wpabuf_alloc(len);
		for (int i=0; i<len;i++)
		{
			wpabuf_put_u8(tlvs[index_tlv].buf, ((unsigned char*)pos)[loc+i]);
			//content_tlv[i]=((unsigned char*)pos)[loc+i];
		}
		
		loc+=len;
		//wpa_printf(MSG_INFO, "PERSO: TLV: type= %d, len=%d, content=%d, buffer=", type, len, ((unsigned char*)pos)[content_pos]);
		wpa_hexdump(MSG_DEBUG, "", wpabuf_mhead(tlvs[index_tlv].buf), wpabuf_len(tlvs[index_tlv].buf));

		
		tlvs[index_tlv].type=type;
		tlvs[index_tlv].len=len;
		tlvs[index_tlv].content_pos=content_pos;
		index_tlv+=1;
		

	}
	return tlvs;
}



void get_configuration_data_from_tlv(struct eap_prov_tlv tlv, char * configuration_data)
{
	u8 * pos=wpabuf_mhead(tlv.buf);
	int l=wpabuf_len(tlv.buf);
	for(int i=0; i<l;i++)
	{
		configuration_data[i]=((unsigned char*)pos)[i];
	}

}