/*
 * EAP-PROV common helper functions (RFC 7170)
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
#include "eap_out_common.h"
#include "crypto/aes.h"




void eap_out_put_tlv_hdr(struct wpabuf *buf, u16 type, u16 len)
{
	struct out_tlv_hdr hdr;

	hdr.tlv_type = host_to_be16(type);
	hdr.length = host_to_be16(len);
	
	//wpa_printf(MSG_INFO, "PERSO: size hdr= %d", sizeof(hdr));
	wpabuf_put_data(buf, &hdr, sizeof(hdr));
	
}


void eap_out_put_tlv(struct wpabuf *buf, u16 type, const void *data, u16 len)
{
	eap_out_put_tlv_hdr(buf, type, len);
	//wpa_printf(MSG_INFO, "PERSO: size data= %d", len);
	wpabuf_put_data(buf, data, len);
	//wpa_printf(MSG_INFO, "PERSO: data added");
}


void eap_out_put_tlv_buf(struct wpabuf *buf, u16 type,
			  const struct wpabuf *data)
{
	eap_out_put_tlv_hdr(buf, type, wpabuf_len(data));
	wpabuf_put_buf(buf, data);
}




void eap_out_tlv_encrypt(struct wpabuf *buf, struct wpabuf * encrypted_buf, const u8 *key)
{
    u8 *pos;
    size_t left, size_encrypted;
    int nb_blocks;

    pos = wpabuf_mhead(buf);
	left = wpabuf_len(buf);
    //wpa_hexdump(MSG_INFO, "\nPERSO: intial content", pos, left);
	if(left%16==0)
    {
        size_encrypted=16*((left/16));
        nb_blocks=left/16;
    }
    else
    {
        size_encrypted=16*((left/16)+1);
        nb_blocks=(left/16)+1;
    }

    void * ctx=aes_encrypt_init(key, 32);
    encrypted_buf->buf=os_malloc(size_encrypted);
    encrypted_buf->used=size_encrypted;
    encrypted_buf->size=size_encrypted;
    
    for(int i=0;i<nb_blocks;i++)
    {
        int res=aes_encrypt(ctx, (buf->buf)+i*16, (encrypted_buf->buf)+i*16);
        if(res!=0)
        {
            wpa_printf(MSG_INFO, "EAP-OUT: encryption failure");
        }
    }
    
    pos = wpabuf_mhead(encrypted_buf);
	left = wpabuf_len(encrypted_buf);
	//wpa_hexdump(MSG_DEBUG, "\nPERSO: encrypted content", pos, left);

    return;
}

void eap_out_tlv_decrypt(struct wpabuf *buf, struct wpabuf * decrypted_buf, const u8 *key)
{
    u8 *pos;
    size_t left, size_decrypted;
    int nb_blocks;

    pos = wpabuf_mhead(buf);
	left = wpabuf_len(buf);
    //wpa_hexdump(MSG_INFO, "\nPERSO: encrypted content", pos, left);
	if(left%16==0)
    {
        size_decrypted=16*((left/16));
        nb_blocks=left/16;
    }
    else
    {
        size_decrypted=16*((left/16)+1);
        nb_blocks=(left/16)+1;
    }

    void * ctx=aes_decrypt_init(key, 32);
    decrypted_buf->buf=os_malloc(size_decrypted);
    decrypted_buf->used=size_decrypted;
    decrypted_buf->size=size_decrypted;
    for(int i=0;i<nb_blocks;i++)
    {
        int res=aes_decrypt(ctx, (buf->buf)+i*16, (decrypted_buf->buf)+i*16);
        if(res!=0)
        {
            wpa_printf(MSG_INFO, "EAP-OUT: decryption failure");
        }
    }

    int len=decrypted_buf->buf[2]*256+decrypted_buf->buf[3]+4;
    decrypted_buf->used=len;

    pos = wpabuf_mhead(decrypted_buf);
	left = wpabuf_len(decrypted_buf);
	//wpa_hexdump(MSG_DEBUG, "\nPERSO: decrypted content", pos, left);

    return;
}




const char * eap_out_tlv_type_str(enum out_tlv_types type)
{
	switch (type) {
    case OUT_TLV_ENCRYPTED:
        return "Encrypted";
	case OUT_TLV_RESULT:
		return "Result";
	case OUT_TLV_NAK:
		return "NAK";
    case OUT_TLV_EAP:
        return "EAP";
	case OUT_TLV_ERROR:
		return "Error";
	case OUT_TLV_CHANNEL_BINDING:
		return "Channel-Binding";
    case OUT_TLV_CONFIG_PAYLOAD:
        return "Config-Payload";
	case OUT_TLV_VERSION:
		return "Request-Version";
	case OUT_TLV_SUCCESS:
		return "EAP-Success";
	case OUT_TLV_FAILURE:
		return "EAP-Failure";
	}

	return "?";
}




int eap_out_get_version(struct wpabuf *buf)
{
    //TODO: parse the buffer to find the real version number
    return 1;
}



int eap_out_get_nb_tlvs(struct wpabuf *respData)
{
	int nb=0;
	u8 *pos;
	size_t left;
	int len;

	pos = wpabuf_mhead(respData);
	left = wpabuf_len(respData);
	
	//wpa_hexdump(MSG_DEBUG, "\nPERSO: TLVs", pos, left);
	int loc=5;
		
	while(loc<left)
	{
		//start new TLV
		if(left-loc<4)
		{
			wpa_printf(MSG_INFO, "EAP-OUT: Incorrect TLV: too short ERROR");
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

int eap_out_parse_tlvs(struct wpabuf *respData, int nb_tlvs, struct eap_out_tlv *tlvs)
{
	
	u8 *pos;
	size_t left;
	int index_tlv=0;
	int type, len;
	pos = wpabuf_mhead(respData);
	left = wpabuf_len(respData);
	
	//wpa_hexdump(MSG_DEBUG, "\nPERSO: TLVs", pos, left);
	int loc=5;
    int encrypted_content=0;
		
	while(loc<left && index_tlv<nb_tlvs)
	{
		//start new TLV
		if(left-loc<4)
		{
			wpa_printf(MSG_INFO, "EAP-OUT: Incorrect TLV: too short ERROR");
			return 0; //tolerance to malformed tlvs (ne error raised)
		}
		type=((unsigned char*)pos)[loc]*256+((unsigned char*)pos)[loc+1];
		loc+=2;
		len=(((unsigned char*)pos)[loc])*256+((unsigned char*)pos)[loc+1];
		loc+=2;
		//int content_pos=loc;
		tlvs[index_tlv].buf = wpabuf_alloc(len);
		for (int i=0; i<len;i++)
		{
			wpabuf_put_u8(tlvs[index_tlv].buf, ((unsigned char*)pos)[loc+i]);
			//content_tlv[i]=((unsigned char*)pos)[loc+i];
		}
		
		loc+=len;
		//wpa_printf(MSG_INFO, "PERSO: TLV: type= %d, len=%d, content=%d, buffer=", type, len, ((unsigned char*)pos)[content_pos]);
		//wpa_hexdump(MSG_DEBUG, "", wpabuf_mhead(tlvs[index_tlv].buf), wpabuf_len(tlvs[index_tlv].buf));

		if(type==OUT_TLV_ENCRYPTED)
        {
            encrypted_content+=1;
        }
		tlvs[index_tlv].type=type;
		tlvs[index_tlv].len=len;
		index_tlv+=1;
		

	}
    return encrypted_content;
	//return tlvs;
}


void eap_out_get_hdr(struct eap_out_tlv_parse *tlv_parse)
{
	
    u8 *pos;
    int left;
	
	pos = wpabuf_mhead(tlv_parse->inner_eap);
	left = wpabuf_len(tlv_parse->inner_eap);

    if(left<4)
    {
        wpa_printf(MSG_INFO, "EAP-OUT: Incorrect TLV: too short ERROR");
		return ;
    }
    tlv_parse->hdr=(struct eap_hdr *)pos;

	/*
    code=pos[0];
    id=pos[1];
    len=pos[2]*256+pos[3];

    hdr->code=code;
    hdr->identifier=id;
    hdr->length=len;
    */
    return;
}



void eap_out_parse_tlvs_step2(u8 * key, struct eap_out_tlv_parse *tlv_parse, int nb_tlvs, struct eap_out_tlv *tlvs)
{
    struct eap_out_tlv tlv;
    

    for(int i=0;i<nb_tlvs;i++)
    {
        tlv=tlvs[i];
        //wpa_printf(MSG_INFO, "PERSO: coomparision %d %d ", tlv.type, OUT_TLV_EAP);
        if(tlv.type==OUT_TLV_EAP)
        {
            //wpa_printf(MSG_INFO, "PERSO: OUT_TLV_EAP type");
            //wpa_printf(MSG_INFO, "TLV is not encrypted");
            tlv_parse->inner_eap=tlv.buf;
            tlv_parse->inner_eap_reqType=tlv.buf->buf[4];
            eap_out_get_hdr(tlv_parse);
            
        } else if(tlv.type==OUT_TLV_VERSION)
        {
            tlv_parse->version=eap_out_get_version(tlv.buf);
        } else if(tlv.type==OUT_TLV_SUCCESS)
        {
            tlv_parse->result=1;
        }
        else if(tlv.type==OUT_TLV_FAILURE)
        {
            tlv_parse->result=0;
        }
        else if(tlv.type==OUT_TLV_ENCRYPTED)
        {
            struct wpabuf decrypted_buf;
            //wpa_printf(MSG_INFO, "PERSO: TLV is encrypted");
            
            eap_out_tlv_decrypt(tlv.buf, &decrypted_buf, key);
            u8 * pos = wpabuf_mhead(&decrypted_buf);
	        size_t left = wpabuf_len(&decrypted_buf);
            //wpa_hexdump(MSG_DEBUG, "decrypted message:", pos, left);
            int loc=0;
            while(loc<left)
            {
                //start new TLV
                if(left-loc<4)
                {
                    wpa_printf(MSG_INFO, "EAP-OUT: Incorrect TLV after decryption : too short ERROR");
                    return; //tolerance to malformed tlvs (no error raised)
                }
                int type=((unsigned char*)pos)[loc]*256+((unsigned char*)pos)[loc+1];
                loc+=2;
                int len=(((unsigned char*)pos)[loc])*256+((unsigned char*)pos)[loc+1];
                loc+=2;
                //int content_pos=loc;
                tlv_parse->inner_eap = wpabuf_alloc(len);
                for (int i=0; i<len;i++)
                {
                    wpabuf_put_u8(tlv_parse->inner_eap, ((unsigned char*)pos)[loc+i]);
                }
                loc+=len;
                //wpa_hexdump(MSG_DEBUG, "decrypted message stored:", wpabuf_mhead(tlv_parse->inner_eap), wpabuf_len(tlv_parse->inner_eap));
                tlv_parse->inner_eap_reqType=tlv_parse->inner_eap->buf[4];
            }
            
            eap_out_get_hdr(tlv_parse);
        }
        //TODO: analyze other types of TLV
    }

    return;
}


int eap_out_get_nb_eap_types_in_nak(struct wpabuf * buf)
{
    int len=buf->buf[2]*256+buf->buf[3];
    int nb_types=len-5;
    return nb_types;
}


void eap_out_get_eap_types_in_nak(int nb_types, enum eap_type * types, struct wpabuf * buf)
{
    
    for(int i=0;i<nb_types;i++)
    {
        types[i]=buf->buf[5+i];
    }
    return;
}