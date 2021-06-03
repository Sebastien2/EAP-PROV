/*
 * hostapd / Test method for vendor specific (expanded) EAP type
 * Copyright (c) 2005-2007, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */


#include "includes.h"

#include "common.h"
#include "crypto/sha1.h"
#include "crypto/tls.h"
#include "crypto/random.h"
#include "eap_i.h"
#include "eap_tls_common.h"
#include "eap_common/eap_tlv_common.h"
#include "eap_common/eap_prov_common.h"
#include "tncs.h"



#ifndef EAP_PROV_VERSION
#define EAP_PROV_VERSION 0x1
#endif

#define EAP_VENDOR_ID EAP_VENDOR_HOSTAP
#define EAP_VENDOR_TYPE 0xfcfbfaf9


struct eap_prov_data {
	enum { INIT, CONFIRM, SUCCESS, FAILURE } state;
	int prov_version;
	int client_wants_config_data;
};


static const char * eap_prov_state_txt(int state)
{
	switch (state) {
	case INIT:
		return "INIT";
	case CONFIRM:
		return "CONFIRM";
	case SUCCESS:
		return "SUCCESS";
	case FAILURE:
		return "FAILURE";
	default:
		return "?";
	}
}


static void eap_prov_state(struct eap_prov_data *data,
				  int state)
{
    //wpa_printf(MSG_INFO, "\nPERSO: %s : %s", __FILE__,  __FUNCTION__);
	//wpa_printf(MSG_DEBUG, "EAP-PROV: %s -> %s", eap_prov_state_txt(data->state), eap_prov_state_txt(state));
	data->state = state;
	wpa_printf(MSG_INFO, "\033[0;31m EAP-iPROV \033[0m: switching to status: %s", eap_prov_state_txt(data->state));
}


static void * eap_prov_init(struct eap_sm *sm)
{
    //wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct eap_prov_data *data;

	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	data->state = INIT;

	return data;
}


static void eap_prov_reset(struct eap_sm *sm, void *priv)
{
    //wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct eap_prov_data *data = priv;
	os_free(data);
}






void eap_prov_generate_config_file(struct eap_sm *sm)
{
	//wpa_printf(MSG_DEBUG, "\n\nStarting notification message building function\n\n");
	
	char username[sm->identity_len+1];
	uint i;
	for (i=0; i< sm->identity_len; i++)
	{
		username[i]= sm->identity[i];
	}
	username[sm->identity_len]=0;
	
	/* wpa_printf(MSG_DEBUG, "\n\nCreating the notification message\n\n"); */
	char * command_generate = os_calloc(256, sizeof(char));
	os_snprintf(command_generate, 256, "python3 /home/pi/radius/notification-message/generate_message.py '%s'", username);
	system(command_generate);
	os_free(command_generate);
	
}

static struct wpabuf * eap_prov_buildReq(struct eap_sm *sm, void *priv,
						u8 id)
{
    //wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);

	struct eap_prov_data *data = priv;
	struct wpabuf *req;
	int outer_tlv_len;
	
	//start = wpabuf_put(req, 0);

	switch (data->state) {
	case INIT:
	
		//wpa_printf(MSG_INFO, "PERSO: status INIT reactivity reached");
		outer_tlv_len=5;
		req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_PROV, outer_tlv_len, EAP_CODE_REQUEST, id);
		if (req == NULL) {
			wpa_printf(MSG_ERROR, "EAP-PROV: Failed to allocate memory for request");
			return NULL;
		}
		int version=1;
		eap_prov_put_tlv(req, PROV_TLV_VERSION, &version, 1);
		wpa_printf(MSG_INFO, "\033[0;31m EAP-iPROV \033[0m: sending message 1");
		break;


	case CONFIRM:
		eap_prov_generate_config_file(sm);
		wpa_printf(MSG_INFO, "\033[0;31m EAP-iPROV \033[0m: sending client tokens in message 2");
		struct wpabuf * buf = eap_prov_tlv_set_config_payload();
		req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_PROV, 4+buf->size, EAP_CODE_REQUEST, id);
		if (req == NULL) {
			wpa_printf(MSG_ERROR, "EAP-PROV: Failed to allocate memory for request");
			return NULL;
		}
		eap_prov_put_tlv(req, PROV_TLV_CONFIG_PAYLOAD, buf->buf, buf->size);



		//wpa_printf(MSG_INFO, "PERSO: status CONFIRM reactivity reached");
		break;
	case SUCCESS:
		//wpa_printf(MSG_INFO, "PERSO: status SUCCESS reactivity reached");
		return NULL;
		break;
	case FAILURE:
		//wpa_printf(MSG_INFO, "PERSO: status FAILURE reactivity reached");
		return NULL;
		break;
	default:
		wpa_printf(MSG_DEBUG, "EAP-PROV: %s - unexpected state %d", __func__, data->state);
		return NULL;
	}
	

	//end = wpabuf_put(req, 0);
	
	
	/*
	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_PROV, 1, EAP_CODE_REQUEST, id);
	wpabuf_put_u8(req, data->state == INIT ? 1 : 3);
	*/
	return req;
}


static bool eap_prov_check(struct eap_sm *sm, void *priv,
				  struct wpabuf *respData)
{
    //wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	const u8 *pos;
	size_t len;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_PROV, respData, &len);
	if (pos == NULL || len < 1) {
		wpa_printf(MSG_INFO, "EAP-PROV: Invalid frame");
		return true;
	}

	return false;
}





static void eap_prov_process(struct eap_sm *sm, void *priv,
				    struct wpabuf *respData)
{
    //wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);

	struct eap_prov_data *data = priv;
	const u8 *pos;
	size_t len;
	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_PROV, respData, &len);
	if (pos == NULL || len < 1)
		return;
	int nb_tlvs=eap_prov_get_nb_tlvs(respData);
	struct eap_prov_tlv tlvs[nb_tlvs];
	eap_prov_parse_tlvs(respData, nb_tlvs, tlvs);
	//wpa_printf(MSG_INFO, "PERSO: nb TLVs=%d", nb_tlvs);
	int returned_version=-1;
	int ack=-1;
	for (int i=0; i<nb_tlvs;i++)
	{
		//wpa_printf(MSG_INFO, "PERSO: TLV 2: type= %d, len=%d, content=%d", tlvs[i].type, tlvs[i].len, ((unsigned char*)respData)[tlvs[i].content_pos]);
		wpa_hexdump(MSG_DEBUG, "", wpabuf_mhead(tlvs[i].buf), wpabuf_len(tlvs[i].buf));
		if(tlvs[i].type==PROV_TLV_VERSION)
		{
			returned_version=tlvs[i].buf->buf[0];
		}
		
		if(tlvs[i].type==PROV_TLV_SUCCESS)
		{
			ack=1;
		}
		
	}
	if (data->state == INIT) {

		if(returned_version==EAP_PROV_VERSION)
		{
			eap_prov_state(data, CONFIRM);
		}
		else
		{
			eap_prov_state(data, FAILURE);
		}
		
	} else if (data->state == CONFIRM) {
		
		if(ack==1)
		{
			
			eap_prov_state(data, SUCCESS);
		}
		else
		{
			
			eap_prov_state(data, FAILURE);
		}
	} else
		eap_prov_state(data, FAILURE);
}


static bool eap_prov_isDone(struct eap_sm *sm, void *priv)
{
    //wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct eap_prov_data *data = priv;
	return data->state == SUCCESS;
}


static u8 * eap_prov_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
    //wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct eap_prov_data *data = priv;
	u8 *key;
	const int key_len = 64;

	if (data->state != SUCCESS)
		return NULL;

	key = os_malloc(key_len);
	if (key == NULL)
		return NULL;

	os_memset(key, 0x11, key_len / 2);
	os_memset(key + key_len / 2, 0x22, key_len / 2);
	*len = key_len;

	return key;
}


static bool eap_prov_isSuccess(struct eap_sm *sm, void *priv)
{
    //wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct eap_prov_data *data = priv;
	return data->state == SUCCESS;
}


int eap_server_prov_register(void)
{
	//wpa_printf(MSG_INFO, "PERSO: %s : %s", __FILE__,  __FUNCTION__);

	struct eap_method *eap;

	eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION,
				      EAP_VENDOR_IETF, EAP_TYPE_PROV,
				      "PROV");
	if (eap == NULL)
		return -1;

	eap->init = eap_prov_init;
	eap->reset = eap_prov_reset;
	eap->buildReq = eap_prov_buildReq;
	eap->check = eap_prov_check;
	eap->process = eap_prov_process;
	eap->isDone = eap_prov_isDone;
	eap->getKey = eap_prov_getKey;
	eap->isSuccess = eap_prov_isSuccess;

	return eap_server_method_register(eap);
}
