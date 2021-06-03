/*
 * EAP peer method: Test method for vendor specific (expanded) EAP type
 * Copyright (c) 2005-2015, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * This file implements a vendor specific test method using EAP expanded types.
 * This is only for test use and must not be used for authentication since no
 * security is provided.
 */

#include "includes.h"

#include "common.h"
#include "crypto/sha1.h"
#include "crypto/tls.h"
#include "crypto/random.h"
#include "eap_i.h"
#include "eloop.h"

#include "eap_tls_common.h"
#include "eap_common/eap_tlv_common.h"
#include "eap_common/eap_prov_common.h"


#include <pthread.h>


#define EAP_VENDOR_ID EAP_VENDOR_HOSTAP
#define EAP_VENDOR_TYPE 0xfcfbfaf9


struct eap_prov_data {
	enum { INIT, CONFIRM, SUCCESS } state;
	int first_try;
	int test_pending_req;
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
	default:
		return "?";
	}
}


static void eap_prov_state(struct eap_prov_data *data, int state)
{
    //wpa_printf(MSG_INFO, "PERSO: %s : %s", __FILE__,  __FUNCTION__);
	//wpa_printf(MSG_DEBUG, "EAP-PROV: %s", eap_prov_state_txt(data->state));
	data->state = state;

	wpa_printf(MSG_INFO, "\033[0;31m EAP-iPROV \033[0m in %s state", eap_prov_state_txt(state));
	
}



static void * eap_prov_init(struct eap_sm *sm)
{
    //wpa_printf(MSG_INFO, "PERSO: %s %s", __FILE__, __FUNCTION__);

	struct eap_prov_data *data;
	const u8 *password;
	size_t password_len;

	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	data->state = INIT;
	data->first_try = 1;

	password = eap_get_config_password(sm, &password_len);
	data->test_pending_req = password && password_len == 7 &&
		os_memcmp(password, "pending", 7) == 0;

	return data;
}


static void eap_prov_deinit(struct eap_sm *sm, void *priv)
{
    //wpa_printf(MSG_INFO, "PERSO: %s %s", __FILE__, __FUNCTION__);

	struct eap_prov_data *data = priv;
	os_free(data);
}


static void eap_vendor_ready(void *eloop_ctx, void *timeout_ctx)
{
    //wpa_printf(MSG_INFO, "PERSO: %s %s", __FILE__, __FUNCTION__);
    
	struct eap_sm *sm = eloop_ctx;
	wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: Ready to re-process pending request");
	eap_notify_pending(sm);
}


void *eap_prov_provision_and_config(void *args)
{
	//wpa_printf(MSG_INFO, "EAP-iPROV: config data: %s", (char *)args);

	char * command = (char *) args;
	char * command_provision = os_calloc(1024, sizeof(char));
	char * command_config = os_calloc(1024, sizeof(char));
	char * command_ping = os_calloc(1024, sizeof(char));

	//wpa_printf(MSG_INFO, "\033[0;31m");
	wpa_printf(MSG_INFO, "\033[0;31m########################################\n### EAP-iPROV received client tokens ###\n########################################\033[0m");
	wpa_printf(MSG_INFO, "%s", (char *)args);
	//wpa_printf(MSG_INFO, "\033[0m");
	
	//os_snprintf(command_ping, 1024, "%s", "python3 /home/pi/pinger.py");
	os_snprintf(command_provision, 1024, "python3 /home/pi/est-client-python/est_client.py '%s'", command);
	os_snprintf(command_config, 1024, "python3 /home/pi/config-server-client/config_client.py '%s'", command);

	// system(command_ping);
	system(command_provision);
	system(command_config);

	os_free(command_provision);
	os_free(command_config);
	os_free(command);

	return NULL;
}


void eap_prov_process_config_message(char * data, int len)
{
	wpa_printf(MSG_INFO, "\033[0;31mEAP-iPROV\033[0m: processing of config data %s", data);
	u8 * config_message = os_calloc(len, sizeof(u8));
	os_memcpy(config_message, data, len);
	pthread_t thread_id;
    pthread_create(&thread_id, NULL, eap_prov_provision_and_config, config_message); 
    pthread_detach(thread_id); 
}






static struct wpabuf * eap_prov_process(struct eap_sm *sm, void *priv,
					       struct eap_method_ret *ret,
					       const struct wpabuf *reqData)
{
    //wpa_printf(MSG_INFO, "PERSO: %s %s", __FILE__, __FUNCTION__);

	struct eap_prov_data *data = priv;
	struct wpabuf *resp, *reqData2;
	const u8 *pos;
	size_t len;
	reqData2=(struct wpabuf *)reqData;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_PROV, reqData, &len);
	if (pos == NULL || len < 1) {
		ret->ignore = true;
		return NULL;
	}
	
	if (data->state == SUCCESS) {
		wpa_printf(MSG_DEBUG, "EAP-PROV: Unexpected message in SUCCESS state");
		ret->ignore = true;
		return NULL;
	}
	
	if (data->state == CONFIRM) {
		if (data->test_pending_req && data->first_try) {
			data->first_try = 0;
			wpa_printf(MSG_DEBUG, "EAP-PROV: Testing pending request");
			ret->ignore = true;
			eloop_register_timeout(1, 0, eap_vendor_ready, sm,
					       NULL);
			return NULL;
		}
	}

	int config_data=-1;
	int returned_version=-1;
	pos = wpabuf_mhead(reqData2);
	//left = wpabuf_len(reqData2);

	int nb_tlvs=eap_prov_get_nb_tlvs(reqData2);
	struct eap_prov_tlv tlvs[nb_tlvs];
	eap_prov_parse_tlvs(reqData2, nb_tlvs, tlvs);
	//wpa_printf(MSG_INFO, "PERSO: nb TLVs=%d", nb_tlvs);
	
	if(data->state==INIT || data->state==CONFIRM)
	{	
		for (int i=0; i<nb_tlvs;i++)
		{
			//wpa_printf(MSG_INFO, "PERSO: TLV 2: type= %d, len=%d, content=%d", tlvs[i].type, tlvs[i].len, ((unsigned char*)reqData2)[tlvs[i].content_pos]);
			wpa_hexdump(MSG_DEBUG, "", wpabuf_mhead(tlvs[i].buf), wpabuf_len(tlvs[i].buf));
			if(tlvs[i].type==PROV_TLV_VERSION)
			{
				returned_version=tlvs[i].buf->buf[0];
			}
			if(tlvs[i].type==PROV_TLV_CONFIG_PAYLOAD)
			{
				config_data=i;
			}
		}
	}
	if(config_data>=0)
	{
		char configuration_data[tlvs[config_data].len];
		get_configuration_data_from_tlv(tlvs[config_data], configuration_data);
		//TODO: what to do with this message:store it in a file, call another program...
		wpa_printf(MSG_INFO, "\033[0;31mEAP-iPROV\033[0m: config data received: %s", configuration_data);
		eap_prov_process_config_message(configuration_data, tlvs[config_data].len);
	}


	ret->ignore = false;

	
	ret->allowNotifications = true;

	resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_PROV, 5, EAP_CODE_RESPONSE, eap_get_id(reqData));
	if (resp == NULL)
    {
        wpa_printf(MSG_INFO, "EAP-PROV: eap_msg_alloc fail");
        return NULL;
    }
	
	if (data->state == INIT) {
		int version=1;
		//TODO: if client does not want config_data, then version is set to 0
		if(returned_version<0 || version > returned_version)
		{
			version=0;
			wpa_printf(MSG_INFO, "EAP-PROV: incompatible versions");
			eap_prov_put_tlv(resp, PROV_TLV_VERSION, &version, 1);
		}
		else
		{
			eap_prov_put_tlv(resp, PROV_TLV_VERSION, &version, 1);
		}
		//wpabuf_put_u8(resp, 2);
		eap_prov_state(data, CONFIRM);
		//data->state = CONFIRM;
		ret->methodState = METHOD_CONT;
		ret->decision = DECISION_FAIL;
	} else if (data->state==CONFIRM){
		int ack;
		if(config_data>=0)
		{
			ack=1;
			eap_prov_put_tlv(resp, PROV_TLV_SUCCESS, &ack, 1);
			wpa_printf(MSG_INFO, "EAP-PROV: config_data received");
		}
		else
		{
			ack=0;
			eap_prov_put_tlv(resp, PROV_TLV_SUCCESS, &ack, 1);
			wpa_printf(MSG_INFO, "EAP-PROV: config_data NOT received");
		}
		//wpabuf_put_u8(resp, 4);
		//data->state = SUCCESS;
		eap_prov_state(data, SUCCESS);
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_UNCOND_SUCC;
	}

	return resp;
}


static bool eap_prov_isKeyAvailable(struct eap_sm *sm, void *priv)
{
	struct eap_prov_data *data = priv;
	return data->state == SUCCESS;
}


static u8 * eap_prov_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
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


int eap_peer_prov_register(void)
{
    //wpa_printf(MSG_INFO, "\n Registering EAP_PROV %d \n", EAP_TYPE_PROV);
	struct eap_method *eap;

	eap = eap_peer_method_alloc(EAP_PEER_METHOD_INTERFACE_VERSION,
				    EAP_VENDOR_IETF, EAP_TYPE_PROV,
				    "PROV");
	if (eap == NULL)
		return -1;

	eap->init = eap_prov_init;
	eap->deinit = eap_prov_deinit;
	eap->process = eap_prov_process;
	eap->isKeyAvailable = eap_prov_isKeyAvailable;
	eap->getKey = eap_prov_getKey;

	return eap_peer_method_register(eap);
}
