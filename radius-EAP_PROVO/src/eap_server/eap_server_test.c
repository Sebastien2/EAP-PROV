/*
 * hostapd / Test method for vendor specific (expanded) EAP type
 * Copyright (c) 2005-2007, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.

 Most basic EAP method for testing: only 1 mesasge exchange, 1 state, and 1 byte payload in each message
 */


#include "includes.h"

#include "common.h"
#include "eap_i.h"



#ifndef EAP_TEST_VERSION
#define EAP_TEST_VERSION 0x1
#endif



struct eap_test_data {
	enum { INIT, SUCCESS, FAILURE } state;
	int test_version;
};


static const char * eap_test_state_txt(int state)
{
	switch (state) {
	case INIT:
		return "INIT";
	case SUCCESS:
		return "SUCCESS";
	case FAILURE:
		return "FAILURE";
	default:
		return "?";
	}
}


static void eap_test_state(struct eap_test_data *data,
				  int state)
{
    //wpa_printf(MSG_INFO, " PERSO: %s : %s", __FILE__,  __FUNCTION__);
	//wpa_printf(MSG_DEBUG, " EAP-TEST: %s -> %s", eap_test_state_txt(data->state), eap_test_state_txt(state));
	data->state = state;
}


static void * eap_test_init(struct eap_sm *sm)
{
    //wpa_printf(MSG_INFO, " PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct eap_test_data *data;

	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	data->state = INIT;

	return data;
}


static void eap_test_reset(struct eap_sm *sm, void *priv)
{
    //wpa_printf(MSG_INFO, " PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct eap_test_data *data = priv;
	os_free(data);
}




static struct wpabuf * eap_test_buildReq(struct eap_sm *sm, void *priv,
						u8 id)
{
    //wpa_printf(MSG_INFO, " PERSO: %s : %s", __FILE__,  __FUNCTION__);

	struct eap_test_data *data = priv;
	struct wpabuf *req;

	
	//start = wpabuf_put(req, 0);

	switch (data->state) {
	case INIT:
		//wpa_printf(MSG_INFO, " PERSO: status INIT reactivity reached");
		req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_TEST, 1, EAP_CODE_REQUEST, id);
		if (req == NULL) {
			wpa_printf(MSG_ERROR, "EAP-TEST: Failed to allocate memory for request");
			return NULL;
		}
		wpabuf_put_u8(req, 6);
		break;
	case SUCCESS:
		//wpa_printf(MSG_INFO, " PERSO: status SUCCESS reactivity reached");
		return NULL;
		break;
	case FAILURE:
		//wpa_printf(MSG_INFO, " PERSO: status FAILURE reactivity reached");
		return NULL;
		break;
	default:
		wpa_printf(MSG_DEBUG, " EAP-TEST: %s - unexpected state %d", __func__, data->state);
		return NULL;
	}
	
	return req;
}


static bool eap_test_check(struct eap_sm *sm, void *priv,
				  struct wpabuf *respData)
{
    //wpa_printf(MSG_INFO, " PERSO: %s : %s", __FILE__,  __FUNCTION__);
	const u8 *pos;
	size_t len;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_TEST, respData, &len);
	if (pos == NULL || len < 1) {
		wpa_printf(MSG_INFO, " EAP-TEST: Invalid frame (len=%d)", len);
		return true;
	}

	return false;
}





static void eap_test_process(struct eap_sm *sm, void *priv,
				    struct wpabuf *respData)
{
    //wpa_printf(MSG_INFO, " PERSO: %s : %s", __FILE__,  __FUNCTION__);

	struct eap_test_data *data = priv;
	const u8 *pos;
	size_t len;
	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_TEST, respData, &len);
	if (pos == NULL || len < 1)
		return;
	
	if (data->state == INIT) 
    {
		eap_test_state(data, SUCCESS);
    } else {
		eap_test_state(data, FAILURE);
    }
}


static bool eap_test_isDone(struct eap_sm *sm, void *priv)
{
    //wpa_printf(MSG_INFO, " PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct eap_test_data *data = priv;
	return data->state == SUCCESS;
}


static u8 * eap_test_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
    //wpa_printf(MSG_INFO, " PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct eap_test_data *data = priv;
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


static bool eap_test_isSuccess(struct eap_sm *sm, void *priv)
{
    //wpa_printf(MSG_INFO, " PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct eap_test_data *data = priv;
	return data->state == SUCCESS;
}


int eap_server_test_register(void)
{
	//wpa_printf(MSG_INFO, "PERSO: %s : %s", __FILE__,  __FUNCTION__);

	struct eap_method *eap;

	eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION,
				      EAP_VENDOR_IETF, EAP_TYPE_TEST,
				      "TEST");
	if (eap == NULL)
		return -1;

	eap->init = eap_test_init;
	eap->reset = eap_test_reset;
	eap->buildReq = eap_test_buildReq;
	eap->check = eap_test_check;
	eap->process = eap_test_process;
	eap->isDone = eap_test_isDone;
	eap->getKey = eap_test_getKey;
	eap->isSuccess = eap_test_isSuccess;

	return eap_server_method_register(eap);
}
