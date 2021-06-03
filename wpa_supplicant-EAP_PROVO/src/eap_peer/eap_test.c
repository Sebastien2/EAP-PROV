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
#include "eap_i.h"
#include "eloop.h"



struct eap_test_data {
	enum { INIT, SUCCESS } state;
};


static void * eap_test_init(struct eap_sm *sm)
{
    //wpa_printf(MSG_INFO, "PERSO: %s %s", __FILE__, __FUNCTION__);

	struct eap_test_data *data;

	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	data->state = INIT;

	return data;
}


static void eap_test_deinit(struct eap_sm *sm, void *priv)
{
    //wpa_printf(MSG_INFO, "PERSO: %s %s", __FILE__, __FUNCTION__);
	struct eap_test_data *data = priv;
	os_free(data);
}



static struct wpabuf * eap_test_process(struct eap_sm *sm, void *priv,
					       struct eap_method_ret *ret,
					       const struct wpabuf *reqData)
{
    //wpa_printf(MSG_INFO, "PERSO: %s %s", __FILE__, __FUNCTION__);

	struct eap_test_data *data = priv;
	struct wpabuf *resp;
	const u8 *pos;
	size_t len;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_TEST, reqData, &len);
	if (pos == NULL || len < 1) {
		ret->ignore = true;
		return NULL;
	}
	
	if (data->state == SUCCESS) {
		wpa_printf(MSG_DEBUG, "EAP-TEST: Unexpected message in SUCCESS state");
		ret->ignore = true;
		return NULL;
	}
	
	ret->ignore = false;

	
	ret->allowNotifications = true;

	resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_TEST, 1, EAP_CODE_RESPONSE, eap_get_id(reqData));
	if (resp == NULL)
    {
        wpa_printf(MSG_INFO, "EAP-TEST: eap_msg_alloc fail");
        return NULL;
    }
	
	if (data->state == INIT) {
		wpabuf_put_u8(resp, 7);
		data->state = SUCCESS;
		ret->methodState = METHOD_CONT;
		ret->decision = DECISION_FAIL;
	}

	return resp;
}


static bool eap_test_isKeyAvailable(struct eap_sm *sm, void *priv)
{
	struct eap_test_data *data = priv;
	return data->state == SUCCESS;
}


static u8 * eap_test_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
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


int eap_peer_test_register(void)
{
    //wpa_printf(MSG_INFO, "\n Registering EAP_TEST %d \n", EAP_TYPE_TEST);
	struct eap_method *eap;

	eap = eap_peer_method_alloc(EAP_PEER_METHOD_INTERFACE_VERSION,
				    EAP_VENDOR_IETF, EAP_TYPE_TEST,
				    "TEST");
	if (eap == NULL)
		return -1;

	eap->init = eap_test_init;
	eap->deinit = eap_test_deinit;
	eap->process = eap_test_process;
	eap->isKeyAvailable = eap_test_isKeyAvailable;
	eap->getKey = eap_test_getKey;

	return eap_peer_method_register(eap);
}
