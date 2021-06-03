/*
 * EAP peer method: Test method for vendor specific (expanded) EAP type
 * Copyright (c) 2005-2015, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * This file implements a vendor specific test method using EAP expanded types.
 * This is only for test use and must not be used for authentication since no
 * security is outided.
 */

#include "includes.h"

#include "common.h"
#include "crypto/sha1.h"
#include "crypto/random.h"
#include "eap_i.h"
#include "eloop.h"

#include "eap_tls_common.h"
#include "eap_common/eap_tlv_common.h"
#include "eap_common/eap_out_common.h"


#define EAP_VENDOR_ID EAP_VENDOR_HOSTAP
#define EAP_VENDOR_TYPE 0xfcfbfaf9



struct eap_out_data {
	enum { INIT, INNER_EAP, SUCCESS, FAILURE } state;
	int first_try;
	int test_pending_req;

    const struct eap_method *phase2_method;
	void *phase2_priv;
	int phase2_success;
	int phase2_start;
	EapDecision decision_succ;

	struct eap_method_type phase2_eap_type;
	struct eap_method_type *phase2_eap_types;
	size_t num_phase2_eap_types;

    u8 ident;
	u8 *session_id;
	size_t id_len;

    struct wpabuf *pending_phase2_req;
	struct wpabuf *pending_resp;

    u8 * key;
    size_t key_len;
    bool can_encrypt;

	int nb_inner_methods;
	int current_index_inner_method;
};




static const char * eap_out_state_txt(int state)
{
	switch (state) {
	case INIT:
		return "INIT";
	case INNER_EAP:
        return "INNER_EAP";
	case SUCCESS:
		return "SUCCESS";
	case FAILURE:
		return "FAILURE";
	default:
		return "?";
	}
}


static void eap_out_state(struct eap_out_data *data,
				  int state)
{
    //wpa_printf(MSG_INFO, "PERSO: %s : %s", __FILE__,  __FUNCTION__);
	//wpa_printf(MSG_DEBUG, "EAP-OUT: %s", eap_out_state_txt(data->state));
	data->state = state;

	wpa_printf(MSG_INFO, "\033[0;35m EAP-oPROV \033[0m in %s state", eap_out_state_txt(state));
}




static void * eap_out_init(struct eap_sm *sm)
{
    //wpa_printf(MSG_INFO, "PERSO: %s %s", __FILE__, __FUNCTION__);

	struct eap_out_data *data;
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

    data->key_len=64;
    data->key = os_malloc(data->key_len);
	if (data->key == NULL)
		return NULL;
    os_memset(data->key, 0x11, data->key_len / 2);
	os_memset(data->key + data->key_len / 2, 0x22, data->key_len / 2);
    data->can_encrypt=false;

	data->nb_inner_methods=2;
	data->current_index_inner_method=0;

	return data;
}


static void eap_out_deinit(struct eap_sm *sm, void *priv)
{
    //wpa_printf(MSG_INFO, "PERSO: %s %s", __FILE__, __FUNCTION__);

	struct eap_out_data *data = priv;
	os_free(data);
}



void eap_out_generate_nak(struct eap_sm *sm, struct eap_out_data *data, struct eap_hdr *hdr, struct wpabuf **resp)
{
    *resp=eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NAK, data->num_phase2_eap_types, EAP_CODE_RESPONSE, hdr->identifier);
    for(int i=0; i<data->num_phase2_eap_types;i++)
    {
        wpabuf_put_u8(*resp, data->phase2_eap_types[i].method);
    }
    return;
}




static int eap_out_phase2_eap_process(struct eap_sm *sm,
				       struct eap_out_data *data,
				       struct eap_method_ret *ret,
				       struct eap_hdr *hdr, size_t len,
				       struct wpabuf **resp)
{
    //wpa_printf(MSG_INFO, "PERSO: %s %s", __FILE__, __FUNCTION__);

	struct wpabuf msg;
	struct eap_method_ret iret;

	os_memset(&iret, 0, sizeof(iret));
	wpabuf_set(&msg, hdr, len);
	*resp = data->phase2_method->process(sm, data->phase2_priv, &iret, &msg);
	//wpa_printf(MSG_INFO, "\n\n\n PERSO: length in inner message: %d %d \n\n\n", (*resp)->used, (*resp)->size);
	if ((iret.methodState == METHOD_DONE ||
	     iret.methodState == METHOD_MAY_CONT) &&
	    (iret.decision == DECISION_UNCOND_SUCC ||
	     iret.decision == DECISION_COND_SUCC ||
	     iret.decision == DECISION_FAIL)) {
		ret->methodState = iret.methodState;
        ret->methodState = METHOD_MAY_CONT;  //allows the execution of successive inner EAP methods
		ret->decision = iret.decision;
        //wpa_printf(MSG_INFO, "PERSO: listing enum: %d %d %d %d %d", METHOD_DONE, METHOD_MAY_CONT, DECISION_UNCOND_SUCC, DECISION_COND_SUCC, DECISION_FAIL);
        //wpa_printf(MSG_INFO, "PERSO: updating ret variable: %d %d ", ret->methodState, ret->decision);
	}

	return 0;
}



static void eap_out_phase2_select_eap_method(struct eap_out_data *data, int vendor, enum eap_type method)
{
    //wpa_printf(MSG_INFO, "PERSO: %s %s", __FILE__, __FUNCTION__);

	size_t i;
	for (i = 0; i < data->num_phase2_eap_types; i++) {
		if (data->phase2_eap_types[i].vendor != vendor ||
		    data->phase2_eap_types[i].method != method)
			continue;

		data->phase2_eap_type.vendor =data->phase2_eap_types[i].vendor;
		data->phase2_eap_type.method =data->phase2_eap_types[i].method;
		wpa_printf(MSG_DEBUG, "EAP-OUT: Selected "
			   "Phase 2 EAP vendor %d method %d",
			   data->phase2_eap_type.vendor,
			   data->phase2_eap_type.method);
		break;
	}
}

static int eap_out_phase2_request_eap_method(struct eap_sm *sm,
					      struct eap_out_data *data,
					      struct eap_method_ret *ret,
					      struct eap_hdr *hdr, size_t len,
					      int vendor, enum eap_type method,
					      struct wpabuf **resp)
{
    //wpa_printf(MSG_INFO, "PERSO: %s %s %u %u", __FILE__, __FUNCTION__, vendor, method);

    

	if (data->phase2_eap_type.vendor == EAP_VENDOR_IETF &&
	    data->phase2_eap_type.method == EAP_TYPE_NONE)
		eap_out_phase2_select_eap_method(data, vendor, method);

    //We start a new EAP method
	if (data->phase2_priv == NULL) {
		data->phase2_method = eap_peer_get_eap_method(vendor, method);
		if (data->phase2_method) {
			sm->init_phase2 = 1;
			data->phase2_priv = data->phase2_method->init(sm);
			sm->init_phase2 = 0;

			//we put that in another function
			//data->current_index_inner_method+=1;
		}
	}

    //If the server starts a new inner EAP method
    if(data->phase2_eap_type.vendor == EAP_VENDOR_IETF && data->phase2_method->method!=method)
    {
        wpa_printf(MSG_INFO, "\033[0;35m EAP-oPROV \033[0m: reinitializing data inner method for new method: %d %s %d ", data->phase2_method->method, data->phase2_method->name, method);
        eap_out_phase2_select_eap_method(data, vendor, method);
        data->phase2_method = eap_peer_get_eap_method(vendor, method);
		if (data->phase2_method) {
			sm->init_phase2 = 1;
			data->phase2_priv = data->phase2_method->init(sm);
			sm->init_phase2 = 0;

			//we put that in another function
			//data->current_index_inner_method+=1;
		}
    }

	if (data->phase2_priv == NULL || data->phase2_method == NULL) {
        //the client sends a NAK with the list of methods supported
        eap_out_generate_nak(sm, data, hdr, resp);
		wpa_printf(MSG_INFO, "EAP-OUT: failed to initialize Phase 2 EAP method %u:%u", vendor, method);
		return -1;
	}

	return eap_out_phase2_eap_process(sm, data, ret, hdr, len, resp);
}


static int eap_out_phase2_request_eap(struct eap_sm *sm, struct eap_out_data *data, struct eap_method_ret *ret, enum eap_type reqType, struct eap_hdr *hdr, struct wpabuf **resp)
{
    //wpa_printf(MSG_INFO, "PERSO: %s %s", __FILE__, __FUNCTION__);

	size_t len = be_to_host16(hdr->length);

	if (len <= sizeof(struct eap_hdr)) {
		wpa_printf(MSG_INFO, "EAP-OUT: too short "
			   "Phase 2 request (len=%lu)", (unsigned long) len);
		return -1;
	}
	wpa_printf(MSG_DEBUG, "EAP-OUT: Phase 2 EAP Request: type=%u", reqType);

	switch (reqType) {
	case EAP_TYPE_IDENTITY:
		*resp = eap_sm_buildIdentity(sm, hdr->identifier, 1);
		break;
	default:
		if (eap_out_phase2_request_eap_method(sm, data, ret, hdr, len, EAP_VENDOR_IETF, reqType, resp) < 0)
		{
            wpa_printf(MSG_INFO, "PERSO: call eap_out_phase2_request_eap_method 2");
            return -1;
        }
		break;
	}

	if (*resp == NULL)
		return -1;

	wpa_hexdump_buf(MSG_DEBUG, "EAP-OUT: sending message", *resp);
	return 1;
}






struct wpabuf* eap_out_buildResp_init(struct eap_sm *sm, struct eap_out_data * data, u8 id)
{
    //wpa_printf(MSG_INFO, "PERSO: %s : %s", __FILE__,  __FUNCTION__);
    char * inner_server_name="pumba";
    int inner_server_name_len=5;
    struct wpabuf *resp, *innerResp;
    innerResp=eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_IDENTITY, inner_server_name_len, EAP_CODE_RESPONSE, id);
    
	for(int i=0; i< inner_server_name_len;i++)
    {
        wpabuf_put_u8(innerResp, inner_server_name[i]);
    }
	
    //wpa_printf(MSG_INFO, "PERSO: inner EAP built");
    //then we put the inner eap in the outer eap message
	//wpa_hexdump_buf(MSG_INFO, "\nEAP-OUT: inner EAP Response", innerResp);
    resp=eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_OUT, 4+innerResp->used, EAP_CODE_RESPONSE, id);
	//wpa_hexdump_buf(MSG_INFO, "\nEAP-OUT: inner EAP Response", resp);
    eap_out_put_tlv(resp, OUT_TLV_EAP, innerResp->buf, innerResp->used);
	//wpa_hexdump_buf(MSG_INFO, "\nEAP-OUT: inner EAP Response", resp);
    return resp;
}




static struct wpabuf * eap_out_process(struct eap_sm *sm, void *priv,
					       struct eap_method_ret *ret,
					       const struct wpabuf *reqData)
{
    //wpa_printf(MSG_INFO, "PERSO: %s %s", __FILE__, __FUNCTION__);
	
    struct eap_out_data *data = priv;
	struct wpabuf *reqData2, *resp;
	const u8 *pos;
	size_t len;
	reqData2=(struct wpabuf *)reqData;
    struct wpabuf *innerResp;  // message to send
    wpa_printf(MSG_INFO, "\033[0;35m EAP-oPROV \033[0m processing  message in step %d/%d", data->current_index_inner_method, data->nb_inner_methods);


    //Verifying the correctness of received message
	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_OUT, reqData, &len);
	if (pos == NULL || len < 1) {
		ret->ignore = true;
		return NULL;
	}
	if (data->state == SUCCESS) {
		wpa_printf(MSG_DEBUG, "EAP-OUT: Unexpected message in SUCCESS state");
		ret->ignore = true;
		return NULL;
	}

	/* Reading all TLVs */
    //pos = wpabuf_mhead(reqData2);
	int nb_tlvs=eap_out_get_nb_tlvs(reqData2);
	struct eap_out_tlv tlvs[nb_tlvs];
	int encrypted_content=eap_out_parse_tlvs(reqData2, nb_tlvs, tlvs);
	//wpa_printf(MSG_INFO, "PERSO: nb TLVs=%d", nb_tlvs);

	//update key if necessary TODO
	if(encrypted_content>0 && !data->can_encrypt)
	{
		size_t len;
		data->key=data->phase2_method->getKey(sm, data->phase2_priv, &len);
		data->key_len=len;
		data->can_encrypt=true;
	}

	ret->ignore = false;
	
	ret->allowNotifications = true;

    struct eap_out_tlv_parse tlv_parse;
    eap_out_parse_tlvs_step2(data->key, &tlv_parse, nb_tlvs, tlvs);

    /* Building response */
	int res;
	//Encrypting
    bool encrypt=true; //TODO:activate encryption


    switch(data->state){
    case INIT:
        //wpa_printf(MSG_INFO, "PERSO: state %s", eap_out_state_txt(data->state));

        if(tlv_parse.inner_eap==NULL)
        {
            //wpa_printf(MSG_INFO, "PERSO: received non-inner EAP message, staying on INIT state");
            //we stay on INIT, to send back an inner identity
        }
        else if(eap_get_type(tlv_parse.inner_eap)==EAP_TYPE_IDENTITY)
        {
            //wpa_printf(MSG_INFO, "PERSO: received inner identity message, change of state");
            resp=eap_out_buildResp_init(sm, data, eap_get_id(reqData));
			//wpa_hexdump_buf(MSG_INFO, "\nEAP-OUT: inner EAP Response", resp);
            eap_out_state(data, INNER_EAP);
        }
        else
        {
            //Error case
            //wpa_printf(MSG_INFO, "PERSO: received crap instead of inner identity message, chagne of state to FAILURE");
            eap_out_state(data, FAILURE);
        }
        break;
        
    case INNER_EAP:
        //wpa_printf(MSG_INFO, "PERSO: state %s", eap_out_state_txt(data->state));
        //we get the inner EAP buffer
        //wpa_printf(MSG_INFO, "PERSO: processing of a message of type=%d", tlv_parse.inner_eap_reqType);
        //wpa_hexdump_buf(MSG_DEBUG, "\nEAP-OUT: inner EAP Response", innerResp);
        res = eap_out_phase2_request_eap(sm, data, ret, tlv_parse.inner_eap_reqType, tlv_parse.hdr, &innerResp);

        //wpa_hexdump_buf_key(MSG_DEBUG, "EAP-OUT/EAP: Encapsulate Inner data", innerResp);
        struct wpabuf tlv_buf, encrypted_buf, decrypted_buf;
        //wpa_printf(MSG_INFO, "PERSO: describing buffer: %d %d", innerResp->used, innerResp->size);
        
        tlv_buf.buf=os_malloc(innerResp->used+4);
        tlv_buf.size=innerResp->used+4;
        tlv_buf.used=0;
        //wpa_printf(MSG_INFO, "blob 1");
        eap_out_put_tlv(&tlv_buf, OUT_TLV_EAP, innerResp->buf, innerResp->used);
        if(encrypt && data->can_encrypt)
        {
            //Encrypting inner message
            //wpa_printf(MSG_INFO, "EAP-OUT/EAP: Encrypting inner EAP msg");
            eap_out_tlv_encrypt(&tlv_buf, &encrypted_buf, data->key);
            //eap_out_tlv_decrypt(&encrypted_buf, &decrypted_buf, data->key);

            //wpa_printf(MSG_INFO, "buf->used=%d buf->size=%d", innerResp->used, innerResp->size);
            resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_OUT, 4+encrypted_buf.used, EAP_CODE_RESPONSE, eap_get_id(reqData));
            eap_out_put_tlv(resp, OUT_TLV_ENCRYPTED, encrypted_buf.buf, encrypted_buf.used);
			
        }
        else
        {
            resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_OUT, 4+innerResp->used, EAP_CODE_RESPONSE, eap_get_id(reqData));
            eap_out_put_tlv(resp, OUT_TLV_EAP, innerResp->buf, innerResp->used);
        }


		//Updating in the index of inner methods
		if(data->phase2_method->isKeyAvailable(sm, data->phase2_priv))
		{
			data->current_index_inner_method+=1;
		}
		//we check if we should switch to status success
		if(data->phase2_method->isKeyAvailable(sm, data->phase2_priv) && data->current_index_inner_method>=data->nb_inner_methods)
		{
			data->phase2_success=1;
			eap_out_state(data, SUCCESS);
		}

        
        //wpa_hexdump_buf(MSG_DEBUG, "\nEAP-OUT: EAP Response", innerResp);

        break;
    case SUCCESS:
        //wpa_printf(MSG_INFO, "PERSO: state %s", eap_out_state_txt(data->state));

        break;
    case FAILURE:
        //wpa_printf(MSG_INFO, "PERSO: state %s", eap_out_state_txt(data->state));

        break;
    default:
        //we initialize resp to failure
        break;
    }

	return resp;
}


static bool eap_out_isKeyAvailable(struct eap_sm *sm, void *priv)
{
	struct eap_out_data *data = priv;
	return data->state == SUCCESS;
}


static u8 * eap_out_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
	//wpa_printf(MSG_INFO, "PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct eap_out_data *data = priv;
	u8 *key=data->key;
	const int key_len = data->key_len;

	if ((data->state != SUCCESS))
		return NULL;

	if (key == NULL)
		return NULL;

	*len = key_len;

	return key;
}


int eap_peer_out_register(void)
{
    //wpa_printf(MSG_INFO, "\n Registering EAP_OUT %d \n", EAP_TYPE_OUT);
	struct eap_method *eap;

	eap = eap_peer_method_alloc(EAP_PEER_METHOD_INTERFACE_VERSION,
				    EAP_VENDOR_IETF, EAP_TYPE_OUT,
				    "OUT");
	if (eap == NULL)
		return -1;

	eap->init = eap_out_init;
	eap->deinit = eap_out_deinit;
	eap->process = eap_out_process;
	eap->isKeyAvailable = eap_out_isKeyAvailable;
	eap->getKey = eap_out_getKey;

	return eap_peer_method_register(eap);
}
