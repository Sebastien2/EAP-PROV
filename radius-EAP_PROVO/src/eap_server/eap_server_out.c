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
#include "eap_common/eap_out_common.h"
#include "tncs.h"



#ifndef EAP_OUT_VERSION
#define EAP_OUT_VERSION 0x1
#endif



struct eap_out_data {
	enum { INIT, INNER_EAP, SUCCESS, FAILURE } state;
	int out_version;
	int client_wants_config_data;

    enum { START, ONGOING, FINISHED } inner_state;
    const struct eap_method *phase2_method;
    void *phase2_priv;
    struct eap_method_ret * ret;
    struct wpabuf *pending_inner_eap_resp;

    bool authentication_done;
    bool provisioning_done;
    enum eap_type authentication_type;
    enum eap_type provisioning_type;

    u8 * key;
    size_t key_len;
    bool can_encrypt;
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
    
	data->state = state;
    wpa_printf(MSG_INFO, "\033[0;35m EAP-oPROV \033[0m switching to state %s", eap_out_state_txt(data->state));
            
}


static void * eap_out_init(struct eap_sm *sm)
{
    //wpa_printf(MSG_INFO, "PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct eap_out_data *data;

	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	data->state = INIT;

    data->key_len=64;
    data->key = os_malloc(data->key_len);
	if (data->key == NULL)
		return NULL;
    os_memset(data->key, 0x11, data->key_len / 2);
	os_memset(data->key + data->key_len / 2, 0x22, data->key_len / 2);
    data->authentication_done=false;
    data->provisioning_done=false;
    data->can_encrypt=false;

	return data;
}


static void eap_out_reset(struct eap_sm *sm, void *priv)
{
    //wpa_printf(MSG_INFO, "PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct eap_out_data *data = priv;
	os_free(data);
}


enum eap_type eap_out_select_next_inner_eap_method(struct eap_sm *sm, struct eap_out_data *data)
{
    enum eap_type next_eap_type = EAP_TYPE_NONE;
    enum eap_type authentication_types[3]={EAP_TYPE_TTLS, EAP_TYPE_TEST, EAP_TYPE_TEAP};
    enum eap_type provisioning_types[1]={EAP_TYPE_PROV};
    if(!data->authentication_done)
    {
        next_eap_type=authentication_types[0];
        data->authentication_type=next_eap_type;
    }
    else if(!data->provisioning_done)
    {
        next_eap_type=provisioning_types[0];
        data->provisioning_type=next_eap_type;
    }
    


    return next_eap_type;
}



static int eap_out_phase2_eap_init(struct eap_sm *sm, struct eap_out_data *data, int vendor, enum eap_type eap_type)
{
	//wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	if (data->phase2_priv && data->phase2_method) {
		data->phase2_method->reset(sm, data->phase2_priv);
		data->phase2_method = NULL;
		data->phase2_priv = NULL;
	}
	data->phase2_method = eap_server_get_eap_method(vendor, eap_type);
	if (!data->phase2_method)
		return -1;

	sm->init_phase2 = 1;
	data->phase2_priv = data->phase2_method->init(sm);
	sm->init_phase2 = 0;
	return data->phase2_priv == NULL ? -1 : 0;
}


static struct wpabuf * eap_out_buildReq_init(struct eap_sm *sm, struct eap_out_data *data, u8 id)
{
    //wpa_printf(MSG_INFO, "PERSO: %s : %s", __FILE__,  __FUNCTION__);

    struct wpabuf * resp, * innerResp;
    char * inner_server_name="zeus";
    int inner_server_name_len=4;
    innerResp=eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_IDENTITY, inner_server_name_len, EAP_CODE_REQUEST, id);
    //wpa_hexdump_buf(MSG_INFO, "\nEAP-OUT: inner EAP Response", innerResp);
    for(int i=0; i<inner_server_name_len;i++)
    {
        wpabuf_put_u8(innerResp, inner_server_name[i]);
    }
    //wpa_printf(MSG_INFO, "PERSO: inner EAP built");
    //then we put the inner eap in the outer eap message
    //wpa_hexdump_buf(MSG_INFO, "\nEAP-OUT: inner EAP Response", innerResp);
    resp=eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_OUT, 4+innerResp->used, EAP_CODE_REQUEST, id);
    //wpa_hexdump_buf(MSG_INFO, "\nEAP-OUT: inner EAP Response", resp);
    eap_out_put_tlv(resp, OUT_TLV_EAP, innerResp->buf, innerResp->used);
    //wpa_hexdump_buf(MSG_INFO, "\nEAP-OUT: inner EAP Response", resp);
    return resp;
}


static struct wpabuf * eap_out_buildReq_phase2_method_eap(struct eap_sm *sm, struct eap_out_data *data, u8 id)
{
    //wpa_printf(MSG_INFO, "PERSO: %s : %s", __FILE__,  __FUNCTION__);

    struct wpabuf * resp, * innerResp;
    if(data->inner_state==START) //TODO we start a new method, determine the rules for selecting a new method
    {
        int next_vendor = EAP_VENDOR_IETF;
        enum eap_type next_eap_type = EAP_TYPE_NONE;
        
        next_eap_type=eap_out_select_next_inner_eap_method(sm, data);
        if(next_eap_type!=EAP_TYPE_NONE)
        {
            if(eap_out_phase2_eap_init(sm, data, next_vendor, next_eap_type))
            {
                wpa_printf(MSG_DEBUG, "EAP-OUT: Failed to initialize EAP type %u:%u",  next_vendor, next_eap_type);
                eap_out_state(data, FAILURE);
                return  NULL;
            }
        }
        /* default srategy of selecting the next EAP method
        if (sm->user && sm->user_eap_method_index < EAP_MAX_METHODS && sm->user->methods[sm->user_eap_method_index].method != EAP_TYPE_NONE) {
                next_vendor = sm->user->methods[sm->user_eap_method_index].vendor;
                next_eap_type = sm->user->methods[sm->user_eap_method_index++].method;
                wpa_printf(MSG_DEBUG, "EAP-OUT: try EAP type %u:%u", next_vendor, next_eap_type);
            if(eap_out_phase2_eap_init(sm, data, next_vendor, next_eap_type))
            {
                wpa_printf(MSG_DEBUG, "EAP-OUT: Failed to initialize EAP type %u:%u",  next_vendor, next_eap_type);
                eap_out_state(data, FAILURE);
                return  NULL;
            }
        }
        */
        else
        {
            wpa_printf(MSG_DEBUG, "PERSO: no new inner method to try");
        }
        if(data->phase2_priv==NULL)
        {
            wpa_printf(MSG_INFO, "PERSO: phase2_priv is NULL");
        }
        if(data->phase2_method==NULL)
        {
            wpa_printf(MSG_INFO, "PERSO: phase2_method name is NULL");
        }
        if(data->phase2_method->name==NULL)
        {
            wpa_printf(MSG_INFO, "PERSO: phase2_method->name is NULL");
        }
        wpa_printf(MSG_INFO, "\033[0;35m EAP-oPROV \033[0m: Inner method building: %s", data->phase2_method->name);
    }

    //Creating message of inner method
    innerResp = data->phase2_method->buildReq(sm, data->phase2_priv, id);
	if (innerResp == NULL)
		return NULL;

    bool encrypt=true; //TODO:activate encryption

    wpa_hexdump_buf_key(MSG_DEBUG, "EAP-OUT/EAP: Encapsulate Inner data", innerResp);
    struct wpabuf tlv_buf, encrypted_buf, decrypted_buf;
    //wpa_printf(MSG_INFO, "PERSO: describing buffer: %d %d", innerResp->used, innerResp->size);
    
    tlv_buf.buf=os_malloc(innerResp->used+4);
    tlv_buf.size=innerResp->used+4;
    tlv_buf.used=0;
    //wpa_printf(MSG_INFO, "blob 1");
    eap_out_put_tlv(&tlv_buf, OUT_TLV_EAP, innerResp->buf, innerResp->used);
    if(data->can_encrypt && encrypt) //TODO: choose when to encrypt
    {
        //Encrypting inner message
        wpa_printf(MSG_INFO, "\033[0;35m EAP-oPROV \033[0m: Encrypting inner EAP message in phase 2");
        eap_out_tlv_encrypt(&tlv_buf, &encrypted_buf, data->key);
        //eap_out_tlv_decrypt(&encrypted_buf, &decrypted_buf, data->key);

        //wpa_printf(MSG_INFO, "buf->used=%d buf->size=%d", innerResp->used, innerResp->size);
        resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_OUT, 4+encrypted_buf.used, EAP_CODE_REQUEST, id);
        eap_out_put_tlv(resp, OUT_TLV_ENCRYPTED, encrypted_buf.buf, encrypted_buf.used);
    }
    else
    {
        resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_OUT, 4+innerResp->used, EAP_CODE_REQUEST, id);
        eap_out_put_tlv(resp, OUT_TLV_EAP, innerResp->buf, innerResp->used);
    }
    
	if (resp == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-OUT/EAP: Failed to encapsulate packet");
		return NULL;
	}

    return resp;
}



static struct wpabuf * eap_out_buildReq(struct eap_sm *sm, void *priv, u8 id)
{
    //wpa_printf(MSG_INFO, "PERSO: %s : %s", __FILE__,  __FUNCTION__);

	struct eap_out_data *data = priv;
	struct wpabuf *req;

	switch (data->state) {
    case INIT:
        data->inner_state=START;
        //wpa_printf(MSG_INFO, "PERSO: state %s", eap_out_state_txt(data->state));
        
        req=eap_out_buildReq_init(sm, data, id);
        break;

    case INNER_EAP:
        //wpa_printf(MSG_INFO, "PERSO: state %s mark 1", eap_out_state_txt(data->state));
        req=eap_out_buildReq_phase2_method_eap(sm, data, id);
        break;
    case SUCCESS:
        //wpa_printf(MSG_INFO, "PERSO: state %s", eap_out_state_txt(data->state));
        return NULL;
        break;

    case FAILURE:
        //wpa_printf(MSG_INFO, "PERSO: state %s", eap_out_state_txt(data->state));
        return NULL;
        break;
    default:
        wpa_printf(MSG_ERROR, "PERSO: state unknown: %s", eap_out_state_txt(data->state));
        return NULL;
    }
    if (req == NULL) {
		wpa_printf(MSG_ERROR, "EAP-OUT: Failed to allocate memory for request, state=%s", eap_out_state_txt(data->state));
		return NULL;
	}
	
	return req;
}


static bool eap_out_check(struct eap_sm *sm, void *priv,
				  struct wpabuf *respData)
{
    //wpa_printf(MSG_INFO, "PERSO: %s : %s", __FILE__,  __FUNCTION__);
	const u8 *pos;
	size_t len;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_OUT, respData, &len);
	if (pos == NULL || len < 1) {
		wpa_printf(MSG_INFO, "EAP-OUT: Invalid frame");
		return true;
	}

	return false;
}













int eap_out_process_inner_eap(struct eap_sm *sm, struct eap_out_data *data, struct wpabuf *respData)
{
    //wpa_printf(MSG_INFO, "PERSO: %s : %s", __FILE__,  __FUNCTION__);


	struct wpabuf buf;
	const struct eap_method *m = data->phase2_method;
	void *priv = data->phase2_priv;

	if (priv == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-OUT/EAP: %s - Phase2 not initialized?!", __func__);
		return -1;
	}

	//Else we check the message
	wpabuf_set(&buf, (respData->buf), (respData->used));

	if (m->check(sm, priv, &buf)) {
		wpa_printf(MSG_DEBUG, "EAP-OUT/EAP: Phase2 check() asked to ignore the packet");
		return -1;
	}

	//we process the message
	m->process(sm, priv, &buf);


	if (!m->isDone(sm, priv))
    {
        //wpa_printf(MSG_ERROR, "\033[0;35m EAP-oPROV \033[0m : inner isDone() failed");
        return -1;
    }
	
	if (!m->isSuccess(sm, priv)) {
		//wpa_printf(MSG_DEBUG, "EAP-OUT/EAP: Phase2 method failed");
		eap_out_state(data, FAILURE);
		return -1;
	}
    else
    {
        //wpa_printf(MSG_INFO, "PERSO: SUCCESS innner method reached");
        data->inner_state=FINISHED;
        return 1; //Success reached
    }

    return 0; //we should never reach this point
}





static void eap_out_process(struct eap_sm *sm, void *priv, struct wpabuf *respData)
{
    //wpa_printf(MSG_INFO, "PERSO: %s : %s", __FILE__,  __FUNCTION__);

	struct eap_out_data *data = priv;
	const u8 *pos;
	size_t len;

    int phase2_method_satus;



    /*
    wpa_printf(MSG_INFO, "\n\n\n\nPERSO: encryption testing");
    struct wpabuf encrypted_buf;
    struct wpabuf decrypted_buf;//=eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_OUT, 0, EAP_CODE_REQUEST, 1);
    //generating the key
    size_t key_len=64;
    u8 * key = os_malloc(key_len);
	if (key == NULL)
		return;
	os_memset(key, 0x11, key_len / 2);
	os_memset(key + key_len / 2, 0x22, key_len / 2);
    eap_out_tlv_encrypt(respData, &encrypted_buf,  key);
    eap_out_tlv_decrypt(&encrypted_buf, &decrypted_buf,  key);
    os_free(key);
    wpa_printf(MSG_INFO, "\n\n\n");
    */
    




	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_OUT, respData, &len);
	if (pos == NULL || len < 1)
		return;
	int nb_tlvs=eap_out_get_nb_tlvs(respData);
	struct eap_out_tlv tlvs[nb_tlvs];
	eap_out_parse_tlvs(respData, nb_tlvs, tlvs);
	//wpa_printf(MSG_INFO, "PERSO: nb TLVs=%d", nb_tlvs);
    //wpa_hexdump_buf(MSG_INFO, "\nEAP-OUT: EAP Response", respData);
    
    struct eap_out_tlv_parse tlv_parse;
    eap_out_parse_tlvs_step2(data->key, &tlv_parse, nb_tlvs, tlvs);

    switch(data->state) {
    case INIT:
        //wpa_printf(MSG_INFO, "PERSO: state %s position 2", eap_out_state_txt(data->state));
        //wpa_hexdump_buf(MSG_INFO, "\nEAP-OUT: inner EAP Response", tlv_parse.inner_eap);
        //we check we received an identity message
        if(tlv_parse.inner_eap==NULL)
        {
            //wpa_printf(MSG_INFO, "PERSO: received non-iinr EAP message, staying on INIT state");
            wpa_printf(MSG_INFO, "\033[0;35m EAP-oPROV \033[0m received non-inner EAP message, staying on INIT state");
            //we stay on INIT, to send abck an inner identity
        }
        else if(eap_get_type(tlv_parse.inner_eap)==EAP_TYPE_IDENTITY)
        {
            wpa_printf(MSG_INFO, "\033[0;35m EAP-oPROV \033[0m received inner identity message, chagne of state to %s", eap_out_state_txt(INNER_EAP));
            //wpa_printf(MSG_INFO, "PERSO: received inner identity message, chagne of state");
            eap_out_state(data, INNER_EAP);
        }
        else
        {
            //Error case
            wpa_printf(MSG_INFO, "\033[0;35m EAP-oPROV \033[0m received crap instead of inner identity message, chagne of state to FAILURE");
            //wpa_printf(MSG_INFO, "PERSO: received crap instead of inner identity message, chagne of state to FAILURE");
            eap_out_state(data, FAILURE);
        }
        break;
    
    case INNER_EAP:
        //wpa_printf(MSG_INFO, "PERSO: state %s", eap_out_state_txt(data->state));
        //we process the inner EAP
        
        if(eap_get_type(tlv_parse.inner_eap)==EAP_TYPE_NAK)
        {
            wpa_printf(MSG_INFO, "\033[0;35m EAP-oPROV \033[0m processing inner EAP method NAK message");
            //we get the list of methods requested in the message
            int nb_types=eap_out_get_nb_eap_types_in_nak(tlv_parse.inner_eap);
            enum eap_type types[nb_types];
            eap_out_get_eap_types_in_nak(nb_types, types, tlv_parse.inner_eap);
            if(nb_types==0)
            {
                eap_out_state(data, FAILURE);
            }
            else
            {
                data->phase2_method=eap_server_get_eap_method(EAP_VENDOR_IETF, types[0]); //TODO: if vendor is different, make it different + find the method compatible with server (see method choice for authentication & provisioning)
                eap_out_state(data, INNER_EAP);
            }
        }
        else if(eap_get_type(tlv_parse.inner_eap)==data->phase2_method->method)
        {
            //we can process the 1st message of the method
            wpa_printf(MSG_INFO, "\033[0;35m EAP-oPROV \033[0m processing inner EAP method %d message", eap_get_type(tlv_parse.inner_eap));
            
            data->inner_state=ONGOING;
            phase2_method_satus=eap_out_process_inner_eap(sm, data, tlv_parse.inner_eap);
            if(phase2_method_satus==1)
            {
                //TODO: if we want to execute another method, then we return on INNER_EAP with the new method
                if(data->inner_state==FINISHED)
                {
                    if(!data->authentication_done)
                    {
                        wpa_printf(MSG_INFO, "\033[0;35m EAP-oPROV \033[0m inner phase 1 for authentication done, switching to encrypted inner phase 2 method");
            
                        data->authentication_done=true;
                        data->inner_state=START;
                        //we get the key TODO
                        size_t len;
                        data->key=data->phase2_method->getKey(sm, data->phase2_priv, &len);
                        data->can_encrypt=true;
                    }
                    else if(!data->provisioning_done)
                    {
                        wpa_printf(MSG_INFO, "\033[0;35m EAP-oPROV \033[0m inner phase 2 for provisioning done");
            
                        data->provisioning_done=true;
                        eap_out_state(data, SUCCESS);
                    }
                    else
                    {
                        eap_out_state(data, SUCCESS);
                    }
                }
                
            }
            else
            {
                eap_out_state(data, INNER_EAP);
            }
        }
        break;
    case SUCCESS:
        //wpa_printf(MSG_INFO, "PERSO: state %s", eap_out_state_txt(data->state));
        break;
    case FAILURE:
        //wpa_printf(MSG_INFO, "PERSO: state %s", eap_out_state_txt(data->state));

        break;
    
    }
	
}







static bool eap_out_isDone(struct eap_sm *sm, void *priv)
{
    //wpa_printf(MSG_INFO, "PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct eap_out_data *data = priv;
	return data->state == SUCCESS;
}



static u8 * eap_out_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
    //wpa_printf(MSG_INFO, "PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct eap_out_data *data = priv;
	u8 *key=data->key;
	const int key_len = data->key_len;

	if (data->state != SUCCESS)
		return NULL;

	if (key == NULL)
		return NULL;

	*len = key_len;

	return key;
}


static bool eap_out_isSuccess(struct eap_sm *sm, void *priv)
{
    //wpa_printf(MSG_INFO, "PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct eap_out_data *data = priv;
	return data->state == SUCCESS;
}


int eap_server_out_register(void)
{
	//wpa_printf(MSG_INFO, "PERSO: %s : %s", __FILE__,  __FUNCTION__);

	struct eap_method *eap;

	eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION, EAP_VENDOR_IETF, EAP_TYPE_OUT, "OUT");
	if (eap == NULL)
		return -1;

	eap->init = eap_out_init;
	eap->reset = eap_out_reset;
	eap->buildReq = eap_out_buildReq;
	eap->check = eap_out_check;
	eap->process = eap_out_process;
	eap->isDone = eap_out_isDone;
	eap->getKey = eap_out_getKey;
	eap->isSuccess = eap_out_isSuccess;

	return eap_server_method_register(eap);
}
