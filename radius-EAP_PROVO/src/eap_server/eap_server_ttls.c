/*
 * hostapd / EAP-TTLS (RFC 5281)
 * Copyright (c) 2004-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include <unistd.h>

#include "includes.h"

#include <unistd.h>
#include <stdio.h>

#include "common.h"
#include "utils/json.h"
#include "crypto/ms_funcs.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "crypto/tls.h"
#include "eap_server/eap_i.h"
#include "eap_server/eap_tls_common.h"
#include "eap_common/chap.h"
#include "eap_common/eap_ttls.h"


#define EAP_TTLS_VERSION 0


static void eap_ttls_reset(struct eap_sm *sm, void *priv);


struct eap_ttls_data {
	struct eap_ssl_data ssl;
	enum {
		START, PHASE1, PHASE2_START, PHASE2_METHOD,
		PHASE2_MSCHAPV2_RESP, SUCCESS, FAILURE
	} state;

	int ttls_version;
	const struct eap_method *phase2_method;
	void *phase2_priv;
	int mschapv2_resp_ok;
	u8 mschapv2_auth_response[20];
	u8 mschapv2_ident;
	struct wpabuf *pending_phase2_eap_resp;
	int tnc_started;
};


static const char * eap_ttls_state_txt(int state)
{
	switch (state) {
	case START:
		return "START";
	case PHASE1:
		return "PHASE1";
	case PHASE2_START:
		return "PHASE2_START";
	case PHASE2_METHOD:
		return "PHASE2_METHOD";
	case PHASE2_MSCHAPV2_RESP:
		return "PHASE2_MSCHAPV2_RESP";
	case SUCCESS:
		return "SUCCESS";
	case FAILURE:
		return "FAILURE";
	default:
		return "Unknown?!";
	}
}


static void eap_ttls_state(struct eap_ttls_data *data, int state)
{
	
	data->state = state;
	if (state == FAILURE)
		tls_connection_remove_session(data->ssl.conn);
	
	
	wpa_printf(MSG_INFO, "\033[0;36m EAP-TTLS \033[0m: switching to state %s", eap_ttls_state_txt(data->state));
}


static void eap_ttls_valid_session(struct eap_sm *sm,
				   struct eap_ttls_data *data)
{
	struct wpabuf *buf;

	if (!sm->cfg->tls_session_lifetime)
		return;

	buf = wpabuf_alloc(1 + 1 + sm->identity_len);
	if (!buf)
		return;
	wpabuf_put_u8(buf, EAP_TYPE_TTLS);
	if (sm->identity) {
		u8 id_len;

		if (sm->identity_len <= 255)
			id_len = sm->identity_len;
		else
			id_len = 255;
		wpabuf_put_u8(buf, id_len);
		wpabuf_put_data(buf, sm->identity, id_len);
	} else {
		wpabuf_put_u8(buf, 0);
	}
	tls_connection_set_success_data(data->ssl.conn, buf);
}


static u8 * eap_ttls_avp_hdr(u8 *avphdr, u32 avp_code, u32 vendor_id,
			     int mandatory, size_t len)
{
	struct ttls_avp_vendor *avp;
	u8 flags;
	size_t hdrlen;

	avp = (struct ttls_avp_vendor *) avphdr;
	flags = mandatory ? AVP_FLAGS_MANDATORY : 0;
	if (vendor_id) {
		flags |= AVP_FLAGS_VENDOR;
		hdrlen = sizeof(*avp);
		avp->vendor_id = host_to_be32(vendor_id);
	} else {
		hdrlen = sizeof(struct ttls_avp);
	}

	avp->avp_code = host_to_be32(avp_code);
	avp->avp_length = host_to_be32(((u32) flags << 24) |
				       ((u32) (hdrlen + len)));

	return avphdr + hdrlen;
}


static struct wpabuf * eap_ttls_avp_encapsulate(struct wpabuf *resp,
						u32 avp_code, int mandatory)
{
	struct wpabuf *avp;
	u8 *pos;

	avp = wpabuf_alloc(sizeof(struct ttls_avp) + wpabuf_len(resp) + 4);
	if (avp == NULL) {
		wpabuf_free(resp);
		return NULL;
	}

	pos = eap_ttls_avp_hdr(wpabuf_mhead(avp), avp_code, 0, mandatory,
			       wpabuf_len(resp));
	os_memcpy(pos, wpabuf_head(resp), wpabuf_len(resp));
	pos += wpabuf_len(resp);
	AVP_PAD((const u8 *) wpabuf_head(avp), pos);
	wpabuf_free(resp);
	wpabuf_put(avp, pos - (u8 *) wpabuf_head(avp));
	return avp;
}


struct eap_ttls_avp {
	 /* Note: eap is allocated memory; caller is responsible for freeing
	  * it. All the other pointers are pointing to the packet data, i.e.,
	  * they must not be freed separately. */
	u8 *eap;
	size_t eap_len;
	u8 *user_name;
	size_t user_name_len;
	u8 *user_password;
	size_t user_password_len;
	u8 *chap_challenge;
	size_t chap_challenge_len;
	u8 *chap_password;
	size_t chap_password_len;
	u8 *mschap_challenge;
	size_t mschap_challenge_len;
	u8 *mschap_response;
	size_t mschap_response_len;
	u8 *mschap2_response;
	size_t mschap2_response_len;
	u8 *eap_message;
	size_t eap_message_len;
};


static int eap_ttls_avp_parse(struct wpabuf *buf, struct eap_ttls_avp *parse)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);

	struct ttls_avp *avp;
	u8 *pos;
	int left;

	pos = wpabuf_mhead(buf);
	left = wpabuf_len(buf);
	os_memset(parse, 0, sizeof(*parse));

	while (left > 0) {
		u32 avp_code, avp_length, vendor_id = 0;
		u8 avp_flags, *dpos;
		size_t pad, dlen;
		avp = (struct ttls_avp *) pos;
		avp_code = be_to_host32(avp->avp_code);
		avp_length = be_to_host32(avp->avp_length);
		avp_flags = (avp_length >> 24) & 0xff;
		avp_length &= 0xffffff;
		wpa_printf(MSG_DEBUG, "EAP-TTLS: AVP: code=%d flags=0x%02x "
			   "length=%d", (int) avp_code, avp_flags,
			   (int) avp_length);
		if ((int) avp_length > left) {
			wpa_printf(MSG_WARNING, "EAP-TTLS: AVP overflow "
				   "(len=%d, left=%d) - dropped",
				   (int) avp_length, left);
			goto fail;
		}
		if (avp_length < sizeof(*avp)) {
			wpa_printf(MSG_WARNING, "EAP-TTLS: Invalid AVP length "
				   "%d", avp_length);
			goto fail;
		}
		dpos = (u8 *) (avp + 1);
		dlen = avp_length - sizeof(*avp);
		if (avp_flags & AVP_FLAGS_VENDOR) {
			if (dlen < 4) {
				wpa_printf(MSG_WARNING, "EAP-TTLS: vendor AVP "
					   "underflow");
				goto fail;
			}
			vendor_id = be_to_host32(* (be32 *) dpos);
			wpa_printf(MSG_DEBUG, "EAP-TTLS: AVP vendor_id %d",
				   (int) vendor_id);
			dpos += 4;
			dlen -= 4;
		}

		wpa_hexdump(MSG_DEBUG, "EAP-TTLS: AVP data", dpos, dlen);

		if (vendor_id == 0 && avp_code == RADIUS_ATTR_EAP_MESSAGE) {
			wpa_printf(MSG_DEBUG, "EAP-TTLS: AVP - EAP Message");
			if (parse->eap == NULL) {
				parse->eap = os_memdup(dpos, dlen);
				if (parse->eap == NULL) {
					wpa_printf(MSG_WARNING, "EAP-TTLS: "
						   "failed to allocate memory "
						   "for Phase 2 EAP data");
					goto fail;
				}
				parse->eap_len = dlen;
			} else {
				u8 *neweap = os_realloc(parse->eap,
							parse->eap_len + dlen);
				if (neweap == NULL) {
					wpa_printf(MSG_WARNING, "EAP-TTLS: "
						   "failed to allocate memory "
						   "for Phase 2 EAP data");
					goto fail;
				}
				os_memcpy(neweap + parse->eap_len, dpos, dlen);
				parse->eap = neweap;
				parse->eap_len += dlen;
			}
		} else if (vendor_id == 0 &&
			   avp_code == RADIUS_ATTR_USER_NAME) {
			wpa_hexdump_ascii(MSG_DEBUG, "EAP-TTLS: User-Name",
					  dpos, dlen);
			parse->user_name = dpos;
			parse->user_name_len = dlen;
		} else if (vendor_id == 0 &&
			   avp_code == RADIUS_ATTR_USER_PASSWORD) {
			u8 *password = dpos;
			size_t password_len = dlen;
			while (password_len > 0 &&
			       password[password_len - 1] == '\0') {
				password_len--;
			}
			wpa_hexdump_ascii_key(MSG_DEBUG, "EAP-TTLS: "
					      "User-Password (PAP)",
					      password, password_len);
			parse->user_password = password;
			parse->user_password_len = password_len;
		} else if (vendor_id == 0 &&
			   avp_code == RADIUS_ATTR_CHAP_CHALLENGE) {
			wpa_hexdump(MSG_DEBUG,
				    "EAP-TTLS: CHAP-Challenge (CHAP)",
				    dpos, dlen);
			parse->chap_challenge = dpos;
			parse->chap_challenge_len = dlen;
		} else if (vendor_id == 0 &&
			   avp_code == RADIUS_ATTR_CHAP_PASSWORD) {
			wpa_hexdump(MSG_DEBUG,
				    "EAP-TTLS: CHAP-Password (CHAP)",
				    dpos, dlen);
			parse->chap_password = dpos;
			parse->chap_password_len = dlen;
		} else if (vendor_id == RADIUS_VENDOR_ID_MICROSOFT &&
			   avp_code == RADIUS_ATTR_MS_CHAP_CHALLENGE) {
			wpa_hexdump(MSG_DEBUG,
				    "EAP-TTLS: MS-CHAP-Challenge",
				    dpos, dlen);
			parse->mschap_challenge = dpos;
			parse->mschap_challenge_len = dlen;
		} else if (vendor_id == RADIUS_VENDOR_ID_MICROSOFT &&
			   avp_code == RADIUS_ATTR_MS_CHAP_RESPONSE) {
			wpa_hexdump(MSG_DEBUG,
				    "EAP-TTLS: MS-CHAP-Response (MSCHAP)",
				    dpos, dlen);
			parse->mschap_response = dpos;
			parse->mschap_response_len = dlen;
		} else if (vendor_id == RADIUS_VENDOR_ID_MICROSOFT &&
			   avp_code == RADIUS_ATTR_MS_CHAP2_RESPONSE) {
			wpa_hexdump(MSG_DEBUG,
				    "EAP-TTLS: MS-CHAP2-Response (MSCHAPV2)",
				    dpos, dlen);
			parse->mschap2_response = dpos;
			parse->mschap2_response_len = dlen;
		} else if (vendor_id == RADIUS_VENDOR_ID_MICROSOFT &&
			   avp_code == RADIUS_ATTR_EAP_MESSAGE) {
			wpa_hexdump_ascii(MSG_DEBUG,
				    "EAP-TTLS: EAP Message",
				    dpos, dlen);
			parse->eap_message = dpos;
			parse->eap_message_len = dlen;
		} else if (avp_flags & AVP_FLAGS_MANDATORY) {
			wpa_printf(MSG_WARNING, "EAP-TTLS: Unsupported "
				   "mandatory AVP code %d vendor_id %d - "
				   "dropped", (int) avp_code, (int) vendor_id);
			goto fail;
		} else {
			wpa_printf(MSG_DEBUG, "EAP-TTLS: Ignoring unsupported "
				   "AVP code %d vendor_id %d",
				   (int) avp_code, (int) vendor_id);
		}

		pad = (4 - (avp_length & 3)) & 3;
		pos += avp_length + pad;
		left -= avp_length + pad;
	}

	return 0;

fail:
	os_free(parse->eap);
	parse->eap = NULL;
	return -1;
}


static u8 * eap_ttls_implicit_challenge(struct eap_sm *sm,
					struct eap_ttls_data *data, size_t len)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	return eap_server_tls_derive_key(sm, &data->ssl, "ttls challenge",
					 NULL, 0, len);
}


static void * eap_ttls_init(struct eap_sm *sm)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	

	struct eap_ttls_data *data;

	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	data->ttls_version = EAP_TTLS_VERSION;
	data->state = START;

	 /* 
	 TODO: eap_server_tls_ssl_init -> change the second arg. Initial value=0: no client certificate requested,
	  0: do not request a certificate
	  1: client cert requested, if none, failure,
	  2: client cert requested, if none contniue
	 */
	int client_config_cert=2;
	wpa_printf(MSG_INFO, "\033[0;36m EAP-TTLS \033[0m: Certificate client configuration: %d", client_config_cert);
	if (eap_server_tls_ssl_init(sm, &data->ssl, client_config_cert, EAP_TYPE_TTLS)) {
		wpa_printf(MSG_INFO, "EAP-TTLS: Failed to initialize SSL.");
		eap_ttls_reset(sm, data);
		return NULL;
	}

	return data;
}


static void eap_ttls_reset(struct eap_sm *sm, void *priv)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);

	struct eap_ttls_data *data = priv;
	if (data == NULL)
		return;
	if (data->phase2_priv && data->phase2_method)
		data->phase2_method->reset(sm, data->phase2_priv);
	eap_server_tls_ssl_deinit(sm, &data->ssl);
	wpabuf_free(data->pending_phase2_eap_resp);
	bin_clear_free(data, sizeof(*data));
}


static struct wpabuf * eap_ttls_build_start(struct eap_sm *sm,
					    struct eap_ttls_data *data, u8 id)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	wpa_printf(MSG_INFO, "\033[0;36m EAP-TTLS \033[0m: building initialization message");

	struct wpabuf *req;
	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_TTLS, 1, EAP_CODE_REQUEST, id);
	if (req == NULL) {
		wpa_printf(MSG_ERROR, "EAP-TTLS: Failed to allocate memory for"
			   " request");
		eap_ttls_state(data, FAILURE);
		return NULL;
	}

	wpabuf_put_u8(req, EAP_TLS_FLAGS_START | data->ttls_version);

	eap_ttls_state(data, PHASE1);

	return req;
}


static struct wpabuf * eap_ttls_build_phase2_eap_req(
	struct eap_sm *sm, struct eap_ttls_data *data, u8 id)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);

	struct wpabuf *buf, *encr_req;

	wpa_printf(MSG_INFO, "\033[0;36m EAP-TTLS \033[0m: building phase 2 message for inner method %s", data->phase2_method->name);

	buf = data->phase2_method->buildReq(sm, data->phase2_priv, id);
	if (buf == NULL)
		return NULL;

	wpa_hexdump_buf_key(MSG_DEBUG, "EAP-TTLS/EAP: Encapsulate Phase 2 data", buf);

	buf = eap_ttls_avp_encapsulate(buf, RADIUS_ATTR_EAP_MESSAGE, 1);
	if (buf == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/EAP: Failed to encapsulate packet");
		return NULL;
	}

	wpa_hexdump_buf_key(MSG_DEBUG, "EAP-TTLS/EAP: Encrypt encapsulated Phase 2 data", buf);

	encr_req = eap_server_tls_encrypt(sm, &data->ssl, buf);
	wpabuf_free(buf);

	return encr_req;
}

static u8 * eap_ttls_avp_add(u8 *start, u8 *avphdr, u32 avp_code,
			     u32 vendor_id, int mandatory,
			     const u8 *data, size_t len)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	u8 *pos;
	pos = eap_ttls_avp_hdr(avphdr, avp_code, vendor_id, mandatory, len);
	os_memcpy(pos, data, len);
	pos += len;
	AVP_PAD(start, pos);
	return pos;
}

static int eap_ttls_get_config_msg(struct eap_sm *sm, struct wpabuf **buf_ref)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	
	
	wpa_printf(MSG_INFO, "\033[0;36m EAP-TTLS \033[0m: Starting notification message building function");
	
	char username[sm->identity_len+1];
	/* wpa_printf(MSG_DEBUG, "\n\nPrinting one arg\n\n"); */
	uint i;
	for (i=0; i< sm->identity_len; i++)
	{
		username[i]= sm->identity[i];
	}
	username[sm->identity_len]=0;
	/* wpa_printf(MSG_DEBUG, "\n\n%s\n\n", username); */
	
	/*
	 * Create a new notification message in JWT format
	 */
	
	/* wpa_printf(MSG_DEBUG, "\n\nCreating the notification message\n\n"); */
	char * command_generate = os_calloc(256, sizeof(char));
	os_snprintf(command_generate, 256, "python3 /home/pi/radius/notification-message/generate_message.py '%s'", username);
	system(command_generate);
	os_free(command_generate);
	//sleep(1);
	


	size_t password_len, max_hash_count, max_hash_len, token_len;
	token_len = password_len = 16;
	max_hash_count = 5;
	max_hash_len = 16;

	u8 password_buf[password_len];
	u8 token_buf[token_len];

	/*
	 * The token_len, password_len, max_hash_len indicates the value length in bytes.
	 * However, these values will transmitted as hex string.
	 * They need to be converted hex string so the size is length_in_bytes * 2.
	 * And the last 1 character is for the terminatin NULL character.
	 */
	char password_buf_hex[password_len * 2 + 1];
	char token_buf_hex[token_len * 2 + 1];
	char provision_server_hash[max_hash_count][max_hash_len * 2 + 1];
	char config_server_hash[max_hash_count][max_hash_len * 2 + 1];

	/*
	 * Check for message.json file. 
	 * If the files exsits, then read the message from the file and send it.
	 */
	
	//char message_file_path[]="message.json";
	char message_file_path[]="/home/pi/radius/notification-message/notification-message.txt";

	//TODO: delete this parag
	/*
	int len=4000;
	struct wpabuf *buf = wpabuf_alloc(len);
	for(int i=0;i<len;i++)
	{
		wpabuf_put_u8(buf, 6);
	}
	*buf_ref = buf;
	return len;
	*/
	

	/* wpa_printf(MSG_DEBUG, "\n\nF_OK: %d; R_OK: %d\n\n", access( message_file_path, F_OK ), access( message_file_path, R_OK)); */
	if(access( message_file_path, F_OK ) == 0  && access( message_file_path, R_OK) == 0)
	{
		/* wpa_printf(MSG_DEBUG, "\n\nOpening message file\n\n"); */
		FILE *file = fopen(message_file_path, "r");
		
		fseek(file, 0L, SEEK_END);
		size_t file_size = ftell(file);
		rewind(file);
		if(file_size > 1000)
		{
			fclose(file);
			wpa_printf(MSG_ERROR, "The \"message.json\" file is too big!");
		}
		else
		{
			wpa_printf(MSG_DEBUG, "Reading the config message from \"message.json\" file");
			/* add couple of extra bytes to stay safe */
			struct wpabuf *buf = wpabuf_alloc(file_size + 5);
			
			*buf_ref = buf;
			fread(buf->buf, file_size, sizeof(char), file);
			fclose(file);
			
			buf->used = file_size;
			wpa_printf(MSG_DEBUG, "%zu byte is read", file_size);
			wpa_hexdump_ascii(MSG_DEBUG, "The read content", buf->buf, file_size);
			
			wpa_printf(MSG_DEBUG, "\n\nSize of file being sent: %d\n\n", file_size);
			return file_size;
			
		}
	
	}

	return 0;

	/*
	//Zeroize the arrays
	
	os_memset(provision_server_hash, '\0', sizeof(char) * max_hash_count * max_hash_len * 2 + 1);
	os_memset(config_server_hash, '\0', sizeof(char) * max_hash_count * max_hash_len * 2 + 1);

	//Use a static provision server hash for demo purpose
	
	os_memcpy(provision_server_hash[0], "8704efc8123f341151c7be646aa3cb36", 
		os_strlen("8704efc8123f341151c7be646aa3cb36"));
	os_memcpy(config_server_hash[0], "bbca86f0f644ee6be86b4e546aa4719c", 
		os_strlen("bbca86f0f644ee6be86b4e546aa4719c"));

	os_get_random((unsigned char *)password_buf, password_len);
	os_get_random((unsigned char *)token_buf, token_len);
	wpa_snprintf_hex(password_buf_hex, password_len * 2 + 1, password_buf, password_len);
	wpa_snprintf_hex(token_buf_hex, token_len * 2 + 1, token_buf, token_len);

	struct wpabuf *buf = wpabuf_alloc(512);
	*buf_ref = buf;


	json_start_object(buf, NULL);
	json_start_array(buf, "provision");

	json_start_object(buf, NULL);
	json_add_string_escape(buf, "url", "rpi2", 
		os_strlen("rpi2"));
	json_end_object(buf);

	json_value_sep(buf);

	json_start_object(buf, NULL);
	json_add_string_escape(buf, "user", sm->identity, sm->identity_len);
	json_end_object(buf);

    json_value_sep(buf);

	
	//For demo use a static password 
	
	json_start_object(buf, NULL);
    json_add_string_escape(buf, "password", "e70cd192f02e96a281a546057f5152c1",
		os_strlen("e70cd192f02e96a281a546057f5152c1"));
	// json_add_string(buf, "password", password_buf_hex);
	json_end_object(buf);

    json_value_sep(buf);

	json_start_object(buf, NULL);
	json_start_array(buf, "server_cert_hashes");
	for(int i = 0; i < max_hash_count && provision_server_hash[i][0] != '\0'; i++)
	{	
		
		//The string will be at most 2 char long -> h1, h2, h3, h4, h5
		//To stay safe lets make it 4 char long
		
		char str[4] = {0};
		os_snprintf(str, 3, "h%d", i);
		json_start_object(buf, NULL);
		json_add_string(buf, str, &provision_server_hash[0][0]);
		json_end_object(buf);
		
		if(i + 1 < max_hash_count && provision_server_hash[i + 1][0])
			json_value_sep(buf);
	}
	json_end_array(buf);
	json_end_object(buf);

	json_end_array(buf);

	json_value_sep(buf);

    json_start_array(buf, "config");

    json_start_object(buf, NULL);
	json_add_string_escape(buf, "url", "https://rpi2:8443", os_strlen("https://rpi2:8443"));
	json_end_object(buf);

	json_value_sep(buf);

	
	// For demo use a static client_token 
	
	json_start_object(buf, NULL);
	json_add_string(buf, "client_token", "07cabab341734082f207a23f57ca0897");
	json_end_object(buf);

    json_value_sep(buf);

	json_start_object(buf, NULL);
	json_add_string_escape(buf, "user", sm->identity, sm->identity_len);
	json_end_object(buf);

    json_value_sep(buf);

	json_start_object(buf, NULL);
	json_start_array(buf, "server_cert_hashes");
	for(int i = 0; i < max_hash_count && config_server_hash[i][0] != '\0'; i++)
	{	
		
		// The string will be at most 2 char long -> h1, h2, h3, h4, h5
		// To stay safe it is 4 char long
		
		char str[4] = {0};
		os_snprintf(str, 3, "h%d", i);
		json_start_object(buf, NULL);
		json_add_string(buf, str, &config_server_hash[i][0]);
		json_end_object(buf);
		
		if(i + 1 < max_hash_count && config_server_hash[i + 1][0])
			json_value_sep(buf);
	}
	json_end_array(buf);
	json_end_object(buf);

	json_end_array(buf);

	json_end_object(buf);

	return buf->used;
	*/
}

static struct wpabuf * eap_ttls_build_phase2_mschapv2(struct eap_sm *sm, struct eap_ttls_data *data)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct wpabuf *encr_req, msgbuf;
	u8 *req, *pos, *end;
	int ret;
	int len=4000;
	pos = req = os_malloc(len);
	if (req == NULL)
		return NULL;
	end = req + len;

	if (data->mschapv2_resp_ok) {
		struct wpabuf *buf;

		/* wpa_printf(MSG_INFO, "\n\n\n Preparing to read the file \n\n\n"); */

		int preverify_ok=0;
		int sz = 0;
		FILE *fp;
		if ((fp = fopen("/home/pi/radius/is_client_authenticated_in_eap_ttls", "r")))
    	{
			fseek(fp, 0L, SEEK_END);
			sz = ftell(fp);
			fseek(fp, 0L, SEEK_SET);
			if (sz>0)
			{
				fscanf(fp, "%d", &preverify_ok);
			}
			fclose(fp);
		}
		

		/* wpa_printf(MSG_INFO, "\n\n\n Reading the file %d %d \n\n\n", sz, preverify_ok); */

		fclose(fopen("/home/pi/radius/is_client_authenticated_in_eap_ttls", "w"));

		/* wpa_printf(MSG_INFO, "%d ", sm->require_identity_match); */
		int wants_config_message=0;  //TODO: choose whether to send the config data in it
		if(preverify_ok==1 && wants_config_message)
		{
			int len = eap_ttls_get_config_msg(sm, &buf);
			pos = eap_ttls_avp_add(req, pos, EAP_TTLS_CONFIG_MESSAGE,
					RADIUS_VENDOR_ID_HUAWEI, 1,
					buf->buf, len);
		}
		pos = eap_ttls_avp_hdr(pos, RADIUS_ATTR_MS_CHAP2_SUCCESS,
				       RADIUS_VENDOR_ID_MICROSOFT, 1, 43);
		*pos++ = data->mschapv2_ident;
		ret = os_snprintf((char *) pos, end - pos, "S=");
		if (!os_snprintf_error(end - pos, ret))
			pos += ret;
		pos += wpa_snprintf_hex_uppercase(
			(char *) pos, end - pos, data->mschapv2_auth_response,
			sizeof(data->mschapv2_auth_response));
	} else {
		pos = eap_ttls_avp_hdr(pos, RADIUS_ATTR_MS_CHAP_ERROR,
				       RADIUS_VENDOR_ID_MICROSOFT, 1, 6);
		os_memcpy(pos, "Failed", 6);
		pos += 6;
		AVP_PAD(req, pos);
	}

	wpabuf_set(&msgbuf, req, pos - req);
	wpa_hexdump_buf_key(MSG_DEBUG, "EAP-TTLS/MSCHAPV2: Encrypting Phase 2 "
			    "data", &msgbuf);

	encr_req = eap_server_tls_encrypt(sm, &data->ssl, &msgbuf);
	os_free(req);

	return encr_req;
}


static struct wpabuf * eap_ttls_buildReq(struct eap_sm *sm, void *priv, u8 id)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);

	struct eap_ttls_data *data = priv;

	if (data->ssl.state == FRAG_ACK) {
		return eap_server_tls_build_ack(id, EAP_TYPE_TTLS,
						data->ttls_version);
	}

	if (data->ssl.state == WAIT_FRAG_ACK) {
		wpa_printf(MSG_INFO, "\n\n\n Case WAIT_FRAG_ACK: data->ssl.state=%d \n\n\n", data->ssl.state);
		return eap_server_tls_build_msg(&data->ssl, EAP_TYPE_TTLS,
						data->ttls_version, id);
	}

	switch (data->state) {
	case START:
		//wpa_printf(MSG_INFO, "eap_ttls_build_start");
		return eap_ttls_build_start(sm, data, id);
	case PHASE1:
		wpa_printf(MSG_INFO, "\033[0;36m EAP-TTLS \033[0m: processing phase 1 TLS handshake message");
		//wpa_printf(MSG_INFO, "eap_ttls_state");
		if (tls_connection_established(sm->cfg->ssl_ctx,
					       data->ssl.conn)) {
			wpa_printf(MSG_DEBUG, "EAP-TTLS: Phase1 done, "
				   "starting Phase2");
			eap_ttls_state(data, PHASE2_START);
		}
		break;
	case PHASE2_METHOD:
		wpa_printf(MSG_INFO, "\033[0;36m EAP-TTLS \033[0m: processing phase 2 inner EAP method message");
		wpa_printf(MSG_INFO, "PERSO: PHASE2_METHOD for inner eap maybe");
		wpabuf_free(data->ssl.tls_out);
		data->ssl.tls_out_pos = 0;
		data->ssl.tls_out = eap_ttls_build_phase2_eap_req(sm, data, id);
		break;
	case PHASE2_MSCHAPV2_RESP:
		wpa_printf(MSG_INFO, "\033[0;36m EAP-TTLS \033[0m: processing phase 2 MSCHAPv2 message");
		wpabuf_free(data->ssl.tls_out);
		data->ssl.tls_out_pos = 0;
		data->ssl.tls_out = eap_ttls_build_phase2_mschapv2(sm, data);
		break;
	default:
		wpa_printf(MSG_DEBUG, "EAP-TTLS: %s - unexpected state %d",
			   __func__, data->state);
		return NULL;
	}

	return eap_server_tls_build_msg(&data->ssl, EAP_TYPE_TTLS,
					data->ttls_version, id);
}


static bool eap_ttls_check(struct eap_sm *sm, void *priv,
			   struct wpabuf *respData)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	const u8 *pos;
	size_t len;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_TTLS, respData, &len);
	if (pos == NULL || len < 1) {
		wpa_printf(MSG_INFO, "EAP-TTLS: Invalid frame");
		return true;
	}

	return false;
}


static void eap_ttls_process_phase2_pap(struct eap_sm *sm,
					struct eap_ttls_data *data,
					const u8 *user_password,
					size_t user_password_len)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	if (!sm->user || !sm->user->password || sm->user->password_hash ||
	    !(sm->user->ttls_auth & EAP_TTLS_AUTH_PAP)) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/PAP: No plaintext user "
			   "password configured");
		eap_ttls_state(data, FAILURE);
		return;
	}

	if (sm->user->password_len != user_password_len ||
	    os_memcmp_const(sm->user->password, user_password,
			    user_password_len) != 0) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/PAP: Invalid user password");
		eap_ttls_state(data, FAILURE);
		return;
	}

	wpa_printf(MSG_DEBUG, "EAP-TTLS/PAP: Correct user password");
	eap_ttls_state(data, SUCCESS);
	eap_ttls_valid_session(sm, data);
}


static void eap_ttls_process_phase2_chap(struct eap_sm *sm,
					 struct eap_ttls_data *data,
					 const u8 *challenge,
					 size_t challenge_len,
					 const u8 *password,
					 size_t password_len)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	u8 *chal, hash[CHAP_MD5_LEN];

	if (challenge == NULL || password == NULL ||
	    challenge_len != EAP_TTLS_CHAP_CHALLENGE_LEN ||
	    password_len != 1 + EAP_TTLS_CHAP_PASSWORD_LEN) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/CHAP: Invalid CHAP attributes "
			   "(challenge len %lu password len %lu)",
			   (unsigned long) challenge_len,
			   (unsigned long) password_len);
		eap_ttls_state(data, FAILURE);
		return;
	}

	if (!sm->user || !sm->user->password || sm->user->password_hash ||
	    !(sm->user->ttls_auth & EAP_TTLS_AUTH_CHAP)) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/CHAP: No plaintext user "
			   "password configured");
		eap_ttls_state(data, FAILURE);
		return;
	}

	chal = eap_ttls_implicit_challenge(sm, data,
					   EAP_TTLS_CHAP_CHALLENGE_LEN + 1);
	if (chal == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/CHAP: Failed to generate "
			   "challenge from TLS data");
		eap_ttls_state(data, FAILURE);
		return;
	}

	if (os_memcmp_const(challenge, chal, EAP_TTLS_CHAP_CHALLENGE_LEN)
	    != 0 ||
	    password[0] != chal[EAP_TTLS_CHAP_CHALLENGE_LEN]) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/CHAP: Challenge mismatch");
		os_free(chal);
		eap_ttls_state(data, FAILURE);
		return;
	}
	os_free(chal);

	/* MD5(Ident + Password + Challenge) */
	chap_md5(password[0], sm->user->password, sm->user->password_len,
		 challenge, challenge_len, hash);

	if (os_memcmp_const(hash, password + 1, EAP_TTLS_CHAP_PASSWORD_LEN) ==
	    0) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/CHAP: Correct user password");
		eap_ttls_state(data, SUCCESS);
		eap_ttls_valid_session(sm, data);
	} else {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/CHAP: Invalid user password");
		eap_ttls_state(data, FAILURE);
	}
}


static void eap_ttls_process_phase2_mschap(struct eap_sm *sm,
					   struct eap_ttls_data *data,
					   u8 *challenge, size_t challenge_len,
					   u8 *response, size_t response_len)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	u8 *chal, nt_response[24];

	if (challenge == NULL || response == NULL ||
	    challenge_len != EAP_TTLS_MSCHAP_CHALLENGE_LEN ||
	    response_len != EAP_TTLS_MSCHAP_RESPONSE_LEN) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/MSCHAP: Invalid MS-CHAP "
			   "attributes (challenge len %lu response len %lu)",
			   (unsigned long) challenge_len,
			   (unsigned long) response_len);
		eap_ttls_state(data, FAILURE);
		return;
	}

	if (!sm->user || !sm->user->password ||
	    !(sm->user->ttls_auth & EAP_TTLS_AUTH_MSCHAP)) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/MSCHAP: No user password "
			   "configured");
		eap_ttls_state(data, FAILURE);
		return;
	}

	chal = eap_ttls_implicit_challenge(sm, data,
					   EAP_TTLS_MSCHAP_CHALLENGE_LEN + 1);
	if (chal == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/MSCHAP: Failed to generate "
			   "challenge from TLS data");
		eap_ttls_state(data, FAILURE);
		return;
	}

#ifdef CONFIG_TESTING_OPTIONS
	eap_server_mschap_rx_callback(sm, "TTLS-MSCHAP",
				      sm->identity, sm->identity_len,
				      challenge, response + 2 + 24);
#endif /* CONFIG_TESTING_OPTIONS */

	if (os_memcmp_const(challenge, chal, EAP_TTLS_MSCHAP_CHALLENGE_LEN)
	    != 0 ||
	    response[0] != chal[EAP_TTLS_MSCHAP_CHALLENGE_LEN]) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/MSCHAP: Challenge mismatch");
		os_free(chal);
		eap_ttls_state(data, FAILURE);
		return;
	}
	os_free(chal);

	if ((sm->user->password_hash &&
	     challenge_response(challenge, sm->user->password, nt_response)) ||
	    (!sm->user->password_hash &&
	     nt_challenge_response(challenge, sm->user->password,
				   sm->user->password_len, nt_response))) {
		eap_ttls_state(data, FAILURE);
		return;
	}

	if (os_memcmp_const(nt_response, response + 2 + 24, 24) == 0) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/MSCHAP: Correct response");
		eap_ttls_state(data, SUCCESS);
		eap_ttls_valid_session(sm, data);
	} else {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/MSCHAP: Invalid NT-Response");
		wpa_hexdump(MSG_MSGDUMP, "EAP-TTLS/MSCHAP: Received",
			    response + 2 + 24, 24);
		wpa_hexdump(MSG_MSGDUMP, "EAP-TTLS/MSCHAP: Expected",
			    nt_response, 24);
		eap_ttls_state(data, FAILURE);
	}
}


static void eap_ttls_process_phase2_mschapv2(struct eap_sm *sm,
					     struct eap_ttls_data *data,
					     u8 *challenge,
					     size_t challenge_len,
					     u8 *response, size_t response_len)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	u8 *chal, *username, nt_response[24], *rx_resp, *peer_challenge,
		*auth_challenge;
	size_t username_len, i;

	if (challenge == NULL || response == NULL ||
	    challenge_len != EAP_TTLS_MSCHAPV2_CHALLENGE_LEN ||
	    response_len != EAP_TTLS_MSCHAPV2_RESPONSE_LEN) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/MSCHAPV2: Invalid MS-CHAP2 "
			   "attributes (challenge len %lu response len %lu)",
			   (unsigned long) challenge_len,
			   (unsigned long) response_len);
		eap_ttls_state(data, FAILURE);
		return;
	}

	if (!sm->user || !sm->user->password ||
	    !(sm->user->ttls_auth & EAP_TTLS_AUTH_MSCHAPV2)) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/MSCHAPV2: No user password "
			   "configured");
		eap_ttls_state(data, FAILURE);
		return;
	}

	if (sm->identity == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/MSCHAPV2: No user identity "
			   "known");
		eap_ttls_state(data, FAILURE);
		return;
	}

	/* MSCHAPv2 does not include optional domain name in the
	 * challenge-response calculation, so remove domain prefix
	 * (if present). */
	username = sm->identity;
	username_len = sm->identity_len;
	for (i = 0; i < username_len; i++) {
		if (username[i] == '\\') {
			username_len -= i + 1;
			username += i + 1;
			break;
		}
	}

	chal = eap_ttls_implicit_challenge(
		sm, data, EAP_TTLS_MSCHAPV2_CHALLENGE_LEN + 1);
	if (chal == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/MSCHAPV2: Failed to generate "
			   "challenge from TLS data");
		eap_ttls_state(data, FAILURE);
		return;
	}

	if (os_memcmp_const(challenge, chal, EAP_TTLS_MSCHAPV2_CHALLENGE_LEN)
	    != 0 ||
	    response[0] != chal[EAP_TTLS_MSCHAPV2_CHALLENGE_LEN]) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/MSCHAPV2: Challenge mismatch");
		os_free(chal);
		eap_ttls_state(data, FAILURE);
		return;
	}
	os_free(chal);

	auth_challenge = challenge;
	peer_challenge = response + 2;

	wpa_hexdump_ascii(MSG_MSGDUMP, "EAP-TTLS/MSCHAPV2: User",
			  username, username_len);
	wpa_hexdump(MSG_MSGDUMP, "EAP-TTLS/MSCHAPV2: auth_challenge",
		    auth_challenge, EAP_TTLS_MSCHAPV2_CHALLENGE_LEN);
	wpa_hexdump(MSG_MSGDUMP, "EAP-TTLS/MSCHAPV2: peer_challenge",
		    peer_challenge, EAP_TTLS_MSCHAPV2_CHALLENGE_LEN);

	if (sm->user->password_hash) {
		generate_nt_response_pwhash(auth_challenge, peer_challenge,
					    username, username_len,
					    sm->user->password,
					    nt_response);
	} else {
		generate_nt_response(auth_challenge, peer_challenge,
				     username, username_len,
				     sm->user->password,
				     sm->user->password_len,
				     nt_response);
	}

	rx_resp = response + 2 + EAP_TTLS_MSCHAPV2_CHALLENGE_LEN + 8;
#ifdef CONFIG_TESTING_OPTIONS
	{
		u8 challenge2[8];

		if (challenge_hash(peer_challenge, auth_challenge,
				   username, username_len, challenge2) == 0) {
			eap_server_mschap_rx_callback(sm, "TTLS-MSCHAPV2",
						      username, username_len,
						      challenge2, rx_resp);
		}
	}
#endif /* CONFIG_TESTING_OPTIONS */
	if (os_memcmp_const(nt_response, rx_resp, 24) == 0) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/MSCHAPV2: Correct "
			   "NT-Response");
		data->mschapv2_resp_ok = 1;

		if (sm->user->password_hash) {
			generate_authenticator_response_pwhash(
				sm->user->password,
				peer_challenge, auth_challenge,
				username, username_len, nt_response,
				data->mschapv2_auth_response);
		} else {
			generate_authenticator_response(
				sm->user->password, sm->user->password_len,
				peer_challenge, auth_challenge,
				username, username_len, nt_response,
				data->mschapv2_auth_response);
		}
	} else {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/MSCHAPV2: Invalid "
			   "NT-Response");
		wpa_hexdump(MSG_MSGDUMP, "EAP-TTLS/MSCHAPV2: Received",
			    rx_resp, 24);
		wpa_hexdump(MSG_MSGDUMP, "EAP-TTLS/MSCHAPV2: Expected",
			    nt_response, 24);
		data->mschapv2_resp_ok = 0;
	}
	eap_ttls_state(data, PHASE2_MSCHAPV2_RESP);
	data->mschapv2_ident = response[0];
}


static int eap_ttls_phase2_eap_init(struct eap_sm *sm,
				    struct eap_ttls_data *data,
				    int vendor, enum eap_type eap_type)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
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


static void eap_ttls_process_phase2_eap_response(struct eap_sm *sm,
						 struct eap_ttls_data *data,
						 u8 *in_data, size_t in_len)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	int next_vendor = EAP_VENDOR_IETF;
	enum eap_type next_type = EAP_TYPE_NONE;
	struct eap_hdr *hdr;
	u8 *pos;
	size_t left;
	struct wpabuf buf;
	const struct eap_method *m = data->phase2_method;
	void *priv = data->phase2_priv;

	if (priv == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/EAP: %s - Phase2 not "
			   "initialized?!", __func__);
		return;
	}

	hdr = (struct eap_hdr *) in_data;
	pos = (u8 *) (hdr + 1);

	//In case we receive a NAK
	if (in_len > sizeof(*hdr) && *pos == EAP_TYPE_NAK) {
		left = in_len - sizeof(*hdr);
		wpa_hexdump(MSG_DEBUG, "EAP-TTLS/EAP: Phase2 type Nak'ed; "
			    "allowed types", pos + 1, left - 1);
		eap_sm_process_nak(sm, pos + 1, left - 1);
		if (sm->user && sm->user_eap_method_index < EAP_MAX_METHODS &&
		    sm->user->methods[sm->user_eap_method_index].method !=
		    EAP_TYPE_NONE) {
			next_vendor = sm->user->methods[
				sm->user_eap_method_index].vendor;
			next_type = sm->user->methods[
				sm->user_eap_method_index++].method;
			wpa_printf(MSG_DEBUG, "EAP-TTLS: try EAP type %u:%u",
				   next_vendor, next_type);
			if (eap_ttls_phase2_eap_init(sm, data, next_vendor,
						     next_type)) {
				wpa_printf(MSG_DEBUG,
					   "EAP-TTLS: Failed to initialize EAP type %u:%u",
					   next_vendor, next_type);
				eap_ttls_state(data, FAILURE);
				return;
			}
		} else {
			eap_ttls_state(data, FAILURE);
		}
		return;
	}

	//Else we check the message
	wpabuf_set(&buf, in_data, in_len);

	if (m->check(sm, priv, &buf)) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/EAP: Phase2 check() asked to "
			   "ignore the packet");
		return;
	}

	//we process the message
	m->process(sm, priv, &buf);

	if (sm->method_pending == METHOD_PENDING_WAIT) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/EAP: Phase2 method is in "
			   "pending wait state - save decrypted response");
		wpabuf_free(data->pending_phase2_eap_resp);
		data->pending_phase2_eap_resp = wpabuf_dup(&buf);
	}

	if (!m->isDone(sm, priv))
		return;

	if (!m->isSuccess(sm, priv)) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/EAP: Phase2 method failed");
		eap_ttls_state(data, FAILURE);
		return;
	}

	switch (data->state) {
	case PHASE2_START:
		if (eap_user_get(sm, sm->identity, sm->identity_len, 1) != 0) {
			wpa_hexdump_ascii(MSG_DEBUG, "EAP_TTLS: Phase2 "
					  "Identity not found in the user "
					  "database",
					  sm->identity, sm->identity_len);
			eap_ttls_state(data, FAILURE);
			break;
		}

		eap_ttls_state(data, PHASE2_METHOD);
		next_vendor = sm->user->methods[0].vendor;
		next_type = sm->user->methods[0].method;
		sm->user_eap_method_index = 1;
		wpa_printf(MSG_DEBUG, "EAP-TTLS: try EAP type %u:%u",
			   next_vendor, next_type);
		if (eap_ttls_phase2_eap_init(sm, data, next_vendor,
					     next_type)) {
			wpa_printf(MSG_DEBUG,
				   "EAP-TTLS: Failed to initialize EAP type %u:%u",
				   next_vendor, next_type);
			eap_ttls_state(data, FAILURE);
		}
		break;
	case PHASE2_METHOD:
		eap_ttls_state(data, SUCCESS);
		eap_ttls_valid_session(sm, data);
		break;
	case FAILURE:
		break;
	default:
		wpa_printf(MSG_DEBUG, "EAP-TTLS: %s - unexpected state %d",
			   __func__, data->state);
		break;
	}
}


static void eap_ttls_process_phase2_eap(struct eap_sm *sm,
					struct eap_ttls_data *data,
					const u8 *eap, size_t eap_len)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct eap_hdr *hdr;
	size_t len;

	if (data->state == PHASE2_START) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/EAP: initializing Phase 2");
		if (eap_ttls_phase2_eap_init(sm, data, EAP_VENDOR_IETF,
					     EAP_TYPE_IDENTITY) < 0) {
			wpa_printf(MSG_DEBUG, "EAP-TTLS/EAP: failed to "
				   "initialize EAP-Identity");
			return;
		}
	}

	if (eap_len < sizeof(*hdr)) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS/EAP: too short Phase 2 EAP "
			   "packet (len=%lu)", (unsigned long) eap_len);
		return;
	}

	hdr = (struct eap_hdr *) eap;
	len = be_to_host16(hdr->length);
	wpa_printf(MSG_DEBUG, "EAP-TTLS/EAP: received Phase 2 EAP: code=%d "
		   "identifier=%d length=%lu", hdr->code, hdr->identifier,
		   (unsigned long) len);
	if (len > eap_len) {
		wpa_printf(MSG_INFO, "EAP-TTLS/EAP: Length mismatch in Phase 2"
			   " EAP frame (hdr len=%lu, data len in AVP=%lu)",
			   (unsigned long) len, (unsigned long) eap_len);
		return;
	}

	switch (hdr->code) {
	case EAP_CODE_RESPONSE:
		eap_ttls_process_phase2_eap_response(sm, data, (u8 *) hdr,
						     len);
		break;
	default:
		wpa_printf(MSG_INFO, "EAP-TTLS/EAP: Unexpected code=%d in "
			   "Phase 2 EAP header", hdr->code);
		break;
	}
}


static void eap_ttls_process_phase2(struct eap_sm *sm,
				    struct eap_ttls_data *data,
				    struct wpabuf *in_buf)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct wpabuf *in_decrypted;
	struct eap_ttls_avp parse;

	wpa_printf(MSG_DEBUG, "EAP-TTLS: received %lu bytes encrypted data for"
		   " Phase 2", (unsigned long) wpabuf_len(in_buf));

	if (data->pending_phase2_eap_resp) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS: Pending Phase 2 EAP response "
			   "- skip decryption and use old data");
		eap_ttls_process_phase2_eap(
			sm, data, wpabuf_head(data->pending_phase2_eap_resp),
			wpabuf_len(data->pending_phase2_eap_resp));
		wpabuf_free(data->pending_phase2_eap_resp);
		data->pending_phase2_eap_resp = NULL;
		return;
	}

	in_decrypted = tls_connection_decrypt(sm->cfg->ssl_ctx, data->ssl.conn,
					      in_buf);
	if (in_decrypted == NULL) {
		wpa_printf(MSG_INFO, "EAP-TTLS: Failed to decrypt Phase 2 "
			   "data");
		eap_ttls_state(data, FAILURE);
		return;
	}

	wpa_hexdump_buf_key(MSG_DEBUG, "EAP-TTLS: Decrypted Phase 2 EAP",
			    in_decrypted);

	if (eap_ttls_avp_parse(in_decrypted, &parse) < 0) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS: Failed to parse AVPs");
		wpabuf_free(in_decrypted);
		eap_ttls_state(data, FAILURE);
		return;
	}

	if (parse.user_name) {
		char *nbuf;
		nbuf = os_malloc(parse.user_name_len * 4 + 1);
		if (nbuf) {
			printf_encode(nbuf, parse.user_name_len * 4 + 1,
				      parse.user_name,
				      parse.user_name_len);
			eap_log_msg(sm, "TTLS-User-Name '%s'", nbuf);
			os_free(nbuf);
		}

		os_free(sm->identity);
		sm->identity = os_memdup(parse.user_name, parse.user_name_len);
		if (sm->identity == NULL) {
			eap_ttls_state(data, FAILURE);
			goto done;
		}
		sm->identity_len = parse.user_name_len;
		if (eap_user_get(sm, parse.user_name, parse.user_name_len, 1)
		    != 0) {
			wpa_printf(MSG_DEBUG, "EAP-TTLS: Phase2 Identity not "
				   "found in the user database");
			eap_ttls_state(data, FAILURE);
			goto done;
		}
	}

#ifdef EAP_SERVER_TNC
	if (data->tnc_started && parse.eap == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS: TNC started but no EAP "
			   "response from peer");
		eap_ttls_state(data, FAILURE);
		goto done;
	}
#endif /* EAP_SERVER_TNC */

	if (parse.eap) {
		eap_ttls_process_phase2_eap(sm, data, parse.eap,
					    parse.eap_len);
	} else if (parse.user_password) {
		eap_ttls_process_phase2_pap(sm, data, parse.user_password,
					    parse.user_password_len);
	} else if (parse.chap_password) {
		eap_ttls_process_phase2_chap(sm, data,
					     parse.chap_challenge,
					     parse.chap_challenge_len,
					     parse.chap_password,
					     parse.chap_password_len);
	} else if (parse.mschap_response) {
		eap_ttls_process_phase2_mschap(sm, data,
					       parse.mschap_challenge,
					       parse.mschap_challenge_len,
					       parse.mschap_response,
					       parse.mschap_response_len);
	} else if (parse.mschap2_response) {
		eap_ttls_process_phase2_mschapv2(sm, data,
						 parse.mschap_challenge,
						 parse.mschap_challenge_len,
						 parse.mschap2_response,
						 parse.mschap2_response_len);
	}

done:
	wpabuf_free(in_decrypted);
	os_free(parse.eap);
}

/* TNC: trusted network connect */
static void eap_ttls_start_tnc(struct eap_sm *sm, struct eap_ttls_data *data)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
#ifdef EAP_SERVER_TNC
	if (!sm->cfg->tnc || data->state != SUCCESS || data->tnc_started)
		return;

	wpa_printf(MSG_DEBUG, "EAP-TTLS: Initialize TNC");
	if (eap_ttls_phase2_eap_init(sm, data, EAP_VENDOR_IETF, EAP_TYPE_TNC)) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS: Failed to initialize TNC");
		eap_ttls_state(data, FAILURE);
		return;
	}

	data->tnc_started = 1;
	eap_ttls_state(data, PHASE2_METHOD);
#endif /* EAP_SERVER_TNC */
}


static int eap_ttls_process_version(struct eap_sm *sm, void *priv,
				    int peer_version)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct eap_ttls_data *data = priv;
	if (peer_version < data->ttls_version) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS: peer ver=%d, own ver=%d; "
			   "use version %d",
			   peer_version, data->ttls_version, peer_version);
		data->ttls_version = peer_version;
	}

	return 0;
}


static void eap_ttls_process_msg(struct eap_sm *sm, void *priv,
				 const struct wpabuf *respData)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct eap_ttls_data *data = priv;

	switch (data->state) {
	case PHASE1:
		if (eap_server_tls_phase1(sm, &data->ssl) < 0)
			eap_ttls_state(data, FAILURE);
		break;
	case PHASE2_START:
	case PHASE2_METHOD:
		eap_ttls_process_phase2(sm, data, data->ssl.tls_in);
		eap_ttls_start_tnc(sm, data);
		break;
	case PHASE2_MSCHAPV2_RESP:
		if (data->mschapv2_resp_ok && wpabuf_len(data->ssl.tls_in) ==
		    0) {
			wpa_printf(MSG_DEBUG, "EAP-TTLS/MSCHAPV2: Peer "
				   "acknowledged response");
			eap_ttls_state(data, SUCCESS);
			eap_ttls_valid_session(sm, data);
		} else if (!data->mschapv2_resp_ok) {
			wpa_printf(MSG_DEBUG, "EAP-TTLS/MSCHAPV2: Peer "
				   "acknowledged error");
			eap_ttls_state(data, FAILURE);
		} else {
			wpa_printf(MSG_DEBUG, "EAP-TTLS/MSCHAPV2: Unexpected "
				   "frame from peer (payload len %lu, "
				   "expected empty frame)",
				   (unsigned long)
				   wpabuf_len(data->ssl.tls_in));
			eap_ttls_state(data, FAILURE);
		}
		eap_ttls_start_tnc(sm, data);
		break;
	default:
		wpa_printf(MSG_DEBUG, "EAP-TTLS: Unexpected state %d in %s",
			   data->state, __func__);
		break;
	}
}


static void eap_ttls_process(struct eap_sm *sm, void *priv,
			     struct wpabuf *respData)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct eap_ttls_data *data = priv;
	const struct wpabuf *buf;
	const u8 *pos;
	u8 id_len;

	if (eap_server_tls_process(sm, &data->ssl, respData, data,
				   EAP_TYPE_TTLS, eap_ttls_process_version,
				   eap_ttls_process_msg) < 0) {
		eap_ttls_state(data, FAILURE);
		return;
	}

	if (!tls_connection_established(sm->cfg->ssl_ctx, data->ssl.conn) ||
	    !tls_connection_resumed(sm->cfg->ssl_ctx, data->ssl.conn))
		return;

	buf = tls_connection_get_success_data(data->ssl.conn);
	if (!buf || wpabuf_len(buf) < 1) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TTLS: No success data in resumed session - reject attempt");
		eap_ttls_state(data, FAILURE);
		return;
	}

	pos = wpabuf_head(buf);
	if (*pos != EAP_TYPE_TTLS) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TTLS: Resumed session for another EAP type (%u) - reject attempt",
			   *pos);
		eap_ttls_state(data, FAILURE);
		return;
	}

	pos++;
	id_len = *pos++;
	wpa_hexdump_ascii(MSG_DEBUG, "EAP-TTLS: Identity from cached session",
			  pos, id_len);
	os_free(sm->identity);
	sm->identity = os_malloc(id_len ? id_len : 1);
	if (!sm->identity) {
		sm->identity_len = 0;
		eap_ttls_state(data, FAILURE);
		return;
	}

	os_memcpy(sm->identity, pos, id_len);
	sm->identity_len = id_len;

	if (eap_user_get(sm, sm->identity, sm->identity_len, 1) != 0) {
		wpa_hexdump_ascii(MSG_DEBUG, "EAP-TTLS: Phase2 Identity not found in the user database",
				  sm->identity, sm->identity_len);
		eap_ttls_state(data, FAILURE);
		return;
	}

	wpa_printf(MSG_DEBUG,
		   "EAP-TTLS: Resuming previous session - skip Phase2");
	eap_ttls_state(data, SUCCESS);
	tls_connection_set_success_data_resumed(data->ssl.conn);
}


static bool eap_ttls_isDone(struct eap_sm *sm, void *priv)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct eap_ttls_data *data = priv;
	return data->state == SUCCESS || data->state == FAILURE;
}


static u8 * eap_ttls_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct eap_ttls_data *data = priv;
	u8 *eapKeyData;

	if (data->state != SUCCESS)
		return NULL;

	eapKeyData = eap_server_tls_derive_key(sm, &data->ssl,
					       "ttls keying material", NULL, 0,
					       EAP_TLS_KEY_LEN);
	if (eapKeyData) {
		*len = EAP_TLS_KEY_LEN;
		wpa_hexdump_key(MSG_DEBUG, "EAP-TTLS: Derived key",
				eapKeyData, EAP_TLS_KEY_LEN);
	} else {
		wpa_printf(MSG_DEBUG, "EAP-TTLS: Failed to derive key");
	}

	return eapKeyData;
}


static bool eap_ttls_isSuccess(struct eap_sm *sm, void *priv)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct eap_ttls_data *data = priv;
	return data->state == SUCCESS;
}


static u8 * eap_ttls_get_session_id(struct eap_sm *sm, void *priv, size_t *len)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);
	struct eap_ttls_data *data = priv;

	if (data->state != SUCCESS)
		return NULL;

	return eap_server_tls_derive_session_id(sm, &data->ssl, EAP_TYPE_TTLS,
						len);
}


static u8 * eap_ttls_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);

	struct eap_ttls_data *data = priv;
	u8 *eapKeyData, *emsk;

	if (data->state != SUCCESS)
		return NULL;

	eapKeyData = eap_server_tls_derive_key(sm, &data->ssl,
					       "ttls keying material", NULL, 0,
					       EAP_TLS_KEY_LEN + EAP_EMSK_LEN);
	if (eapKeyData) {
		emsk = os_malloc(EAP_EMSK_LEN);
		if (emsk)
			os_memcpy(emsk, eapKeyData + EAP_TLS_KEY_LEN,
				  EAP_EMSK_LEN);
		bin_clear_free(eapKeyData, EAP_TLS_KEY_LEN + EAP_EMSK_LEN);
	} else
		emsk = NULL;

	if (emsk) {
		*len = EAP_EMSK_LEN;
		wpa_hexdump(MSG_DEBUG, "EAP-TTLS: Derived EMSK",
			    emsk, EAP_EMSK_LEN);
	} else {
		wpa_printf(MSG_DEBUG, "EAP-TTLS: Failed to derive EMSK");
	}

	return emsk;
}


int eap_server_ttls_register(void)
{
	// wpa_printf(MSG_INFO, "\n\n PERSO: %s : %s", __FILE__,  __FUNCTION__);

	struct eap_method *eap;

	eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION,
				      EAP_VENDOR_IETF, EAP_TYPE_TTLS, "TTLS");
	if (eap == NULL)
		return -1;

	eap->init = eap_ttls_init;
	eap->reset = eap_ttls_reset;
	eap->buildReq = eap_ttls_buildReq;
	eap->check = eap_ttls_check;
	eap->process = eap_ttls_process;
	eap->isDone = eap_ttls_isDone;
	eap->getKey = eap_ttls_getKey;
	eap->isSuccess = eap_ttls_isSuccess;
	eap->getSessionId = eap_ttls_get_session_id;
	eap->get_emsk = eap_ttls_get_emsk;

	/* wpa_printf(MSG_INFO, "\n\nPERSO: description of eap_method: vendor=%d, eap_type=%d, name=%s\n\n", eap->vendor, eap->method, eap->name); */

	return eap_server_method_register(eap);
}
