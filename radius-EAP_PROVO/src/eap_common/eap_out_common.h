/*
 * EAP-OUT definitions (RFC 7170)
 * Copyright (c) 2004-2019, sebastien.boire@huawei.com
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef EAP_OUT_H
#define EAP_OUT_H

#ifndef EAP_OUT_VERSION
#define EAP_OUT_VERSION 1
#endif



struct out_tlv_hdr {
	be16 tlv_type;
	be16 length;
} STRUCT_PACKED;

/* Result TLV and Intermediate-Result TLV */
struct out_tlv_result {
	be16 tlv_type;
	be16 length;
	be16 status;
	/* for Intermediate-Result TLV, followed by optional TLVs */
} STRUCT_PACKED;

struct out_tlv_nak {
	be16 tlv_type;
	be16 length;
	be32 vendor_id;
	be16 nak_type;
	/* followed by optional TLVs */
} STRUCT_PACKED;




/* RFC 7170, 4.2.1: General TLV Format */
enum out_tlv_types {
	OUT_TLV_ENCRYPTED=2,
    OUT_TLV_RESULT = 3,
	OUT_TLV_NAK = 4,
	OUT_TLV_ERROR = 5,
	OUT_TLV_CHANNEL_BINDING = 6,
    OUT_TLV_EAP=7,
    OUT_TLV_VERSION=8,
	OUT_TLV_CONFIG_PAYLOAD = 9,
    OUT_TLV_SUCCESS=10,
    OUT_TLV_FAILURE=11,
};


enum out_tlv_result_status {
	OUT_STATUS_SUCCESS = 1,
	OUT_STATUS_FAILURE = 2
};


/* Identity-Type values within Identity-Type TLV */
enum out_identity_types {
	OUT_IDENTITY_TYPE_USER = 1,
	OUT_IDENTITY_TYPE_MACHINE = 2,
};

/*
#define OUT_TLV_MANDATORY 0x8000
#define OUT_TLV_TYPE_MASK 0x3fff
*/


/* RFC 7170, 4.2.6: Error TLV */
enum out_error_codes {
	OUT_ERROR_INNER_METHOD = 1001,
	OUT_ERROR_UNSPEC_AUTH_INFRA_PROBLEM = 1002,
	OUT_ERROR_UNSPEC_AUTHENTICATION_FAILURE = 1003,
	OUT_ERROR_UNSPEC_AUTHORIZATION_FAILURE = 1004,
	OUT_ERROR_USER_ACCOUNT_CRED_UNAVAILABLE = 1005,
	OUT_ERROR_USER_ACCOUNT_EXPIRED = 1006,
	OUT_ERROR_USER_ACCOUNT_LOCKED_TRY_AGAIN_LATER = 1007,
	OUT_ERROR_USER_ACCOUNT_LOCKED_ADMIN_REQ = 1008,
	OUT_ERROR_TUNNEL_COMPROMISE_ERROR = 2001,
	OUT_ERROR_UNEXPECTED_TLVS_EXCHANGED = 2002,
};

struct wpabuf;
struct tls_connection;

struct eap_out_tlv_parse {
    struct wpabuf * inner_eap;
    struct eap_hdr * hdr;
    u8 inner_eap_reqType;
    
	int iresult;
	int result;
	u8 *nak;
	size_t nak_len;
	u8 request_action;
	u8 request_action_status;
	u8 *basic_auth_req;
	size_t basic_auth_req_len;
	u8 *basic_auth_resp;
	size_t basic_auth_resp_len;
	u32 error_code;
	u16 identity_type;
	u16 version;

};


//TODO: look into wpabuf structure, maybe there is len inside it already
struct eap_out_tlv {
	int type;
	int len;
	struct wpabuf *buf;
};

void eap_out_put_tlv_hdr(struct wpabuf *buf, u16 type, u16 len);
void eap_out_put_tlv(struct wpabuf *buf, u16 type, const void *data, u16 len);
void eap_out_put_tlv_buf(struct wpabuf *buf, u16 type,
			  const struct wpabuf *data);
void eap_out_tlv_encrypt(struct wpabuf *buf, struct wpabuf * encrypted_buf, const u8 *key);
void eap_out_tlv_decrypt(struct wpabuf *buf, struct wpabuf * decrypted_buf, const u8 *key);
struct wpabuf * eap_out_tlv_eap_payload(struct wpabuf *buf);

// int eap_out_parse_tlv(struct eap_out_tlv_parse *tlv,
// 		       int tlv_type, u8 *pos, size_t len);
const char * eap_out_tlv_type_str(enum out_tlv_types type);

int eap_out_get_version(struct wpabuf *buf);
/*
struct wpabuf * eap_out_tlv_result(int status, int intermediate);
struct wpabuf * eap_out_tlv_error(enum out_error_codes error);
struct wpabuf * eap_out_tlv_identity_type(enum out_identity_types id);
struct wpabuf * eap_out_tlv_set_config_payload();
*/
int eap_out_get_nb_tlvs(struct wpabuf *respData);
int eap_out_parse_tlvs(struct wpabuf *respData, int nb_tlvs, struct eap_out_tlv *tlvs);
void eap_out_get_hdr(struct eap_out_tlv_parse *tlv_parse);
void eap_out_parse_tlvs_step2(u8 * key, struct eap_out_tlv_parse *tlv_parse, int nb_tlvs, struct eap_out_tlv *tlvs);
int eap_out_get_nb_eap_types_in_nak(struct wpabuf * buf);
void eap_out_get_eap_types_in_nak(int nb_types, enum eap_type * types, struct wpabuf * buf);
enum eap_type;

#endif /* EAP_OUT_H */
