/*
 * EAP-PROV definitions (RFC 7170)
 * Copyright (c) 2004-2019, sebastien.boire@huawei.com
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef EAP_PROV_H
#define EAP_PROV_H

#ifndef EAP_PROV_VERSION
#define EAP_PROV_VERSION 1
#endif



struct prov_tlv_hdr {
	be16 tlv_type;
	be16 length;
} STRUCT_PACKED;

/* Result TLV and Intermediate-Result TLV */
struct prov_tlv_result {
	be16 tlv_type;
	be16 length;
	be16 status;
	/* for Intermediate-Result TLV, followed by optional TLVs */
} STRUCT_PACKED;

struct prov_tlv_nak {
	be16 tlv_type;
	be16 length;
	be32 vendor_id;
	be16 nak_type;
	/* followed by optional TLVs */
} STRUCT_PACKED;




/* RFC 7170, 4.2.1: General TLV Format */
enum prov_tlv_types {
	PROV_TLV_AUTHORITY_ID = 1,
	PROV_TLV_IDENTITY_TYPE = 2,
	PROV_TLV_RESULT = 3,
	PROV_TLV_NAK = 4,
	PROV_TLV_ERROR = 5,
	PROV_TLV_CHANNEL_BINDING = 6,
	PROV_TLV_VENDOR_SPECIFIC = 7,
    PROV_TLV_VERSION=8,
	PROV_TLV_CONFIG_PAYLOAD = 9,
    PROV_TLV_SUCCESS=10,
    PROV_TLV_FAILURE=11,
};


enum prov_tlv_result_status {
	PROV_STATUS_SUCCESS = 1,
	PROV_STATUS_FAILURE = 2
};


/* Identity-Type values within Identity-Type TLV */
enum prov_identity_types {
	PROV_IDENTITY_TYPE_USER = 1,
	PROV_IDENTITY_TYPE_MACHINE = 2,
};

/*
#define PROV_TLV_MANDATORY 0x8000
#define PROV_TLV_TYPE_MASK 0x3fff
*/


/* RFC 7170, 4.2.6: Error TLV */
enum prov_error_codes {
	PROV_ERROR_INNER_METHOD = 1001,
	PROV_ERROR_UNSPEC_AUTH_INFRA_PROBLEM = 1002,
	PROV_ERROR_UNSPEC_AUTHENTICATION_FAILURE = 1003,
	PROV_ERROR_UNSPEC_AUTHORIZATION_FAILURE = 1004,
	PROV_ERROR_USER_ACCOUNT_CRED_UNAVAILABLE = 1005,
	PROV_ERROR_USER_ACCOUNT_EXPIRED = 1006,
	PROV_ERROR_USER_ACCOUNT_LOCKED_TRY_AGAIN_LATER = 1007,
	PROV_ERROR_USER_ACCOUNT_LOCKED_ADMIN_REQ = 1008,
	PROV_ERROR_TUNNEL_COMPROMISE_ERROR = 2001,
	PROV_ERROR_UNEXPECTED_TLVS_EXCHANGED = 2002,
};

struct wpabuf;
struct tls_connection;

struct eap_prov_tlv_parse {
	u8 *eap_payload_tlv;
	size_t eap_payload_tlv_len;
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



struct eap_prov_tlv {
	int type;
	int len;
	int content_pos;
	char * content;
	struct wpabuf *buf;
};

void eap_prov_put_tlv_hdr(struct wpabuf *buf, u16 type, u16 len);
void eap_prov_put_tlv(struct wpabuf *buf, u16 type, const void *data, u16 len);
void eap_prov_put_tlv_buf(struct wpabuf *buf, u16 type,
			  const struct wpabuf *data);
struct wpabuf * eap_prov_tlv_eap_payload(struct wpabuf *buf);

int eap_prov_parse_tlv(struct eap_prov_tlv_parse *tlv,
		       int tlv_type, u8 *pos, size_t len);
const char * eap_prov_tlv_type_str(enum prov_tlv_types type);
struct wpabuf * eap_prov_tlv_result(int status, int intermediate);
struct wpabuf * eap_prov_tlv_error(enum prov_error_codes error);
struct wpabuf * eap_prov_tlv_identity_type(enum prov_identity_types id);
struct wpabuf * eap_prov_tlv_set_config_payload();
int eap_prov_get_nb_tlvs(struct wpabuf *respData);
struct eap_prov_tlv * eap_prov_parse_tlvs(struct wpabuf *respData, int nb_tlvs, struct eap_prov_tlv *tlvs);
void get_configuration_data_from_tlv(struct eap_prov_tlv tlv, char * configuration_data);
enum eap_type;

#endif /* EAP_PROV_H */
