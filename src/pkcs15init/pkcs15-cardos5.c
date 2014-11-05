/*
 * Copyright (c) 2014 Pedro Martelletto <pedro@ambientworks.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Alternatively, this file may be distributed under the terms of the GNU
 * Lesser General Public License (LGPL) version 2.1.
 */

#include "config.h"

#include <sys/types.h>

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "libopensc/opensc.h"
#include "libopensc/card-cardos5.h"
#include "libopensc/cardctl.h"
#include "libopensc/log.h"
#include "libopensc/cards.h"
#include "libopensc/asn1.h"
#include "pkcs15-init.h"
#include "profile.h"

typedef struct {
	size_t				bytes;
	struct sc_pkcs15_prkey_rsa	privkey;
	struct sc_pkcs15_pubkey_rsa	pubkey;
} rsa_keypair_t;

typedef struct {
	size_t				bytes;
	struct sc_pkcs15_prkey_ec	privkey;
	struct sc_pkcs15_pubkey_ec	pubkey;
} ec_keypair_t;

typedef struct {
	uint8_t	*ptr;
	size_t	 size;
	size_t	 bytes_used;
} buf_t;

static void
buf_init(buf_t *buf, uint8_t *ptr, size_t size)
{
	buf->ptr = ptr;
	buf->size = size;
	buf->bytes_used = 0;
}

static int
asn1_put_tag(uint8_t tag, const void *tag_content, size_t tag_content_len,
    buf_t *buf)
{
	int r;

	r = sc_asn1_put_tag(tag, (const uint8_t *)tag_content, tag_content_len,
	    buf->ptr, buf->size - buf->bytes_used, &buf->ptr);
	if (r == SC_SUCCESS) {
		buf->bytes_used += tag_content_len + 2;
		return 0;
	}

	return -1;
}

static int
asn1_put_tag0(uint8_t tag, buf_t *buf)
{
	return asn1_put_tag(tag, NULL, 0, buf);
}

static int
asn1_put_tag1(uint8_t tag, uint8_t tag_value, buf_t *buf)
{
	const uint8_t	tag_content[1] = { tag_value };

	return asn1_put_tag(tag, tag_content, sizeof(tag_content), buf);
}

static int
asn1_put_tag2(uint8_t tag, uint8_t a, uint8_t b, buf_t *buf)
{
	const uint8_t	tag_content[2] = { a, b };

	return asn1_put_tag(tag, tag_content, sizeof(tag_content), buf);
}

static int
asn1_put_tag3(uint8_t tag, uint8_t a, uint8_t b, uint8_t c, buf_t *buf)
{
	const uint8_t	tag_content[3] = { a, b, c };

	return asn1_put_tag(tag, tag_content, sizeof(tag_content), buf);
}

static int
add_acl_tag(uint8_t am_byte, unsigned int ac, int key_ref, buf_t *buf)
{
	uint8_t	crt_buf[16];
	buf_t	crt;

	if (asn1_put_tag1(ARL_ACCESS_MODE_BYTE_TAG, am_byte, buf))
		return -1;

	switch (ac) {
	case SC_AC_NONE:
		/* SC_AC_NONE means operation ALWAYS allowed. */
		return asn1_put_tag0(ARL_ALWAYS_TAG, buf);
	case SC_AC_NEVER:
		return asn1_put_tag0(ARL_NEVER_TAG, buf);
	case SC_AC_CHV:
	case SC_AC_TERM:
	case SC_AC_AUT:
		if (key_ref < 0 || (key_ref & BACKTRACK_PIN) ||
		    key_ref > UINT8_MAX)
			return -1;

		buf_init(&crt, crt_buf, sizeof(crt_buf));

		if (asn1_put_tag1(CRT_TAG_PINREF, (uint8_t)key_ref, &crt) ||
		    asn1_put_tag1(CRT_TAG_KUQ, KUQ_USER_AUTH, &crt) ||
		    asn1_put_tag(ARL_USER_AUTH_TAG, crt_buf, crt.bytes_used,
		    buf))
		    	return -1;
		return 0;
	default:
		return -1;
	}
}

static int
store_pin(sc_profile_t *profile, sc_card_t *card,
    sc_pkcs15_auth_info_t *auth_info, int puk_id, const unsigned char *pin,
    size_t pin_len)
{
	struct sc_cardctl_cardos_obj_info	args;
	uint8_t					payload_buf[128];
	uint8_t					arl_buf[128];
	uint8_t					retries_buf[16];
	uint8_t					paddedpin[16];
	buf_t					payload;
	buf_t					arl;
	buf_t					retries_oci;
	unsigned int				maxlen;
	int					pin_ref;
	int					retries;
	int					r;

	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

	r = sc_pkcs15init_set_lifecycle(card, SC_CARDCTRL_LIFECYCLE_ADMIN);
	if (r < 0)
		return r;

	maxlen = profile->pin_maxlen;
	if (maxlen > sizeof(paddedpin))
		maxlen = sizeof(paddedpin);
	if (pin_len > maxlen || profile->pin_pad_char > UINT8_MAX) {
		sc_log(card->ctx, "invalid parameters: pin_len=%zu, "
		    "pin_pad_char=0x%x", pin_len, profile->pin_pad_char);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	memcpy(paddedpin, pin, pin_len);
	while (pin_len < maxlen)
		paddedpin[pin_len++] = (uint8_t)profile->pin_pad_char;

	pin = paddedpin;
	pin_ref = auth_info->attrs.pin.reference;
	if (pin_ref < 0 || pin_ref > UINT8_MAX) {
		sc_log(card->ctx, "invalid pin_ref=%d", pin_ref);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/* The 0x0f limit is imposed by the device .*/
	retries = sc_profile_get_pin_retries(profile, pin_ref);
	if (retries < 0 || retries > 0x0f) {
		sc_log(card->ctx, "invalid number of retries %d", retries);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	buf_init(&payload, payload_buf, sizeof(payload_buf));

	if (asn1_put_tag1(CRT_TAG_PINREF, (uint8_t)pin_ref, &payload) ||
	    asn1_put_tag3(CRT_TAG_OBJPARAM, OBJPARAM_NOBACKTRACK, 0, 0,
	    &payload) || asn1_put_tag1(CRT_TAG_CU, CU_USER_AUTH, &payload) ||
	    asn1_put_tag1(CRT_TAG_KUQ, KUQ_USER_AUTH, &payload) ||
	    asn1_put_tag2(CRT_TAG_ALGO_TYPE, ALGO_TYPE_PIN, 0, &payload) ||
	    asn1_put_tag1(CRT_TAG_LIFECYCLE, LIFECYCLE_OPERATIONAL, &payload)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	buf_init(&retries_oci, retries_buf, sizeof(retries_buf));

	if (asn1_put_tag1(OCI_TAG_RETRIES, retries, &retries_oci)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	buf_init(&arl, arl_buf, sizeof(arl_buf));

	if (add_acl_tag(AM_KEY_USE, SC_AC_NONE, -1, &arl) ||
	    add_acl_tag(AM_KEY_CHANGE, SC_AC_CHV, pin_ref, &arl) ||
	    (puk_id != -1 && add_acl_tag(AM_KEY_RESET_RETRY_CTR, SC_AC_CHV,
	    puk_id, &arl))) {
		sc_log(card->ctx, "could not add acl tag");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	if (asn1_put_tag(FCP_TAG_ARL, arl_buf, arl.bytes_used, &payload) ||
	    asn1_put_tag(CRT_TAG_RETRIES, retries_buf, retries_oci.bytes_used,
	    &payload) || asn1_put_tag(CRT_TAG_KEYDATA, pin, pin_len,
	    &payload)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	args.data = payload_buf;
	args.len = payload.bytes_used;

	return sc_card_ctl(card, SC_CARDCTL_CARDOS_PUT_DATA_OCI, &args);
}

static int
cardos5_create_pin(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
    sc_file_t *df, sc_pkcs15_object_t *pin_obj, const unsigned char *pin,
    size_t pin_len, const unsigned char *puk, size_t puk_len)
{
	sc_pkcs15_auth_info_t	*auth_info;
	sc_pkcs15_auth_info_t	 puk_info;
	struct sc_card		*card = p15card->card;
	int			 puk_id = -1;
	int			 r;

	if (pin == 0 || pin_len == 0)
		return SC_ERROR_INVALID_ARGUMENTS;

	auth_info = (sc_pkcs15_auth_info_t *)pin_obj->data;
	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

	r = sc_select_file(card, &df->path, NULL);
	if (r < 0)
		return r;

	if (puk != 0 && puk_len != 0) {
		sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PUK,
		    &puk_info);
		if (INT_MAX - auth_info->attrs.pin.reference < 2) {
			sc_log(card->ctx, "invalid pin %d",
			    auth_info->attrs.pin.reference);
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		puk_info.attrs.pin.reference = puk_id =
		    auth_info->attrs.pin.reference + 1;
		r = store_pin(profile, card, &puk_info, -1, puk,
		    puk_len);
		if (r != SC_SUCCESS) {
			sc_log(card->ctx, "could not store puk, r=%d", r);
			return r;
		}
	}

	return store_pin(profile, card, auth_info, puk_id, pin, pin_len);
}

static uint32_t	public_exponent = 0x010001; /* 65537 */

static void
fill_in_dummy_rsa_key(rsa_keypair_t *rsa, uint8_t *dummy_data, size_t kbits)
{
	memset(rsa, 0x00, sizeof(*rsa));
	rsa->bytes = kbits / 8;

	rsa->pubkey.modulus.data = dummy_data;
	rsa->pubkey.modulus.len = rsa->bytes;
	rsa->pubkey.exponent.data = (unsigned char *)&public_exponent;
	rsa->pubkey.exponent.len = 3; /* XXX */

	/*
	 * >= 2048-bit keys follow the Chinese Remainder Theorem format. Note
	 * that the card expects Q > P.
	 */
	if (rsa->bytes > 256) {
		rsa->privkey.p.data = dummy_data;
		rsa->privkey.p.len = (rsa->bytes >> 1) - 1;
		rsa->privkey.q.data = dummy_data;
		rsa->privkey.q.len = (rsa->bytes >> 1) + 1;
		rsa->privkey.iqmp.data = dummy_data;
		rsa->privkey.iqmp.len = (rsa->bytes >> 1);
		rsa->privkey.dmp1.data = dummy_data;
		rsa->privkey.dmp1.len = (rsa->bytes >> 1) - 1;
		rsa->privkey.dmq1.data = dummy_data;
		rsa->privkey.dmq1.len = (rsa->bytes >> 1) + 1;
	} else {
		rsa->privkey.modulus.data = dummy_data;
		rsa->privkey.modulus.len = rsa->bytes;
		rsa->privkey.d.data = dummy_data;
		rsa->privkey.d.len = rsa->bytes;
	}
}

static void
fill_in_dummy_ec_key(ec_keypair_t *ec, uint8_t *dummyQ, uint8_t *dummyD,
    size_t kbits)
{
	memset(ec, 0x00, sizeof(*ec));

	ec->bytes = kbits / 8;

	dummyQ[0] = 0x04; /* uncompressed format */
	ec->pubkey.ecpointQ.value = dummyQ;
	ec->pubkey.ecpointQ.len = ec->bytes * 2 + 1;

	ec->privkey.privateD.data = dummyD;
	ec->privkey.privateD.len = ec->bytes;
}

static int
push_obj(sc_card_t *card, const uint8_t *obj, size_t len, uint8_t *key_sha256)
{
	struct sc_cardctl_cardos_acc_obj_info	args;
	uint8_t					payload_buf[128];
	size_t					done;
	size_t					n;
	int					r;

	if (len > UINT16_MAX) {
		sc_log(card->ctx, "invalid len %zu", len);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	for (done = 0; done < len; done += n) {
		buf_t payload = { payload_buf, sizeof(payload_buf), 0 };

		if (done == 0) {
			uint8_t len_hi = (uint8_t)(len >> 8);
			uint8_t len_lo = (uint8_t)(len & 0xFF);
			if (asn1_put_tag2(0x80, len_hi, len_lo, &payload)) {
				sc_log(card->ctx, "asn1 error");
				return SC_ERROR_BUFFER_TOO_SMALL;
			}
			args.append = 0; /* allocate new object */
		} else
			args.append = 1; /* appending to existing object */

		n = len - done;
		if (n > 64)
			n = 64;

		if (asn1_put_tag(CARDOS5_ACCUMULATE_OBJECT_DATA_TAG,
		    obj + done, n, &payload)) {
		    	sc_log(card->ctx, "asn1 error");
		    	return SC_ERROR_BUFFER_TOO_SMALL;
		}

		args.data = payload_buf;
		args.len = payload.bytes_used;

		r = sc_card_ctl(card, SC_CARDCTL_CARDOS_ACCUMULATE_OBJECT_DATA,
		    &args);
		if (r != SC_SUCCESS)
			return r;
	}

	if (key_sha256 != NULL)
		memcpy(key_sha256, args.hash, 32);

	return SC_SUCCESS;
}

/* add a key Control Reference template (CRT) to a buf_t. */
static int
add_key_crt(int key_id, int algo, int active, int pubkey, buf_t *b)
{
	uint8_t	changeable;
	uint8_t	lifecycle;
	uint8_t	kuq;
	uint8_t	algo_type1;
	uint8_t	algo_type2;

	if (active) {
		changeable = OBJPARAM_UNCHANGEABLE;
		lifecycle = LIFECYCLE_OPERATIONAL;
	} else {
		changeable = OBJPARAM_CHANGEABLE;
		lifecycle = LIFECYCLE_CREATION;
	}

	if (pubkey)
		kuq = KUQ_ENCRYPT;
	else
		kuq = KUQ_DECRYPT;

	if (algo == SC_ALGORITHM_RSA) {
		algo_type1 = ALGO_TYPE_RSA;
		algo_type2 = ALGO_TYPE_PARAM;
	} else {
		algo_type1 = ALGO_TYPE_EC;
		algo_type2 = 0;
	}

	if (key_id < 0 || key_id > UINT8_MAX)
		return -1;

	if (asn1_put_tag1(CRT_DO_KEYREF, (uint8_t)key_id, b) ||
	    asn1_put_tag3(CRT_TAG_OBJPARAM, OBJPARAM_NOBACKTRACK, changeable, 0,
	    b) || asn1_put_tag1(CRT_TAG_CU, CU_CIPHER | CU_SIGN, b) ||
	    asn1_put_tag1(CRT_TAG_KUQ, kuq, b) ||
	    asn1_put_tag2(CRT_TAG_ALGO_TYPE, algo_type1, algo_type2, b) ||
	    asn1_put_tag1(CRT_TAG_LIFECYCLE, lifecycle, b))
	    	return -1;

	return 0;
}

static int
bertlv_put_tag(uint8_t tag, const uint8_t *data, size_t length, buf_t *buf)
{
	if (length > UINT16_MAX || buf->bytes_used == buf->size)
		return -1;

	*(buf->ptr)++ = tag;
	buf->bytes_used++;

	if (length < 0x80) {
		if (buf->bytes_used == buf->size)
			return -1;
		*(buf->ptr)++ = (uint8_t)length;
		buf->bytes_used++;
	} else if (length < 0xFF) {
		if (buf->size - buf->bytes_used < 2)
			return -1;
		*(buf->ptr)++ = 0x81;
		*(buf->ptr)++ = (uint8_t)length;
		buf->bytes_used += 2;
	} else {
		if (buf->size - buf->bytes_used < 3)
			return -1;
		*(buf->ptr)++ = 0x82;
		*(buf->ptr)++ = (uint8_t)(length >> 8);
		*(buf->ptr)++ = (uint8_t)(length & 0xFF);
		buf->bytes_used += 3;
	}

	if (buf->bytes_used - buf->size < length)
		return -1;

	memcpy(buf->ptr, data, length);
	buf->ptr += length;
	buf->bytes_used += length;

	return 0;
}

static int
bertlv_get_tag(uint16_t tag, uint8_t **tag_content, uint16_t *tag_length,
    buf_t *buf)
{
	uint8_t	c;

	if (tag > 0xFF) {
		if (buf->size - buf->bytes_used < 2)
			return -1;
		if (*(buf->ptr)++ != (uint8_t)(tag >> 8) ||
		    *(buf->ptr)++ != (uint8_t)(tag))
			return -1;
		buf->bytes_used += 2;
	} else {
		if (buf->size - buf->bytes_used < 1)
			return -1;
		if (*(buf->ptr)++ != (uint8_t)(tag))
			return -1;
		buf->bytes_used += 1;
	}

	if (buf->size - buf->bytes_used < 1)
		return -1;

	c = *(buf->ptr)++;
	buf->bytes_used += 1;

	if (c < 0x80)
		*tag_length = c;
	else if (c == 0x81) {
		if (buf->size - buf->bytes_used < 1)
			return -1;
		buf->bytes_used += 1;
		*tag_length = *(buf->ptr)++;
	} else if (c == 0x82) {
		if (buf->size - buf->bytes_used < 2)
			return -1;
		buf->bytes_used += 2;
		*tag_length = (uint16_t)(*(buf->ptr)++ << 8);
		*tag_length |= *(buf->ptr)++;
	} else
		return -1;

	if (buf->size - buf->bytes_used < *tag_length)
	    	return -1;

	if (tag_content != NULL) {
		if ((*tag_content = malloc(*tag_length)) == NULL)
			return -1;
		memcpy(*tag_content, buf->ptr, *tag_length);
		buf->ptr += *tag_length;
		buf->bytes_used += *tag_length;
	}

	return 0;
}

static int
store_privkey(sc_card_t *card, int key_id, int algo, int active, int pin_id,
    const uint8_t *hash)
{
	struct sc_cardctl_cardos_obj_info	args;
	uint8_t					payload_buf[256];
	uint8_t					arl_buf[128];
	uint8_t					cmd[4];
	buf_t					payload;
	buf_t					arl;

	buf_init(&payload, payload_buf, sizeof(payload_buf));

	if (add_key_crt(key_id, algo, active, 0, &payload)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	buf_init(&arl, arl_buf, sizeof(arl_buf));

	memset(cmd, 0, sizeof(cmd));
	cmd[1] = CARDOS5_GENERATE_KEY_INS;
	cmd[2] = CARDOS5_GENERATE_KEY_P1_EXTRACT;

	if (asn1_put_tag(ARL_COMMAND_TAG, cmd, sizeof(cmd), &arl) ||
	    asn1_put_tag0(ARL_ALWAYS_TAG, &arl)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	if (add_acl_tag(AM_KEY_USE, SC_AC_CHV, pin_id, &arl) ||
	    add_acl_tag(AM_KEY_CHANGE, SC_AC_CHV, pin_id, &arl) ||
	    add_acl_tag(AM_KEY_OCI_UPD, SC_AC_CHV, pin_id, &arl)) {
		sc_log(card->ctx, "could not add acl tag");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	if (asn1_put_tag(FCP_TAG_ARL, arl_buf, arl.bytes_used, &payload) ||
	    asn1_put_tag(CARDOS5_ACCUMULATE_OBJECT_HASH_TAG, hash, 32,
	    &payload)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	memset(&args, 0, sizeof(args));
	args.data = payload_buf;
	args.len = payload.bytes_used;

	return sc_card_ctl(card, SC_CARDCTL_CARDOS_PUT_DATA_OCI, &args);
}

static int
cardos_put_rsa_privkey(sc_profile_t *profile, struct sc_pkcs15_card *p15card,
    sc_pkcs15_prkey_info_t *keyinfo, const rsa_keypair_t *rsa, int active)
{
	struct sc_card	*card = p15card->card;
	uint8_t		 hash[32];
	uint8_t		 payload_buf[2048];
	uint8_t		 object_buf[2048];
	buf_t		 payload;
	buf_t		 object;
	int		 pin_ref;
	int		 r;

	pin_ref = sc_pkcs15init_get_pin_reference(p15card, profile,
	    SC_AC_SYMBOLIC, SC_PKCS15INIT_USER_PIN);
	if (pin_ref < 0 || pin_ref & BACKTRACK_PIN) {
		sc_log(card->ctx, "invalid pin_ref=%d", pin_ref);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	r = sc_pkcs15init_set_lifecycle(card, SC_CARDCTRL_LIFECYCLE_ADMIN);
	if (r != SC_SUCCESS)
		return r;

	buf_init(&payload, payload_buf, sizeof(payload_buf));

	/* >= 2048-bit keys follow the Chinese Remainder Theorem format. */
	if (rsa->bytes > 256) {
		if (bertlv_put_tag(RSA_PRIVKEY_PRIME_P_TAG, rsa->privkey.p.data,
		    rsa->privkey.p.len, &payload))
		    	goto asn1_error;

		if (bertlv_put_tag(RSA_PRIVKEY_PRIME_Q_TAG, rsa->privkey.q.data,
		    rsa->privkey.q.len, &payload))
		    	goto asn1_error;

		if (bertlv_put_tag(RSA_PRIVKEY_QINV_TAG, rsa->privkey.iqmp.data,
		    rsa->privkey.iqmp.len, &payload))
		    	goto asn1_error;

		if (bertlv_put_tag(RSA_PRIVKEY_REMAINDER1_TAG,
		    rsa->privkey.dmp1.data, rsa->privkey.dmp1.len, &payload))
		    	goto asn1_error;

		if (bertlv_put_tag(RSA_PRIVKEY_REMAINDER2_TAG,
		    rsa->privkey.dmq1.data, rsa->privkey.dmq1.len, &payload))
		    	goto asn1_error;
	} else {
		if (bertlv_put_tag(RSA_PRIVKEY_MODULUS_TAG,
		    rsa->privkey.modulus.data, rsa->privkey.modulus.len,
		    &payload))
		    	goto asn1_error;

		if (bertlv_put_tag(RSA_PRIVKEY_EXPONENT_TAG,
		    rsa->privkey.d.data, rsa->privkey.d.len, &payload))
		    	goto asn1_error;
	}

	buf_init(&object, object_buf, sizeof(object_buf));

	if (bertlv_put_tag(CONSTRUCTED_DATA_TAG, payload_buf,
	    payload.bytes_used, &object))
	    	goto asn1_error;

	r = push_obj(card, object_buf, object.bytes_used, hash);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "could not push key, r=%d", r);
		return r;
	}

	r = sc_select_file(p15card->card, &keyinfo->path, NULL);
	if (r != SC_SUCCESS)
		return r;

	return store_privkey(card, keyinfo->key_reference, SC_ALGORITHM_RSA,
	    active, pin_ref, hash);

asn1_error:
	sc_log(card->ctx, "asn1 error");

	return SC_ERROR_BUFFER_TOO_SMALL;
}

static int
extract_curve_oid(struct sc_card *card, const sc_pkcs15_prkey_info_t *keyinfo,
    buf_t *payload)
{
	struct sc_pkcs15_ec_parameters	*param;

	if (keyinfo->params.len != sizeof(struct sc_pkcs15_ec_parameters)) {
		sc_log(card->ctx, "invalid keyinfo->params.len=%zu",
		    keyinfo->params.len);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	param = (struct sc_pkcs15_ec_parameters *)keyinfo->params.data;
	if (param == NULL) {
	    	sc_log(card->ctx, "invalid param=%p", param);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (payload->size - payload->bytes_used < param->der.len) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	memcpy(payload->ptr, param->der.value, param->der.len);
	payload->ptr += param->der.len;
	payload->bytes_used += param->der.len;

	return SC_SUCCESS;
}

static int
put_ec_privkey(sc_profile_t *profile, struct sc_pkcs15_card *p15card,
    sc_pkcs15_prkey_info_t *keyinfo, const ec_keypair_t *ec, int active)
{
	struct sc_card *card = p15card->card;
	unsigned char	hash[32];
	unsigned char	payload_buf[256];
	unsigned char	object_buf[256];
	buf_t		payload;
	buf_t		object;
	int		pin_ref;
	int		r;

	pin_ref = sc_pkcs15init_get_pin_reference(p15card, profile,
	    SC_AC_SYMBOLIC, SC_PKCS15INIT_USER_PIN);
	if (pin_ref < 0 || pin_ref & BACKTRACK_PIN) {
		sc_log(card->ctx, "invalid pin reference 0x%x", pin_ref);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	buf_init(&payload, payload_buf, sizeof(payload_buf));

	if ((r = extract_curve_oid(card, keyinfo, &payload)) != SC_SUCCESS)
		return r;

	r = sc_pkcs15init_set_lifecycle(card, SC_CARDCTRL_LIFECYCLE_ADMIN);
	if (r != SC_SUCCESS)
		return r;

	if (bertlv_put_tag(ECC_PRIVKEY_D, ec->privkey.privateD.data,
	    ec->privkey.privateD.len, &payload)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	buf_init(&object, object_buf, sizeof(object_buf));

	if (bertlv_put_tag(CONSTRUCTED_DATA_TAG, payload_buf,
	    payload.bytes_used, &object)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	r = push_obj(card, object_buf, object.bytes_used, hash);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "could not push key, r=%d", r);
		return r;
	}

	r = sc_select_file(p15card->card, &keyinfo->path, NULL);
	if (r != SC_SUCCESS)
		return r;

	return store_privkey(card, keyinfo->key_reference, SC_ALGORITHM_EC,
	    active, pin_ref, hash);
}

static int
store_pubkey(sc_card_t *card, int key_id, int algo, unsigned char *hash)
{
	struct sc_cardctl_cardos_obj_info	args;
	uint8_t					payload_buf[256];
	buf_t					payload;

	buf_init(&payload, payload_buf, sizeof(payload_buf));

	if (add_key_crt(key_id, algo, 0, 1, &payload) ||
	    asn1_put_tag(CARDOS5_ACCUMULATE_OBJECT_HASH_TAG, hash, 32,
	    &payload)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	memset(&args, 0, sizeof(args));
	args.data = payload_buf;
	args.len = payload.bytes_used;

	return sc_card_ctl(card, SC_CARDCTL_CARDOS_PUT_DATA_OCI, &args);
}

static int
cardos_put_rsa_pubkey(struct sc_pkcs15_card *p15card,
    sc_pkcs15_prkey_info_t *keyinfo, rsa_keypair_t *rsa)
{
	struct sc_card	*card = p15card->card;
	uint8_t		 hash[32];
	uint8_t		 payload_buf[768];
	uint8_t		 object_buf[768];
	buf_t		 payload;
	buf_t		 object;
	int		 r;

	r = sc_pkcs15init_set_lifecycle(card, SC_CARDCTRL_LIFECYCLE_ADMIN);
	if (r != SC_SUCCESS)
		return r;

	buf_init(&payload, payload_buf, sizeof(payload_buf));

	if (bertlv_put_tag(RSA_PUBKEY_MODULUS, rsa->pubkey.modulus.data,
	    rsa->pubkey.modulus.len, &payload))
	    	goto asn1_error;

	if (bertlv_put_tag(RSA_PUBKEY_EXPONENT, rsa->pubkey.exponent.data,
	    rsa->pubkey.exponent.len, &payload))
	    	goto asn1_error;

	buf_init(&object, object_buf, sizeof(object_buf));

	if (bertlv_put_tag(CONSTRUCTED_DATA_TAG, payload_buf,
	    payload.bytes_used, &object))
	    	goto asn1_error;

	r = push_obj(card, object_buf, object.bytes_used, hash);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "could not push key, r=%d", r);
		return r;
	}

	r = sc_select_file(p15card->card, &keyinfo->path, NULL);
	if (r != SC_SUCCESS)
		return r;

	return store_pubkey(card, keyinfo->key_reference, SC_ALGORITHM_RSA,
	    hash);

asn1_error:
	sc_log(card->ctx, "asn1 error");

	return SC_ERROR_BUFFER_TOO_SMALL;
}

static int
put_ec_pubkey(struct sc_pkcs15_card *p15card, sc_pkcs15_prkey_info_t *keyinfo,
    ec_keypair_t *ec)
{
	struct sc_card *card = p15card->card;
	unsigned char	hash[32];
	unsigned char	payload_buf[256];
	unsigned char	object_buf[256];
	buf_t		payload;
	buf_t		object;
	int		r;

	buf_init(&payload, payload_buf, sizeof(payload_buf));

	if ((r = extract_curve_oid(card, keyinfo, &payload)) != SC_SUCCESS)
		return r;

	r = sc_pkcs15init_set_lifecycle(card, SC_CARDCTRL_LIFECYCLE_ADMIN);
	if (r != SC_SUCCESS)
		return r;

	if (bertlv_put_tag(ECC_PUBKEY_Y, ec->pubkey.ecpointQ.value,
	    ec->pubkey.ecpointQ.len, &payload)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	buf_init(&object, object_buf, sizeof(object_buf));

	if (bertlv_put_tag(CONSTRUCTED_DATA_TAG, payload_buf,
	    payload.bytes_used, &object)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	r = push_obj(card, object_buf, object.bytes_used, hash);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "could not push key, r=%d", r);
		return r;
	}

	r = sc_select_file(p15card->card, &keyinfo->path, NULL);
	if (r != SC_SUCCESS)
		return r;

	return store_pubkey(card, keyinfo->key_reference, SC_ALGORITHM_EC,
	    hash);
}

static int
extract_rsa_pubkey(sc_card_t *card, struct sc_pkcs15_prkey_info *keyinfo,
    sc_pkcs15_pubkey_t *pubkey)
{
	struct sc_cardctl_cardos5_genkey_info	args;
	uint16_t				taglen;
	uint8_t					payload_buf[256];
	uint8_t					crt_buf[24];
	size_t					modulus_bytes;
	buf_t					crt;
	buf_t					payload;
	buf_t					keybuf;
	int					r;

	modulus_bytes = keyinfo->modulus_length / 8;
	if (modulus_bytes == 0 || modulus_bytes > 1024) {
		sc_log(card->ctx, "invalid modulus %zu", modulus_bytes);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	buf_init(&crt, crt_buf, sizeof(crt_buf));
	buf_init(&payload, payload_buf, sizeof(payload_buf));

	if (add_key_crt(keyinfo->key_reference, SC_ALGORITHM_RSA, 1, 1, &crt) ||
	    asn1_put_tag(CRT_DO_DST, crt_buf, crt.bytes_used, &payload)) {
	    	sc_log(card->ctx, "asn1 error");
	    	return SC_ERROR_BUFFER_TOO_SMALL;
	}

	memset(&args, 0, sizeof(args));
	args.data = payload_buf;
	args.len = payload.bytes_used;
	r = sc_card_ctl(card, SC_CARDCTL_CARDOS_EXTRACT_KEY, &args);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "key extraction failed, r=%d", r);
		return r;
	}

	buf_init(&keybuf, args.data, args.len);

	if (bertlv_get_tag(0x7F49, NULL, &taglen, &keybuf))
		goto parse_error;

	if (bertlv_get_tag(RSA_PUBKEY_MODULUS, &pubkey->u.rsa.modulus.data,
	    (uint16_t *)&pubkey->u.rsa.modulus.len, &keybuf))
	    	goto parse_error;

	if (pubkey->u.rsa.modulus.len != modulus_bytes)
		goto parse_error;

	if (bertlv_get_tag(RSA_PUBKEY_EXPONENT, &pubkey->u.rsa.exponent.data,
	    (uint16_t *)&pubkey->u.rsa.exponent.len, &keybuf))
	    	goto parse_error;

	free(args.data);

	pubkey->algorithm = SC_ALGORITHM_RSA;

	return SC_SUCCESS;

parse_error:
    	free(args.data);
	sc_log(card->ctx, "couldn't parse rsa pubkey");

	return SC_ERROR_OBJECT_NOT_VALID;
}

/* Components of a public key as produced by the card. */
static const uint16_t pubkey_parts[] = {
	0x7F49,
	ECC_PUBKEY_OID,
	ECD_PRIME_P,
	ECD_COEFFICIENT_A,
	ECD_COEFFICIENT_B,
	ECD_GENERATOR_POINT_G,
	ECD_ORDER_R,
};

static const int n_pubkey_parts = sizeof(pubkey_parts) / sizeof(uint16_t);

static int
extract_ec_pubkey(sc_card_t *card, sc_pkcs15_prkey_info_t *keyinfo,
    sc_pkcs15_pubkey_t *pubkey)
{
	struct sc_cardctl_cardos5_genkey_info	 args;
	struct sc_ec_params			*ecp = NULL;
	uint8_t			 		 payload_buf[768];
	uint8_t			 		 crt_buf[24];
	buf_t			 		 payload;
	buf_t			 		 crt;
	buf_t			 		 keybuf;
	int			 		 i;
	int			 		 r;

	buf_init(&crt, crt_buf, sizeof(crt_buf));
	buf_init(&payload, payload_buf, sizeof(payload_buf));

	if (add_key_crt(keyinfo->key_reference, SC_ALGORITHM_EC, 1, 1, &crt) ||
	    asn1_put_tag(CRT_DO_DST, crt_buf, crt.bytes_used, &payload)) {
	    	sc_log(card->ctx, "asn1 error");
	    	return SC_ERROR_BUFFER_TOO_SMALL;
	}

	memset(&args, 0, sizeof(args));
	args.data = payload_buf;
	args.len = payload.bytes_used;

	r = sc_card_ctl(card, SC_CARDCTL_CARDOS_EXTRACT_KEY, &args);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "key extraction failed, r=%d", r);
		return r;
	}

	ecp = calloc(1, sizeof(*ecp));
	if (ecp == NULL) {
		sc_log(card->ctx, "calloc");
		return SC_ERROR_OUT_OF_MEMORY;
	}

	pubkey->alg_id = calloc(1, sizeof(struct sc_algorithm_id));
	if (pubkey->alg_id == NULL) {
		sc_log(card->ctx, "calloc");
		return SC_ERROR_OUT_OF_MEMORY;
	}

	buf_init(&keybuf, args.data, args.len);

	/* Skip parts we are not interested in. */
	for (i = 0; i < n_pubkey_parts; i++) {
		uint16_t taglen;

		if (pubkey_parts[i] == ECC_PUBKEY_OID) {
			uint8_t	*oid, *encoded_oid_buf;
			buf_t	 encoded_oid;

			if (bertlv_get_tag(ECC_PUBKEY_OID, &oid, &taglen,
			    &keybuf)) {
				sc_log(card->ctx, "couldn't get oid");
				goto parse_error;
			}

			encoded_oid_buf = calloc(1, taglen + 2);
			if (encoded_oid_buf == NULL) {
				sc_log(card->ctx, "calloc");
				goto parse_error;
			}

			buf_init(&encoded_oid, encoded_oid_buf, taglen + 2);

			if (bertlv_put_tag(ECC_PUBKEY_OID, oid, taglen,
			    &encoded_oid)) {
				sc_log(card->ctx, "couldn't encode oid");
				free(encoded_oid_buf);
				goto parse_error;
			}

			ecp->der_len = encoded_oid.bytes_used;
			ecp->der = encoded_oid_buf;
			ecp->type = 1;

			pubkey->u.ec.params.der.value = calloc(1, ecp->der_len);
			if (pubkey->u.ec.params.der.value == NULL) {
				sc_log(card->ctx, "calloc");
				free(encoded_oid_buf);
				goto parse_error;
			}

			memcpy(pubkey->u.ec.params.der.value, ecp->der,
			    ecp->der_len);
			pubkey->u.ec.params.der.len = ecp->der_len;
		} else {
			if (bertlv_get_tag(pubkey_parts[i], NULL, &taglen,
			    &keybuf)) {
				sc_log(card->ctx, "couldn't parse ec pubkey "
				    "(0x%x)", pubkey_parts[i]);
				goto parse_error;
			}

			if (i > 0) {
				keybuf.ptr += taglen;
				keybuf.bytes_used += taglen;
			}
		}
	}

	if (bertlv_get_tag(ECC_PUBKEY_Y, &pubkey->u.ec.ecpointQ.value,
	    (uint16_t *)&pubkey->u.ec.ecpointQ.len, &keybuf)) {
		sc_log(card->ctx, "couldn't parse ec pubkey");
	    	goto parse_error;
	}

	free(args.data);

	pubkey->algorithm = SC_ALGORITHM_EC;
	pubkey->alg_id->algorithm = SC_ALGORITHM_EC;
	pubkey->alg_id->params = ecp;

	sc_pkcs15_fix_ec_parameters(card->ctx, &pubkey->u.ec.params);

	return SC_SUCCESS;

parse_error:
    	free(args.data);
	free(ecp);
	return SC_ERROR_OBJECT_NOT_VALID;
}

static int
generate_rsa_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
    sc_pkcs15_object_t *obj, sc_pkcs15_pubkey_t *pubkey)
{
	struct sc_cardctl_cardos5_genkey_info args;
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *keyinfo = obj->data;
	unsigned char dummy_key_data[512], payload_buf[256];
	unsigned char crt_buf[24]; /* Control Reference Template */
	buf_t crt = { crt_buf, sizeof(crt_buf), 0 };
	buf_t payload = { payload_buf, sizeof(payload_buf), 0 };
	struct sc_file *file = NULL;
	size_t keybits;
	rsa_keypair_t rsa;
	int r;

	if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA)
		return SC_ERROR_NOT_SUPPORTED;

	if ((keybits = keyinfo->modulus_length & ~7UL) > 4096) {
		sc_log(ctx, "unsupported key size %zu", keybits);
		return SC_ERROR_NOT_SUPPORTED;
	}

	r = sc_select_file(p15card->card, &keyinfo->path, &file);
	if (r) {
		sc_log(ctx, "sc_select_file failed, r=%d", r);
		return r;
	}

	r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_UPDATE);
	sc_file_free(file);
	if (r) {
		sc_log(ctx, "sc_pkcs15init_authenticate failed, r=%d", r);
		return r;
	}

	memset(dummy_key_data, 0xFF, sizeof(dummy_key_data));
	fill_in_dummy_rsa_key(&rsa, dummy_key_data, keybits);

	r = cardos_put_rsa_privkey(profile, p15card, keyinfo, &rsa, 0);
	if (r != SC_SUCCESS) {
		sc_log(ctx, "could not put privkey, r=%d", r);
		return r;
	}

	/*
	 * CardOS 5 requires an additional public key stub for key generation.
	 */
	if ((r = cardos_put_rsa_pubkey(p15card, keyinfo, &rsa)) != SC_SUCCESS) {
		sc_log(ctx, "could not put pubkey, r=%d", r);
		return r;
	}

	if (add_key_crt(keyinfo->key_reference, SC_ALGORITHM_RSA, 0, 0, &crt) ||
	    asn1_put_tag(CRT_DO_DST, crt_buf, crt.bytes_used, &payload)) {
	    	sc_log(ctx, "asn1 error");
	    	return SC_ERROR_BUFFER_TOO_SMALL;
	}

	memset(&args, 0, sizeof(args));
	args.data = payload_buf;
	args.len = payload.bytes_used;
	r = sc_card_ctl(p15card->card, SC_CARDCTL_CARDOS_GENERATE_KEY, &args);
	if (r != SC_SUCCESS) {
		sc_log(ctx, "key generation failed, r=%d", r);
		return r;
	}

	memset(pubkey, 0, sizeof(*pubkey));
	r = extract_rsa_pubkey(p15card->card, keyinfo, pubkey);
	if (r != SC_SUCCESS) {
		sc_log(ctx, "key extraction failed, r=%d", r);
		if (pubkey->u.rsa.modulus.data != NULL)
			free(pubkey->u.rsa.modulus.data);
		if (pubkey->u.rsa.exponent.data != NULL)
			free(pubkey->u.rsa.exponent.data);
		return r;
	}

	return SC_SUCCESS;
}

static int
generate_ec_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
    sc_pkcs15_object_t *obj, sc_pkcs15_pubkey_t *pubkey)
{
	struct sc_cardctl_cardos5_genkey_info	 args;
	struct sc_pkcs15_prkey_info		*keyinfo = obj->data;
	struct sc_context			*ctx = p15card->card->ctx;
	struct sc_file				*file = NULL;
	ec_keypair_t				 ec;
	uint8_t					 dummyQ[256];
	uint8_t					 dummyD[256];
	uint8_t					 payload_buf[256];
	uint8_t					 crt_buf[24];
	size_t					 keybits;
	buf_t					 crt;
	buf_t					 payload;
	int					 r;

	if (obj->type != SC_PKCS15_TYPE_PRKEY_EC)
		return SC_ERROR_NOT_SUPPORTED;

	keybits = keyinfo->modulus_length & ~7UL;
	if (keybits < 160 || keybits > 512) {
		sc_log(ctx, "unsupported key size %zu", keybits);
		return SC_ERROR_NOT_SUPPORTED;
	}

	r = sc_select_file(p15card->card, &keyinfo->path, &file);
	if (r) {
		sc_log(ctx, "sc_select_file failed, r=%d", r);
		return r;
	}

	r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_UPDATE);
	sc_file_free(file);
	if (r) {
		sc_log(ctx, "sc_pkcs15init_authenticate failed, r=%d", r);
		return r;
	}

	memset(dummyQ, 0xFF, sizeof(dummyQ));
	memset(dummyD, 0xFF, sizeof(dummyD));
	fill_in_dummy_ec_key(&ec, dummyQ, dummyD, keybits);

	r = put_ec_privkey(profile, p15card, keyinfo, &ec, 0);
	if (r != SC_SUCCESS) {
		sc_log(ctx, "could not put privkey, r=%d", r);
		return r;
	}

	/*
	 * CardOS 5 requires an additional public key stub for key generation.
	 */
	r = put_ec_pubkey(p15card, keyinfo, &ec);
	if (r != SC_SUCCESS) {
		sc_log(ctx, "could not put pubkey, r=%d", r);
		return r;
	}

	buf_init(&crt, crt_buf, sizeof(crt_buf));
	buf_init(&payload, payload_buf, sizeof(payload_buf));

	if (add_key_crt(keyinfo->key_reference, SC_ALGORITHM_EC, 0, 0, &crt) ||
	    asn1_put_tag(CRT_DO_DST, crt_buf, crt.bytes_used, &payload)) {
	    	sc_log(ctx, "asn1 error");
	    	return SC_ERROR_BUFFER_TOO_SMALL;
	}

	memset(&args, 0, sizeof(args));
	args.data = payload_buf;
	args.len = payload.bytes_used;
	r = sc_card_ctl(p15card->card, SC_CARDCTL_CARDOS_GENERATE_KEY, &args);
	if (r != SC_SUCCESS) {
		sc_log(ctx, "key generation failed, r=%d", r);
		return r;
	}

	memset(pubkey, 0, sizeof(*pubkey));
	r = extract_ec_pubkey(p15card->card, keyinfo, pubkey);
	if (r != SC_SUCCESS) {
		free(pubkey->u.ec.ecpointQ.value);
		return r;
	}

	return SC_SUCCESS;
}

static int
cardos5_generate_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
    sc_pkcs15_object_t *obj, sc_pkcs15_pubkey_t *pubkey)
{
	struct sc_context	*ctx = p15card->card->ctx;

	switch (obj->type) {
	case SC_PKCS15_TYPE_PRKEY_RSA:
		return generate_rsa_key(profile, p15card, obj, pubkey);
	case SC_PKCS15_TYPE_PRKEY_EC:
		return generate_ec_key(profile, p15card, obj, pubkey);
	default:
		sc_log(ctx, "unsupported key type %d", (int)obj->type);
		return SC_ERROR_NOT_SUPPORTED;
	}
}

static int
cardos5_store_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
    sc_pkcs15_object_t *obj, sc_pkcs15_prkey_t *key)
{
	struct sc_context	*ctx = p15card->card->ctx;
	sc_pkcs15_prkey_info_t	*keyinfo = obj->data;
	struct sc_file		*file = NULL;
	rsa_keypair_t		 rsa;
	int			 r;

	if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA ||
	    keyinfo->usage != SC_PKCS15_PRKEY_USAGE_SIGN ||
	    keyinfo->modulus_length > 4096) {
	    	sc_log(ctx, "only sign rsa keys <= 4096-bit are supported");
	    	return SC_ERROR_NOT_SUPPORTED;
	}

	r = sc_select_file(p15card->card, &keyinfo->path, &file);
	if (r) {
		sc_log(ctx, "sc_select_file failed, r=%d", r);
		return r;
	}

	r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_UPDATE);
	sc_file_free(file);
	if (r) {
		sc_log(ctx, "sc_pkcs15init_authenticate failed, r=%d", r);
		return r;
	}

	memset(&rsa, 0x00, sizeof(rsa));
	rsa.bytes = keyinfo->modulus_length / 8;

	/* >= 2048-bit keys follow the Chinese Remainder Theorem format. */
	if (rsa.bytes > 256) {
		rsa.privkey.p.data = key->u.rsa.p.data;
		rsa.privkey.p.len = key->u.rsa.p.len;
		rsa.privkey.q.data = key->u.rsa.q.data;
		rsa.privkey.q.len = key->u.rsa.q.len;
		rsa.privkey.iqmp.data = key->u.rsa.iqmp.data;
		rsa.privkey.iqmp.len = key->u.rsa.iqmp.len;
		rsa.privkey.dmp1.data = key->u.rsa.dmp1.data;
		rsa.privkey.dmp1.len = key->u.rsa.dmp1.len;
		rsa.privkey.dmq1.data = key->u.rsa.dmq1.data;
		rsa.privkey.dmq1.len = key->u.rsa.dmq1.len;
	} else {
		rsa.privkey.modulus.data = key->u.rsa.modulus.data;
		rsa.privkey.modulus.len = key->u.rsa.modulus.len;
		rsa.privkey.d.data = key->u.rsa.d.data;
		rsa.privkey.d.len = key->u.rsa.d.len;
	}

	r = cardos_put_rsa_privkey(profile, p15card, keyinfo, &rsa, 1);
	if (r != SC_SUCCESS) {
		sc_log(ctx, "could not put privkey, r=%d", r);
		return r;
	}

	return SC_SUCCESS;
}

static int
cardos5_init_card(sc_profile_t *profile, sc_pkcs15_card_t *p15card)
{
	return sc_card_ctl(p15card->card, SC_CARDCTL_CARDOS_INIT_CARD, NULL);
}

static struct sc_pkcs15init_operations cardos5_ops, *cardos4_ops = NULL;

struct sc_pkcs15init_operations *
sc_pkcs15init_get_cardos5_ops(void)
{
	if (cardos4_ops == NULL)
		cardos4_ops = sc_pkcs15init_get_cardos_ops();

	cardos5_ops = *cardos4_ops;
	cardos5_ops.create_pin = cardos5_create_pin;
	cardos5_ops.generate_key = cardos5_generate_key;
	cardos5_ops.store_key = cardos5_store_key;
	cardos5_ops.init_card = cardos5_init_card;

	return &cardos5_ops;
}
