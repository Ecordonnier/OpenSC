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

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "asn1.h"
#include "iso7816.h"
#include "cardctl.h"
#include "card-cardos5.h"

static struct sc_cardos5_am_byte ef_acl[] = {
	{ AM_EF_DELETE,			SC_AC_OP_DELETE },
	{ AM_EF_TERMINATE,		-1U },
	{ AM_EF_ACTIVATE,		SC_AC_OP_REHABILITATE },
	{ AM_EF_DEACTIVATE,		SC_AC_OP_INVALIDATE },
	{ AM_EF_WRITE,			SC_AC_OP_WRITE },
	{ AM_EF_UPDATE,			SC_AC_OP_UPDATE },
	{ AM_EF_READ,			SC_AC_OP_READ },
	{ AM_EF_INCREASE,		-1U },
	{ AM_EF_DECREASE,		-1U },
};

static struct sc_cardos5_am_byte df_acl[] = {
	{ AM_DF_DELETE_SELF,		SC_AC_OP_DELETE },
	{ AM_DF_TERMINATE,		-1U },
	{ AM_DF_ACTIVATE,		SC_AC_OP_REHABILITATE },
	{ AM_DF_DEACTIVATE,		SC_AC_OP_INVALIDATE },
	{ AM_DF_CREATE_DF_FILE,		SC_AC_OP_CREATE },
	{ AM_DF_CREATE_EF_FILE,		SC_AC_OP_CREATE },
	{ AM_DF_DELETE_CHILD,		-1U },
	{ AM_DF_PUT_DATA_OCI,		SC_AC_OP_CREATE },
	{ AM_DF_PUT_DATA_OCI_UPDATE,	SC_AC_OP_UPDATE },
	{ AM_DF_LOAD_EXECUTABLE,	-1U },
	{ AM_DF_PUT_DATA_FCI,		SC_AC_OP_CREATE },
};

static const int ef_acl_n = sizeof(ef_acl) / sizeof(struct sc_cardos5_am_byte);
static const int df_acl_n = sizeof(df_acl) / sizeof(struct sc_cardos5_am_byte);
static const struct sc_card_operations *iso_ops = NULL;
static const struct sc_card_operations *cardos4_ops = NULL;

static struct sc_card_operations cardos5_ops;

static struct sc_card_driver cardos5_drv = {
	"Atos CardOS",
	"cardos5",
	&cardos5_ops,
	NULL, 0, NULL
};

static struct sc_atr_table cardos5_atrs[] = {
	/* CardOS v5.0 */
	{ "3b:d2:18:00:81:31:fe:58:c9:01:14", NULL, NULL,
	  SC_CARD_TYPE_CARDOS_V5_0, 0, NULL},
	/* CardOS v5.3 */
	{ "3b:d2:18:00:81:31:fe:58:c9:03:16", NULL, NULL,
	  SC_CARD_TYPE_CARDOS_V5_3, 0, NULL},
	{ NULL, NULL, NULL, 0, 0, NULL }
};

typedef struct {
	uint8_t	*ptr;
	size_t	 size;
	size_t	 bytes_used;
} buf_t;

typedef struct {
	uint8_t *encoded_ptr;
	size_t	 encoded_len;
	size_t	 raw_len;
} coordinate_t;

struct cardos5_private_data {
	/* Current Security Environment Algorithm */
	unsigned int	cse_algorithm;
};

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
add_acl_tag(uint8_t am_byte, unsigned int ac, unsigned int key_ref, buf_t *buf)
{
	uint8_t	crt_buf[16];
	buf_t	crt;

	if (am_byte != 0xff)
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
		if ((key_ref & BACKTRACK_PIN) || key_ref > UINT8_MAX)
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
cardos5_match_card(sc_card_t *card)
{
	if (_sc_match_atr(card, cardos5_atrs, &card->type) < 0)
		return 0;

	return 1;
}

static int
cardos5_init(sc_card_t *card)
{
	struct cardos5_private_data	*priv;
	unsigned int			 flags;

	priv = calloc(1, sizeof(*priv));
	if (priv == NULL) {
		sc_log(card->ctx, "calloc");
		return SC_ERROR_OUT_OF_MEMORY;
	}

	priv->cse_algorithm = -1U;
	card->drv_data = priv;

	flags = SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_HASH_NONE |
	    SC_ALGORITHM_ONBOARD_KEY_GEN;

	card->name = "CardOS M5";
	card->caps |= SC_CARD_CAP_APDU_EXT;
	card->cla = 0x00;

	_sc_card_add_rsa_alg(card,  512, flags, 0);
	_sc_card_add_rsa_alg(card,  768, flags, 0);
	_sc_card_add_rsa_alg(card, 1024, flags, 0);
	_sc_card_add_rsa_alg(card, 1280, flags, 0);
	_sc_card_add_rsa_alg(card, 1536, flags, 0);
	_sc_card_add_rsa_alg(card, 1792, flags, 0);
	_sc_card_add_rsa_alg(card, 2048, flags, 0);
	_sc_card_add_rsa_alg(card, 2304, flags, 0);
	_sc_card_add_rsa_alg(card, 2560, flags, 0);
	_sc_card_add_rsa_alg(card, 2816, flags, 0);
	_sc_card_add_rsa_alg(card, 3072, flags, 0);
	_sc_card_add_rsa_alg(card, 3328, flags, 0);
	_sc_card_add_rsa_alg(card, 3584, flags, 0);
	_sc_card_add_rsa_alg(card, 3840, flags, 0);
	_sc_card_add_rsa_alg(card, 4096, flags, 0);

	flags = SC_ALGORITHM_ECDSA_RAW | SC_ALGORITHM_ONBOARD_KEY_GEN;

	_sc_card_add_ec_alg(card, 192, flags, 0);
	_sc_card_add_ec_alg(card, 224, flags, 0);
	_sc_card_add_ec_alg(card, 256, flags, 0);
	_sc_card_add_ec_alg(card, 384, flags, 0);
	_sc_card_add_ec_alg(card, 512, flags, 0);

	return 0;
}

static int
cardos5_finish(sc_card_t *card)
{
	free(card->drv_data);
	card->drv_data = NULL;

	return SC_SUCCESS;
}

static int
cardos5_list_files(sc_card_t *card, unsigned char *buf, size_t buflen)
{
	return SC_ERROR_NOT_SUPPORTED;
}

static int
parse_df_arl(sc_card_t *card, sc_file_t *file, const uint8_t *arl, size_t len)
{
	unsigned long	ref;
	unsigned int	ac;
	int		i;
	int		r;

	/*
	 * The MF is created with an ARL consisting of the sequence { 0x81,
	 * 0x00, 0x90, 0x00 }, meaning "allow everything". Recognise it, and
	 * call sc_file_add_acl_entry() accordingly.
	 */

	if (file->id == 0x3f00) {
		for (i = 0; i < df_acl_n; i++) {
			if (df_acl[i].op_byte != -1U) {
				r = sc_file_add_acl_entry(file,
				    df_acl[i].op_byte, SC_AC_NONE,
				    SC_AC_KEY_REF_NONE);
				if (r != SC_SUCCESS)
					return r;
			}
		}
		return SC_SUCCESS;
	}

	while (len >= 5) {
		/* This is needed to allow ACCUMULATE OBJECT DATA. */
		if (arl[0] == ARL_COMMAND_TAG) {
			if (len < 8)
				return SC_ERROR_WRONG_LENGTH;
			if (arl[6] == ARL_USER_AUTH_TAG) {
				size_t skip = arl[7];
				if (len < skip + 8)
					return SC_ERROR_WRONG_LENGTH;
				arl += skip;
				len -= skip;
			}
			arl += 8;
			len -= 8;
			continue;
		}

		if (arl[0] != ARL_ACCESS_MODE_BYTE_TAG ||
		    arl[1] != ARL_ACCESS_MODE_BYTE_LEN)
			return SC_ERROR_NO_CARD_SUPPORT;

		for (i = 0; i < df_acl_n; i++)
			if (df_acl[i].am_byte == arl[2])
				break;
		if (i == df_acl_n)
			return SC_ERROR_NO_CARD_SUPPORT;

		ref = SC_AC_KEY_REF_NONE;

		switch (arl[3]) {
		case ARL_ALWAYS_TAG:
			if (arl[4] != ARL_ALWAYS_LEN)
				return SC_ERROR_NO_CARD_SUPPORT;
			ac = SC_AC_NONE;
			arl += 5;
			len -= 5;
			break;
		case ARL_NEVER_TAG:
			if (arl[4] != ARL_NEVER_LEN)
				return SC_ERROR_NO_CARD_SUPPORT;
			ac = SC_AC_NEVER;
			arl += 5;
			len -= 5;
			break;
		case ARL_USER_AUTH_TAG:
			if (len < 11)
				return SC_ERROR_WRONG_LENGTH;
			if (arl[4] != ARL_USER_AUTH_LEN ||
			    arl[5] != CRT_TAG_PINREF ||
			    arl[6] != CRT_LEN_PINREF)
				return SC_ERROR_NO_CARD_SUPPORT;
			if (arl[8] != CRT_TAG_KUQ ||
			    arl[9] != CRT_LEN_KUQ ||
			    arl[10] != KUQ_USER_AUTH)
				return SC_ERROR_NO_CARD_SUPPORT;
			ac = SC_AC_CHV;
			ref = arl[7] & BACKTRACK_MASK;
			arl += 11;
			len -= 11;
			break;
		default:
			return SC_ERROR_NO_CARD_SUPPORT;
		}

		if (df_acl[i].op_byte != -1U) {
			r = sc_file_add_acl_entry(file, df_acl[i].op_byte, ac,
			    ref);
			if (r != SC_SUCCESS)
				return r;
		}
	}

	if (len != 0)
		return SC_ERROR_WRONG_LENGTH;

	return SC_SUCCESS;
}

static int
parse_ef_arl(sc_card_t *card, sc_file_t *file, const uint8_t *arl, size_t len)
{
	unsigned long	ref;
	unsigned int	ac;
	int		i;
	int		r;

	while (len >= 5) {
		if (arl[0] != ARL_ACCESS_MODE_BYTE_TAG ||
		    arl[1] != ARL_ACCESS_MODE_BYTE_LEN)
			return SC_ERROR_NO_CARD_SUPPORT;

		for (i = 0; i < ef_acl_n; i++)
			if (ef_acl[i].am_byte == arl[2])
				break;
		if (i == ef_acl_n)
			return SC_ERROR_NO_CARD_SUPPORT;

		ref = SC_AC_KEY_REF_NONE;

		switch (arl[3]) {
		case ARL_ALWAYS_TAG:
			if (arl[4] != ARL_ALWAYS_LEN)
				return SC_ERROR_NO_CARD_SUPPORT;
			ac = SC_AC_NONE;
			arl += 5;
			len -= 5;
			break;
		case ARL_NEVER_TAG:
			if (arl[4] != ARL_NEVER_LEN)
				return SC_ERROR_NO_CARD_SUPPORT;
			ac = SC_AC_NEVER;
			arl += 5;
			len -= 5;
			break;
		case ARL_USER_AUTH_TAG:
			if (len < 11)
				return SC_ERROR_WRONG_LENGTH;
			if (arl[4] != ARL_USER_AUTH_LEN ||
			    arl[5] != CRT_TAG_PINREF ||
			    arl[6] != CRT_LEN_PINREF)
				return SC_ERROR_NO_CARD_SUPPORT;
			if (arl[8] != CRT_TAG_KUQ ||
			    arl[9] != CRT_LEN_KUQ ||
			    arl[10] != KUQ_USER_AUTH)
				return SC_ERROR_NO_CARD_SUPPORT;
			ac = SC_AC_CHV;
			ref = arl[7] & BACKTRACK_MASK;
			arl += 11;
			len -= 11;
			break;
		default:
			return SC_ERROR_NO_CARD_SUPPORT;
		}

		if (ef_acl[i].op_byte != -1U) {
			r = sc_file_add_acl_entry(file, ef_acl[i].op_byte, ac,
			    ref);
			if (r != SC_SUCCESS)
				return r;
		}
	}

	if (len != 0)
		return SC_ERROR_WRONG_LENGTH;

	return SC_SUCCESS;
}

static int
parse_arl(sc_card_t *card, sc_file_t *file, const uint8_t *arl, size_t len)
{
	switch (file->type) {
	case SC_FILE_TYPE_DF:
		return parse_df_arl(card, file, arl, len);
	case SC_FILE_TYPE_WORKING_EF:
		return parse_ef_arl(card, file, arl, len);
	default:
		sc_log(card->ctx, "invalid file type %d", file->type);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
}

static int
cardos5_process_fci(struct sc_card *card, struct sc_file *file,
    const unsigned char *buf, size_t buflen)
{
	const uint8_t	*tag;
	size_t		 taglen;
	int		 r;

	if ((r = iso_ops->process_fci(card, file, buf, buflen)) != SC_SUCCESS)
		return r;

	tag = sc_asn1_find_tag(card->ctx, buf, buflen, 0xAB, &taglen);
	if (tag != NULL && taglen != 0)
		sc_file_set_sec_attr(file, tag, taglen);

	return SC_SUCCESS;
}

static int
cardos5_select_file(sc_card_t *card, const sc_path_t *path,
    sc_file_t **file_out)
{
	struct sc_context	*ctx = card->ctx;
	struct sc_file		*file = NULL;
	struct sc_apdu		 apdu;
	uint8_t			 buf[SC_MAX_APDU_BUFFER_SIZE];
	int			 r;

	if (path->type != SC_PATH_TYPE_PATH || path->len < 2 ||
	    path->value[0] != 0x3F || path->value[1] != 0x00) {
		sc_log(ctx, "invalid arguments");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	memset(&buf, 0, sizeof(buf));
	memset(&apdu, 0, sizeof(apdu));
	apdu.ins = CARDOS5_SELECT_INS;

	if (path->len == 2) {
		/*
		 * only 0x3F00 supplied; keep it.
		 */
		apdu.p1 = CARDOS5_SELECT_P1_FILE_ID;
		apdu.lc = path->len;
		apdu.data = (unsigned char *)path->value;
		apdu.datalen = path->len;
	} else {
		/*
		 * skip 0x3F00; 'path' holds a complete path relative to the MF.
		 */
		apdu.p1 = CARDOS5_SELECT_P1_FULL_PATH;
		apdu.lc = path->len - 2;
		apdu.data = (unsigned char *)path->value + 2;
		apdu.datalen = path->len - 2;
	}


	if (file_out != NULL) {
		/* ask the card to return FCI metadata. */
		apdu.p2 = CARDOS5_SELECT_P2_FCI;
		apdu.resp = buf;
		apdu.resplen = sizeof(buf);
		apdu.le = 256;
		apdu.cse = SC_APDU_CASE_4_SHORT;
	} else {
		/* no metadata required. */
		apdu.p2 = CARDOS5_SELECT_P2_NO_RESPONSE;
		apdu.cse = SC_APDU_CASE_3_SHORT;
	}

	if ((r = sc_transmit_apdu(card, &apdu)) != SC_SUCCESS) {
		sc_log(ctx, "tx/rx error");
		return r;
	}

	if ((r = sc_check_sw(card, apdu.sw1, apdu.sw2)) != SC_SUCCESS) {
		sc_log(ctx, "command failed");
		return r;
	}

	if (file_out == NULL)
		return SC_SUCCESS;

	if (apdu.resplen < 2 || apdu.resp[0] != ISO7816_TAG_FCI ||
	    (apdu.resp[1] != 0x81 && apdu.resp[1] != 0x82)) {
		sc_log(ctx, "invalid response");
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	}

	if ((file = sc_file_new()) == NULL) {
		sc_log(ctx, "out of memory");
		return SC_ERROR_OUT_OF_MEMORY;
	}

	/*
	 * In CardOS 5.0 with FCI, the length is BER-TLV encoded.
	 */
	if (apdu.resp[1] == 0x81) {
		card->ops->process_fci(card, file,
		    (unsigned char *)apdu.resp + 3, apdu.resp[2]);
	} else if (apdu.resp[1] == 0x82) {
		int len = (apdu.resp[2] << 8) | apdu.resp[3];
		card->ops->process_fci(card, file,
		    (unsigned char *)apdu.resp + 4, (size_t)len);
	}

	r = parse_arl(card, file, file->sec_attr, file->sec_attr_len);
	if (r != SC_SUCCESS) {
		sc_file_free(file);
		sc_log(card->ctx, "could not parse arl");
		return r;
	}

	*file_out = file;

	return SC_SUCCESS;
}

static int
construct_df_fcp(sc_card_t *card, const sc_file_t *df, buf_t *fcp)
{
	const sc_acl_entry_t	*e = NULL;
	uint8_t			 df_size[2];
	uint8_t			 arl_buf[128];
	uint8_t			 cmd[4];
	buf_t			 arl;
	int			 i;

	if (df->size > UINT16_MAX) {
		sc_log(card->ctx, "df->size too large: %zu", df->size);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	df_size[0] = (df->size >> 8) & 0xff;
	df_size[1] = (df->size & 0xff);

	if (asn1_put_tag1(FCP_TAG_DESCRIPTOR, FCP_TYPE_DF, fcp) ||
	    asn1_put_tag(FCP_TAG_DF_SIZE, df_size, sizeof(df_size), fcp)) {
	    	sc_log(card->ctx, "asn1 error");
	    	return SC_ERROR_BUFFER_TOO_SMALL;
	}

	if (df->namelen != 0 && asn1_put_tag(FCP_TAG_DF_NAME, df->name,
	    df->namelen, fcp)) {
	    	sc_log(card->ctx, "asn1 error");
	    	return SC_ERROR_BUFFER_TOO_SMALL;
	}

	buf_init(&arl, arl_buf, sizeof(arl_buf));

	e = sc_file_get_acl_entry(df, SC_AC_OP_UPDATE);
	if (e != NULL) {
		cmd[0] = 0x00;
		cmd[1] = CARDOS5_PUT_DATA_INS;
		cmd[2] = CARDOS5_PUT_DATA_ECD_P1;
		cmd[3] = CARDOS5_PUT_DATA_ECD_P2;
		if (asn1_put_tag(ARL_COMMAND_TAG, cmd, sizeof(cmd), &arl) ||
		    add_acl_tag(0xff, e->method, e->key_ref, &arl)) {
			return SC_ERROR_BUFFER_TOO_SMALL;
		}

	}

	/* Populate ARL. */
	for (i = 0; i < df_acl_n; i++) {
		unsigned int		 ac = SC_AC_NEVER;
		unsigned int		 keyref = -1U;

		if (df_acl[i].op_byte != -1U) {
			e = sc_file_get_acl_entry(df, df_acl[i].op_byte);
			if (e != NULL) {
				ac = e->method;
				keyref = e->key_ref;
			}
		}

		if (add_acl_tag(df_acl[i].am_byte, ac, keyref, &arl)) {
			sc_log(card->ctx, "could not add acl tag");
			return SC_ERROR_BUFFER_TOO_SMALL;
		}
	}

	/*
	 * Always allow lifecycle toggling through PHASE CONTROL for this DF.
	 */
	cmd[0] = CARDOS5_PHASE_CONTROL_CLA;
	cmd[1] = CARDOS5_PHASE_CONTROL_INS;
	cmd[2] = CARDOS5_PHASE_CONTROL_P1_TOGGLE;
	cmd[3] = CARDOS5_PHASE_CONTROL_P2_TOGGLE;
	if (asn1_put_tag(ARL_COMMAND_TAG, cmd, sizeof(cmd), &arl) ||
	    asn1_put_tag0(ARL_ALWAYS_TAG, &arl)) {
	    	sc_log(card->ctx, "asn1 error");
	    	return SC_ERROR_BUFFER_TOO_SMALL;
	}

	/*
	 * Always allow ACCUMULATE OBJECT DATA for new objects.
	 */
	cmd[0] = CARDOS5_ACCUMULATE_OBJECT_DATA_CLA;
	cmd[1] = CARDOS5_ACCUMULATE_OBJECT_DATA_INS;
	cmd[2] = CARDOS5_ACCUMULATE_OBJECT_DATA_P1_NEW;
	cmd[3] = 0x00;
	if (asn1_put_tag(ARL_COMMAND_TAG, cmd, sizeof(cmd), &arl) ||
	    asn1_put_tag0(ARL_ALWAYS_TAG, &arl)) {
	    	sc_log(card->ctx, "asn1 error");
	    	return SC_ERROR_BUFFER_TOO_SMALL;
	}

	/*
	 * Always allow ACCUMULATE OBJECT DATA for existing objects.
	 */
	cmd[2] = CARDOS5_ACCUMULATE_OBJECT_DATA_P1_APPEND;
	if (asn1_put_tag(ARL_COMMAND_TAG, cmd, sizeof(cmd), &arl) ||
	    asn1_put_tag0(ARL_ALWAYS_TAG, &arl)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	if (asn1_put_tag(FCP_TAG_ARL, arl_buf, arl.bytes_used, fcp)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	return SC_SUCCESS;
}

static int
construct_ef_fcp(sc_card_t *card, const sc_file_t *ef, buf_t *fcp)
{
	uint8_t	ef_size[2];
	uint8_t	arl_buf[96];
	buf_t	arl;
	int	i;

	if (ef->ef_structure != SC_FILE_EF_TRANSPARENT) {
		sc_log(card->ctx, "unsupported ef type %u", ef->type);
		return SC_ERROR_NOT_SUPPORTED;
	}

	if (ef->size > UINT16_MAX) {
		sc_log(card->ctx, "ef->size too large: %zu", ef->size);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	ef_size[0] = (ef->size >> 8) & 0xff;
	ef_size[1] = (ef->size & 0xff);

	if (asn1_put_tag1(FCP_TAG_DESCRIPTOR, FCP_TYPE_BINARY_EF, fcp) ||
	    asn1_put_tag(FCP_TAG_EF_SIZE, ef_size, sizeof(ef_size), fcp) ||
	    asn1_put_tag0(FCP_TAG_EF_SFID, fcp)) {
	    	sc_log(card->ctx, "asn1 error");
	    	return SC_ERROR_BUFFER_TOO_SMALL;
	}

	buf_init(&arl, arl_buf, sizeof(arl_buf));

	/* Populate ARL. */
	for (i = 0; i < ef_acl_n; i++) {
		const sc_acl_entry_t	*e = NULL;
		unsigned int		 ac = SC_AC_NEVER;
		unsigned int		 keyref = -1U;

		if (ef_acl[i].op_byte != -1U) {
			e = sc_file_get_acl_entry(ef, ef_acl[i].op_byte);
			if (e != NULL) {
				ac = e->method;
				keyref = (uint8_t)e->key_ref;
			}
		}

		if (add_acl_tag(ef_acl[i].am_byte, ac, keyref, &arl)) {
			sc_log(card->ctx, "could not add acl tag");
			return SC_ERROR_BUFFER_TOO_SMALL;
		}
	}

	if (asn1_put_tag(FCP_TAG_ARL, arl_buf, arl.bytes_used, fcp)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	return SC_SUCCESS;
}

static int
construct_fcp(sc_card_t *card, const sc_file_t *file, buf_t *buf)
{
	uint8_t	file_id[2];
	uint8_t	fcp_buf[128];
	buf_t	fcp;
	int	r;

	buf_init(&fcp, fcp_buf, sizeof(fcp_buf));

	switch (file->type) {
	case SC_FILE_TYPE_DF:
		r = construct_df_fcp(card, file, &fcp);
		break;
	case SC_FILE_TYPE_WORKING_EF:
		r = construct_ef_fcp(card, file, &fcp);
		break;
	default:
		sc_log(card->ctx, "unsupported file type %u", file->type);
		return SC_ERROR_NOT_SUPPORTED;
	}

	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "could not construct fcp, r=%d", r);
		return r;
	}

	if (file->id < 0 || file->id > UINT16_MAX) {
		sc_log(card->ctx, "invalid file->id=%d", file->id);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	file_id[0] = (file->id >> 8) & 0xff;
	file_id[1] = (file->id & 0xff);

	if (asn1_put_tag(FCP_TAG_FILEID, file_id, sizeof(file_id), &fcp)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	if (asn1_put_tag(FCP_TAG_START, fcp_buf, fcp.bytes_used, buf)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	return SC_SUCCESS;
}

static int
cardos5_create_file(sc_card_t *card, sc_file_t *file)
{
	sc_apdu_t	apdu;
	uint8_t		fcp_buf[SC_MAX_APDU_BUFFER_SIZE];
	buf_t		fcp;
	int		r;

	buf_init(&fcp, fcp_buf, sizeof(fcp_buf));

	if ((r = construct_fcp(card, file, &fcp)) != SC_SUCCESS) {
		sc_log(card->ctx, "could not construct fcp");
		return r;
	}

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.ins = CARDOS5_CREATE_FILE_INS;
	apdu.lc = fcp.bytes_used;
	apdu.datalen = fcp.bytes_used;
	apdu.data = fcp_buf;

	if ((r = sc_transmit_apdu(card, &apdu)) != SC_SUCCESS) {
		sc_log(card->ctx, "tx/rx error");
		return r;
	}

	if ((r = sc_check_sw(card, apdu.sw1, apdu.sw2)) != SC_SUCCESS) {
		sc_log(card->ctx, "command failed");
		return r;
	}

	return SC_SUCCESS;
}

static int
cardos5_restore_security_env(sc_card_t *card, int se_num)
{
	return SC_ERROR_NOT_SUPPORTED;
}

static int
cardos5_set_security_env(sc_card_t *card, const sc_security_env_t *env,
    int se_num)
{
	struct cardos5_private_data	*priv;
	sc_apdu_t			 apdu;
	uint8_t				 data[16];
	buf_t				 buf;
	int				 r;

	priv = card->drv_data;
	if (priv == NULL) {
		sc_log(card->ctx, "inconsistent driver state");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	priv->cse_algorithm = -1U;

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.ins = CARDOS5_MANAGE_SECURITY_ENVIRONMENT_INS;
	apdu.p1 = CARDOS5_MANAGE_SECURITY_ENVIRONMENT_P1_SET;

	switch (env->operation) {
	case SC_SEC_OPERATION_DECIPHER:
		apdu.p2 = CARDOS5_MANAGE_SECURITY_ENVIRONMENT_P2_DECIPHER;
		break;
	case SC_SEC_OPERATION_SIGN:
		apdu.p2 = CARDOS5_MANAGE_SECURITY_ENVIRONMENT_P2_SIGN;
		break;
	default:
		sc_log(card->ctx, "invalid security operation");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	buf_init(&buf, data, sizeof(data));

	if (asn1_put_tag1(CRT_TAG_KEYREF, env->key_ref[0], &buf) ||
	    asn1_put_tag1(CRT_TAG_KUQ, KUQ_DECRYPT, &buf)) {
	    	sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	apdu.lc = apdu.datalen = buf.bytes_used;
	apdu.data = data;

	if ((r = sc_transmit_apdu(card, &apdu)) != SC_SUCCESS) {
		sc_log(card->ctx, "tx/rx error");
		return r;
	}

	if ((r = sc_check_sw(card, apdu.sw1, apdu.sw2)) != SC_SUCCESS) {
		sc_log(card->ctx, "command failed");
		return r;
	}

	priv->cse_algorithm = env->algorithm;

	return SC_SUCCESS;
}

static int
extract_coordinate(sc_card_t *card, coordinate_t *c, buf_t *signature)
{
	if (signature->size - signature->bytes_used < c->raw_len ||
	    c->raw_len >= INT8_MAX)
		return SC_ERROR_BUFFER_TOO_SMALL;

	if (signature->ptr[0] & 0x80) {
		c->encoded_len = c->raw_len + 3;
		c->encoded_ptr = calloc(1, c->encoded_len);
		if (c->encoded_ptr == NULL) {
			sc_log(card->ctx, "malloc");
			return SC_ERROR_OUT_OF_MEMORY;
		}

		c->encoded_ptr[0] = 0x02;
		c->encoded_ptr[1] = (uint8_t)c->raw_len + 1;
		c->encoded_ptr[2] = 0x00; /* Padding byte. */

		memcpy(c->encoded_ptr + 3, signature->ptr, c->raw_len);
	} else {
		c->encoded_len = c->raw_len + 2;
		c->encoded_ptr = calloc(1, c->encoded_len);
		if (c->encoded_ptr == NULL) {
			sc_log(card->ctx, "malloc");
			return SC_ERROR_OUT_OF_MEMORY;
		}

		c->encoded_ptr[0] = 0x02;
		c->encoded_ptr[1] = (uint8_t)c->raw_len;

		memcpy(c->encoded_ptr + 2, signature->ptr, c->raw_len);
	}

	signature->ptr += c->raw_len;
	signature->bytes_used += c->raw_len;

	if (card->type == SC_CARD_TYPE_CARDOS_V5_0) {
		if (signature->size - signature->bytes_used < 2)
			return SC_ERROR_BUFFER_TOO_SMALL;
		signature->ptr += 2;
		signature->bytes_used += 2;
	}

	return SC_SUCCESS;
}

static int
get_point(const coordinate_t *X, const coordinate_t *Y, buf_t *encoded_sig)
{
	uint8_t	*point;
	size_t	 point_len;

	point_len = X->encoded_len + Y->encoded_len;
	if (point_len < X->encoded_len || point_len > UINT16_MAX)
		return SC_ERROR_INVALID_ARGUMENTS;

	point = calloc(1, point_len);
	if (point == NULL)
		return SC_ERROR_OUT_OF_MEMORY;

	memcpy(point, X->encoded_ptr, X->encoded_len);
	memcpy(point + X->encoded_len, Y->encoded_ptr, Y->encoded_len);

	if (bertlv_put_tag(0x30, point, point_len, encoded_sig)) {
		free(point);
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	free(point);

	return SC_SUCCESS;
}

static int
encode_ec_sig(sc_card_t *card, uint8_t *sig, size_t siglen, size_t sigbufsiz)
{
	coordinate_t	 X;
	coordinate_t	 Y;
	uint8_t		*raw_sig_buf;
	size_t		 coordinate_raw_len;
	buf_t		 raw_sig;
	buf_t		 encoded_sig;
	int		 r;

	if (siglen < 4 || siglen > sigbufsiz || (siglen % 2) != 0) {
		sc_log(card->ctx, "invalid siglen=%zu, sigbufsiz=%zu", siglen,
		    sigbufsiz);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (card->type == SC_CARD_TYPE_CARDOS_V5_0)
		coordinate_raw_len = (siglen - 4) / 2;
	else if (card->type == SC_CARD_TYPE_CARDOS_V5_3)
		coordinate_raw_len = siglen / 2;
	else {
		sc_log(card->ctx, "invalid card type %d", card->type);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	raw_sig_buf = calloc(1, siglen);
	if (raw_sig_buf == NULL) {
		sc_log(card->ctx, "calloc");
		return SC_ERROR_OUT_OF_MEMORY;
	}

	memcpy(raw_sig_buf, sig, siglen);
	memset(sig, 0, sigbufsiz);

	buf_init(&raw_sig, raw_sig_buf, siglen);

	memset(&X, 0, sizeof(X));
	memset(&Y, 0, sizeof(Y));

	X.raw_len = Y.raw_len = coordinate_raw_len;

	if ((r = extract_coordinate(card, &X, &raw_sig)) ||
	    (r = extract_coordinate(card, &Y, &raw_sig))) {
		sc_log(card->ctx, "could not decode signature");
		goto bail;
	}

	buf_init(&encoded_sig, sig, sigbufsiz);

	if ((r = get_point(&X, &Y, &encoded_sig))) {
		sc_log(card->ctx, "could not decode signature");
		goto bail;
	}

	r = (int)encoded_sig.bytes_used;

bail:
	free(X.encoded_ptr);
	free(Y.encoded_ptr);
	free(raw_sig_buf);

	return r;
}

static int
cardos5_compute_signature(sc_card_t *card, const unsigned char *data,
    size_t datalen, unsigned char *out, size_t outlen)
{
	struct cardos5_private_data	*priv;
	sc_apdu_t			 apdu;
	int				 r;

	priv = card->drv_data;
	if (priv == NULL || priv->cse_algorithm == -1U) {
		sc_log(card->ctx, "inconsistent driver state");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (outlen < datalen) {
		sc_log(card->ctx, "invalid outlen %zu", outlen);
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_4_EXT;
	apdu.ins = CARDOS5_PERFORM_SECURITY_OPERATION_INS;
	apdu.p1 = CARDOS5_PERFORM_SECURITY_OPERATION_P1_SIGN;
	apdu.p2 = CARDOS5_PERFORM_SECURITY_OPERATION_P2_SIGN;
	apdu.data = (unsigned char *)data;
	apdu.datalen = datalen;
	apdu.lc = datalen;
	apdu.resp = out;
	apdu.resplen = outlen;
	apdu.le = outlen;

	if ((r = sc_transmit_apdu(card, &apdu)) != SC_SUCCESS) {
		sc_log(card->ctx, "tx/rx error");
		return r;
	}

	if ((r = sc_check_sw(card, apdu.sw1, apdu.sw2)) != SC_SUCCESS) {
		sc_log(card->ctx, "command failed");
		return r;
	}

	if (apdu.resplen > INT_MAX) {
		sc_log(card->ctx, "reply too large (%zu bytes)", apdu.resplen);
		return SC_ERROR_WRONG_LENGTH;
	}

	if (priv->cse_algorithm == SC_ALGORITHM_RSA)
		return (int)apdu.resplen;
	else if (priv->cse_algorithm == SC_ALGORITHM_EC)
		return encode_ec_sig(card, out, apdu.resplen, outlen);

	sc_log(card->ctx, "unknown algorithm %d", priv->cse_algorithm);

	return SC_ERROR_INVALID_ARGUMENTS;
}

static int
accumulate_object_data(sc_card_t *card, struct sc_cardctl_cardos_acc_obj_info *args)
{
	sc_apdu_t	apdu;
	uint8_t		rbuf[64];
	int		r;

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_4_SHORT;
	apdu.cla = CARDOS5_ACCUMULATE_OBJECT_DATA_CLA;
	apdu.ins = CARDOS5_ACCUMULATE_OBJECT_DATA_INS;

	if (args->append == 0) {
		/* New object. Allocate + write. */
		apdu.p1 = CARDOS5_ACCUMULATE_OBJECT_DATA_P1_NEW;
	}

	apdu.lc = args->len;
	apdu.data = args->data;
	apdu.datalen = args->len;
	apdu.le = sizeof(rbuf);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);

	if ((r = sc_transmit_apdu(card, &apdu)) != SC_SUCCESS) {
		sc_log(card->ctx, "tx/rx error");
		return r;
	}

	if ((r = sc_check_sw(card, apdu.sw1, apdu.sw2)) != SC_SUCCESS) {
		sc_log(card->ctx, "command failed");
		return r;
	}

	if (apdu.resplen != sizeof(args->hash) + 2) {
		sc_log(card->ctx, "wrong reply length");
		return SC_ERROR_CARD_CMD_FAILED;
	}

	memcpy(&args->hash, apdu.resp + 2, sizeof(args->hash));

	return SC_SUCCESS;
}

static int
generate_key(sc_card_t *card,
    struct sc_cardctl_cardos5_genkey_info *args)
{
	sc_apdu_t	apdu;
	int		r;

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.ins = CARDOS5_GENERATE_KEY_INS;
	apdu.p1  = CARDOS5_GENERATE_KEY_P1_GENERATE;
	apdu.lc = args->len;
	apdu.data = args->data;
	apdu.datalen = args->len;

	if ((r = sc_transmit_apdu(card, &apdu)) != SC_SUCCESS) {
		sc_log(card->ctx, "tx/rx error");
		return r;
	}

	if ((r = sc_check_sw(card, apdu.sw1, apdu.sw2)) != SC_SUCCESS) {
		sc_log(card->ctx, "command failed");
		return r;
	}

	return SC_SUCCESS;
}

static int
extract_key(sc_card_t *card, struct sc_cardctl_cardos5_genkey_info *args)
{
	sc_apdu_t	apdu;
	uint8_t		rbuf[768];
	int		r;

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_4_EXT;
	apdu.ins = CARDOS5_GENERATE_KEY_INS;
	apdu.p1  = CARDOS5_GENERATE_KEY_P1_EXTRACT;
	apdu.lc = args->len;
	apdu.data = args->data;
	apdu.datalen = args->len;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = sizeof(rbuf);

	if ((r = sc_transmit_apdu(card, &apdu)) != SC_SUCCESS) {
		sc_log(card->ctx, "tx/rx error");
		return r;
	}

	if ((r = sc_check_sw(card, apdu.sw1, apdu.sw2)) != SC_SUCCESS) {
		sc_log(card->ctx, "command failed");
		return r;
	}

	args->len = apdu.resplen;
	args->data = malloc(apdu.resplen);
	if (args->data == NULL)
		return SC_ERROR_MEMORY_FAILURE;

	memcpy(args->data, apdu.resp, apdu.resplen);

	return SC_SUCCESS;
}

static int
init_card(sc_card_t *card)
{
	sc_apdu_t	apdu;
	int		r;

	/*
	 * XXX This APDU only takes effect after the next reset! P1 and P2 form
	 * the desired data field length (highest, lowest), which is stored by
	 * the card in its EEPROM.
	 */
	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_1;
	apdu.cla = CARDOS5_SET_DATA_FIELD_LENGTH_CLA;
	apdu.ins = CARDOS5_SET_DATA_FIELD_LENGTH_INS;
	apdu.p1 = 0x03;
	apdu.p2 = 0x00;

	if ((r = sc_transmit_apdu(card, &apdu)) != SC_SUCCESS) {
		sc_log(card->ctx, "tx/rx error");
		return r;
	}

	if ((r = sc_check_sw(card, apdu.sw1, apdu.sw2)) != SC_SUCCESS) {
		sc_log(card->ctx, "command failed");
		return r;
	}

	return SC_SUCCESS;
}

static int
put_data_ecd(sc_card_t *card, struct sc_cardctl_cardos_obj_info *args)
{
	sc_apdu_t	apdu;
	int		r;

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.ins = CARDOS5_PUT_DATA_INS;
	apdu.p1 = CARDOS5_PUT_DATA_ECD_P1;
	apdu.p2 = CARDOS5_PUT_DATA_ECD_P2;
	apdu.lc = args->len;
	apdu.data = args->data;
	apdu.datalen = args->len;

	if ((r = sc_transmit_apdu(card, &apdu)) != SC_SUCCESS) {
		sc_log(card->ctx, "tx/rx error");
		return r;
	}

	if ((r = sc_check_sw(card, apdu.sw1, apdu.sw2)) != SC_SUCCESS) {
		sc_log(card->ctx, "command failed");
		return r;
	}

	return SC_SUCCESS;
}

static int
cardos5_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	switch (cmd) {
	case SC_CARDCTL_CARDOS_ACCUMULATE_OBJECT_DATA:
		return accumulate_object_data(card,
		    (struct sc_cardctl_cardos_acc_obj_info *)ptr);
	case SC_CARDCTL_CARDOS_GENERATE_KEY:
		return generate_key(card,
		    (struct sc_cardctl_cardos5_genkey_info *)ptr);
	case SC_CARDCTL_CARDOS_EXTRACT_KEY:
		return extract_key(card,
		    (struct sc_cardctl_cardos5_genkey_info *)ptr);
	case SC_CARDCTL_CARDOS_PUT_DATA_ECD:
		return put_data_ecd(card,
		    (struct sc_cardctl_cardos_obj_info *)ptr);
	case SC_CARDCTL_CARDOS_INIT_CARD:
		return init_card(card);
	case SC_CARDCTL_CARDOS_PUT_DATA_OCI:
	case SC_CARDCTL_CARDOS_PUT_DATA_SECI:
	case SC_CARDCTL_LIFECYCLE_GET:
	case SC_CARDCTL_LIFECYCLE_SET:
		return cardos4_ops->card_ctl(card, cmd, ptr);
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}
}

static int
cardos5_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	if (data->pin_reference & BACKTRACK_PIN) {
		sc_log(card->ctx, "pin with backtrack bit set");
		return SC_ERROR_INCORRECT_PARAMETERS;
	}

	data->pin_reference |= BACKTRACK_PIN;

	return iso_ops->pin_cmd(card, data, tries_left);
}

static int
cardos5_get_data(struct sc_card *card, unsigned int tag,  unsigned char *buf,
    size_t len)
{
	return SC_ERROR_NOT_SUPPORTED;
}

struct sc_card_driver *
sc_get_cardos5_driver(void)
{
	if (iso_ops == NULL)
		iso_ops = sc_get_iso7816_driver()->ops;

	/* We rely on the CardOS 4 driver for some operations. */
	if (cardos4_ops == NULL)
		cardos4_ops = sc_get_cardos_driver()->ops;

	cardos5_ops = *iso_ops;
	cardos5_ops.match_card = cardos5_match_card;
	cardos5_ops.init = cardos5_init;
	cardos5_ops.finish = cardos5_finish;
	cardos5_ops.process_fci = cardos5_process_fci;
	cardos5_ops.select_file = cardos5_select_file;
	cardos5_ops.create_file = cardos5_create_file;
	cardos5_ops.set_security_env = cardos5_set_security_env;
	cardos5_ops.restore_security_env = cardos5_restore_security_env;
	cardos5_ops.compute_signature = cardos5_compute_signature;

	cardos5_ops.list_files = cardos5_list_files;
	cardos5_ops.check_sw = cardos4_ops->check_sw;
	cardos5_ops.card_ctl = cardos5_card_ctl;
	cardos5_ops.pin_cmd = cardos5_pin_cmd;
	cardos5_ops.logout  = cardos4_ops->logout;
	cardos5_ops.get_data = cardos5_get_data;

	return &cardos5_drv;
}
