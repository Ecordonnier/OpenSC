/*
 * Copyright (c) 2014 Hans-Joerg Hoexer
 * Copyright (c) 2014 Pedro Martelletto
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

#include <sys/param.h>
#include <sys/stat.h>

#include <libopensc/opensc.h>
#include <libopensc/card-cardos5.h>
#include <libopensc/cardctl.h>
#include <libopensc/asn1.h>
#include <libopensc/log.h>

#include <pkcs15init/pkcs15-init.h>
#include <pkcs15init/profile.h>

#include "config.h"
#include <openssl/aes.h>
#ifdef HAVE_OPENSSL_CMAC_H
#include <openssl/cmac.h>
#endif
#include <openssl/des.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util.h"

#ifndef SC_DEFAULT_MAX_RECV_SIZE
#define SC_DEFAULT_MAX_RECV_SIZE	256
#endif

sc_card_t		*card;
sc_profile_t		*profile;
sc_pkcs15_card_t	*p15card;

const char		*seed_path = NULL;
const char		*pin = NULL;

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
asn1_put_tag(unsigned char tag, const unsigned char *tag_content,
    size_t tag_content_len, buf_t *buf)
{
	int r;

	r = sc_asn1_put_tag(tag, tag_content, tag_content_len, buf->ptr,
	    buf->size - buf->bytes_used, &buf->ptr);
	if (r == SC_SUCCESS) {
		buf->bytes_used += tag_content_len + 2;
		return 0;
	}

	return -1;
}

static int
asn1_put_tag1(unsigned char tag, unsigned char tag_value, buf_t *buf)
{
	const unsigned char tag_content[1] = { tag_value };

	return asn1_put_tag(tag, tag_content, sizeof(tag_content), buf);
}

static int
asn1_put_tag2(unsigned char tag, uint8_t a, uint8_t b, buf_t *buf)
{
	const unsigned char tag_content[2] = { a, b };

	return asn1_put_tag(tag, tag_content, sizeof(tag_content), buf);
}

static int
bertlv_put_tag(uint8_t tag, const uint8_t *data, uint16_t length, buf_t *buf)
{
	if (buf->bytes_used == buf->size)
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
bertlv_get_tag(uint16_t tag, unsigned char **tag_content, uint16_t *tag_length,
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
		*tag_length = *(buf->ptr)++ << 8;
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

int
get_cycle_phase(void)
{
	sc_apdu_t	apdu;
	uint8_t		buf[SC_DEFAULT_MAX_RECV_SIZE];
	int		r;

	memset(&apdu, 0, sizeof(apdu));
	memset(&buf, 0, sizeof(buf));
	apdu.cse = SC_APDU_CASE_2_SHORT;
	apdu.ins = 0xca;
	apdu.le = sizeof(buf);
	apdu.p1 = 0x01;
	apdu.p2 = 0x83;
	apdu.resp = buf;
	apdu.resplen = sizeof(buf);

	r = sc_transmit_apdu(card, &apdu);
	if (r != SC_SUCCESS)
		errx(1, "%s: sc_transmit_apdu: %s", __func__, sc_strerror(r));

	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		errx(1, "%s: command failed: %02x %02x", __func__, apdu.sw1,
		    apdu.sw2);

	return ((int)buf[0]);
}

/*
 * Switch between the "operational" and "administration" cycle phases.
 */
void
switch_adm2op(void)
{
	sc_apdu_t	apdu;
	int		phase;
	int		r;

	/*
	 * Verify that the card is in administration or operational states.
	 */
	phase = get_cycle_phase();
	if (phase != 0x20 && phase != 0x10)
		errx(1, "%s: card must be in cycle phases 'administration' or "
		    "'operational' cycle phase", __func__);

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_1;
	apdu.cla = 0x80;
	apdu.ins = 0x10;

	r = sc_transmit_apdu(card, &apdu);
	if (r != SC_SUCCESS)
		errx(1, "%s: sc_transmit_apdu: %s", __func__, sc_strerror(r));

	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		errx(1, "%s: command failed: %02x %02x", __func__, apdu.sw1,
		    apdu.sw2);
}

void	usage(void);

void
load_file(const char *path, ssize_t min, ssize_t max, uint8_t **data,
    ssize_t *data_len)
{
	int		fd;
	struct stat	st;
	ssize_t		n;

	if (path == NULL)
		usage();

	if ((fd = open(path, O_RDONLY)) < 0)
		err(1, "%s: open %s", __func__, path);

	if (fstat(fd, &st) < 0)
		err(1, "%s: fstat %s", __func__, path);

	if (st.st_size < min || st.st_size > max)
		errx(1, "%s: invalid file size: %s", __func__, path);

	*data_len = st.st_size;
	if ((*data = calloc(1, *data_len)) == NULL)
		err(1, "%s: calloc", __func__);

	if ((n = read(fd, *data, *data_len)) != *data_len) {
		if (n < 0)
			err(1, "%s: read %s", __func__, path);
		else
			errx(1, "%s: short read: %s", __func__, path);
	}

	close(fd);
}

void
switch_keys(const char *apdu_path)
{
	uint8_t		*data;
	ssize_t		 data_len;
	sc_apdu_t	 apdu;
	int	 	 r;

	/* We need at least CLA, INS, P1 and P2. */
	load_file(apdu_path, 4, SC_MAX_APDU_BUFFER_SIZE, &data, &data_len);

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.cla = data[0];
	apdu.ins = data[1];
	apdu.p1 = data[2];
	apdu.p2 = data[3];
	if (data_len > 4) {
		/* Inconsistent LC or LE != 0. */
		if (data[4] != data_len - 4)
			errx(1, "%s: bogus apdu in %s", __func__, apdu_path);
		if (data_len > 5) {
			apdu.lc = data[4];
			apdu.data = &data[5];
			apdu.datalen = data[4];
		}
	}

	if (apdu.cla != 0x84 || apdu.ins != 0x24)
		errx(1, "%s: bogus apdu in file %s", __func__, apdu_path);

	r = sc_transmit_apdu(card, &apdu);
	if (r != SC_SUCCESS)
		errx(1, "%s: sc_transmit_apdu: %s", __func__, sc_strerror(r));

	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		errx(1, "%s: command failed: %02x %02x", __func__, apdu.sw1,
		    apdu.sw2);

	free(data);
}

/*
 * Calculate the Message Authentication Code (MAC) of "data" according to AES
 * CMAC 128 ECB using "key" as the cryptographic key. The result is stored in
 * "mac", which is allocated with *mac_len bytes.
 *
 * This function fails if AES_BLOCK_SIZE is not 16.
 */
int
aes_cmac(const uint8_t *data, size_t data_len, const uint8_t *key,
    size_t key_len, uint8_t **mac, size_t *mac_len)
{
#ifdef HAVE_OPENSSL_CMAC_H
	CMAC_CTX	*ctx;
	uint8_t		 tmp[AES_BLOCK_SIZE];
	size_t		 tmp_len;

	ctx = CMAC_CTX_new();
	if (ctx == NULL)
		return -1;

	if (CMAC_Init(ctx, key, key_len, EVP_aes_128_cbc(), NULL) == 0 ||
	    CMAC_Update(ctx, data, data_len) == 0 ||
	    CMAC_Final(ctx, tmp, &tmp_len) == 0 ||
	    tmp_len != AES_BLOCK_SIZE ||
	    tmp_len != 16) {
		CMAC_CTX_free(ctx);
		return -1;
	}

	CMAC_CTX_free(ctx);

	/*
	 * CardOS 5.0 User's Manual, section 2.6.2 (pg. 89) states: "From the
	 * 16 bytes returned by AES-CMAC computation, the most significant 8
	 * bytes are used for secure messaging purposes."
	 */

	*mac = calloc(8, sizeof(char));
	if (*mac == NULL)
		return -1;

	memcpy(*mac, tmp, 8);
	*mac_len = 8;

	return 0;
#else
	warnx("%s: AES-CMAC support missing in OpenSSL", __func__);
	return -1;
#endif
}

/*
 * Perform AES CBC as described in CardOS 5.0 User's Manual. The relevant
 * sections and figures are: 2.6.2 (pg. 89), 2.6.2-2 (pg. 91), and 4.1.1 in the
 * Packages & Release Notes (PRN).
 *
 * We receive a system key (which is the StartKey) and use the invariant seed
 * value to derive an encryption key from it. This derivation process is
 * underdocumented and therefore unclear; the only hint in the manual being
 * "SMx4H_ENC_KEY = ENC_SYSTEMKEY(SEED)". It does not state which
 * initialisation vector (IV) should be used in this calculation.
 *
 * Once in possession of the encryption key, figure 2.6.2-2 (referenced above)
 * suggests that we need to encrypt 16 zero bytes to get the IV to be used when
 * encrypting the data payload.
 */
int
aes_cbc(const uint8_t *data, size_t data_len, const uint8_t *syskey,
    size_t syskey_len, uint8_t **out, size_t *out_len)
{
	AES_KEY		 k;
	uint8_t		 zero_iv[AES_BLOCK_SIZE];
	uint8_t		 unencrypted_iv[AES_BLOCK_SIZE];
	uint8_t		 encrypted_iv[AES_BLOCK_SIZE];
	uint8_t		 enckey[AES_BLOCK_SIZE];
	uint8_t		*seed;
	ssize_t		 seed_len;

	/*
	 * Step 1: Derive encryption key from system key using the invariant
	 * seed.
	 */

	load_file(seed_path, 16, 16, &seed, &seed_len);
	memset(unencrypted_iv, 0, sizeof(unencrypted_iv));
	memset(zero_iv, 0, sizeof(zero_iv));

	AES_set_encrypt_key(syskey, syskey_len * NBBY, &k);
	AES_cbc_encrypt(unencrypted_iv, encrypted_iv, sizeof(encrypted_iv), &k,
	    zero_iv, AES_ENCRYPT);
	AES_cbc_encrypt(seed, enckey, sizeof(enckey), &k, encrypted_iv,
	    AES_ENCRYPT);

	/*
	 * Step 2: Use encryption key to encrypt the IV.
	 */

	memset(unencrypted_iv, 0, sizeof(unencrypted_iv));
	memset(zero_iv, 0, sizeof(zero_iv));

	AES_set_encrypt_key(enckey, sizeof(enckey) * NBBY, &k);
	AES_cbc_encrypt(unencrypted_iv, encrypted_iv, sizeof(encrypted_iv), &k,
	    zero_iv, AES_ENCRYPT);

	/*
	 * Step 3: Encrypt the payload.
	 */

	*out = calloc(data_len, sizeof(char));
	if (*out == NULL)
		return -1;

	*out_len = data_len;
	AES_cbc_encrypt(data, *out, data_len, &k, encrypted_iv, AES_ENCRYPT);

	return 0;
}

/* ISO padding for blocksize m adds 1 to m bytes */
#define ISO_PAD_LEN(u, m)	((m) - ((u) % (m)))
#define BLOCK_SIZE		8

int
add_iso_pad(uint8_t *buf, size_t buflen, size_t datalen, size_t m)
{
	size_t i;

	if (buflen % BLOCK_SIZE != 0)
		return -1;

	/* We always add at least one byte */
	if (buflen < datalen + 1)
		return -1;
	if (datalen + ISO_PAD_LEN(datalen, m) != buflen)
		return -1;

	/* First pad byte is 0x80, rest is 0x0 */
	buf[datalen] = 0x80;
	for (i = datalen + 1; i < buflen; i++)
		buf[i] = 0x0;	/* obsolete if buffer was calloc'd */

	return 0;
}

#define MAC_HDR		4

void
smmodex4h(const uint8_t *data, size_t data_len, uint8_t *key, size_t key_len)
{
	uint8_t		*mac;
	uint8_t		*mac_buf;
	uint8_t		*enc_buf;
	uint8_t		*sm_buf;
	uint8_t		*payload;
	uint8_t		 lc;
	size_t		 len;
	size_t		 w;
	size_t		 mac_len;
	size_t		 payload_len;
	sc_apdu_t	 apdu;
	int		 r;

	if (key == NULL || key_len != 16 || data == NULL || data_len < 4)
		errx(1, "%s: bogus arguments", __func__);

	/*
         * No extended APDUs are allowed, thus both le and lc are
         * always just one byte.  Thus 0 means le/lc is not present.
	 */
	if (data_len > 5)
		lc = data[4];
	else
		lc = 0;
	if ((lc && data_len > (size_t)5 + lc) || (lc == 0 && data_len == 5))
		warnx("%s: bogus apdu; LE != 0", __func__);

	len = MAC_HDR + lc;
	if ((mac_buf = calloc(1, len)) == NULL)
		err(1, "%s: calloc", __func__);

	/* Build data to be mac'ed */
	memcpy(mac_buf, data + 1, 3);
	mac_buf[3] = lc + 8;
	if (lc > 0)
		memcpy(mac_buf + MAC_HDR, data + 5, lc);

	if (aes_cmac(mac_buf, len, key, 16, &mac, &mac_len) < 0)
		errx(1, "%s: aes_cmac() failed", __func__);

	free(mac_buf);

	w = lc + mac_len + ISO_PAD_LEN(lc + mac_len, AES_BLOCK_SIZE);
	if ((enc_buf = calloc(1, w)) == NULL)
		err(1, "%s: calloc", __func__);

	/* Build data to be encrypted */
	if (lc > 0)
		memcpy(enc_buf, data + 5, lc);
	memcpy(enc_buf + lc, mac, mac_len);
	free(mac);

	/* Add ISO padding for AES CBC */
	if (add_iso_pad(enc_buf, w, lc + mac_len, AES_BLOCK_SIZE) < 0)
		errx(1, "%s: add_iso_pad() failed", __func__);

	/* Build the SM-APDU, which always includes lc. */
	len = w + 5;

	if ((sm_buf = calloc(1, len)) == NULL)
		err(1, "%s: calloc", __func__);

	/* Build header */
	sm_buf[0] = data[0] | 0x04;
	memcpy(sm_buf + 1, data + 1, 3);
	sm_buf[4] = w;

	/* Encrypt data */
	if (aes_cbc(enc_buf, w, key, key_len, &payload, &payload_len) < 0)
		errx(1, "%s: aes_cbc() failed", __func__);

	memcpy(sm_buf + 5, payload, payload_len);
	free(enc_buf);
	free(payload);

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.cla = sm_buf[0];
	apdu.ins = sm_buf[1];
	apdu.p1 = sm_buf[2];
	apdu.p2 = sm_buf[3];
	apdu.lc = sm_buf[4];
	apdu.data = &sm_buf[5];
	apdu.datalen = sm_buf[4];

	r = sc_transmit_apdu(card, &apdu);
	if (r != SC_SUCCESS)
		errx(1, "%s: sc_transmit_apdu: %s", __func__, sc_strerror(r));

	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		errx(1, "%s: command failed: %02x %02x", __func__, apdu.sw1,
		    apdu.sw2);
}

void
full_erase(const char *startkey_path)
{
	const uint8_t	 full_erase_files_apdu[] = { 0x84, 0x06, 0x01, 0x00, };
	uint8_t		*startkey;
	ssize_t		 startkey_len;

	/*
	 * If we are in cycle phase 'operational', switch to cycle phase
	 * 'administration', otherwise the ERASE FILES APDU will fail.
	 */
	if (get_cycle_phase() == 0x10)
		switch_adm2op();

	/* The key must be an AES-128 key. */
	load_file(startkey_path, 16, 16, &startkey, &startkey_len);

	smmodex4h(full_erase_files_apdu, sizeof(full_erase_files_apdu),
	    startkey, startkey_len);

	free(startkey);
}

/*
 * format_apdu: everything is wrapped in a 0x62 (FCP) tag:
 *	- 0xc1: MF body size (0x0400 = 1024 bytes)
 *	- 0x85: checksum over header only (0x01)
 *	- 0xab: Access Rule List (ARL):
 *		- We don't allow PUT_DATA commands on the MF.
 *		- We allow everything else.
 */
void
format(const char *startkey_path)
{
	const uint8_t	 format_apdu[] = {
		0x84, 0x40, 0x00, 0x01, 0x14, 0x62, 0x12, 0xc1, 0x02, 0x04,
		0x00, 0x85, 0x01, 0x01, 0xab, 0x09, 0x84, 0x01, 0xda, 0x97,
		0x00, 0x81, 0x00, 0x90, 0x00,
	};
	const uint8_t	 erase_files_apdu[] = {
		0x84, 0x06, 0x00, 0x00,
	};
	uint8_t		*startkey;
	ssize_t		 startkey_len;

	/*
	 * If we are in cycle phase 'operational', switch to cycle phase
	 * 'administration', otherwise the ERASE FILES APDU will fail.
	 */
	if (get_cycle_phase() == 0x10)
		switch_adm2op();

	/* The key must be an AES-128 key. */
	load_file(startkey_path, 16, 16, &startkey, &startkey_len);

	smmodex4h(erase_files_apdu, sizeof(erase_files_apdu), startkey,
	    startkey_len);
	smmodex4h(format_apdu, sizeof(format_apdu), startkey, startkey_len);

	free(startkey);
}

/*
 * Poor man's DER parser. The format used to encode curve parameters seems
 * simple enough to warrant a quick reimplementation. It certainly appears to
 * be easier (and better) than to rely on OpenSSL's parser, anyway.
 *
 * The syntax expected here was obtained from:
 * http://www.ecc-brainpool.org/download/Domain-parameters.pdf, page 34.
 */

#define INTEGER_TAG		0x02
#define BIT_STRING_TAG		0x03
#define OCTET_STRING_TAG	0x04
#define OID_TAG			0x06
#define SEQUENCE_TAG		0x30

struct obj {
	uint8_t		*data;
	uint16_t	 len;
};

struct curve_parameters {
	struct obj	oid;
	struct obj	p;
	struct obj	a;
	struct obj	b;
	struct obj	g;
	struct obj	r;
	struct obj	f;
};

void
extract_curve_parameters(uint8_t *curve_der, ssize_t curve_der_len,
    struct curve_parameters *param)
{
	uint8_t		*tag = NULL;
	uint16_t	 taglen;
	buf_t		 der;

	bzero(param, sizeof(*param));

	buf_init(&der, curve_der, curve_der_len);

	if (bertlv_get_tag(SEQUENCE_TAG, NULL, &taglen, &der))
		errx(1, "%s: error decoding curve der 1", __func__);

	/* XXX What is the meaning of this INTEGER tag set to 1? */
	if (bertlv_get_tag(INTEGER_TAG, &tag, &taglen, &der) ||
	    taglen != 1 || tag[0] != 0x01)
		errx(1, "%s: error decoding curve der 2", __func__);

	/* OID and P are grouped in a sequence. */
	if (bertlv_get_tag(SEQUENCE_TAG, NULL, &taglen, &der) ||
	    bertlv_get_tag(OID_TAG, &param->oid.data, &param->oid.len, &der) ||
	    bertlv_get_tag(INTEGER_TAG, &param->p.data, &param->p.len, &der))
		errx(1, "%s: error decoding curve der 3", __func__);

	/* A and B are grouped in a sequence. */
	if (bertlv_get_tag(SEQUENCE_TAG, NULL, &taglen, &der) ||
	    bertlv_get_tag(OCTET_STRING_TAG, &param->a.data, &param->a.len,
	    &der) || bertlv_get_tag(OCTET_STRING_TAG, &param->b.data,
	    &param->b.len, &der))
		errx(1, "%s: error decoding curve der 4", __func__);

	free(tag);

	/* Some curves have an optional seed value: skip it. */
	if (der.ptr[0] == BIT_STRING_TAG && bertlv_get_tag(BIT_STRING_TAG, &tag,
	    &taglen, &der))
		errx(1, "%s: error decoding curve der 5", __func__);

	/* G, R and F are ungrouped, but appear sequentially. */
	if (bertlv_get_tag(OCTET_STRING_TAG, &param->g.data, &param->g.len,
	    &der) || bertlv_get_tag(INTEGER_TAG, &param->r.data, &param->r.len,
	    &der) || bertlv_get_tag(INTEGER_TAG, &param->f.data, &param->f.len,
	    &der))
		errx(1, "%s: error decoding curve der 6", __func__);

	/* Make sure that we consumed the whole buffer. */
	if (der.size != der.bytes_used)
		errx(1, "%s: error decoding curve der 7", __func__);
}

void
extract_curve_oid(uint8_t *curve_oid, ssize_t curve_oid_len,
    struct curve_parameters *param)
{
	buf_t	oid;

	/* free oid obtained by extract_curve_parameters() */
	free(param->oid.data);

	buf_init(&oid, curve_oid, curve_oid_len);

	if (bertlv_get_tag(OID_TAG, &param->oid.data, &param->oid.len, &oid))
		errx(1, "%s: error decoding curve oid", __func__);
}

/*
 * Transfer an object to the card in chunks. In the end, gather the object's
 * SHA256 checksum and handle it back to the caller, who may use the checksum
 * to reference the object in further commands.
 */
void
push_object(const uint8_t *object, size_t object_len, uint8_t *sha256)
{
	struct sc_cardctl_cardos_acc_obj_info	args;
	uint8_t					payload_buf[128];
	size_t					done;
	size_t					n;
	int					r;

	if (object_len > UINT16_MAX)
		errx(1, "%s: invalid len %zu", __func__, object_len);

	for (done = 0; done < object_len; done += n) {
		buf_t	payload;

		buf_init(&payload, payload_buf, sizeof(payload_buf));

		if (done == 0) {
			uint8_t len_hi = (uint8_t)(object_len >> 8);
			uint8_t len_lo = (uint8_t)(object_len & 0xFF);
			if (asn1_put_tag2(0x80, len_hi, len_lo, &payload))
				errx(1, "%s: asn1 error", __func__);
			args.append = 0; /* allocate new object */
		} else
			args.append = 1; /* appending to existing object */

		n = object_len - done;
		if (n > 64)
			n = 64;

		if (asn1_put_tag(CARDOS5_ACCUMULATE_OBJECT_DATA_TAG,
		    object + done, n, &payload))
			errx(1, "%s: asn1 error", __func__);

		args.data = payload_buf;
		args.len = payload.bytes_used;

		r = sc_card_ctl(card, SC_CARDCTL_CARDOS_ACCUMULATE_OBJECT_DATA,
		    &args);
		if (r != SC_SUCCESS)
			errx(1, "%s: sc_card_ctl: %s", __func__,
			    sc_strerror(r));
	}

	if (sha256 != NULL)
		memcpy(sha256, args.hash, 32);
}

int
get_pin(sc_profile_t *profile, int id, const struct sc_pkcs15_auth_info *info,
    const char *label, uint8_t *pinbuf, size_t *pinsize)
{
	if (pin == NULL)
		return -1;

	memcpy(pinbuf, pin, strlen(pin) + 1);
	*pinsize = strlen(pin);

	return 0;
}

void
push_curve_parameters(const struct curve_parameters *p)
{
	uint8_t		sha256[32];
	uint8_t		ecd_buf[256];
	uint8_t		obj_buf[256];
	uint8_t		payload_buf[256];
	buf_t		ecd;
	buf_t		obj;
	buf_t		payload;
	sc_apdu_t	apdu;
	int		pin_id;
	int		r;

	pin_id = sc_pkcs15init_get_pin_reference(p15card, profile,
	    SC_AC_SYMBOLIC, SC_PKCS15INIT_SO_PIN);
	if (pin_id < 0)
		errx(1, "%s: invalid pin id: %d", __func__, pin_id);

	if (get_cycle_phase() == 0x10)
		switch_adm2op();
	if (get_cycle_phase() != 0x20)
		errx(1, "%s: card not in cycle phase 'administration'",
		    __func__);

	/*
	 * First, we build an Elliptic Curve Domain object with the curve
	 * parameters obtained from the curve's DER file.
	 */

	buf_init(&ecd, ecd_buf, sizeof(ecd_buf));

        if (bertlv_put_tag(ECD_CURVE_OID, p->oid.data, p->oid.len, &ecd) ||
	    bertlv_put_tag(ECD_PRIME_P, p->p.data, p->p.len, &ecd) ||
	    bertlv_put_tag(ECD_COEFFICIENT_A, p->a.data, p->a.len, &ecd) ||
	    bertlv_put_tag(ECD_COEFFICIENT_B, p->b.data, p->b.len, &ecd) ||
	    bertlv_put_tag(ECD_GENERATOR_POINT_G, p->g.data, p->g.len, &ecd) ||
	    bertlv_put_tag(ECD_ORDER_R, p->r.data, p->r.len, &ecd) ||
	    bertlv_put_tag(ECD_CO_FACTOR_F, p->f.data, p->f.len, &ecd))
		errx(1, "%s: asn1 error", __func__);

	/*
	 * We then wrap this ECD object inside a CONSTRUCTED_DATA_TAG object.
	 * We push this object to the card and retrieve its SHA256 hash.
	 */

	buf_init(&obj, obj_buf, sizeof(obj_buf));

        if (bertlv_put_tag(CONSTRUCTED_DATA_TAG, ecd_buf, ecd.bytes_used, &obj))
		errx(1, "%s: asn1 error", __func__);

	push_object(obj_buf, obj.bytes_used, sha256);

	/*
	 * Finally, we build the APDU payload (containing the hash) and send it.
	 * XXX The curve reference (ID) is hardcoded to 0x01.
	 */

	buf_init(&payload, payload_buf, sizeof(payload_buf));

	if (asn1_put_tag1(CRT_DO_KEYREF, 0x01, &payload) ||
	    asn1_put_tag1(CRT_TAG_ALGO_TYPE, 0x0D, &payload) ||
	    asn1_put_tag(CARDOS5_ACCUMULATE_OBJECT_HASH_TAG, sha256,
	    sizeof(sha256), &payload))
		errx(1, "%s: asn1 error", __func__);

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.data = payload_buf;
	apdu.datalen = payload.bytes_used;
	apdu.ins = CARDOS5_PUT_DATA_INS;
	apdu.lc = payload.bytes_used;
	apdu.p1 = CARDOS5_PUT_DATA_ECD_P1;
	apdu.p2 = CARDOS5_PUT_DATA_ECD_P2;

	/*
	 * Authenticate using the Security Officer PIN.
	 */

	r = sc_pkcs15init_verify_secret(profile, p15card, NULL, SC_AC_CHV,
	    pin_id);
	if (r != SC_SUCCESS)
		errx(1, "%s: sc_pkcs15init_verify_secret: %s", __func__,
		    sc_strerror(r));

	r = sc_transmit_apdu(card, &apdu);
	if (r != SC_SUCCESS)
		errx(1, "%s: sc_transmit_apdu: %s", __func__, sc_strerror(r));

	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		errx(1, "%s: command failed: %02x %02x", __func__, apdu.sw1,
		    apdu.sw2);
}

void
configure_curve(const char *curve_oid_path, const char *curve_der_path)
{
	uint8_t			*curve_der;
	uint8_t			*curve_oid;
	ssize_t			 curve_der_len;
	ssize_t	 		 curve_oid_len;
	struct curve_parameters	 param;
	int			 r;

	if (pin == NULL)
		usage();

	r = sc_pkcs15_bind(card, NULL, &p15card);
	if (r != SC_SUCCESS)
		errx(1, "%s: sc_pkcs15_bind: %s", __func__, sc_strerror(r));

	load_file(curve_der_path, 0, SSIZE_MAX, &curve_der, &curve_der_len);
	load_file(curve_oid_path, 0, SSIZE_MAX, &curve_oid, &curve_oid_len);

	extract_curve_parameters(curve_der, curve_der_len, &param);
	extract_curve_oid(curve_oid, curve_oid_len, &param);

	push_curve_parameters(&param);

	free(curve_der);
	free(curve_oid);
}

void
get_serial(void)
{
	sc_apdu_t	apdu;
	uint8_t		buf[SC_DEFAULT_MAX_RECV_SIZE];
	int		r;

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_2_SHORT;
	apdu.ins = 0xca;
	apdu.p1 = 0x01;
	apdu.p2 = 0x81;
	apdu.le = sizeof(buf);;
	apdu.resp = buf;
	apdu.resplen = sizeof(buf);

	r = sc_transmit_apdu(card, &apdu);
	if (r != SC_SUCCESS)
		errx(1, "%s: sc_transmit_apdu: %s", __func__, sc_strerror(r));

	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		errx(1, "%s: command failed: %02x %02x", __func__, apdu.sw1,
		    apdu.sw2);

	/*
	 * XXX pedro: The CardOS 5.0 User's Manual (pg. 173)  only
	 * states that the response to a ins=0xca, p1=0x01, p2=0x81
	 * command consists of 8 bytes. It does not specify whether
	 * some of these bytes have a meaning (like in CardOS 4.4) so
	 * we consider them all part of the serial number.
	 */
	printf("serial: %02x %02x %02x %02x %02x %02x %02x %02x\n", buf[0],
	    buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
}

void
get_info(void)
{
	size_t		l;
	sc_apdu_t	apdu;
	uint8_t		buf[SC_DEFAULT_MAX_RECV_SIZE];
	int		r;

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_2_SHORT;
	apdu.ins = 0xca;
	apdu.p1 = 0x01;
	apdu.p2 = 0x80;
	apdu.le = sizeof(buf);
	apdu.resp = buf;
	apdu.resplen = sizeof(buf);

	r = sc_transmit_apdu(card, &apdu);
	if (r != SC_SUCCESS)
		errx(1, "%s: sc_transmit_apdu: %s", __func__, sc_strerror(r));

	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		errx(1, "%s: command failed: %02x %02x", __func__, apdu.sw1,
		    apdu.sw2);

	buf[sizeof(buf)-1] = '\0';
	printf("label: %s\n", buf);

	apdu.p2 = 0x82;
	apdu.resplen = sizeof(buf);

	r = sc_transmit_apdu(card, &apdu);
	if (r != SC_SUCCESS)
		errx(1, "%s: sc_transmit_apdu: %s", __func__, sc_strerror(r));

	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		errx(1, "%s: command failed: %02x %02x", __func__, apdu.sw1,
		    apdu.sw2);

	printf("model: ");

	if (buf[0] == 0xc9)
		switch (buf[1]) {
		case 0x01:
			printf("5.0\n");
			break;
		case 0x03:
			printf("5.3\n");
			break;
		default:
			printf("unknown cardos 5, %02x\n", buf[1]);
		}
	else
		printf("unknown, %02x %02x\n", buf[0], buf[1]);

	printf("atr: ");

	if (card->atr.len == 0)
		printf("couldn't read\n");
	else {
		for (l = 0; l < card->atr.len; l++)
			printf("%02x ", card->atr.value[l]);
		putchar('\n');
	}

	get_serial();

	printf("cycle phase: ");

	switch (get_cycle_phase()) {
	case 0x10:
		printf("operational\n");
		break;
	case 0x20:
		printf("administration\n");
		break;
	case 0x23:
		printf("personalization\n");
		break;
	case 0x26:
		printf("initialization\n");
		break;
	case 0x29:
		printf("erase in progress\n");
		break;
	case 0x34:
		printf("manufacturing\n");
		break;
	case 0x3f:
		printf("death\n");
		break;
	default:
		printf("unknown, %02x\n", buf[0]);
	}

	apdu.p2 = 0x96;
	apdu.resplen = sizeof(buf);

	r = sc_transmit_apdu(card, &apdu);
	if (r != SC_SUCCESS)
		errx(1, "%s: sc_transmit_apdu: %s", __func__, sc_strerror(r));

	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		errx(1, "%s: command failed: %02x %02x", __func__, apdu.sw1,
		    apdu.sw2);

	printf("pkgldkey version: %02x\n", buf[0]);
	printf("pkgldkey tries: %u\n", (unsigned int)buf[1]);
	printf("startkey version: %02x\n", buf[2]);
	printf("startkey tries: %u\n", (unsigned int)buf[3]);

	apdu.p2 = 0x89;
	apdu.resplen = sizeof(buf);

	r = sc_transmit_apdu(card, &apdu);
	if (r != SC_SUCCESS)
		errx(1, "%s: sc_transmit_apdu: %s", __func__, sc_strerror(r));

	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		errx(1, "%s: command failed: %02x %02x", __func__, apdu.sw1,
		    apdu.sw2);

	printf("xram size (in kbytes): %u\n",
	    (unsigned int)ntohs(*(u_int16_t *)&buf[0]));

	printf("eeprom size (in kbytes): %u\n",
	    (unsigned int)ntohs(*(u_int16_t *)&buf[2]));

	apdu.p2 = 0x8a;
	apdu.resplen = sizeof(buf);

	r = sc_transmit_apdu(card, &apdu);
	if (r != SC_SUCCESS)
		errx(1, "%s: sc_transmit_apdu: %s", __func__, sc_strerror(r));

	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		errx(1, "%s: command failed: %02x %02x", __func__, apdu.sw1,
		    apdu.sw2);

	printf("eeprom free space (in kbytes): %u\n",
	    (unsigned int)ntohs(*(u_int16_t *)&buf[0])/1024);
}

void
once(int ch, const char **arg, const char *val)
{
	if (*arg != NULL)
		errx(1, "option -%c may only be specified once", (char)ch);
	*arg = val;
}

extern char	*__progname;

void
usage(void)
{
	fprintf(stderr, "usage: %s [-CEFhKvW] [-a apdu] [-d curve_der] "
	    "[-k key] [-o curve_oid] [-p pin] [-r reader] [-s seed]\n",
	    __progname);
	exit(1);
}

int	get_pin(sc_profile_t *, int, const sc_pkcs15_auth_info_t *,
	    const char *, uint8_t *, size_t *);

struct sc_pkcs15init_callbacks callbacks = { get_pin, NULL, };

void
connect_card(sc_context_t **ctx, const char *reader, int wait, int verbosity)
{
	sc_context_param_t	ctxpar;
	int			r;

	memset(&ctxpar, 0, sizeof(ctxpar));
	ctxpar.app_name = __progname;
	r = sc_context_create(ctx, &ctxpar);
	if (r != SC_SUCCESS)
		errx(1, "%s: sc_context_create: %s", __func__, sc_strerror(r));

	r = util_connect_card(*ctx, &card, reader, wait, verbosity);
	if (r != SC_SUCCESS)
		errx(1, "%s: util_connect_card: %s", __func__, sc_strerror(r));

	r = sc_pkcs15init_bind(card, "pkcs15", NULL, NULL, &profile);
	if (r != SC_SUCCESS)
		errx(1, "%s: sc_pkcs15init_bind: %s", __func__, sc_strerror(r));

	sc_pkcs15init_set_callbacks(&callbacks);
}

void
disconnect_card(sc_context_t *ctx)
{
	sc_unlock(card);
	sc_disconnect_card(card);
	sc_release_context(ctx);
}

int
main(int argc, char **argv)
{
	int		do_curve = 0;
	int		do_full_erase = 0;
	int		do_format = 0;
	int		do_key = 0;
	int		do_wait = 0;
	int		do_info = 0;
	int		verbosity = 0;
	int		ch;
	const char	*apdu = NULL;
	const char	*startkey = NULL;
	const char	*curve_der = NULL;
	const char	*curve_oid = NULL;
	const char	*reader = NULL;
	sc_context_t	*ctx = NULL;

	while ((ch = getopt(argc, argv, "a:Cd:EFhIKk:o:p:r:s:vW")) != -1)
		switch (ch) {
		case 'a':
			once(ch, &apdu, optarg);
			break;
		case 'C':
			do_curve = 1;
			break;
		case 'd':
			once(ch, &curve_der, optarg);
			break;
		case 'E':
			do_full_erase = 1;
			break;
		case 'F':
			do_format = 1;
			break;
		case 'h':
			usage();
			/* NOTREACHED */
		case 'I':
			do_info = 1;
			break;
		case 'K':
			do_key = 1;
			break;
		case 'k':
			once(ch, &startkey, optarg);
			break;
		case 'o':
			once(ch, &curve_oid, optarg);
			break;
		case 'p':
			once(ch, &pin, optarg);
			break;
		case 'r':
			once(ch, &reader, optarg);
			break;
		case 's':
			once(ch, &seed_path, optarg);
			break;
		case 'v':
			verbosity++;
			break;
		case 'W':
			do_wait = 1;
			break;
	}

	if (do_curve)
		if (do_format || do_key)
			errx(1, "-C can't be combined with options -FK");

	connect_card(&ctx, reader, do_wait, verbosity);

	if (verbosity > 1) {
		ctx->debug = verbosity;
		sc_ctx_log_to_file(ctx, "stderr");
	}

	if (do_key)
		switch_keys(apdu);
	if (do_full_erase)
		full_erase(startkey);
	if (do_format)
		format(startkey);
	if (do_curve)
		configure_curve(curve_oid, curve_der);
	if (do_info)
		get_info();

	disconnect_card(ctx);

	exit(0);
}
