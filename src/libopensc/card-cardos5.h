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

#ifndef _OPENSC_CARD_CARDOS5_H
#define _OPENSC_CARD_CARDOS5_H

#define BACKTRACK_PIN	0x80	/* look for PIN object in parent DFs as well */
#define BACKTRACK_MASK	0x7F

#define CARDOS5_ACCUMULATE_OBJECT_DATA_CLA		0x80
#define CARDOS5_ACCUMULATE_OBJECT_DATA_INS		0xE0
#define CARDOS5_ACCUMULATE_OBJECT_DATA_P1_NEW		0x01
#define CARDOS5_ACCUMULATE_OBJECT_DATA_P1_APPEND	0x00
#define CARDOS5_ACCUMULATE_OBJECT_DATA_TAG		0x53
#define CARDOS5_ACCUMULATE_OBJECT_HASH_TAG		0xCF

#define CARDOS5_PHASE_CONTROL_CLA			0x80
#define CARDOS5_PHASE_CONTROL_INS			0x10
#define CARDOS5_PHASE_CONTROL_P1_TOGGLE			0x00
#define CARDOS5_PHASE_CONTROL_P2_TOGGLE			0x00

#define CARDOS5_SET_DATA_FIELD_LENGTH_CLA		0x80
#define CARDOS5_SET_DATA_FIELD_LENGTH_INS		0x18

#define CARDOS5_CREATE_FILE_INS				0xE0

#define CARDOS5_SELECT_INS				0xA4
#define CARDOS5_SELECT_P1_FILE_ID			0x00
#define CARDOS5_SELECT_P1_FULL_PATH			0x08
#define CARDOS5_SELECT_P2_FCI				0x00
#define CARDOS5_SELECT_P2_NO_RESPONSE			0x0C

#define CARDOS5_PUT_DATA_INS				0xDA
#define CARDOS5_PUT_DATA_ECD_P1				0x01
#define CARDOS5_PUT_DATA_ECD_P2				0x6C

/*
 * The GENERATE KEY command can be used to create a private key and to extract
 * a public key, depending on the value of P1.
 */

#define CARDOS5_GENERATE_KEY_INS		0x47
#define CARDOS5_GENERATE_KEY_P1_GENERATE	0x82
#define CARDOS5_GENERATE_KEY_P1_EXTRACT		0x83

#define CARDOS5_PERFORM_SECURITY_OPERATION_INS		0x2A
#define CARDOS5_PERFORM_SECURITY_OPERATION_P1_SIGN	0x9E
#define CARDOS5_PERFORM_SECURITY_OPERATION_P2_SIGN	0x9A
#define CARDOS5_PERFORM_SECURITY_OPERATION_P1_DECIPHER	0x80
#define CARDOS5_PERFORM_SECURITY_OPERATION_P2_DECIPHER	0x86

#define CARDOS5_MANAGE_SECURITY_ENVIRONMENT_INS		0x22
#define CARDOS5_MANAGE_SECURITY_ENVIRONMENT_P1_SET	0x41
#define CARDOS5_MANAGE_SECURITY_ENVIRONMENT_P2_DECIPHER	0xB8
#define CARDOS5_MANAGE_SECURITY_ENVIRONMENT_P2_SIGN	0xB6

#define CARDOS5_DIRECTORY_CLA	0x80
#define CARDOS5_DIRECTORY_INS	0x16
#define CARDOS5_DIRECTORY_P1	0x02

#define DIR_ENTRY_TAG		0x6F
#define FILE_ID_TAG		0x86
#define FILE_NEXT_OFFSET_TAG	0x8A

#define CRT_TAG_PINREF		0x83
#define CRT_LEN_PINREF		0x01

#define CRT_TAG_KEYREF		0x84

#define CRT_TAG_OBJPARAM	0x85
/* byte 1 */
#define OBJPARAM_NOBACKTRACK	0x20
/* byte 2 */
#define OBJPARAM_UNCHANGEABLE	0x00
#define OBJPARAM_CHANGEABLE	0x20

#define CRT_TAG_LIFECYCLE	0x8A
#define CRT_LEN_LIFECYCLE	0x01

#define LIFECYCLE_CREATION	0x01
#define LIFECYCLE_OPERATIONAL	0x05

#define CRT_TAG_KEYDATA		0x8F
#define CRT_TAG_RETRIES		0xA3
#define OCI_TAG_RETRIES		0x91

#define CRT_TAG_KUQ		0x95	/* key usage qualifier */
#define CRT_LEN_KUQ		0x01

#define KUQ_USER_AUTH		0x08
#define KUQ_DECRYPT		0x40
#define KUQ_ENCRYPT		0x80

#define CRT_TAG_CU		0xC2	/* cryptographic usage */
#define CRT_LEN_CU		0x01

#define CU_USER_AUTH		0x20
#define CU_CIPHER		0x02
#define CU_SIGN			0x01

#define CRT_TAG_ALGO_TYPE	0xC4
#define CRT_LEN_ALGO_TYPE	0x02

#define ALGO_TYPE_RSA		0x01
#define ALGO_TYPE_PIN		0x05
#define ALGO_TYPE_EC		0x0D

/* No internal hashing; padding done with leading zeroes. */
#define ALGO_TYPE_PARAM		0x08

#define CRT_DO_DST		0xB6
#define CRT_DO_KEYREF		0x83

#define CONSTRUCTED_DATA_TAG	0xAF

/* Format of RSA private keys <= 2048 bits. */
#define RSA_PRIVKEY_MODULUS_TAG		0x81
#define RSA_PRIVKEY_EXPONENT_TAG	0x82

/* Format of RSA private keys > 2048 bits. */
#define RSA_PRIVKEY_PRIME_P_TAG		0x92
#define RSA_PRIVKEY_PRIME_Q_TAG		0x93
#define RSA_PRIVKEY_QINV_TAG		0x94
#define RSA_PRIVKEY_REMAINDER1_TAG	0x95
#define RSA_PRIVKEY_REMAINDER2_TAG	0x96

/* Format of *all* RSA public keys. */
#define RSA_PUBKEY_MODULUS		0x81
#define RSA_PUBKEY_EXPONENT		0x82

/* Elliptic Curve Domain (ECD) parts */
#define ECD_CURVE_OID		0x06
#define ECD_PRIME_P		0x81
#define ECD_COEFFICIENT_A	0x82
#define ECD_COEFFICIENT_B	0x83
#define ECD_GENERATOR_POINT_G	0x84	/* 0x04 || x || y */
#define ECD_ORDER_R		0x85	/* order q */
#define ECD_CO_FACTOR_F		0x87	/* h */

#define ARL_ACCESS_MODE_BYTE_TAG	0x80
#define ARL_ACCESS_MODE_BYTE_LEN	0x01

/* Format of ECC private keys. */
#define ECC_PRIVKEY_OID	0x06
#define ECC_PRIVKEY_D	0x90

/* Format of ECC public keys. */
#define ECC_PUBKEY_OID	0x06
#define ECC_PUBKEY_Y	0x86

/* Operation always allowed. */
#define ARL_ALWAYS_TAG			0x90
#define ARL_ALWAYS_LEN			0x00

/* Operation never allowed. */
#define ARL_NEVER_TAG			0x97
#define ARL_NEVER_LEN			0x00

/* Operation allowed pending user authentication. */
#define ARL_USER_AUTH_TAG		0xA4
#define ARL_USER_AUTH_LEN		0x06

#define ARL_DUMMY_TAG	0x81
#define ARL_DUMMY_LEN	0x00

/* Contents of tag describe parameters of a command to be allowed/denied. */
#define ARL_COMMAND_TAG	0x8F
#define ARL_COMMAND_LEN	0x04	/* CLA + INS + P1 + P2 */

/*
 * Mapping between access control operations as understood by libopensc and
 * bits composing CardOS 5's access mode byte. The card allows for these bits
 * to be combined, but we list them separately, since that eases abstraction by
 * libopensc.
 */
struct sc_cardos5_am_byte {
	uint8_t		am_byte;	/* CardOS access mode byte */
	unsigned int	op_byte;	/* corresponding SC_AC_OP_ */
};

#define AM_EF_DELETE			0x40
#define AM_EF_TERMINATE			0x20
#define AM_EF_ACTIVATE			0x10
#define AM_EF_DEACTIVATE		0x08
#define AM_EF_WRITE			0x04
#define AM_EF_UPDATE			0x02
#define AM_EF_READ			0x01
#define AM_EF_INCREASE			0xC0
#define AM_EF_DECREASE			0xA0

#define AM_DF_DELETE_SELF		0x40
#define AM_DF_TERMINATE			0x20
#define AM_DF_ACTIVATE			0x10
#define AM_DF_DEACTIVATE		0x08
#define AM_DF_CREATE_DF_FILE		0x04
#define AM_DF_CREATE_EF_FILE		0x02
#define AM_DF_DELETE_CHILD		0x01
#define AM_DF_PUT_DATA_OCI		0xC0
#define AM_DF_PUT_DATA_OCI_UPDATE	0xA0
#define AM_DF_LOAD_EXECUTABLE		0x90
#define AM_DF_PUT_DATA_FCI		0x88

#define AM_KEY_OCI_UPD			0x82
#define AM_KEY_RESET_RETRY_CTR		0x88
#define AM_KEY_CHANGE			0xA0	/* CHANGE KEY/REF DATA */
#define AM_KEY_USE			0xC0	/* VERIFY, PSO */

#define FCP_TAG_START			0x62
#define FCP_TAG_EF_SIZE			0x80
#define FCP_TAG_DESCRIPTOR		0x82
#define FCP_TAG_FILEID			0x83
#define FCP_TAG_DF_NAME			0x84
#define FCP_TAG_EF_SFID			0x88
#define FCP_TAG_ARL			0xAB
#define FCP_TAG_DF_SIZE			0xC1

#define FCP_TYPE_BINARY_EF		0x01
#define FCP_TYPE_DF			0x38

#endif /* !_OPENSC_CARD_CARDOS5_H */
