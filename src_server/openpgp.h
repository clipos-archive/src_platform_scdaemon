// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
/*
 *  scdaemon
 *  Copyright (C) 2013 SGDSN/ANSSI
 *
 *  All rights reserved.
 *
 */

#ifndef __OPENPGP_H__
#define __OPENPGP_H__


#include "pcsc.h"
#include "card.h"
#include "common.h"

typedef enum {
  InvalidSex = 0x0,
  Male = 0x31,
  Female = 0x32,
  Undetermined = 0x39
} sex_t;


typedef enum {
  TripleDes = 0x00,
  Aes = 0x01
} sm_t;

typedef enum {
  InvalidAlgorithm = 0x0,
  RSA = 0x1
} algorithm_t;

typedef enum {
  SHA1,
  SHA224,
  SHA256,
  SHA384,
  SHA512,
  RIPEMD160
} signature_t;

typedef enum {
  StandardKey = 0x0,
  StandardKeyWithModulus = 0x1,
  ChineseRemainderTheorem = 0x2,
  ChineseRemainderTheoremWithModulus = 0x3,
} private_key_format_t;

typedef struct {
  algorithm_t algorithm;
  unsigned short modulus_size;
  unsigned short public_exponent_size;
  private_key_format_t private_key_format;
} key_settings_t;

typedef enum {
  KeySignature = 0xB6,
  KeyDecryption = 0xB8,
  KeyAuthentication = 0xA4,
} openpgp_key_type_t;

typedef struct {
  data_t modulus;
  data_t public_exponent;
  data_t fingerprint;
  data_t s_expression;
  data_t keygrip;
  time_t generation_date;
} openpgp_key_t;


typedef struct {
  unsigned char remaining_tries;
  unsigned char max_length;
} pin_t;


typedef enum {
  UserPin = 0x81,
  ResetCode = 0x82,
  AdminPin = 0x83
} pin_descriptor_t;



typedef struct {
  unsigned char application_version_major;
  unsigned char application_version_minor;
  unsigned int manufacturer;
  unsigned int serial_number;

  data_t aid;
  data_t historical_bytes;
  data_t login;
  data_t url;
  data_t name;
  data_t language;

  sex_t sex;

  unsigned char supports_secure_messaging;
  unsigned char supports_get_challenge;
  unsigned char supports_key_import;
  unsigned char supports_pw_status_change;
  unsigned char supports_private_dos;
  unsigned char supports_algorithm_attributes_change;

  sm_t secure_messaging_algorithm;
  unsigned short maximum_length_of_challenge;
  unsigned short maximum_length_of_cardholder_cert;
  unsigned short maximum_length_of_command;
  unsigned short maximum_length_of_response;

  key_settings_t signature_settings;
  key_settings_t decryption_settings;
  key_settings_t authentication_settings;

  unsigned char supported_user_pin_cache;
  pin_t user_pin;
  pin_t reset_code;
  pin_t admin_pin;

  unsigned int signatures_counter;
    
  openpgp_key_t signature_key;
  openpgp_key_t decryption_key;
  openpgp_key_t authentication_key;

  data_t ca_fingerprint_signature;
  data_t ca_fingerprint_decryption;
  data_t ca_fingerprint_authentication;

} openpgp_card_t;


extern void
init_openpgp_card(openpgp_card_t *card);

extern void
clean_openpgp_card(openpgp_card_t *card);




extern pcsc_error
select_openpgp_application(reader_t *reader);

extern pcsc_error
get_data_aid(reader_t *reader,
             openpgp_card_t *card);

extern pcsc_error
get_data_historical_bytes(reader_t *reader,
                          openpgp_card_t *card);

extern pcsc_error
get_data_login(reader_t *reader,
               openpgp_card_t *card);

extern pcsc_error
get_data_url(reader_t *reader,
             openpgp_card_t *card);

extern pcsc_error
get_data_cardholder(reader_t *reader,
                    openpgp_card_t *card);

extern pcsc_error
get_data_security_support_template(reader_t *reader,
                                   openpgp_card_t *card);

extern pcsc_error
get_data_application(reader_t *reader,
                     openpgp_card_t *card);

extern pcsc_error
get_data_pw_status(reader_t *reader,
                   openpgp_card_t *card);


extern pcsc_error
verify_pin(reader_t *reader,
           openpgp_card_t *card,
           const pin_descriptor_t pin_desc,
           const unsigned char user_pin_for_signature,
           const data_t pin);

extern pcsc_error
change_pin(reader_t *reader,
           openpgp_card_t *card,
           const pin_descriptor_t pin_desc,
           const data_t actual_pin,
           const data_t new_pin);



extern pcsc_error
read_openpgp_signature_key(reader_t *reader,
                           openpgp_card_t *card);

extern pcsc_error
read_openpgp_decryption_key(reader_t *reader,
                            openpgp_card_t *card);

extern pcsc_error
read_openpgp_authentication_key(reader_t *reader,
                                openpgp_card_t *card);

extern pcsc_error
decipher(reader_t *reader,
         openpgp_card_t *card,
         const data_t data,
         data_t *answer);

extern pcsc_error
authenticate(reader_t *reader,
             openpgp_card_t *card,
             const data_t data,
             data_t *answer);

extern pcsc_error
sign(reader_t *reader,
     openpgp_card_t *card,
     const signature_t algo,
     const data_t data,
     data_t *answer);

#endif
