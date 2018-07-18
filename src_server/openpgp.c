// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
/*
 *  scdaemon
 *  Copyright (C) 2013 SGDSN/ANSSI
 *
 *  All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define _GCRYPT_IN_LIBGCRYPT 1
#include <gcrypt.h>

#include "common.h"
#include "card.h"
#include "openpgp.h"


#define OPENPGP_APPLICATION ((unsigned char []) { 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01 })


#define OPENPGP_GET_DATA_TAG_AID 0x004F
#define OPENPGP_GET_DATA_TAG_HISTORICAL_BYTES 0x5F52
#define OPENPGP_GET_DATA_TAG_SECURITY_SUPPORT_TEMPLATE 0x7A

#define OPENPGP_GET_DATA_TAG_LOGIN_DATA 0x005E
#define OPENPGP_GET_DATA_TAG_URL 0x5F50
#define OPENPGP_GET_DATA_TAG_CARDHOLDER_RELATED_DATA 0x0065
#define OPENPGP_GET_DATA_TAG_APPLICATION_RELATED_DATA 0x006E
#define OPENPGP_GET_DATA_TAG_PW_STATUS 0x00C4


#define OPENPGP_FINGERPRINT_SIZE 20
#define OPENPGP_KEYGRIP_SIZE 20
#define OPENPGP_CA_FINGERPRINT_SIZE OPENPGP_FINGERPRINT_SIZE



#define OPENPGP_SHA1_HASH_LENGTH      20
#define OPENPGP_RIPEMD160_HASH_LENGTH 20
#define OPENPGP_SHA224_HASH_LENGTH    28
#define OPENPGP_SHA256_HASH_LENGTH    32
#define OPENPGP_SHA384_HASH_LENGTH    48
#define OPENPGP_SHA512_HASH_LENGTH    64

#define OPENPGP_SHA1_SIGNATURE_HEADER      "3021300906052B0E03021A05000414"
#define OPENPGP_RIPEMD160_SIGNATURE_HEADER "3021300906052B2403020105000414"
#define OPENPGP_SHA224_SIGNATURE_HEADER    "302D300D06096086480165030402040500041C"
#define OPENPGP_SHA256_SIGNATURE_HEADER    "3031300D060960864801650304020105000420"
#define OPENPGP_SHA384_SIGNATURE_HEADER    "3041300D060960864801650304020205000430"
#define OPENPGP_SHA512_SIGNATURE_HEADER    "3051300D060960864801650304020305000440"



void
init_openpgp_key(openpgp_key_t *key) {
  (void)memset(key, 0, sizeof(openpgp_key_t));
  init_data(&(key->modulus));
  init_data(&(key->public_exponent));
  init_data(&(key->fingerprint));
  init_data(&(key->s_expression));
  init_data(&(key->keygrip));
}


void
init_openpgp_card(openpgp_card_t *card) {
  (void)memset(card, 0, sizeof(openpgp_card_t));
  init_data(&(card->aid));
  init_data(&(card->historical_bytes));
  init_data(&(card->login));
  init_data(&(card->url));
  init_data(&(card->name));
  init_data(&(card->language));
  init_data(&(card->ca_fingerprint_signature));
  init_data(&(card->ca_fingerprint_decryption));
  init_data(&(card->ca_fingerprint_authentication));

  init_openpgp_key(&(card->signature_key));
  init_openpgp_key(&(card->decryption_key));
  init_openpgp_key(&(card->authentication_key));
}


void
clean_openpgp_key(openpgp_key_t *key,
                  const unsigned char include_fingerprint) {
  clean_data(&(key->modulus));
  clean_data(&(key->public_exponent));
  clean_data(&(key->s_expression));
  clean_data(&(key->keygrip));
  if(include_fingerprint) {
    clean_data(&(key->fingerprint));
  }
}

void
clean_openpgp_card(openpgp_card_t *card) {
  clean_data(&(card->aid));
  clean_data(&(card->historical_bytes));
  clean_data(&(card->login));
  clean_data(&(card->url));
  clean_data(&(card->name));
  clean_data(&(card->language));
  clean_data(&(card->ca_fingerprint_signature));
  clean_data(&(card->ca_fingerprint_decryption));
  clean_data(&(card->ca_fingerprint_authentication));

  clean_openpgp_key(&(card->signature_key), 1);
  clean_openpgp_key(&(card->decryption_key), 1);
  clean_openpgp_key(&(card->authentication_key), 1);
}









pcsc_error
select_openpgp_application(reader_t *reader) {
  pcsc_error scarderr = SCARD_S_SUCCESS;
  data_t answer;
  
#ifdef DEBUG_OPENPGP
  log_debug("OPENPGP SELECTING APPLICATION");
#endif

  init_data(&answer);

  scarderr = send_apdu(reader,
                       0x0, 0xA4, 0x4, 0x0,
                       OPENPGP_APPLICATION,
                       sizeof(OPENPGP_APPLICATION),
                       1, 0,
                       &answer);

  if(scarderr == SCARD_S_SUCCESS) {
    clean_data(&answer);
  }
  
  return scarderr;
}



pcsc_error
get_data_generic(reader_t *reader,
                 const unsigned short tag,
                 data_t *answer) {
  pcsc_error scarderr = SCARD_S_SUCCESS;

#ifdef DEBUG_OPENPGP
  log_debug("OPENPGP GET DATA GENERIC TAG 0x%x", tag);
#endif
  
  scarderr = send_apdu(reader,
                       0x0, 0xCA, (tag >> 8) & 0xff, (tag & 0xff),
                       NULL, 0,
                       1, 0,
                       answer);

  return scarderr;
}



void
parse_algorithm_attributes(key_settings_t *aa,
                           const unsigned char *data,
                           const unsigned int length) {

  (void)memset(aa, 0, sizeof(key_settings_t));

  if(length) {
    switch(data[0]) {
    case RSA:
      aa->algorithm = data[0];
      break;
    }

    if(length > 2) {
      aa->modulus_size = ((unsigned short)(data[1]) << 8) | data[2];
      
      if(length > 4) {
        aa->public_exponent_size = ((unsigned short)(data[3]) << 8) | data[4];
        
        if(length > 5) {
          switch(data[5]) {
          case StandardKey:
          case StandardKeyWithModulus:
          case ChineseRemainderTheorem:
          case ChineseRemainderTheoremWithModulus:
            aa->private_key_format = data[5];
          }
        }
      }
    }
  }
}



void
parse_date(time_t *date,
           const unsigned char *data,
           const unsigned int length) {

  *date = 0;
  if(length > 3) {
    *date =
      ((unsigned int)data[0] << 24) |
      ((unsigned int)data[1] << 16) |
      ((unsigned int)data[2] << 8) |
      data[3];
  }
}


void
parse_pw_status(openpgp_card_t *card,
                const unsigned char *data,
                const unsigned int length) {
  card->supported_user_pin_cache = 0;
  (void)memset(&(card->user_pin), 0, sizeof(pin_t));
  (void)memset(&(card->reset_code), 0, sizeof(pin_t));
  (void)memset(&(card->admin_pin), 0, sizeof(pin_t));
  
  if(length) card->supported_user_pin_cache = data[0] & 0x1;
  if(length > 1) card->user_pin.max_length = data[1];
  if(length > 2) card->reset_code.max_length = data[2];
  if(length > 3) card->admin_pin.max_length = data[3];
  if(length > 4) card->user_pin.remaining_tries = data[4];
  if(length > 5) card->reset_code.remaining_tries = data[5];
  if(length > 6) card->admin_pin.remaining_tries = data[6];
}



int
parse_tlv(openpgp_card_t *card,
          const unsigned char *data,
          const unsigned int data_length) {

  unsigned int length = 0;
  unsigned int plength = 2;
  
  if(data_length < 2) return 1;

#ifdef DEBUG_OPENPGP

  log_debug("OPENPGP PARSE TLV tag = 0x%x", data[0]);

#endif
  
  switch(data[0]) {
  case 0x4f:
    clean_data(&(card->aid));
    card->application_version_major = 0;
    card->application_version_minor = 0;
    card->manufacturer = 0;
    card->serial_number = 0;
    
    if((length = data[plength - 1]) && (plength + length <= data_length)) {
      data_memcpy(&(card->aid), &(data[plength]), length);
      if(card->aid.data_length > 7) {
        card->application_version_major = card->aid.data[6];
        card->application_version_minor = card->aid.data[7];
      }
      if(card->aid.data_length > 9) card->manufacturer = ((unsigned int)(card->aid.data[8]) << 8) | card->aid.data[9];
      if(card->aid.data_length > 13) {
        card->serial_number =
          ((unsigned int)(card->aid.data[10]) << 24) |
          ((unsigned int)(card->aid.data[11]) << 16) |
          ((unsigned int)(card->aid.data[12]) << 8) |
          card->aid.data[13];
      }
    }
    break;

  case 0x5b:
    clean_data(&(card->name));
    if((length = data[plength - 1]) && (plength + length <= data_length)) {
      data_memcpy(&(card->name), &(data[plength]), length);
    }
   break;
   
  case 0x5f:
    if(data_length < 3) return 3;
    plength = 3;
    
    switch(data[1]) {
    case 0x2d:
      clean_data(&(card->language));
      if((length = data[plength - 1]) && (plength + length <= data_length)) {
        data_memcpy(&(card->language), &(data[plength]), length);
      }
      break;
      
    case 0x35:
      card->sex = 0;
      if((length = data[plength - 1]) && (plength + length <= data_length)) {
        switch(data[plength]) {
        case Male:
        case Female:
        case Undetermined:
          card->sex = data[plength];
          break;
        }
      }
      break;
      
    case 0x52:
      clean_data(&(card->historical_bytes));
      if((length = data[plength - 1]) && (plength + length <= data_length)) {
        data_memcpy(&(card->historical_bytes), &(data[plength]), length);
      }
      break;
      
    default:
      return 1;
    }
    break;

  case 0x73:
    if(data_length < 3) return 3;
    plength = 1;
    length = 2;
    break;

  case 0x93:
    card->signatures_counter = 0;

    if((length = data[plength - 1]) && (plength + length <= data_length)) {
      if(length > 2) {
        card->signatures_counter =
          ((unsigned int)data[plength] << 16) |
          ((unsigned int)data[plength + 1] << 8) |
          data[plength + 2];
      }
    }
    break;

  case 0xC0:
    card->supports_secure_messaging = 0;
    card->supports_get_challenge = 0;
    card->supports_key_import = 0;
    card->supports_pw_status_change = 0;
    card->supports_private_dos = 0;
    card->supports_algorithm_attributes_change = 0;
    card->secure_messaging_algorithm = 0;
    card->maximum_length_of_challenge = 0;
    card->maximum_length_of_cardholder_cert = 0;
    card->maximum_length_of_command = 0;
    card->maximum_length_of_response = 0;
    
    if((length = data[plength - 1]) && (plength + length <= data_length)) {
      if(length > 1) {
        card->supports_secure_messaging = data[plength] & 0x80;
        card->supports_get_challenge = data[plength] & 0x40;
        card->supports_key_import = data[plength] & 0x20;
        card->supports_pw_status_change = data[plength] & 0x10;
        card->supports_private_dos = data[plength] & 0x08;
        card->supports_algorithm_attributes_change = data[plength] & 0x04;

        if(card->supports_secure_messaging && (length > 1)) {
          switch(data[plength + 1]) {
          case TripleDes:
          case Aes:
            card->secure_messaging_algorithm = data[plength + 1];
            break;
          }
        }
        
        if(length > 3) {
          if(card->supports_get_challenge)
            card->maximum_length_of_challenge = ((unsigned short)(data[plength + 2]) << 8) | data[plength + 3];
          
          if(length > 5) {
            card->maximum_length_of_cardholder_cert = ((unsigned short)(data[plength + 4]) << 8) | data[plength + 5];
            
            if(length > 7) {
              card->maximum_length_of_command = ((unsigned short)(data[plength + 6]) << 8) | data[plength + 7];
              
              if(length > 9) {
                card->maximum_length_of_response = ((unsigned short)(data[plength + 8]) << 8) | data[plength + 9];
              }
            }
          }
        }
      }
    }
    break;

  case 0xC1:
    length = data[plength - 1];
    parse_algorithm_attributes(&(card->signature_settings),
                               &(data[plength]),
                               (plength + length <= data_length) ? length : 0);
    break;

  case 0xC2:
    length = data[plength - 1];
    parse_algorithm_attributes(&(card->decryption_settings),
                               &(data[plength]),
                               (plength + length <= data_length) ? length : 0);
    break;    

  case 0xC3:
    length = data[plength - 1];
    parse_algorithm_attributes(&(card->authentication_settings),
                               &(data[plength]),
                               (plength + length <= data_length) ? length : 0);
    break;    

  case 0xC4:
    card->supported_user_pin_cache = 0;
    (void)memset(&(card->user_pin), 0, sizeof(pin_t));
    (void)memset(&(card->reset_code), 0, sizeof(pin_t));
    (void)memset(&(card->admin_pin), 0, sizeof(pin_t));

    length = data[plength - 1];
    if(plength + length <= data_length) {
      parse_pw_status(card, &(data[plength]), length);
    }
    break;    

  case 0xC5:
    clean_data(&(card->signature_key.fingerprint));
    clean_data(&(card->decryption_key.fingerprint));
    clean_data(&(card->authentication_key.fingerprint));
    
    if((length = data[plength - 1]) && (plength + length <= data_length)) {
      if(length == 3*OPENPGP_FINGERPRINT_SIZE) {
        data_memcpy(&(card->signature_key.fingerprint), &(data[plength]), OPENPGP_FINGERPRINT_SIZE);
        data_memcpy(&(card->decryption_key.fingerprint), &(data[plength+OPENPGP_FINGERPRINT_SIZE]), OPENPGP_FINGERPRINT_SIZE);
        data_memcpy(&(card->authentication_key.fingerprint), &(data[plength+2*OPENPGP_FINGERPRINT_SIZE]), OPENPGP_FINGERPRINT_SIZE);
      }
    }
    break;    

  case 0xC6:
    clean_data(&(card->ca_fingerprint_signature));
    clean_data(&(card->ca_fingerprint_decryption));
    clean_data(&(card->ca_fingerprint_authentication));
    
    if((length = data[plength - 1]) && (plength + length <= data_length)) {
      if(length == 3*OPENPGP_CA_FINGERPRINT_SIZE) {
        data_memcpy(&(card->ca_fingerprint_signature), &(data[plength]), OPENPGP_CA_FINGERPRINT_SIZE);
        data_memcpy(&(card->ca_fingerprint_decryption), &(data[plength+OPENPGP_CA_FINGERPRINT_SIZE]), OPENPGP_CA_FINGERPRINT_SIZE);
        data_memcpy(&(card->ca_fingerprint_authentication), &(data[plength+2*OPENPGP_CA_FINGERPRINT_SIZE]), OPENPGP_CA_FINGERPRINT_SIZE);
      }
    }
    break;    

  case 0xCD:

    (void)memset(&(card->signature_key.generation_date), 0, sizeof(time_t));
    (void)memset(&(card->decryption_key.generation_date), 0, sizeof(time_t));
    (void)memset(&(card->authentication_key.generation_date), 0, sizeof(time_t));
    
    length = data[plength - 1];

    if(plength + length <= data_length) {
      parse_date(&(card->signature_key.generation_date),
                 &(data[plength]), length);
      if(length > 7)
        parse_date(&(card->decryption_key.generation_date),
                   &(data[plength + 4]), length - 4);
      if(length > 11)
        parse_date(&(card->authentication_key.generation_date),
                   &(data[plength + 8]), length - 8);
    }
    break;
    
  default:
    return 1;
  }
  
  if((plength + length) < data_length)
    return parse_tlv(card,
                     &(data[plength + length]),
                     data_length - plength - length);

  return 0;
}



int
parse_do_7f49(openpgp_key_t *key,
              const unsigned char *data,
              const unsigned int data_length) {

  unsigned short plength;
  unsigned short length;


#ifdef DEBUG_OPENPGP

  log_debug("OPENPGP PARSE DO 7F49 tag = 0x%x", data[0]);

#endif

  if(data_length < 2) return 1;
  
  plength = 2;
  length = 0;

  if(data[1] < 0x80) length = data[1];
  else if((data_length > 2) && (data[1] == 0x81)) { plength = 3; length = data[2]; }
  else if((data_length > 3) && (data[1] == 0x82)) { plength = 4; length = ((unsigned int)(data[2]) << 8) | data[3]; }
  else return 2;

  if((plength + length) > data_length)
    return 3;

  switch(data[0]) {
  case 0x81:
    clean_data(&(key->modulus));
    data_memcpy(&(key->modulus), &(data[plength]), length);
    break;

  case 0x82:
    clean_data(&(key->public_exponent));
    data_memcpy(&(key->public_exponent), &(data[plength]), length);
    break;

  default:
    return 4;
  }

  if((plength + length) < data_length)
    return parse_do_7f49(key,
                         &(data[plength + length]),
                         data_length - plength - length);

  return 0;
}







pcsc_error
get_data_aid(reader_t *reader,
             openpgp_card_t *card) {
  
  clean_data(&(card->aid));

#ifdef DEBUG_OPENPGP
  log_debug("OPENPGP GET DATA AID");
#endif

  return get_data_generic(reader,
                          OPENPGP_GET_DATA_TAG_AID,
                          &(card->aid));
}


pcsc_error
get_data_historical_bytes(reader_t *reader,
                          openpgp_card_t *card) {

  clean_data(&(card->historical_bytes));

#ifdef DEBUG_OPENPGP
  log_debug("OPENPGP GET HISTORICAL BYTES");
#endif

  return get_data_generic(reader,
                          OPENPGP_GET_DATA_TAG_HISTORICAL_BYTES,
                          &(card->historical_bytes));
}


pcsc_error
get_data_login(reader_t *reader,
               openpgp_card_t *card) {

  clean_data(&(card->login));

#ifdef DEBUG_OPENPGP
  log_debug("OPENPGP GET LOGIN");
#endif

  return get_data_generic(reader, OPENPGP_GET_DATA_TAG_LOGIN_DATA,
                          &(card->login));
}


pcsc_error
get_data_url(reader_t *reader,
             openpgp_card_t *card) {

  clean_data(&(card->url));

#ifdef DEBUG_OPENPGP
  log_debug("OPENPGP GET URL");
#endif

  return get_data_generic(reader, OPENPGP_GET_DATA_TAG_URL,
                          &(card->url));
}


pcsc_error
get_data_cardholder(reader_t *reader,
                    openpgp_card_t *card) {

  pcsc_error scarderr;
  data_t answer;

#ifdef DEBUG_OPENPGP
  log_debug("OPENPGP GET CARDHOLDER RELATED DATA");
#endif
  
  init_data(&answer);

  if((scarderr = get_data_generic(reader, OPENPGP_GET_DATA_TAG_CARDHOLDER_RELATED_DATA, &answer)) == SCARD_S_SUCCESS) {
    if(parse_tlv(card, answer.data, answer.data_length)) {
      clean_data(&answer);
      return SCARD_E_INVALID_VALUE;
    }

    clean_data(&answer);
  }
  
  return scarderr;
}


pcsc_error
get_data_security_support_template(reader_t *reader,
                                   openpgp_card_t *card) {
  pcsc_error scarderr;
  data_t answer;

#ifdef DEBUG_OPENPGP
  log_debug("OPENPGP GET SECURITY SUPPORT TEMPLATE");
#endif

  init_data(&answer);

  card->signatures_counter = 0;

  if((scarderr = get_data_generic(reader,
                                  OPENPGP_GET_DATA_TAG_SECURITY_SUPPORT_TEMPLATE, &answer)) == SCARD_S_SUCCESS) {
    if(parse_tlv(card, answer.data, answer.data_length)) {
      clean_data(&answer);
      return SCARD_E_INVALID_VALUE;
    }
    
    clean_data(&answer);
  }     
  
  return scarderr;
}



pcsc_error
get_data_application(reader_t *reader,
                     openpgp_card_t *card) {

  pcsc_error scarderr;
  data_t answer;

#ifdef DEBUG_OPENPGP
  log_debug("OPENPGP GET APPLICATION RELATED DATA");
#endif

  init_data(&answer);

  if((scarderr = get_data_generic(reader, OPENPGP_GET_DATA_TAG_APPLICATION_RELATED_DATA, &answer)) == SCARD_S_SUCCESS) {
    if(parse_tlv(card, answer.data, answer.data_length)) {
      clean_data(&answer);
      return SCARD_E_INVALID_VALUE;
    }

    clean_data(&answer);
  }
  
  return scarderr;
}




pcsc_error
get_data_pw_status(reader_t *reader,
                   openpgp_card_t *card) {

  pcsc_error scarderr;
  data_t answer;

#ifdef DEBUG_OPENPGP
  log_debug("OPENPGP GET PW STATUS");
#endif

  init_data(&answer);
  
  if((scarderr = get_data_generic(reader, OPENPGP_GET_DATA_TAG_PW_STATUS, &answer)) == SCARD_S_SUCCESS) {
    
    parse_pw_status(card, answer.data, answer.data_length);
    clean_data(&answer);
  }
  
  return scarderr;
}





pcsc_error
verify_pin(reader_t *reader,
           openpgp_card_t *card,
           const pin_descriptor_t pin_desc,
           const unsigned char user_pin_for_signature,
           const data_t pin) {

  pcsc_error scarderr = SCARD_S_SUCCESS;
  unsigned char real_pin = 0;

#ifdef DEBUG_OPENPGP
  log_debug("OPENPGP VERIFY PIN");
#endif
    
  if(pin.data_length) {

    switch(pin_desc) {
    case UserPin:
      if(pin.data_length > card->user_pin.max_length)
        scarderr = SCARD_E_INVALID_VALUE;
      real_pin = user_pin_for_signature ? 0x81 : 0x82;
      break;
      
    case ResetCode:
      /*      if(pin.data_length > card->reset_code.max_length)*/
        scarderr = SCARD_E_INVALID_VALUE;
      break;
      
    case AdminPin:
      if(pin.data_length > card->admin_pin.max_length)
        scarderr = SCARD_E_INVALID_VALUE;
      real_pin = 0x83;
      break;
      
    default:
      scarderr = SCARD_E_INVALID_VALUE;
      break;
    }
  
    if(scarderr == SCARD_S_SUCCESS) {
      data_t answer;

      init_data(&answer);

      if((scarderr = send_apdu(reader,
                               0x00, 0x20, 0x00, real_pin,
                               pin.data, pin.data_length,
                               0, 0,
                               &answer)) == SCARD_S_SUCCESS) {
        clean_data(&answer);
      } else {
        (void)get_data_pw_status(reader, card);
      }
        
    }
    
  } else {
    scarderr = SCARD_E_INVALID_CHV;
  }

  return scarderr;
}










pcsc_error
change_pin(reader_t *reader,
           openpgp_card_t *card,
           const pin_descriptor_t pin_desc,
           const data_t actual_pin,
           const data_t new_pin) {
  
  pcsc_error scarderr = SCARD_S_SUCCESS;

#ifdef DEBUG_OPENPGP
  log_debug("OPENPGP CHANGE PIN");
#endif
  
  if(actual_pin.data_length && new_pin.data_length) {
    
    switch(pin_desc) {
    case UserPin:
      if((actual_pin.data_length > card->user_pin.max_length) ||
         (new_pin.data_length > card->user_pin.max_length))
        scarderr = SCARD_E_INVALID_VALUE;
      break;
      
    case AdminPin:
      if((actual_pin.data_length > card->admin_pin.max_length) ||
         (new_pin.data_length > card->admin_pin.max_length))
        scarderr = SCARD_E_INVALID_VALUE;
      break;
      
    case ResetCode:
    default:
      scarderr = SCARD_E_INVALID_VALUE;
      break;
    }
    
    
    if(scarderr == SCARD_S_SUCCESS) {
      data_t data, answer;
      
      init_data(&data);
      init_data(&answer);
      
      data_append(&data, actual_pin.data, actual_pin.data_length);
      data_append(&data, new_pin.data, new_pin.data_length);
      
      if((scarderr = send_apdu(reader,
                               0x00, 0x24, 0x00, pin_desc,
                               data.data, data.data_length,
                               0, 0,
                               &answer)) == SCARD_S_SUCCESS) {
        clean_data(&answer);
      }
      
      clean_data(&data);
      
      (void)get_data_pw_status(reader, card);
    }

  } else scarderr = SCARD_E_INVALID_CHV;

  return scarderr;
}










pcsc_error
read_openpgp_key_generic(reader_t *reader,
                         openpgp_card_t *card,
                         openpgp_key_t *key,
                         openpgp_key_type_t key_type) {

  pcsc_error scarderr = SCARD_S_SUCCESS;
  data_t answer;
  unsigned char data[2];


#ifdef DEBUG_OPENPGP
  log_debug("OPENPGP READ KEY GENERIC");
#endif
  
  clean_openpgp_key(key, 0);
  
  switch(key_type) {
  case KeySignature:
  case KeyDecryption:
  case KeyAuthentication:
   break;
  default:
    return SCARD_E_INVALID_VALUE;
  }
  
  data[0] = key_type;
  data[1] = 0x00;

  init_data(&answer);

  if((scarderr = send_apdu(reader,
                           0x0, 0x47, 0x81, 0x00,
                           data, 2,
                           1, card->maximum_length_of_response,
                           &answer)) == SCARD_S_SUCCESS) {
    
    if(answer.data) {
      
      if(answer.data_length < 3) scarderr = SCARD_E_INVALID_VALUE;
      else {
        unsigned short tag = ((unsigned short)(answer.data[0]) << 8) | answer.data[1];
        
        if(tag != 0x7f49) scarderr = SCARD_E_INVALID_VALUE;
        else {
          unsigned short plength = 3;
          unsigned short length = 0;
          
          if(answer.data[2] < 0x80) length = answer.data[2];
          else if((answer.data_length > 3) && (answer.data[2] == 0x81)) { plength = 4; length = answer.data[3]; }
          else if((answer.data_length > 4) && (answer.data[2] == 0x82)) { plength = 5; length = ((unsigned int)(answer.data[3]) << 8) | answer.data[4]; }
          else scarderr = SCARD_E_INVALID_VALUE;
          
          if(scarderr == SCARD_S_SUCCESS) {
            if(length && ((plength + length) == answer.data_length)) {
              if(parse_do_7f49(key, &(answer.data[plength]), length))
                scarderr = SCARD_E_INVALID_VALUE;
            } else scarderr = SCARD_E_INVALID_VALUE;
          }
        }
      }
      
      clean_data(&answer);
    }
  }


  if(key->modulus.data && key->public_exponent.data) {
    char *tmpn = NULL, *tmpe = NULL;
    unsigned int unbugged_mod_length, unbugged_exp_length, rval;

    unbugged_mod_length = key->modulus.data_length;
    unbugged_exp_length = key->public_exponent.data_length;

#ifdef FIX_S_EXPRESSION_NUMBERS
    if(key->modulus.data_length && (key->modulus.data[0] & 0x80))
      ++unbugged_mod_length;

    if(key->public_exponent.data_length && (key->public_exponent.data[0] & 0x80))
      ++unbugged_exp_length;
#endif

    rval = asprintf(&tmpn, "(10:public-key(3:rsa(1:n%u:", unbugged_mod_length);
    rval = asprintf(&tmpe, ")(1:e%u:", unbugged_exp_length);

    if(rval && tmpn && tmpe) {
      unsigned int tmpn_len = strlen(tmpn);
      unsigned int tmpe_len = strlen(tmpe);

      clean_data(&(key->s_expression));

      data_append(&(key->s_expression), (unsigned char*)tmpn, tmpn_len);

#ifdef FIX_S_EXPRESSION_NUMBERS
      if(unbugged_mod_length > key->modulus.data_length)
        data_append(&(key->s_expression), (unsigned char*)"\0", 1);
#endif
          
      data_append(&(key->s_expression), key->modulus.data, key->modulus.data_length);
      
      data_append(&(key->s_expression), (unsigned char*)tmpe, tmpe_len);

#ifdef FIX_S_EXPRESSION_NUMBERS
      if(unbugged_exp_length > key->public_exponent.data_length)
        data_append(&(key->s_expression), (unsigned char*)"\0", 1);
#endif
      
      data_append(&(key->s_expression), key->public_exponent.data, key->public_exponent.data_length);

      data_append(&(key->s_expression), (unsigned char*)")))", 3);
    }
    
    if(tmpn) { free(tmpn); }
    if(tmpe) { free(tmpe); }
    
    if(key->s_expression.data) {
      gcry_sexp_t gsexp;

      if(!gcry_sexp_sscan(&gsexp, NULL, (char *)(key->s_expression.data), key->s_expression.data_length)) {

        clean_data(&(key->keygrip));
        
        key->keygrip.data = (unsigned char *)malloc((OPENPGP_KEYGRIP_SIZE + 1) * sizeof(unsigned char));
        if(key->keygrip.data) {
          if(gcry_pk_get_keygrip(gsexp, key->keygrip.data)) {
            key->keygrip.data_length = OPENPGP_KEYGRIP_SIZE;
          } else {
            clean_data(&(key->keygrip));
          }
        }

        gcry_sexp_release(gsexp);
      }
    }
  }


  return scarderr;
}




pcsc_error
read_openpgp_signature_key(reader_t *reader,
                           openpgp_card_t *card) {
#ifdef DEBUG_OPENPGP
  log_debug("OPENPGP READ SIGNATURE KEY");
#endif

  return read_openpgp_key_generic(reader, card,
                                  &(card->signature_key),
                                  KeySignature);
}

pcsc_error
read_openpgp_decryption_key(reader_t *reader,
                            openpgp_card_t *card) {

#ifdef DEBUG_OPENPGP
  log_debug("OPENPGP READ DECRYPTION KEY");
#endif

  return read_openpgp_key_generic(reader, card,
                                  &(card->decryption_key),
                                  KeyDecryption);
}

pcsc_error
read_openpgp_authentication_key(reader_t *reader,
                                openpgp_card_t *card) {
#ifdef DEBUG_OPENPGP
  log_debug("OPENPGP READ AUTHENTICATION KEY");
#endif

  return read_openpgp_key_generic(reader, card,
                                  &(card->authentication_key),
                                  KeyAuthentication);
}



pcsc_error
decipher(reader_t *reader,
         openpgp_card_t *card,
         const data_t data,
         data_t *answer) {

  pcsc_error scarderr = SCARD_S_SUCCESS;
  data_t pkcs1;

#ifdef DEBUG_OPENPGP

  log_debug("OPENPGP DECIPHER");

#endif

  init_data(&pkcs1);

  data_memcpy(&pkcs1, (unsigned char *)"\0", 1);
  data_append(&pkcs1, data.data, data.data_length);

  clean_data(answer);
  
  if((scarderr = send_apdu(reader,
                           0x00, 0x2A, 0x80, 0x86,
                           pkcs1.data, pkcs1.data_length,
                           1, card->maximum_length_of_response,
                           answer)) != SCARD_S_SUCCESS) {
    clean_data(answer);
  }
  
  clean_data(&pkcs1);
  
  return scarderr;
}




pcsc_error
authenticate(reader_t *reader,
             openpgp_card_t *card,
             const data_t data,
             data_t *answer) {

  pcsc_error scarderr = SCARD_S_SUCCESS;
  data_t pkcs1;

#ifdef DEBUG_OPENPGP

  log_debug("OPENPGP AUTHENTICATE");

#endif

  init_data(&pkcs1);

  data_append(&pkcs1, data.data, data.data_length);

  clean_data(answer);
  
  if((scarderr = send_apdu(reader,
                           0x00, 0x88, 0x00, 0x00,
                           pkcs1.data, pkcs1.data_length,
                           1, card->maximum_length_of_response,
                           answer)) != SCARD_S_SUCCESS) {
    clean_data(answer);
  }
  
  clean_data(&pkcs1);
  
  return scarderr;
}





pcsc_error
sign(reader_t *reader,
     openpgp_card_t *card,
     const signature_t algo,
     const data_t data,
     data_t *answer) {
  
  pcsc_error scarderr = SCARD_S_SUCCESS;
  data_t blob, hexheader;
  char *header = NULL;
  unsigned int hash_length = 0;

#ifdef DEBUG_OPENPGP

  log_debug("OPENPGP SIGNATURE");

#endif

  switch(algo) {
  case SHA1:
    header = OPENPGP_SHA1_SIGNATURE_HEADER;
    hash_length = OPENPGP_SHA1_HASH_LENGTH;
    break;
  case SHA224:
    header = OPENPGP_SHA224_SIGNATURE_HEADER;
    hash_length = OPENPGP_SHA224_HASH_LENGTH;
    break;
  case SHA256:
    header = OPENPGP_SHA256_SIGNATURE_HEADER;
    hash_length = OPENPGP_SHA256_HASH_LENGTH;
    break;
  case SHA384:
    header = OPENPGP_SHA384_SIGNATURE_HEADER;
    hash_length = OPENPGP_SHA384_HASH_LENGTH;
    break;
  case SHA512:
    header = OPENPGP_SHA512_SIGNATURE_HEADER;
    hash_length = OPENPGP_SHA512_HASH_LENGTH;
    break;
  case RIPEMD160:
    header = OPENPGP_RIPEMD160_SIGNATURE_HEADER;
    hash_length = OPENPGP_RIPEMD160_HASH_LENGTH;
    break;
  }

  if(!header)
    return SCARD_E_INVALID_VALUE;

  if(data.data_length != hash_length)
    return SCARD_E_INVALID_VALUE;

  init_data(&blob);

  init_data(&hexheader);
  data_memcpy(&hexheader, (unsigned char*)header, strlen(header));
  data_of_hex_string(hexheader, &blob);
  clean_data(&hexheader);

  data_append(&blob, data.data, data.data_length);

  clean_data(answer);
  
  if((scarderr = send_apdu(reader,
                           0x00, 0x2A, 0x9E, 0x9A,
                           blob.data, blob.data_length,
                           1, card->maximum_length_of_response,
                           answer)) != SCARD_S_SUCCESS) {
    clean_data(answer);
  }
  
  clean_data(&blob);
  
  return scarderr;
}
