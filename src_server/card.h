// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
/*
 *  scdaemon
 *  Copyright (C) 2013 SGDSN/ANSSI
 *
 *  All rights reserved.
 *
 */

#ifndef __CARD_H__
#define __CARD_H__

#include <stdint.h>

#include "defaults.h"
#include "pcsc.h"
#include "common.h"



#define MAX_ATR_LENGTH SCARD_ATR_LENGTH
#define MAX_APDU_SEND_BUFFER_LENGTH (1 + 1 + 1 + 1 + 3 + 65535 + 3)
#define MAX_APDU_RECEIVE_BUFFER_LENGTH (65536 + 2)



typedef struct {
  data_t name;

  unsigned char is_connected;
  SCARDHANDLE handle;
  unsigned char is_locked;
  DWORD protocol;
  DWORD state;

  unsigned char send_buffer[MAX_APDU_SEND_BUFFER_LENGTH];
  unsigned int send_length;
  unsigned char receive_buffer[MAX_APDU_RECEIVE_BUFFER_LENGTH];
  unsigned int receive_length;

  unsigned char is_containing_card;
  data_t atr;
} reader_t;

typedef struct {
  unsigned char is_available;
  SCARDCONTEXT context;

  unsigned int nb_readers;
  reader_t *readers;
} service_t;


extern pcsc_error
connect_service(service_t *service);

extern pcsc_error
update_service_content(service_t *service);

extern void
disconnect_service(service_t *service);

extern void
clean_service(service_t *service);


extern pcsc_error
connect_reader(service_t *service,
               unsigned char locked,
               reader_t *reader);

extern void
disconnect_reader(reader_t *reader,
                  unsigned int reset);



extern pcsc_error
send_apdu(reader_t *reader,
          const unsigned char cla,
          const unsigned char ins,
          const unsigned char p1,
          const unsigned char p2,
          const unsigned char *data,
          const unsigned short data_length,
          const unsigned char is_extended,
          const unsigned short le,
          data_t *answer);

#endif
