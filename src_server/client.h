// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
/*
 *  scdaemon
 *  Copyright (C) 2013 SGDSN/ANSSI
 *
 *  All rights reserved.
 *
 */

#ifndef __CLIENT_H__
#define __CLIENT_H__

#include <semaphore.h>

#include "card.h"

typedef struct {
  int id;

  int fd_in;
  int fd_out;

  unsigned char is_socket;

  service_t service;
} client_t;


typedef struct {
  reader_t *reader;
  data_t aid;
} openpgp_reader_t;


#ifdef DEBUG
extern void
log_debug_client(client_t *client,
                 const char *fmt,
                 ...);
#endif

extern void
log_error_client(client_t *client,
                 const char *fmt,
                 ...);

extern void
log_info_client(client_t *client,
                const char *fmt,
                ...);


extern int
handle_client(const int client_id,
              const int client_fd_in,
              const int client_fd_out,
              const unsigned char is_socket);

extern pcsc_error
list_reader_with_openpgp_cards(client_t *client,
                               openpgp_reader_t **result,
                               unsigned short *result_length);

#endif
