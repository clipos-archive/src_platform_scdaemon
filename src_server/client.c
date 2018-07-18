// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
/*
 *  scdaemon
 *  Copyright (C) 2013 SGDSN/ANSSI
 *
 *  All rights reserved.
 *
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <time.h>
#include <signal.h>
#include <syslog.h>

#include "defaults.h"
#include "common.h"
#include "client.h"
#include "pcsc.h"
#include "card.h"
#include "openpgp.h"

#include "agent.h"



void
logger_client(const char *level,
              const unsigned int syslog_level,
              const int color,
              client_t *client,
              const char *fmt,
              va_list args) {
  char *ret;
  int rval = 0;

  ret = NULL;
  if(SCDAEMON_colors_enabled) {
    rval = asprintf(&ret, "\x1b[38;5;%dm[client %8x]\x1b[0m  %s", RGB(0,0,1), client->id, fmt);
  } else {
    rval = asprintf(&ret, "[client %8x]  %s", client->id, fmt);
  }

  if(rval) { logger(level, syslog_level, color, ret, args); free(ret); }
  else { logger(level, syslog_level, color, fmt, args); }
}

#ifdef DEBUG
void
log_debug_client(client_t *client,
                 const char *fmt,
                 ...) {
  va_list args;
  va_start(args, fmt);
  logger_client("debug", LOG_DEBUG, RGB(1,0,1), client, fmt, args);
  va_end(args);
}
#endif

void
log_error_client(client_t *client,
                 const char *fmt,
                 ...) {
  va_list args;
  va_start(args, fmt);
  logger_client("error", LOG_ERR, RGB(1,0,0), client, fmt, args);
  va_end(args);
}

void
log_info_client(client_t *client,
                const char *fmt,
                ...) {
  va_list args;
  va_start(args, fmt);
  logger_client("info", LOG_INFO, RGB(1,1,1), client, fmt, args);
  va_end(args);
}










pcsc_error
list_reader_with_openpgp_cards(client_t *client,
                               openpgp_reader_t **result,
                               unsigned short *result_length) {
  unsigned int i;
  pcsc_error scarderr = SCARD_S_SUCCESS;

  if(((scarderr = connect_service(&(client->service))) != SCARD_S_SUCCESS) ||
     ((scarderr = update_service_content(&(client->service))) != SCARD_S_SUCCESS)) {
    return scarderr;
  }

  *result = NULL;
  *result_length = 0;
  
  for(i = 0; i < client->service.nb_readers; ++i) {
    reader_t *reader = &(client->service.readers[i]);

    if(reader->is_containing_card) {
      unsigned char was_connected = reader->is_connected;
      
      if(!(reader->is_connected)) {
        (void)connect_reader(&(client->service), 0, reader);
      }

      if(reader->is_connected) {
        openpgp_card_t ocard;

        init_openpgp_card(&ocard);
        
        if((select_openpgp_application(reader) == SCARD_S_SUCCESS) &&
           (get_data_aid(reader, &ocard) == SCARD_S_SUCCESS)) {

          if(ocard.aid.data && ocard.aid.data_length) {
            if(*result) {
              *result = realloc(*result, ((*result_length)+1) * sizeof(openpgp_reader_t));
            } else {
              *result_length = 0;
              *result = malloc(((*result_length)+1) * sizeof(openpgp_reader_t));
            }

            if(*result) {
              (*result)[*result_length].reader = reader;
              init_data(&((*result)[*result_length].aid));
              data_dup(&((*result)[*result_length].aid), ocard.aid);
              ++(*result_length);
            }
          }
          
        }
        
        clean_openpgp_card(&ocard);
      } else {
        if(!was_connected && reader->is_connected) {
          (void)disconnect_reader(reader, 1);
        }
      }
     
    }
    
  }

  return scarderr;
}






int
handle_client(const int client_id,
              const int client_fd_in,
              const int client_fd_out,
              const unsigned char is_socket) {
  int error;
  client_t client;

  struct sigaction sigpipe_handler;

  sigpipe_handler.sa_handler = SIG_IGN;
  sigpipe_handler.sa_flags = 0;
  sigemptyset(&sigpipe_handler.sa_mask);
  if(sigaction(SIGPIPE, &sigpipe_handler, NULL)) {
    log_error("failed to set client signal action", strerror(errno));
    error = errno;
    return error;
  }


  (void)memset(&client, 0, sizeof(client_t));
  
  client.id = client_id;
  client.fd_in = client_fd_in;
  client.fd_out = client_fd_out;
  client.is_socket = is_socket;

  log_info_client(&client, "accepted");

  error = agent_loop(&client);

  disconnect_service(&(client.service));

  clean_service(&(client.service));
  
  if(!SCDAEMON_do_stop && error) {
    log_error_client(&client, "protocol error");
  }

  log_info_client(&client, "disconnected");

  return error;
}
