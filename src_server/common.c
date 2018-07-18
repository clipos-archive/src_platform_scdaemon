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
#include <unistd.h>
#include <semaphore.h>
#include <assert.h>
#include <syslog.h>

#include "defaults.h"
#include "common.h"


volatile unsigned int SCDAEMON_do_stop = 0;

unsigned int SCDAEMON_colors_enabled = DEFAULT_COLORS_ENABLED;

FILE *SCDAEMON_log_file = NULL;

char *SCDAEMON_socket_path = NULL;

char *SCDAEMON_socket_path_for_clients = NULL;




void
init_data(data_t *data) {
  (void)memset(data, 0, sizeof(data_t));
}

void
clean_data(data_t *data) {
  if(data) {
    if(data->data) {
      (void)memset(data->data, 0, data->data_length * sizeof(unsigned char));
      free(data->data);
    }
    data->data = NULL;
    data->data_length = 0;
  }
}


void
data_memcpy(data_t *res,
            const unsigned char *data,
            const unsigned int data_length) {
  if(res) {

    clean_data(res);

    res->data = (unsigned char*)malloc((data_length + 1) * sizeof(unsigned char));
    assert(res->data != NULL);
    if(data) {
      (void)memcpy(res->data, data, data_length * sizeof(unsigned char));
      res->data_length = data_length;
    }
    res->data[res->data_length] = 0;
  }
}

void
data_dup(data_t *res,
         const data_t data) {
  data_memcpy(res, data.data, data.data_length);
}

void
data_append(data_t *res,
            const unsigned char *data,
            const unsigned int data_length) {
  if(res->data) {
    res->data = (unsigned char*)realloc(res->data, (res->data_length + data_length + 1) * sizeof(unsigned char));
    assert(res->data != NULL);
    if(data) {
      (void)memcpy(&(res->data[res->data_length]), data, data_length * sizeof(unsigned char));
      res->data_length += data_length;
    }
    res->data[res->data_length] = 0;
  } else data_memcpy(res, data, data_length);
}


int
data_compare(const data_t data1,
             const data_t data2) {
  unsigned int i;
  if(data1.data_length < data2.data_length) return -1;
  if(data1.data_length > data2.data_length) return 1;
  for(i = 0; i < data1.data_length; ++i) {
    if(data1.data[i] < data2.data[i]) return -1;
    if(data1.data[i] > data2.data[i]) return 1;
  }
  return 0;
}


void
data_assuan_escaped(const data_t in,
                    data_t *out) {
  unsigned int i, newsize;
  
  clean_data(out);

  newsize = 0;
  for(i = 0; i < in.data_length; ++i) {
    switch(in.data[i]) {
    case '\n':
    case '\r':
    case '%':
      newsize += 3;
      break;

    default:
      ++newsize;
      break;
    }
  }

  out->data = (unsigned char *)malloc((newsize + 1) * sizeof(unsigned char));
  assert(out->data != NULL);
  out->data_length = newsize;
  out->data[out->data_length] = 0;
  
  newsize = 0;
  for(i = 0; i < in.data_length; ++i) {
    switch(in.data[i]) {
    case '\n':
      out->data[newsize++] = '%';
      out->data[newsize++] = '0';
      out->data[newsize++] = 'A';
      break;

    case '\r':
      out->data[newsize++] = '%';
      out->data[newsize++] = '0';
      out->data[newsize++] = 'D';
      break;

    case '%':
      out->data[newsize++] = '%';
      out->data[newsize++] = '2';
      out->data[newsize++] = '5';
      break;

    default:
      out->data[newsize++] = in.data[i];
      break;
    }
  }
  
}




void
logger(const char *level,
       const int syslog_level,
       const int color,
       const char *fmt,
       va_list args) {
  char *ret;
  int rval = 0;

  ret = NULL;

  if(SCDAEMON_log_file) {

    if(SCDAEMON_colors_enabled) {
      rval = asprintf(&ret, "\x1b[1m\x1b[38;5;%dm[%5s]\x1b[0m  %s\n", color, level, fmt);
    } else {
      rval = asprintf(&ret, "[%5s]  %s\n", level, fmt);
    }

    if(rval) { (void)vfprintf(SCDAEMON_log_file, ret, args); free(ret); }
    else { (void)vfprintf(SCDAEMON_log_file, fmt, args); }

  } else {
    
    vsyslog(LOG_DAEMON | syslog_level, fmt, args);

  }
}


void
data_of_hex_string(const data_t in,
                   data_t *res) {

  unsigned int i;

  (*res).data = NULL;
  (*res).data_length = 0;

  if(in.data_length%2) return;
  
  i = 0;
  while((i < in.data_length) && ((in.data[i] == '0') ||
                                 (in.data[i] == '1') ||
                                 (in.data[i] == '2') ||
                                 (in.data[i] == '3') ||
                                 (in.data[i] == '4') ||
                                 (in.data[i] == '5') ||
                                 (in.data[i] == '6') ||
                                 (in.data[i] == '7') ||
                                 (in.data[i] == '8') ||
                                 (in.data[i] == '9') ||
                                 (in.data[i] == 'a') || (in.data[i] == 'A') ||
                                 (in.data[i] == 'b') || (in.data[i] == 'B') ||
                                 (in.data[i] == 'c') || (in.data[i] == 'C') ||
                                 (in.data[i] == 'd') || (in.data[i] == 'D') ||
                                 (in.data[i] == 'e') || (in.data[i] == 'E') ||
                                 (in.data[i] == 'f') || (in.data[i] == 'F'))) ++i;

  if(i < in.data_length) return;

  (*res).data = (unsigned char *)malloc((in.data_length/2) * sizeof(unsigned char));
  if((*res).data) {
    for(i = 0; i < (in.data_length/2); ++i) {
      unsigned int data;
      char tmp[3];
      tmp[0] = in.data[2*i];
      tmp[1] = in.data[2*i + 1];
      tmp[2] = 0;
      (void)sscanf(tmp, "%x", &data);
      (*res).data[i] = (unsigned char)data;
    }
    (*res).data_length = in.data_length/2;
  }

}




#ifdef DEBUG
void
log_debug(const char *fmt,
          ...) {
  va_list args;
  va_start(args, fmt);
  logger("debug", LOG_DEBUG, RGB(1,0,1), fmt, args);
  va_end(args);
}
#endif

void
log_error(const char *fmt,
          ...) {
  va_list args;
  va_start(args, fmt);
  logger("error", LOG_ERR, RGB(1,0,0), fmt, args);
  va_end(args);   
}

void
log_info(const char *fmt, 
         ...) {
  va_list args;
  va_start(args, fmt);
  logger("info", LOG_INFO, RGB(1,1,1), fmt, args);
  va_end(args);    
}





char *
hex_string(const unsigned char with_spaces,
           const unsigned char *in,
           const unsigned int in_length) {

  char *res = NULL;
  unsigned int per_char_size = with_spaces ? 3 : 2;
  
  res = (char*)malloc((per_char_size*in_length + 1) * sizeof(char));

  if(res) {
    if(in) {
      unsigned int i;
      for(i = 0; i < in_length; ++i)
        (void)sprintf(res + per_char_size*i, "%02X%s", in[i], with_spaces ? " " : "");
    }
    res[per_char_size * in_length] = 0;
  }
  
  return res;
}


char *
hex_string_data(const unsigned char with_spaces,
                const data_t in) {
  return hex_string(with_spaces, in.data, in.data_length);
}




char *
readable_string(const unsigned char *in,
                const unsigned int in_length) {

  char *res = NULL;
  
  res = (char*)malloc((in_length + 1) * sizeof(unsigned char));

  if(res) {
    if(in_length) {
      (void)memcpy(res, in, in_length * sizeof(unsigned char));
    }
    res[in_length] = 0;
  }
    
  return res;
}


unsigned char *
memndup(const unsigned char *src,
        const unsigned int len) {

  unsigned char * res = malloc(len * sizeof(unsigned char));

  if(res)
    return memcpy(res, src, len * sizeof(unsigned char));

  return res;
}


