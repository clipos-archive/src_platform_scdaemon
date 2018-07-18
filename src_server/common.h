// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
/*
 *  scdaemon
 *  Copyright (C) 2013 SGDSN/ANSSI
 *
 *  All rights reserved.
 *
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdarg.h>
#include <stdio.h>
#include <semaphore.h>

extern volatile unsigned int SCDAEMON_do_stop;

extern unsigned int SCDAEMON_colors_enabled;

extern FILE *SCDAEMON_log_file;

extern char *SCDAEMON_socket_path;

extern char *SCDAEMON_socket_path_for_clients;




typedef struct {
  unsigned char *data;
  unsigned int data_length;
} data_t;

extern void
init_data(data_t *data);

extern void
clean_data(data_t *data);

extern void
data_memcpy(data_t *res,
            const unsigned char *data,
            const unsigned int data_length);

extern void
data_dup(data_t *res,
         const data_t data);

extern void
data_append(data_t *res,
            const unsigned char *data,
            const unsigned int data_length);


extern int
data_compare(const data_t data1,
             const data_t data2);

extern void
data_assuan_escaped(const data_t in,
                    data_t *out);



#define RGB(Red,Green,Blue) ((int)(16 + (((Red) * 5.0) * 36) + (((Green) * 5.0) * 6) + ((Blue) * 5.0)))


extern void
logger(const char *level,
       const int syslog_level,
       const int color,
       const char *fmt,
       va_list args);

#ifdef DEBUG
extern void
log_debug(const char *fmt, ...);
#endif

extern void
log_error(const char *fmt, ...);

extern void
log_info(const char *fmt, ...);

extern void
data_of_hex_string(const data_t in,
                   data_t *res);

extern char *
hex_string(const unsigned char with_spaces,
           const unsigned char *in,
           const unsigned int in_length);

extern char *
hex_string_data(const unsigned char with_spaces,
                const data_t in);

extern char *
readable_string(const unsigned char *in,
                const unsigned int in_length);

extern unsigned char *
memndup(const unsigned char *src,
        const unsigned int len);


#endif
