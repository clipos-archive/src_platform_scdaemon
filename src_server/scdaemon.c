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
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <syslog.h>

#ifdef CLIP
#include <clip/clip.h>
#endif



#include "defaults.h"
#include "common.h"
#include "server.h"
#include "client.h"


typedef enum {
  MODE_UNKNOWN = 0,
  MODE_DAEMON,
  MODE_SERVER,
  MODE_MULTISERVER,
} scdaemon_mode_t;













static struct option longopts[] = {
  { "multi-server",  no_argument,       NULL, 'm' },
  { "server",        no_argument,       NULL, 's' },
  { "daemon",        no_argument,       NULL, 'd' },
  { "socket",        required_argument, NULL, 'S' },
  { "socket-fake",   required_argument, NULL, 'C' },
  { "context",       required_argument, NULL, 'X' },
  { "syslog",        no_argument,       NULL, 'q' },
  { NULL,            0,                 NULL, 0 }
};




int
main(int argc,
     char **argv) {
  char ch;
  int ret = 0;
  pid_t server_socket_pid = 0;
  scdaemon_mode_t mode = MODE_UNKNOWN;
  unsigned long clip_context = 0;

  SCDAEMON_log_file = stderr;


  while ((ch = getopt_long(argc, argv, "dmqs:S:C:X:", longopts, NULL)) != -1) {
    switch (ch) {
    case 'd':
      if(mode) {
        log_error("--multi-server xor --server xor --daemon");
        goto main_leave;
      } else mode = MODE_DAEMON;
      break;

    case 's':
      if(mode) {
        log_error("--multi-server xor --server xor --daemon");
        goto main_leave;
      } else mode = MODE_SERVER;
      break;

    case 'm':
      if(mode) {
        log_error("--multi-server xor --server xor --daemon");
        goto main_leave;
      } else mode = MODE_MULTISERVER;
      break;

    case 'q':
      openlog("scdaemon", LOG_PID, LOG_DAEMON);
      SCDAEMON_colors_enabled = 0;
      SCDAEMON_log_file = NULL;
      break;

    case 'S':
      if(SCDAEMON_socket_path) {
        log_error("--socket already defined");
        goto main_leave;
      } else SCDAEMON_socket_path = strdup(optarg);
      break;

    case 'C':
      if(SCDAEMON_socket_path_for_clients) {
        log_error("--socket-fake already defined");
        goto main_leave;
      } else SCDAEMON_socket_path_for_clients = strdup(optarg);
      break;

    case 'X':
#ifdef CLIP
      clip_context = atol(optarg);
      break;
#else
      log_error("context cannot be set with this build");
      ret = 42;
      goto main_leave;
#endif

    default:
      log_error("invalid option '%c'", ch);
      goto main_leave;
    }
  }


  if(!SCDAEMON_socket_path) {
    SCDAEMON_socket_path = DEFAULT_SOCKET_SERVER_PATH;
  }

  if(!SCDAEMON_socket_path_for_clients) {
    SCDAEMON_socket_path_for_clients = SCDAEMON_socket_path;
  }




  switch(mode) {
  case MODE_UNKNOWN:
  case MODE_MULTISERVER:
  case MODE_DAEMON:


#ifdef CLIP
    if(clip_daemonize()) {
      log_error("failed to clip_daemonize");
      goto main_leave;
    } else {
#else
      if(!(server_socket_pid = fork())) {
#endif

        if((ret = serve_clients(clip_context, (mode == MODE_MULTISERVER) ? 1 : 0))) {
        log_error("exiting with errors");
      } else {
        log_info("clean exit");
      }

      goto main_leave;
    }

  case MODE_SERVER:
    break;
  }
    


  switch(mode) {
  case MODE_UNKNOWN:
  case MODE_MULTISERVER:
  case MODE_SERVER:
    /* serving client on stdin */

    ret = handle_client(1, STDIN_FILENO, STDOUT_FILENO, 0);

    /* if a server_socket exists, notifying it and waiting for clients
       to leave */
    if(server_socket_pid) {
      (void)kill(server_socket_pid, SIGCHLD);
      (void)waitpid(server_socket_pid, NULL, 0);
    }

  case MODE_DAEMON:
    break;
  }

  

  switch(mode) {
  case MODE_UNKNOWN:
  case MODE_MULTISERVER:
  case MODE_DAEMON:
    /* we have had a child that will close everything */
    return ret;

  case MODE_SERVER:
    break;
  }


main_leave:

  log_info("exiting");

  return ret;
}
