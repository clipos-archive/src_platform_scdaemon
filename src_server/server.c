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
#include <sys/un.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>




#ifdef CLIP
#include <limits.h>
#include <fcntl.h>
#include <clip/clip.h>
#include <linux/capability.h>
#include <clip/clip-vserver.h>
#endif



#include "defaults.h"
#include "common.h"
#include "client.h"




#ifdef CLIP

static int
drop_privs(unsigned long context) {
  if(context && clip_enter_context(context)) {
    log_error("Failed to enter context %lu\n", context);
    return -1;
  }
  
  return 0;
}

#endif




void
signal_usr1_handler(int signal) {
  SCDAEMON_do_stop = 1;
  (void)kill(0, signal);
}

void
signal_child_handler(int signal) {
  (void)waitpid(-1, NULL, 0); /* handle child exit */
}
  
unsigned int
accept_loop(const int server_fd,
            const unsigned char exit_after_last_children) {
  int error;
  struct sigaction signal_child;
  struct sigaction signal_usr1;

  if(exit_after_last_children) {
    signal_child.sa_handler = signal_child_handler;
    signal_child.sa_flags = 0;
    sigemptyset(&signal_child.sa_mask);
  
    if(sigaction(SIGCHLD, &signal_child, NULL)) {
      log_error("failed to set signal actions : %s", strerror(errno));
      return errno;
    }
  } else {
    signal_child.sa_handler = SIG_IGN;
    signal_child.sa_flags = SA_NOCLDWAIT; /* no zombie */
    sigemptyset(&signal_child.sa_mask);
  
    if(sigaction(SIGCHLD, &signal_child, NULL)) {
      log_error("failed to set signal actions : %s", strerror(errno));
      return errno;
    }
  }

  signal_usr1.sa_handler = signal_usr1_handler;
  signal_usr1.sa_flags = 0;
  sigemptyset(&signal_usr1.sa_mask);
  
  if(sigaction(SIGUSR1, &signal_usr1, NULL)) {
    log_error("failed to set signal actions : %s", strerror(errno));
    return errno;
  }

  error = 0;
  
  while(!(error || SCDAEMON_do_stop)) {
    int client_fd;
    struct sockaddr_un addr;
    socklen_t addr_len;
    
    if(!SCDAEMON_do_stop) {

      addr_len = sizeof(addr);
      if((client_fd = accept(server_fd, (struct sockaddr *)&addr, &addr_len)) <= 0) {

        if(exit_after_last_children) {
          if(waitpid(-1, NULL, WNOHANG) < 0) {
            SCDAEMON_do_stop = 1;
          }
        }

        if(!SCDAEMON_do_stop) {
          log_error("failed to accept client : %s", strerror(errno));
          error = 1;
        }
        
      } else {
        int id = random();
        
        if(!fork()) {
          unsigned int ev;
          
          ev = handle_client(id, client_fd, client_fd, 1);
          
          (void)close(client_fd);

          exit(ev);
        }
        
        (void)close(client_fd);
        
      }
    }
  }

  return error;
}







int
serve_clients(const unsigned long clip_context,
              const unsigned char exit_after_last_children) {
  int ret;
  int server_fd;
  struct sockaddr_un server;
  mode_t prev_umask; 

  ret = 0;
  server_fd = 0;
  (void)memset(&server, 0, sizeof(server));

  prev_umask = umask(0);

  if((server_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    log_error("failed to create socket : %s", strerror(errno));
    ret = errno;
    goto serve_clients_leave;
  }

  server.sun_family = AF_UNIX;
  (void)strcpy(server.sun_path, SCDAEMON_socket_path);

  (void)unlink(server.sun_path);
  if(bind(server_fd, (struct sockaddr *)&server, sizeof(server))) {
    log_error("failed to bind socket '%s' : %s", SCDAEMON_socket_path, strerror(errno));
    ret = errno;
    goto serve_clients_leave;
  }

  (void)umask(prev_umask);

  log_info("accepting socket is '%s'", SCDAEMON_socket_path);

  if(listen(server_fd, DEFAULT_SOCKET_SERVER_BACKLOG)) {
    log_error("failed to listen on socket : %s", strerror(errno));
    ret = errno;
    goto serve_clients_leave;
  }


#ifdef CLIP
  if(clip_context) {
    if(drop_privs(clip_context)) {
      log_error("couldn't jail process\n");
      goto serve_clients_leave;
    }
    
    log_info("daemon jailed in context %lu", clip_context);
  }
#endif


  log_info("entering accepting loop");

  if((ret = accept_loop(server_fd, exit_after_last_children))) {
    log_error("accepting loop has exited with error");
  } else {
    log_info("exiting accepting loop");
  }

 serve_clients_leave:

  (void)umask(prev_umask);
  
  if(server_fd) { (void)close(server_fd); }

  if(server.sun_path) { (void)unlink(server.sun_path); }
  
  return ret;
}
