// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
/*
 *  scdaemon
 *  Copyright (C) 2013 SGDSN/ANSSI
 *
 *  All rights reserved.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>


#include "common.h"
#include "client.h"
#include "agent.h"

#include "agent_parser.h"
#include "agent_lexer.h"
#include "gpg-error.h"



#define OPENPGP_APPLICATION_NAME "openpgp"


/* grrrrr */
extern int
agent_parse(agent_t *agent,
            yyscan_t scanner);



void
init_pending_command(pending_command_t *command) {
  (void)memset(command, 0, sizeof(pending_command_t));
  init_data(&(command->parameters));
}

void
init_agent(agent_t *agent) {
  (void)memset(agent, 0, sizeof(agent_t));
  init_data(&(agent->setdata));
  init_openpgp_card(&(agent->card));  
  init_pending_command(&(agent->pending));
}

void
clean_pending_command(pending_command_t *command) {
  unsigned int i;

  clean_data(&(command->parameters));
  if(command->inquire) {
    for(i = 0; i < command->inquire_length; ++i) {
      clean_data(&(command->inquire[i]));
    }
    free(command->inquire);
  }
  (void)memset(command, 0, sizeof(pending_command_t));
}

void
clean_agent(agent_t *agent) {
  clean_pending_command(&(agent->pending));
  clean_openpgp_card(&(agent->card));
  clean_data(&(agent->setdata));
  (void)memset(agent, 0, sizeof(agent_t));
}



ssize_t
agent_read(agent_t *agent,
           char *dest,
           int dest_max_size) {
  size_t max_size = dest_max_size;
  ssize_t nbread;

  if(agent->did_bye) return 0;

  if(agent->client->is_socket) {

    if((nbread = recv(agent->client->fd_in, dest, max_size, 0)) > 0) {
      
#ifdef DEBUG_AGENT
      {
        char *rs = readable_string((unsigned char*)dest, nbread);
        if(rs) {
          log_debug_client(agent->client, "AGENT READ : '%s'", rs);
          free(rs);
        }
      }
#endif
      
      return nbread;
    }
    
  } else {
    
    if((nbread = read(agent->client->fd_in, dest, max_size)) > 0) {
      
#ifdef DEBUG_AGENT
      {
        char *rs = readable_string((unsigned char*)dest, nbread);
        if(rs) {
          log_debug_client(agent->client, "AGENT READ : '%s'", rs);
          free(rs);
        }
      }
#endif
      
      return nbread;
    }
    
  }
  
  return 0;
}


ssize_t
agent_write_data(agent_t *agent,
                 const data_t data) {

  data_t escaped;
  ssize_t res;

  if(agent->did_bye) return 0;
  
  init_data(&escaped);

  data_assuan_escaped(data, &escaped);

#ifdef DEBUG_AGENT
  log_debug_client(agent->client, "AGENT WRITE : '%s'", data.data);
#endif

  if(agent->client->is_socket) {
    res = send(agent->client->fd_out,
               escaped.data, escaped.data_length * sizeof(unsigned char), 0);
  } else {
    res = write(agent->client->fd_out,
                escaped.data, escaped.data_length * sizeof(unsigned char));
  }

  clean_data(&escaped);

  return res;
}

ssize_t
agent_write_fmt(agent_t *agent,
                const char *fmt,
                ...) {
  data_t res;
  ssize_t ret;
  va_list args;

  va_start(args, fmt);
  res.data_length = vasprintf((char**)&(res.data), fmt, args);
  va_end(args);

  ret = agent_write_data(agent, res);

  clean_data(&res);

  return ret;
}

ssize_t
agent_write_hex(agent_t *agent,
                const unsigned char *str,
                const unsigned int str_length) {
  char *inhex = hex_string(0, str, str_length);
  ssize_t ret = 0;

  if(inhex) {
    ret = agent_write_fmt(agent, "%s", inhex);
    free(inhex);
  }

  return ret;
}

ssize_t
agent_write_hex_data(agent_t *agent,
                     const data_t data) {
  return agent_write_hex(agent, data.data, data.data_length);
}


ssize_t
agent_write_end(agent_t *agent) {
  if(agent->client->is_socket)
    return send(agent->client->fd_out, "\n", sizeof(char), 0);

  return write(agent->client->fd_out, "\n", sizeof(char));
}


ssize_t
agent_write_ok(agent_t *agent) {
  char ok[] = "OK";
  return agent_write_fmt(agent, "%s", ok)
    + agent_write_end(agent);
}

ssize_t
agent_write_err(agent_t *agent,
                const gpg_error_t rawerr) {
  ssize_t ret;
  gpg_error_t err;
  const char *gpgstrerr = NULL;
  const char *gpgstrsrc = NULL;

  err = gpg_err_make(GPG_ERR_SOURCE_SCD, rawerr);
  gpgstrerr = gpg_strerror(err);
  gpgstrsrc = gpg_strsource(err);

  ret = agent_write_fmt(agent, "ERR %u %s <%s>",
                        err,
                        gpgstrerr,
                        gpgstrsrc)
    + agent_write_end(agent);
  
  return ret;
}



ssize_t
agent_inquire_needuserpin(agent_t *agent,
                          const unsigned char user_pin_for_signature) {
  char *message = NULL;
  ssize_t ret = 0;

  if(user_pin_for_signature) {
    ret = asprintf(&message, "OpenPGP PIN utilisateur pour signature\n    Carte %X\n    %u essais restants\n    %u signatures",
                   agent->card.serial_number,
                   agent->card.user_pin.remaining_tries,
                   agent->card.signatures_counter);
  } else {
    ret = asprintf(&message, "OpenPGP PIN utilisateur\n    Carte %X\n    %u essais restants",
                   agent->card.serial_number,
                   agent->card.user_pin.remaining_tries);
  }

  ret = agent_write_fmt(agent, "INQUIRE NEEDPIN ||%s",
                        message ? message : "PIN utilisateur OpenPGP")
    + agent_write_end(agent);
  
  if(message) {
    free(message);
  }

  return ret;
}


void
agent_echo(agent_t *agent,
           char *text,
           unsigned int text_length) {
  char *res = strndup(text, text_length);
  if(res) {
#ifdef DEBUG_AGENT
    log_debug_client(agent->client, "AGENT PARSER ECHO : '%s'", res);
#endif
    free(res);
  }
}


void
agent_error(agent_t *agent,
            yyscan_t *scanner,
            char const *message) {

  ++(agent->nb_errors);

#ifdef DEBUG_AGENT
  log_error_client(agent->client, "%s on '%s'", message, agent_get_text(scanner));
#endif

}





unsigned int
agent_loop(client_t *client) {
  yyscan_t scan;
  agent_t agent;
  
  init_agent(&agent);
  agent.client = client;
  
  if(agent_write_ok(&agent) <= 0) goto agent_loop_exit;

  agent_lex_init_extra(&agent, &scan);
  agent_parse(&agent, scan);
  agent_lex_destroy(scan);

agent_loop_exit:

  clean_agent(&agent);

  return agent.nb_errors;
}




void
agent_answer(agent_t *agent,
             const agent_errno error) {

  switch(error) {
  case AGENT_SUCCESS:
    (void)agent_write_ok(agent);
    break;

  case AGENT_PENDING_INQUIRE:
    break;

  case AGENT_ERROR_PROTOCOL:
    (void)agent_write_err(agent, GPG_ERR_ASS_UNKNOWN_CMD);
    break;

  case AGENT_ERROR_NOT_SUPPORTED:
    (void)agent_write_err(agent, GPG_ERR_NOT_SUPPORTED);
    break;

  case AGENT_ERROR_NO_CARD:
    (void)agent_write_err(agent, GPG_ERR_CARD_NOT_PRESENT);
    break;

  case AGENT_ERROR_CARD_REMOVED:
    (void)agent_write_err(agent, GPG_ERR_CARD_REMOVED);
    break;

  case AGENT_ERROR_INVALID_VALUE:
    (void)agent_write_err(agent, GPG_ERR_INV_VALUE);
    break;

  case AGENT_ERROR_PCSC_ERROR:
    (void)agent_write_err(agent, GPG_ERR_CARD);
    break;

  default:
    log_error_client(agent->client, "**** STRONG BUG IN PARSER : unknown agent_errno ****");
  }
}





agent_errno
agent_card_connect(agent_t *agent,
                   reader_t **result,
                   const unsigned char lock) {
  openpgp_reader_t *readers;
  unsigned short nb_readers;
  agent_errno err;
  unsigned int pass = 0;

 agent_card_connect_respawn:
  
  err = AGENT_SUCCESS;
  *result = NULL;
  nb_readers = 0;
  
  if(list_reader_with_openpgp_cards(agent->client,
                                    &readers,
                                    &nb_readers) != SCARD_S_SUCCESS) {
    agent->userpin_ok = 0;
    agent->userpin_signature_ok = 0;
    return AGENT_ERROR_PCSC_ERROR;
  }

  /* card learned, resolving in which reader */
  if(agent->card.aid.data) {
    unsigned short i = 0;
    
    while((i < nb_readers) &&
          data_compare(readers[i].aid,
                       agent->card.aid)) ++i;
    
    if(i < nb_readers) {
      *result = readers[i].reader;
    } else {
      agent->userpin_ok = 0;
      agent->userpin_signature_ok = 0;
      err = AGENT_ERROR_CARD_REMOVED;
    }

  } else if(nb_readers) {
    openpgp_reader_t *or = &(readers[0]);
    /* no better choice than choosing the first reader... */
    *result = or->reader;
    agent->userpin_ok = 0;
    agent->userpin_signature_ok = 0;
    clean_openpgp_card(&(agent->card));
    init_openpgp_card(&(agent->card));
    data_dup(&(agent->card.aid), or->aid);
  }

  if(*result) {
    if(connect_reader(&(agent->client->service), lock, *result) != SCARD_S_SUCCESS) {
      agent->userpin_ok = 0;
      agent->userpin_signature_ok = 0;
      err = AGENT_ERROR_PCSC_ERROR;
    } else if(!(agent->card.historical_bytes.data)) {
      err = get_data_application(*result, &(agent->card));

      if(err == AGENT_SUCCESS) {
        char *hs = hex_string(0, agent->card.aid.data, agent->card.aid.data_length);
        if(hs) {
          log_info_client(agent->client, "connected to card %s", hs);
          free(hs);
        }
      }
    }
  } else {
    agent->userpin_ok = 0;
    agent->userpin_signature_ok = 0;
    err = AGENT_ERROR_NO_CARD;
  }
  
  while(nb_readers) {
    clean_data(&(readers[--nb_readers].aid));
  }
  free(readers);

  if((err != AGENT_SUCCESS) && !pass) {
    disconnect_service(&(agent->client->service));
    pass = 1;
    goto agent_card_connect_respawn;
  }

  return err;

}




agent_errno
agent_command_getinfo_socket_name(agent_t *agent) {
  agent_errno err = AGENT_SUCCESS;

  (void)agent_write_fmt(agent, "D %s", SCDAEMON_socket_path_for_clients);
  (void)agent_write_end(agent);

  return err;
}






agent_errno
agent_command_serialno(agent_t *agent,
                       const data_t id) {
  agent_errno err = AGENT_SUCCESS;

  if(id.data && (strlen(OPENPGP_APPLICATION_NAME) == id.data_length)) {
    if(strncmp((char *)id.data, OPENPGP_APPLICATION_NAME, id.data_length)) {
      err = AGENT_ERROR_NOT_SUPPORTED;
    }
  }

  if(err == AGENT_SUCCESS) {
    reader_t *reader = NULL;
    
    if((err = agent_card_connect(agent, &reader, 0)) == AGENT_SUCCESS) {
      (void)agent_write_fmt(agent, "S SERIALNO ");
      (void)agent_write_hex_data(agent, agent->card.aid);
      (void)agent_write_fmt(agent, " 0");
      (void)agent_write_end(agent);
    } else err = AGENT_ERROR_NO_CARD;
  }

  return err;
}


agent_errno
agent_command_learn(agent_t *agent,
                    const unsigned char force) {

  agent_errno err = AGENT_SUCCESS;
  pcsc_error scarderr = SCARD_S_SUCCESS;
  reader_t *reader = NULL;

  if((err = agent_card_connect(agent, &reader, 0)) == AGENT_SUCCESS) {

    if(force) {
      if(((scarderr = get_data_cardholder(reader, &(agent->card))) != SCARD_S_SUCCESS) ||
         ((scarderr = get_data_application(reader, &(agent->card))) != SCARD_S_SUCCESS) ||
         ((scarderr = get_data_url(reader, &(agent->card))) != SCARD_S_SUCCESS) ||
         ((scarderr = get_data_login(reader, &(agent->card))) != SCARD_S_SUCCESS) ||
         ((scarderr = get_data_pw_status(reader, &(agent->card))) != SCARD_S_SUCCESS) ||
         ((scarderr = get_data_security_support_template(reader, &(agent->card))) != SCARD_S_SUCCESS) ||
         ((scarderr = read_openpgp_signature_key(reader, &(agent->card))) != SCARD_S_SUCCESS) ||
         ((scarderr = read_openpgp_decryption_key(reader, &(agent->card))) != SCARD_S_SUCCESS) ||
         ((scarderr = read_openpgp_authentication_key(reader, &(agent->card))) != SCARD_S_SUCCESS)) {
        err = AGENT_ERROR_PCSC_ERROR;
        return err;
      }
    }

    if(agent->card.aid.data) {
      (void)agent_write_fmt(agent, "S SERIALNO ");
      (void)agent_write_hex_data(agent, agent->card.aid);
      (void)agent_write_fmt(agent, " 0");
      (void)agent_write_end(agent);
    }
        
    (void)agent_write_fmt(agent, "S APPTYPE OPENPGP");
    (void)agent_write_end(agent);

    (void)agent_write_fmt(agent, "S EXTCAP gc=%u+ki=%u+fc=%u+pd=%u+mcl3=%u+aac=%u+sm=%u",
                          (agent->card.supports_get_challenge ? 1 : 0),
                          (agent->card.supports_key_import ? 1 : 0),
                          (agent->card.supports_pw_status_change ? 1 : 0),
                          (agent->card.supports_private_dos ? 1 : 0),
                          agent->card.maximum_length_of_cardholder_cert,
                          (agent->card.supports_algorithm_attributes_change ? 1 : 0),
                          (agent->card.supports_secure_messaging ?
                           ((agent->card.secure_messaging_algorithm == Aes) ? 7 : 2): 0));
    (void)agent_write_end(agent);
    
    if(agent->card.name.data) {
      (void)agent_write_fmt(agent, "S DISP-NAME ");
      (void)agent_write_data(agent, agent->card.name);
      (void)agent_write_end(agent);
    }

    if(agent->card.language.data) {
      (void)agent_write_fmt(agent, "S DISP-LANG ");
      (void)agent_write_data(agent, agent->card.language);
      (void)agent_write_end(agent);
    }

    switch(agent->card.sex) {
    case Male:
    case Female:
    case Undetermined:
      (void)agent_write_fmt(agent, "S DISP-SEX %u", agent->card.sex & 0xf);
      (void)agent_write_end(agent);      
      break;

    case InvalidSex:
    default:
      break;
    }

    if(agent->card.url.data) {
      (void)agent_write_fmt(agent, "S PUBKEY-URL ");
      (void)agent_write_data(agent, agent->card.url);
      (void)agent_write_end(agent);
    }

    if(agent->card.login.data) {
      (void)agent_write_fmt(agent, "S LOGIN-DATA ");
      (void)agent_write_data(agent, agent->card.login);
      (void)agent_write_end(agent);
    }

    if(agent->card.signature_key.fingerprint.data) {
      (void)agent_write_fmt(agent, "S KEY-FPR 1 ");
      (void)agent_write_hex_data(agent, agent->card.signature_key.fingerprint);
      (void)agent_write_end(agent);
    }

    if(agent->card.decryption_key.fingerprint.data) {
      (void)agent_write_fmt(agent, "S KEY-FPR 2 ");
      (void)agent_write_hex_data(agent, agent->card.decryption_key.fingerprint);
      (void)agent_write_end(agent);
    }

    if(agent->card.authentication_key.fingerprint.data) {
      (void)agent_write_fmt(agent, "S KEY-FPR 3 ");
      (void)agent_write_hex_data(agent, agent->card.authentication_key.fingerprint);
      (void)agent_write_end(agent);
    }

    if(agent->card.signature_key.generation_date) {
      (void)agent_write_fmt(agent, "S KEY-TIME 1 %u", agent->card.signature_key.generation_date);
      (void)agent_write_end(agent);
    }

    if(agent->card.decryption_key.generation_date) {
      (void)agent_write_fmt(agent, "S KEY-TIME 2 %u", agent->card.decryption_key.generation_date);
      (void)agent_write_end(agent);      
    }

    if(agent->card.authentication_key.generation_date) {
      (void)agent_write_fmt(agent, "S KEY-TIME 3 %u", agent->card.authentication_key.generation_date);
      (void)agent_write_end(agent);      
    }

    (void)agent_write_fmt(agent, "S CHV-STATUS +%u+%u+%u+%u+%u+%u+%u",
                          agent->card.supported_user_pin_cache,
                          agent->card.user_pin.max_length,
                          agent->card.reset_code.max_length,
                          agent->card.admin_pin.max_length,
                          agent->card.user_pin.remaining_tries,
                          agent->card.reset_code.remaining_tries,
                          agent->card.admin_pin.remaining_tries);
    (void)agent_write_end(agent);

    if(agent->card.signatures_counter) {
      (void)agent_write_fmt(agent, "S SIG-COUNTER %u", agent->card.signatures_counter);
      (void)agent_write_end(agent);      
    }

    if(agent->card.supports_private_dos) {
      (void)agent_write_fmt(agent, "S PRIVATE-DO-1");
      (void)agent_write_end(agent);      
      (void)agent_write_fmt(agent, "S PRIVATE-DO-2");
      (void)agent_write_end(agent);      
    }

    if(agent->card.signature_key.keygrip.data) {
      (void)agent_write_fmt(agent, "S KEYPAIRINFO ");
      (void)agent_write_hex_data(agent, agent->card.signature_key.keygrip);
      (void)agent_write_fmt(agent, " OPENPGP.1");
      (void)agent_write_end(agent);
    }

    if(agent->card.decryption_key.keygrip.data) {
      (void)agent_write_fmt(agent, "S KEYPAIRINFO ");
      (void)agent_write_hex_data(agent, agent->card.decryption_key.keygrip);
      (void)agent_write_fmt(agent, " OPENPGP.2");
      (void)agent_write_end(agent);
    }

    if(agent->card.authentication_key.keygrip.data) {
      (void)agent_write_fmt(agent, "S KEYPAIRINFO ");
      (void)agent_write_hex_data(agent, agent->card.authentication_key.keygrip);
      (void)agent_write_fmt(agent, " OPENPGP.3");
      (void)agent_write_end(agent);
    }

  } else err = AGENT_ERROR_PCSC_ERROR;

  return err;
}


agent_errno
agent_command_readcert(agent_t *agent,
                       const data_t id) {
  return AGENT_SUCCESS;
}


agent_errno
agent_command_readkey(agent_t *agent,
                      const data_t id) {

  agent_errno err = AGENT_SUCCESS;
  openpgp_key_t *key = NULL;
  reader_t *reader = NULL;

  if((err = agent_card_connect(agent, &reader, 0)) != AGENT_SUCCESS)
    return err;

  if(strcmp("OPENPGP.1", (char *)(id.data)) == 0) {

    if(!(agent->card.signature_key.s_expression.data) &&
       (read_openpgp_signature_key(reader, &(agent->card)) != SCARD_S_SUCCESS)) {
      err = AGENT_ERROR_PCSC_ERROR;
    }

    key = &(agent->card.signature_key);

  } else if(strcmp("OPENPGP.2", (char *)(id.data)) == 0) {

    if(!(agent->card.decryption_key.s_expression.data) &&
       (read_openpgp_decryption_key(reader, &(agent->card)) != SCARD_S_SUCCESS)) {
      err = AGENT_ERROR_PCSC_ERROR;
    }

    key = &(agent->card.decryption_key);

  } else if(strcmp("OPENPGP.3", (char *)(id.data)) == 0) {

    if(!(agent->card.authentication_key.s_expression.data) &&
       (read_openpgp_authentication_key(reader, &(agent->card)) != SCARD_S_SUCCESS)) {
      err = AGENT_ERROR_PCSC_ERROR;
    }

    key = &(agent->card.authentication_key);

  }
  
  if(key && key->s_expression.data) {

    (void)agent_write_fmt(agent, "D ");
    (void)agent_write_data(agent, key->s_expression);
    (void)agent_write_end(agent);

  } else err = AGENT_ERROR_NOT_SUPPORTED;

  return err;
}


agent_errno
agent_command_setdata(agent_t *agent,
                      const unsigned char more,
                      const data_t id) {
  agent_errno err = AGENT_SUCCESS;
  data_t raw;

  if(!more) {
    clean_data(&(agent->setdata));
  }
  
  init_data(&raw);

  data_of_hex_string(id, &raw);

  data_append(&(agent->setdata), raw.data, raw.data_length);

  clean_data(&raw);

  return err;
}



agent_errno
agent_command_pk_generic_callback(agent_t *agent,
                                  const unsigned char user_pin_for_signature,
                                  agent_errno (*callback)(agent_t *,
                                                          reader_t *reader)) {

  agent_errno err = AGENT_SUCCESS;
  unsigned char *pin_ok;

  if(user_pin_for_signature)
    pin_ok = &(agent->userpin_signature_ok);
  else
    pin_ok = &(agent->userpin_ok);

  if(!(*pin_ok) &&
     (agent->pending.inquire_length != 1)) {

    err = AGENT_ERROR_PROTOCOL;

  } else if(!(agent->setdata.data_length)) {

    err = AGENT_ERROR_PROTOCOL;    

  } else {
    reader_t *reader = NULL;

    if((err = agent_card_connect(agent, &reader, 1)) == AGENT_SUCCESS) {
      pcsc_error scarderr = SCARD_S_SUCCESS;

      if(!(*pin_ok)) {
        /* dealing with their stupid way to retrieve pin */
        agent->pending.inquire[0].data_length = strlen((char*)(agent->pending.inquire[0].data));
        
        if((scarderr = verify_pin(reader, &(agent->card),
                                  UserPin, user_pin_for_signature,
                                  agent->pending.inquire[0])) != SCARD_S_SUCCESS) {
          *pin_ok = 0;
          err = AGENT_ERROR_INVALID_VALUE;
        } else {
          *pin_ok = 1;
        }
      }

      if(*pin_ok) {
        err = callback(agent, reader);
      }
    }
  }
  
  clean_data(&(agent->setdata));

  return err;
}




agent_errno
agent_command_pk_generic(agent_t *agent,
                         agent_errno (*callback)(agent_t *,
                                                 reader_t *reader),
                         const unsigned char user_pin_for_signature,
                         const unsigned char ignore_pin_cache) {
  unsigned char *pin_ok;

  if(user_pin_for_signature)
    pin_ok = &(agent->userpin_signature_ok);
  else
    pin_ok = &(agent->userpin_ok);

  if(ignore_pin_cache)
    *pin_ok = 0;
  
  if(*pin_ok) return agent_command_pk_generic_callback(agent,
                                                       user_pin_for_signature,
                                                       callback);
  else {
    reader_t *reader = NULL;
    if(agent_card_connect(agent, &reader, 0) == AGENT_SUCCESS) {
      /* updates remaining tries */
      (void)get_data_pw_status(reader, &(agent->card));
      /* updates signature counter */
      (void)get_data_security_support_template(reader, &(agent->card));
    }
    
    (void)agent_inquire_needuserpin(agent, user_pin_for_signature);
    
    return AGENT_PENDING_INQUIRE;
  }
}



agent_errno
agent_command_pkauth_callback(agent_t *agent,
                              reader_t *reader) {
  agent_errno err = AGENT_SUCCESS;
  data_t signature;

  if(!(agent->pending.parameters.data)) {
    return AGENT_ERROR_INVALID_VALUE;
  }
  
  if(strcmp("OPENPGP.3", (char*)(agent->pending.parameters.data))) {
    return AGENT_ERROR_NOT_SUPPORTED;
  }

  init_data(&signature);
        
  if(authenticate(reader, &(agent->card),
                  agent->setdata, &signature) != SCARD_S_SUCCESS) {
    err = AGENT_ERROR_PCSC_ERROR;
  } else {
    (void)agent_write_fmt(agent, "D ");
    (void)agent_write_data(agent, signature);
    (void)agent_write_end(agent);
  }
  
  clean_data(&signature);
  
  return err;
}



agent_errno
agent_command_pkauth(agent_t *agent,
                     const data_t id) {

  clean_pending_command(&(agent->pending));
  
  agent->pending.command = Authenticate;
  data_dup(&(agent->pending.parameters), id);

  return agent_command_pk_generic(agent, agent_command_pkauth_callback, 0, 0);
}



agent_errno
agent_command_pkdecrypt_callback(agent_t *agent,
                                 reader_t *reader) {
  agent_errno err = AGENT_SUCCESS;
  data_t eaid, efpr, tmp;
  unsigned int sindex = 0;

  if(agent->pending.parameters.data == NULL) {
    return AGENT_ERROR_PROTOCOL;
  }

  sindex = 0;
  while((sindex < agent->pending.parameters.data_length) &&
        agent->pending.parameters.data[sindex] != '/') ++sindex;

  if((sindex + 1) >= agent->pending.parameters.data_length) {
    return AGENT_ERROR_PROTOCOL;
  }

  init_data(&eaid);
  init_data(&efpr);
  init_data(&tmp);

  data_memcpy(&tmp, agent->pending.parameters.data, sindex);
  data_of_hex_string(tmp, &eaid);
  data_memcpy(&tmp, &(agent->pending.parameters.data[sindex+1]), agent->pending.parameters.data_length - sindex - 1);
  data_of_hex_string(tmp, &efpr);


  if(efpr.data == NULL) {
    err = AGENT_ERROR_PROTOCOL;

  } else if(data_compare(agent->card.aid, eaid) ||
            data_compare(agent->card.decryption_key.fingerprint, efpr)) {
    err = AGENT_ERROR_PCSC_ERROR;
    
  } else {
    data_t deciphered;
    
    init_data(&deciphered);
    
    if(decipher(reader, &(agent->card),
                agent->setdata, &deciphered) != SCARD_S_SUCCESS) {
      err = AGENT_ERROR_PCSC_ERROR;
    } else {
      (void)agent_write_fmt(agent, "D ");
      (void)agent_write_data(agent, deciphered);
      (void)agent_write_end(agent);
    }
    
    clean_data(&deciphered);    
  }

  clean_data(&tmp);
  clean_data(&efpr);
  clean_data(&eaid);
  
  return err;
}




agent_errno
agent_command_pkdecrypt(agent_t *agent,
                        const data_t id) {

  clean_pending_command(&(agent->pending));

  agent->pending.command = Decrypt;
  data_dup(&(agent->pending.parameters), id);

  return agent_command_pk_generic(agent, agent_command_pkdecrypt_callback, 0, 0);
}




agent_errno
agent_command_pksign_callback(agent_t *agent,
                              reader_t *reader) {
  agent_errno err = AGENT_SUCCESS;
  data_t eaid, efpr, tmp;
  unsigned int sindex = 0;

  if(agent->pending.parameters.data == NULL) {
    return AGENT_ERROR_PROTOCOL;
  }

  sindex = 0;
  while((sindex < agent->pending.parameters.data_length) &&
        agent->pending.parameters.data[sindex] != '/') ++sindex;

  if((sindex + 1) >= agent->pending.parameters.data_length) {
    return AGENT_ERROR_PROTOCOL;
  }

  init_data(&eaid);
  init_data(&efpr);
  init_data(&tmp);

  data_memcpy(&tmp, agent->pending.parameters.data, sindex);
  data_of_hex_string(tmp, &eaid);
  data_memcpy(&tmp, &(agent->pending.parameters.data[sindex+1]), agent->pending.parameters.data_length - sindex - 1);
  data_of_hex_string(tmp, &efpr);


  if(efpr.data == NULL) {
    err = AGENT_ERROR_PROTOCOL;

  } else if(data_compare(agent->card.aid, eaid) ||
            data_compare(agent->card.signature_key.fingerprint, efpr)) {
    err = AGENT_ERROR_PCSC_ERROR;
    
  } else {
    data_t signature;
    signature_t algo;

    switch(agent->pending.command) {
    case SignatureRipeMd160:
      algo = RIPEMD160;
      break;
    case SignatureSha512:
      algo = SHA512;
      break;
    case SignatureSha384:
      algo = SHA384;
      break;
    case SignatureSha256:
      algo = SHA256;
      break;
    case SignatureSha224:
      algo = SHA224;
      break;
    case SignatureSha1:
    default:
      algo = SHA1;
      break;
    }

    init_data(&signature);
    
    if(sign(reader, &(agent->card),
            algo,
            agent->setdata,
            &signature) != SCARD_S_SUCCESS) {
      err = AGENT_ERROR_PCSC_ERROR;
    } else {
      (void)agent_write_fmt(agent, "D ");
      (void)agent_write_data(agent, signature);
      (void)agent_write_end(agent);
    }
    
    clean_data(&signature);
  }

  clean_data(&tmp);
  clean_data(&efpr);
  clean_data(&eaid);

  return err;
}


agent_errno
agent_command_pksign(agent_t *agent,
                     const data_t hash,
                     const data_t id) {
  pending_command_type_t pct = SignatureSha1;

  clean_pending_command(&(agent->pending));

  if(hash.data) {
    if(!strcmp((char*)(hash.data), "sha1")) {
      pct = SignatureSha1;
    } else if(!strcmp((char*)(hash.data), "sha224")) {
      pct = SignatureSha224;
    } else if(!strcmp((char*)(hash.data), "sha256")) {
      pct = SignatureSha256;
    } else if(!strcmp((char*)(hash.data), "sha384")) {
      pct = SignatureSha384;
    } else if(!strcmp((char*)(hash.data), "sha512")) {
      pct = SignatureSha512;
    } else if(!strcmp((char*)(hash.data), "ripemd160")) {
      pct = SignatureRipeMd160;
    }
  }

  agent->pending.command = pct;
  data_dup(&(agent->pending.parameters), id);

  return agent_command_pk_generic(agent,
                                  agent_command_pksign_callback,
                                  1,
                                  agent->card.supported_user_pin_cache ? 0 : 1);
}





agent_errno
agent_command_getattr(agent_t *agent,
                      const attribute_t attr) {
  agent_errno err = AGENT_SUCCESS;
  reader_t *reader = NULL;
  

  if((err = agent_card_connect(agent, &reader, 0)) != AGENT_SUCCESS)
    return AGENT_ERROR_PROTOCOL;


  switch(attr) {
  case AttributeDISP_NAME:
    break;

  case AttributeLOGIN_DATA:
    break;

  case AttributeDISP_LANG:
    break;

  case AttributeDISP_SEX:
    break;

  case AttributePUBKEY_URL:
    if(agent->card.url.data) {
      (void)agent_write_fmt(agent, "S PUBKEY-URL ");
      (void)agent_write_data(agent, agent->card.url);
      (void)agent_write_end(agent);
    }
    break;

  case AttributeCHV_STATUS_1:
    break;

  case AttributeCA_FPR_1:
    break;

  case AttributeCA_FPR_2:
    break;

  case AttributeCA_FPR_3:
    break;

  case AttributePRIVATE_DO_1:
    break;

  case AttributePRIVATE_DO_2:
    break;

  case AttributePRIVATE_DO_3:
    break;

  case AttributePRIVATE_DO_4:
    break;

  case AttributeCERT_3:
    break;

  case AttributeSM_KEY_ENC:
    break;

  case AttributeSM_KEY_MAC:
    break;

  case AttributeKEY_ATTR:
    (void)agent_write_fmt(agent, "S KEY-ATTR 1 %u %u %u %u",
                          agent->card.signature_settings.algorithm,
                          agent->card.signature_settings.modulus_size,
                          agent->card.signature_settings.public_exponent_size,
                          1 + agent->card.signature_settings.private_key_format);
    (void)agent_write_end(agent);
    (void)agent_write_fmt(agent, "S KEY-ATTR 2 %u %u %u %u",
                          agent->card.decryption_settings.algorithm,
                          agent->card.decryption_settings.modulus_size,
                          agent->card.decryption_settings.public_exponent_size,
                          1 + agent->card.decryption_settings.private_key_format);
    (void)agent_write_end(agent);
    (void)agent_write_fmt(agent, "S KEY-ATTR 3 %u %u %u %u",
                          agent->card.authentication_settings.algorithm,
                          agent->card.authentication_settings.modulus_size,
                          agent->card.authentication_settings.public_exponent_size,
                          1 + agent->card.authentication_settings.private_key_format);
    (void)agent_write_end(agent);
    break;

  case AttributeKEY_FPR:
    if(agent->card.signature_key.fingerprint.data) {
      (void)agent_write_fmt(agent, "S KEY-FPR 1 ");
      (void)agent_write_hex_data(agent, agent->card.signature_key.fingerprint);
      (void)agent_write_end(agent);
    }

    if(agent->card.decryption_key.fingerprint.data) {
      (void)agent_write_fmt(agent, "S KEY-FPR 2 ");
      (void)agent_write_hex_data(agent, agent->card.decryption_key.fingerprint);
      (void)agent_write_end(agent);
    }

    if(agent->card.authentication_key.fingerprint.data) {
      (void)agent_write_fmt(agent, "S KEY-FPR 3 ");
      (void)agent_write_hex_data(agent, agent->card.authentication_key.fingerprint);
      (void)agent_write_end(agent);
    }
    break;

  case AttributeSERIALNO:
    if(!(agent->card.aid.data) && reader) {
      (void)get_data_aid(reader, &(agent->card));
    }
    (void)agent_write_fmt(agent, "S SERIALNO ");
    (void)agent_write_hex_data(agent, agent->card.aid);
    (void)agent_write_end(agent);
    break;

  case AttributeAUTHKEYID:
    (void)agent_write_fmt(agent, "S $AUTHKEYID OPENPGP.3");
    (void)agent_write_end(agent);
    break;

  case AttributeDISPSERIALNO:
    (void)agent_write_fmt(agent, "S $DISPSERIALNO %04X%08X",
                          agent->card.manufacturer, agent->card.serial_number);
    (void)agent_write_end(agent);
    break;

  default:
    err = AGENT_ERROR_PROTOCOL;
    break;
  }

  return err;
}


agent_errno
agent_command_checkpin(agent_t *agent,
                       const data_t id) {

  return AGENT_SUCCESS;
}


agent_errno
agent_command_writekey(agent_t *agent,
                       const unsigned char force,
                       const data_t id) {
  return AGENT_SUCCESS;
}


agent_errno
agent_command_passwd(agent_t *agent,
                     const unsigned char reset,
                     const unsigned char nullpin,
                     const data_t id) {
  return AGENT_SUCCESS;
}


agent_errno
agent_command_apdu(agent_t *agent,
                   const unsigned char atr,
                   const unsigned char more,
                   const data_t exlen,
                   const data_t id) {

  return AGENT_ERROR_NOT_SUPPORTED;
}


agent_errno
agent_command_restart(agent_t *agent) {

  /*clean_openpgp_card(&(agent->card));*/

  return AGENT_SUCCESS;
}


agent_errno
agent_command_bye(agent_t *agent) {
 
  (void)agent_write_fmt(agent, "OK closing connection");
  (void)agent_write_end(agent);

  agent->did_bye = 1;

  return AGENT_SUCCESS;
}




agent_errno
agent_inquire_data(agent_t *agent,
                   const data_t data) {

  agent_errno err = AGENT_PENDING_INQUIRE;

  if(!(agent->pending.command)) err = AGENT_ERROR_PROTOCOL;
  else {
    if(data.data && data.data_length) {
      if(agent->pending.inquire) {
        agent->pending.inquire = (data_t *)realloc(agent->pending.inquire,
                                                   (agent->pending.inquire_length + 1) * sizeof(data_t));
      } else {
        agent->pending.inquire = (data_t *)malloc(sizeof(data_t));
      }
      
      if(agent->pending.inquire) {
        init_data(&(agent->pending.inquire[agent->pending.inquire_length]));
        data_dup(&(agent->pending.inquire[agent->pending.inquire_length]), data);
        ++(agent->pending.inquire_length);
      }
    }
  }
  
  return err;
}




agent_errno
agent_inquire_end(agent_t *agent) {

  agent_errno err = AGENT_SUCCESS;

  switch(agent->pending.command) {
  case NoPendingCommand:
    err = AGENT_ERROR_PROTOCOL;
    break;

  case Decrypt:
    err = agent_command_pk_generic_callback(agent, 0,
                                            agent_command_pkdecrypt_callback);
    break;

  case SignatureSha1:
  case SignatureSha224:
  case SignatureSha256:
  case SignatureSha384:
  case SignatureSha512:
  case SignatureRipeMd160:
    err = agent_command_pk_generic_callback(agent, 1,
                                            agent_command_pksign_callback);
    break;

  case Authenticate:
    err = agent_command_pk_generic_callback(agent, 0,
                                            agent_command_pkauth_callback);
    break;

  default:
    log_error_client(agent->client, "*** STRONG BUG IN PENDING CONNECTION ***");
    err = AGENT_ERROR_PROTOCOL;
    break;
  }

  clean_pending_command(&(agent->pending));

  return err;
}

