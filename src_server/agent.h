// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
/*
 *  scdaemon
 *  Copyright (C) 2013 SGDSN/ANSSI
 *
 *  All rights reserved.
 *
 */

#ifndef __AGENT_H__
#define __AGENT_H__

#include "client.h"
#include "openpgp.h"
#include "common.h"

typedef enum {
  AttributeDISP_NAME,
  AttributeLOGIN_DATA,
  AttributeDISP_LANG,
  AttributeDISP_SEX,
  AttributePUBKEY_URL,
  AttributeCHV_STATUS_1,
  AttributeCA_FPR_1,
  AttributeCA_FPR_2,
  AttributeCA_FPR_3,
  AttributePRIVATE_DO_1,
  AttributePRIVATE_DO_2,
  AttributePRIVATE_DO_3,
  AttributePRIVATE_DO_4,
  AttributeCERT_3,
  AttributeSM_KEY_ENC,
  AttributeSM_KEY_MAC,
  AttributeKEY_ATTR,
  AttributeKEY_FPR,
  AttributeSERIALNO,
  AttributeAUTHKEYID,
  AttributeDISPSERIALNO
} attribute_t;


typedef enum {
  NoPendingCommand=0,
  Decrypt,
  Authenticate,
  SignatureSha1,
  SignatureSha224,
  SignatureSha256,
  SignatureSha384,
  SignatureSha512,
  SignatureRipeMd160
} pending_command_type_t;

typedef struct {
  pending_command_type_t command;

  data_t parameters;

  data_t *inquire;
  unsigned int inquire_length;
} pending_command_t;


typedef struct {
  client_t *client;

  openpgp_card_t card;
  unsigned char userpin_ok;
  unsigned char userpin_signature_ok;

  unsigned int nb_errors;

  unsigned char did_bye;

  data_t setdata;

  pending_command_t pending;
} agent_t;


typedef enum {
  AGENT_SUCCESS = 0,
  AGENT_PENDING_INQUIRE,
  AGENT_ERROR_PROTOCOL,
  AGENT_ERROR_PCSC_ERROR,
  AGENT_ERROR_NOT_SUPPORTED,
  AGENT_ERROR_INVALID_VALUE,
  AGENT_ERROR_NO_CARD,
  AGENT_ERROR_CARD_REMOVED
} agent_errno;


extern void
clean_pending_command(pending_command_t *command);


extern ssize_t
agent_read(agent_t *agent,
           char *dest,
           int max_size);

extern void
agent_echo(agent_t *agent,
           char *text,
           unsigned int text_length);


extern unsigned int
agent_loop(client_t *client);


extern void
agent_answer(agent_t *agent,
             const agent_errno error);

extern agent_errno
agent_command_getinfo_socket_name(agent_t *agent);

extern agent_errno
agent_command_serialno(agent_t *agent,
                       const data_t id);

extern agent_errno
agent_command_learn(agent_t *agent,
                    const unsigned char force);

extern agent_errno
agent_command_readcert(agent_t *agent,
                       const data_t id);

extern agent_errno
agent_command_readkey(agent_t *agent,
                      const data_t id);

extern agent_errno
agent_command_setdata(agent_t *agent,
                      const unsigned char more,
                      const data_t id);

extern agent_errno
agent_command_pksign(agent_t *agent,
                     const data_t hash,
                     const data_t id);

extern agent_errno
agent_command_pkauth(agent_t *agent,
                     const data_t id);

extern agent_errno
agent_command_pkdecrypt(agent_t *agent,
                        const data_t id);

extern agent_errno
agent_command_getattr(agent_t *agent,
                      const attribute_t attr);

extern agent_errno
agent_command_checkpin(agent_t *agent,
                       const data_t id);

extern agent_errno
agent_command_writekey(agent_t *agent,
                       const unsigned char force,
                       const data_t id);

extern agent_errno
agent_command_passwd(agent_t *agent,
                     const unsigned char reset,
                     const unsigned char nullpin,
                     const data_t id);

extern agent_errno
agent_command_apdu(agent_t *agent,
                   const unsigned char atr,
                   const unsigned char more,
                   const data_t exlen,
                   const data_t id);

extern agent_errno
agent_command_restart(agent_t *agent);

extern agent_errno
agent_command_bye(agent_t *agent);

extern agent_errno
agent_inquire_data(agent_t *agent,
                   const data_t data);

extern agent_errno
agent_inquire_end(agent_t *agent);


#endif
