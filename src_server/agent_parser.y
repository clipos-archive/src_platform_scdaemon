%{
/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2013-2018 ANSSI. All Rights Reserved.
 *
 *  scdaemon
 *
 */
#include "agent.h"

#include "agent_parser.h"
#include "agent_lexer.h"


  /* grrrrr */
extern void
agent_error(agent_t *agent,
            yyscan_t *scanner,
            char const *message);

%}

%name-prefix="agent_"
%pure-parser

%parse-param { agent_t *agent }
%parse-param { void *scanner }
%lex-param { yyscan_t *scanner }

%union{
  unsigned char boolean;
  unsigned int integer;
  attribute_t attribute;
  agent_errno error;
  data_t data;
 }


%token NEWLINE
%token GETINFO SERIALNO LEARN READCERT READKEY SETDATA PKAUTH PKSIGN PKDECRYPT GETATTR SETATTR WRITEKEY GENKEY RANDOM PASSWD CHECKPIN RESTART APDU BYE
%token OPTION_SOCKET_NAME OPTION_FORCE OPTION_RESET OPTION_NULLPIN OPTION_ATR OPTION_MORE
%token ATTR_DISP_NAME ATTR_LOGIN_DATA ATTR_DISP_LANG ATTR_DISP_SEX ATTR_PUBKEY_URL ATTR_CHV_STATUS_1 ATTR_CA_FPR_1 ATTR_CA_FPR_2 ATTR_CA_FPR_3 ATTR_PRIVATE_DO_1 ATTR_PRIVATE_DO_2 ATTR_PRIVATE_DO_3 ATTR_PRIVATE_DO_4 ATTR_CERT_3 ATTR_SM_KEY_ENC ATTR_SM_KEY_MAC ATTR_KEY_ATTR ATTR_KEY_FPR ATTR_SERIALNO ATTR_AUTHKEYID ATTR_DISPSERIALNO

%token INQUIRE_ANSWER INQUIRE_END

%token<data> ID
%token<data> OPTION_HASH OPTION_EXLEN

%type<error> command command_getinfo command_serialno command_learn command_readcert command_readkey command_setdata command_pkauth command_pksign command_pkdecrypt command_getattr command_setattr command_checkpin command_writekey command_passwd command_apdu command_restart command_bye
%type<error> inquire_answer

%type<boolean> option_force option_reset option_nullpin option_atr option_more
%type<data> option_id option_hash option_exlen
%type<attribute> attribute


%%


input_list:
input_list
{
  if(agent->pending.command) {
    clean_pending_command(&(agent->pending));
    YYERROR; /* stop evaluation and start error recovery in order not to execute the command */
  }
}
command
{ agent_answer(agent, $3); }
|
input_list
inquire_answer
{ agent_answer(agent, $2); }
|
input_list
NEWLINE
|
input_list
error
NEWLINE
{ agent_answer(agent, AGENT_ERROR_PROTOCOL); }
|
;





inquire_answer:
INQUIRE_ANSWER option_id NEWLINE
{
  $$ = agent_inquire_data(agent, $2);
  clean_data(&($2));
}
|
INQUIRE_END NEWLINE
{ $$ = agent_inquire_end(agent); }
;




command:
command_getinfo
| command_serialno
| command_learn
| command_readcert
| command_readkey
| command_setdata
| command_pkauth
| command_pksign
| command_pkdecrypt
| command_getattr
| command_setattr
| command_writekey
| command_passwd
| command_checkpin
| command_restart
| command_apdu
| command_bye
;


command_getinfo:
GETINFO OPTION_SOCKET_NAME NEWLINE
{ $$ = agent_command_getinfo_socket_name(agent); }
;




command_serialno:
SERIALNO option_id NEWLINE
{
  $$ = agent_command_serialno(agent, $2);
  clean_data(&($2));
}
;


command_learn:
LEARN option_force NEWLINE
{ $$ = agent_command_learn(agent, $2); }
;


command_readcert:
READCERT ID NEWLINE
{
  $$ = agent_command_readcert(agent, $2);
  clean_data(&($2));
}
;


command_readkey:
READKEY ID NEWLINE
{
  $$ = agent_command_readkey(agent, $2);
  clean_data(&($2));
}
;


command_setdata:
SETDATA option_more ID NEWLINE
{
  $$ = agent_command_setdata(agent, $2, $3);
  clean_data(&($3));
}
;

command_pkauth:
PKAUTH ID NEWLINE
{
  $$ = agent_command_pkauth(agent, $2);
  clean_data(&($2));
}
;

command_pksign:
PKSIGN option_hash ID NEWLINE
{
  $$ = agent_command_pksign(agent, $2, $3);
  clean_data(&($2));
  clean_data(&($3));
}
;


command_pkdecrypt:
PKDECRYPT ID NEWLINE
{
  $$ = agent_command_pkdecrypt(agent, $2);
  clean_data(&($2));
}
;


command_getattr:
GETATTR attribute NEWLINE
{ $$ = agent_command_getattr(agent, $2); }
;


command_setattr:
SETATTR attribute NEWLINE
{ $$ = AGENT_ERROR_NOT_SUPPORTED; }
;


attribute:
ATTR_DISP_NAME { $$ = AttributeDISP_NAME; }
| ATTR_LOGIN_DATA { $$ = AttributeLOGIN_DATA; }
| ATTR_DISP_LANG { $$ = AttributeDISP_LANG; }
| ATTR_DISP_SEX { $$ = AttributeDISP_SEX; }
| ATTR_PUBKEY_URL { $$ = AttributePUBKEY_URL; }
| ATTR_CHV_STATUS_1 { $$ = AttributeCHV_STATUS_1; }
| ATTR_CA_FPR_1 { $$ = AttributeCA_FPR_1; }
| ATTR_CA_FPR_2 { $$ = AttributeCA_FPR_2; }
| ATTR_CA_FPR_3 { $$ = AttributeCA_FPR_3; }
| ATTR_PRIVATE_DO_1 { $$ = AttributePRIVATE_DO_1; }
| ATTR_PRIVATE_DO_2 { $$ = AttributePRIVATE_DO_2; }
| ATTR_PRIVATE_DO_3 { $$ = AttributePRIVATE_DO_3; }
| ATTR_PRIVATE_DO_4 { $$ = AttributePRIVATE_DO_4; }
| ATTR_CERT_3 { $$ = AttributeCERT_3; }
| ATTR_SM_KEY_ENC { $$ = AttributeSM_KEY_ENC; }
| ATTR_SM_KEY_MAC { $$ = AttributeSM_KEY_MAC; }
| ATTR_KEY_ATTR { $$ = AttributeKEY_ATTR; }
| ATTR_KEY_FPR { $$ = AttributeKEY_FPR; }
| ATTR_SERIALNO { $$ = AttributeSERIALNO; }
| ATTR_AUTHKEYID { $$ = AttributeAUTHKEYID; }
| ATTR_DISPSERIALNO { $$ = AttributeDISPSERIALNO; }
;





command_writekey:
WRITEKEY option_force ID NEWLINE
{
  $$ = agent_command_writekey(agent, $2, $3);
  clean_data(&($3));
}
;


command_passwd:
PASSWD option_reset option_nullpin ID NEWLINE
{
  $$ = agent_command_passwd(agent, $2, $3, $4);
  clean_data(&($4));
}
;


command_checkpin:
CHECKPIN ID NEWLINE
{
  $$ = agent_command_checkpin(agent, $2);
  clean_data(&($2));
}
;


command_apdu:
APDU option_atr option_more option_exlen option_id NEWLINE
{
  $$ = agent_command_apdu(agent, $2, $3, $4, $5);
  clean_data(&($4));
  clean_data(&($5));
}
;


command_restart:
RESTART NEWLINE
{ $$ = agent_command_restart(agent); }
;


command_bye:
BYE NEWLINE
{
  $$ = agent_command_bye(agent);
  YYACCEPT; /* terminate parsing loop */
}
;







option_force:
OPTION_FORCE { $$ = 1; }
| { $$ = 0; }
;

option_hash:
OPTION_HASH { $$ = $1; }
| { init_data(&($$)); }
;

option_reset:
OPTION_RESET { $$ = 1; }
| { $$ = 0; }
;

option_nullpin:
OPTION_NULLPIN { $$ = 1; }
| { $$ = 0; }
;

option_atr:
OPTION_ATR { $$ = 1; }
| { $$ = 0; }
;

option_more:
OPTION_MORE { $$ = 1; }
| { $$ = 0; }
;

option_exlen:
OPTION_EXLEN { $$ = $1; }
| { init_data(&($$)); }
;

option_id:
ID { $$ = $1; }
| { init_data(&($$)); }
;




%%

