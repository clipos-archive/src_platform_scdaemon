%{
/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2013-2018 ANSSI. All Rights Reserved.
 *
 *  scdaemon
 *
 */

#include "agent.h"

#define YY_EXTRA_TYPE agent_t *


#define YY_INPUT(buf,result,max_size) \
    do { result = agent_read(yyextra, buf, max_size); } while(0)

#define ECHO do { agent_echo(yyextra, yytext, yyleng); } while(0)

#include "agent_parser.h"

#include "common.h"

%}


%option 8bit
%option align
%option always-interactive
%option case-insensitive
%option noinput
%option nounput
%option noyywrap
%option nostdinit
%option reentrant
%option posix-compat
%option bison-bridge
%option prefix="agent_"


%s option attr
%x inquire_answer

%%

<INITIAL>{
"GETINFO" { BEGIN(option); return GETINFO; }
"SERIALNO" { return SERIALNO; }
"LEARN" { BEGIN(option); return LEARN; }
"READCERT" { return READCERT; }
"READKEY" { return READKEY; }
"SETDATA" { BEGIN(option); return SETDATA; }
"PKAUTH" { return PKAUTH; }
"PKSIGN" { BEGIN(option); return PKSIGN; }
"PKDECRYPT" { return PKDECRYPT; }
"GETATTR" { BEGIN(attr); return GETATTR; }
"SETATTR" { return SETATTR; }
"WRITEKEY" { BEGIN(option); return WRITEKEY; }
"GENKEY" { return GENKEY; }
"RANDOM" { return RANDOM; }
"PASSWD" { BEGIN(option); return PASSWD; }
"CHECKPIN" { return CHECKPIN; }
"RESTART" { return RESTART; }
"APDU" { BEGIN(option); return APDU; }
"BYE" { return BYE; }
"D" { BEGIN(inquire_answer); return INQUIRE_ANSWER; }
"END" { return INQUIRE_END; }
}

<inquire_answer>{
" "[^\n]+ {
            unsigned int length = yyleng - 1;
            init_data(&(yylval->data));
            data_memcpy(&(yylval->data), (unsigned char*)&(yytext[yyleng - length]), length);
            return ID;
          }
[\n] { BEGIN(INITIAL); return NEWLINE; }
}

<attr>{
"DISP-NAME" { return ATTR_DISP_NAME; }
"LOGIN-DATA" { return ATTR_LOGIN_DATA; }
"DISP-LANG" { return ATTR_DISP_LANG; }
"DISP-SEX" { return ATTR_DISP_SEX; }
"PUBKEY-URL" { return ATTR_PUBKEY_URL; }
"CHV-STATUS-1" { return ATTR_CHV_STATUS_1; }
"CA-FPR-1" { return ATTR_CA_FPR_1; }
"CA-FPR-2" { return ATTR_CA_FPR_2; }
"CA-FPR-3" { return ATTR_CA_FPR_3; }
"PRIVATE-DO-1" { return ATTR_PRIVATE_DO_1; }
"PRIVATE-DO-2" { return ATTR_PRIVATE_DO_2; }
"PRIVATE-DO-3" { return ATTR_PRIVATE_DO_3; }
"PRIVATE-DO-4" { return ATTR_PRIVATE_DO_4; }
"CERT-3" { return ATTR_CERT_3; }
"SM-KEY-ENC" { return ATTR_SM_KEY_ENC; }
"SM-KEY-MAC" { return ATTR_SM_KEY_MAC; }
"KEY-ATTR" { return ATTR_KEY_ATTR; }
"KEY-FPR" { return ATTR_KEY_FPR; }
"SERIALNO" { return ATTR_SERIALNO; }
"$AUTHKEYID" { return ATTR_AUTHKEYID; }
"$DISPSERIALNO" { return ATTR_DISPSERIALNO; }
}

<option>{
"socket_name" { return OPTION_SOCKET_NAME; }
"--force" { return OPTION_FORCE; }
"--hash="[^ \t\n]+ {
                     unsigned int length = yyleng-7;
                     init_data(&(yylval->data));
                     data_memcpy(&(yylval->data), (unsigned char*)&(yytext[yyleng - length]), length);
                     return OPTION_HASH;
                   }
"--reset" { return OPTION_RESET; }
"--nullpin" { return OPTION_NULLPIN; }
"--atr" { return OPTION_ATR; }
("--more")|("--append") { return OPTION_MORE; }
"--exlen"("="[0-9]+)? {
                        unsigned int length = yyleng-7;
                        if(length) --length;
                        init_data(&(yylval->data));
                        data_memcpy(&(yylval->data), (unsigned char*)&(yytext[yyleng - length]), length);
                        return OPTION_EXLEN;
                     }
}

[\n] { BEGIN(INITIAL); return NEWLINE; }

[ \t] {}

[^ \t\n]+ {
            unsigned int length = yyleng;
            init_data(&(yylval->data));
            data_memcpy(&(yylval->data), (unsigned char*)&(yytext[yyleng - length]), length);
            return ID;
          }


%%

