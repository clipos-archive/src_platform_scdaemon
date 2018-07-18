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

#include "defaults.h"
#include "common.h"
#include "card.h"

void
init_reader(reader_t *reader) {
  (void)memset(reader, 0, sizeof(reader_t));
  init_data(&(reader->name));  
  init_data(&(reader->atr));
}

void
clean_reader(reader_t *reader) {
  disconnect_reader(reader, 1);
  clean_data(&(reader->atr));
  clean_data(&(reader->name));
  (void)memset(reader, 0, sizeof(reader_t));
}

void
clean_readers(service_t *service) {
  unsigned int i;
  
  for(i = 0; i < service->nb_readers; ++i)
    clean_reader(&(service->readers[i]));
  
  if(service->readers) free(service->readers);
  service->readers = NULL;  
  service->nb_readers = 0;
}

void
clean_service(service_t *service) {
  clean_readers(service);
  disconnect_service(service);
  (void)memset(service, 0, sizeof(service_t));
}













pcsc_error
transmit_apdu(reader_t *reader) {

  pcsc_error scarderr = SCARD_S_SUCCESS;
  const SCARD_IO_REQUEST *pciSend;
  SCARD_IO_REQUEST pciRecv;
  DWORD receive_length;

  if(reader->protocol == SCARD_PROTOCOL_T0) pciSend = SCARD_PCI_T0;
  else pciSend = SCARD_PCI_T1;
  
#ifdef DEBUG_APDU
  {
    char *tracked = hex_string(1, reader->send_buffer, reader->send_length);
    log_debug("APDU (reader '%s')    send : %s", reader->name.data, tracked);
    free(tracked);
  }
#endif
  
  receive_length = MAX_APDU_RECEIVE_BUFFER_LENGTH;
  if((scarderr = SCardTransmit(reader->handle,
                               pciSend,
                               reader->send_buffer,
                               reader->send_length,
                               &pciRecv,
                               reader->receive_buffer,
                               &receive_length)) != SCARD_S_SUCCESS) {
    reader->receive_length = 0;
  } else reader->receive_length = receive_length;


#ifdef DEBUG_APDU
  if(scarderr == SCARD_S_SUCCESS) {
    char *tracked = hex_string(1, reader->receive_buffer, reader->receive_length);
    log_debug("APDU (reader '%s')    receive : %s", reader->name.data, tracked);
    free(tracked);
  }
#endif

  return scarderr;
}







pcsc_error
send_single_apdu(reader_t *reader,
                 const unsigned char cla,
                 const unsigned char ins,
                 const unsigned char p1,
                 const unsigned char p2,
                 const unsigned char *data,
                 const unsigned short data_length,
                 const unsigned char is_extended,
                 const unsigned short le) {

  pcsc_error scarderr = SCARD_S_SUCCESS;
  
  reader->send_length = 0;

  reader->send_buffer[reader->send_length++] = cla;
  reader->send_buffer[reader->send_length++] = ins;
  reader->send_buffer[reader->send_length++] = p1;
  reader->send_buffer[reader->send_length++] = p2;

  if(data_length) {
    if((data_length <= 255) && (!is_extended || le <= 255))
      reader->send_buffer[reader->send_length++] = (unsigned char)data_length;
    else {
      reader->send_buffer[reader->send_length++] = 0;
      reader->send_buffer[reader->send_length++] = (unsigned char)(data_length >> 8);
      reader->send_buffer[reader->send_length++] = (unsigned char)(data_length);
    }

    (void)memcpy(&(reader->send_buffer[reader->send_length]), data, data_length * sizeof(unsigned char));
    reader->send_length += data_length;
  }

  if(is_extended) {
    if(le <= 255) {
      reader->send_buffer[reader->send_length++] = (unsigned char)le;
    } else {
      if(data_length == 0)
        reader->send_buffer[reader->send_length++] = 0;
      reader->send_buffer[reader->send_length++] = (unsigned char)(le >> 8);
      reader->send_buffer[reader->send_length++] = (unsigned char)(le);
    }
  }

  (void)memset(reader->receive_buffer, 0, MAX_APDU_RECEIVE_BUFFER_LENGTH * sizeof(unsigned char));
  reader->receive_length = MAX_APDU_RECEIVE_BUFFER_LENGTH;
  
  scarderr = transmit_apdu(reader);

  (void)memset(reader->send_buffer, 0, MAX_APDU_SEND_BUFFER_LENGTH);
  reader->send_length = 0;

  return scarderr;
}





pcsc_error
send_apdu(reader_t *reader,
          const unsigned char cla,
          const unsigned char ins,
          const unsigned char p1,
          const unsigned char p2,
          const unsigned char *data,
          const unsigned short data_length,
          const unsigned char is_extended, /* le ? */
          const unsigned short le,
          data_t *answer) {
  
  pcsc_error scarderr;
  unsigned char loop;
  
  init_data(answer);
  
  loop = 1;
  scarderr = send_single_apdu(reader, cla, ins, p1, p2, data, data_length, is_extended, le);

  while(loop && (scarderr == SCARD_S_SUCCESS)) {

    loop = 0;

    if(reader->receive_length < 2) {

      clean_data(answer);
      scarderr = SCARD_E_UNEXPECTED;

    } else if(((reader->receive_buffer[reader->receive_length - 2] == 0x90) &&
               (reader->receive_buffer[reader->receive_length - 1] == 0x00)) ||
              (reader->receive_buffer[reader->receive_length - 2] == 0x61)) {

      if(reader->receive_length > 2) {
        data_append(answer, reader->receive_buffer, reader->receive_length - 2);
      }

      if(reader->receive_buffer[reader->receive_length - 2] == 0x61) {
        loop = 1;
        scarderr = send_single_apdu(reader, cla, 0xC0, 0x00, 0x00, NULL, 0, 1, reader->receive_buffer[reader->receive_length - 1]);
      }
    } else {
      scarderr = SCARD_E_UNEXPECTED;
    }
  }

  (void)memset(reader->receive_buffer, 0, MAX_APDU_RECEIVE_BUFFER_LENGTH * sizeof(unsigned char));

  return scarderr;
}






pcsc_error
update_reader_content(reader_t *reader) {

  pcsc_error scarderr = SCARD_S_SUCCESS;
  DWORD namesize;
  DWORD atr_len;

  if(reader->is_containing_card) clean_data(&(reader->atr));
  reader->is_containing_card = 0;

  init_data(&(reader->atr));

  reader->atr.data_length = MAX_ATR_LENGTH;
  reader->atr.data = (unsigned char *)malloc((reader->atr.data_length + 1) * sizeof(unsigned char));
  if(reader->atr.data == NULL) {
    reader->atr.data_length = 0;
    return SCARD_E_NO_MEMORY;
  }

  namesize = reader->name.data_length + 1;
  atr_len = reader->atr.data_length;
  if((scarderr = SCardStatus(reader->handle,
                             (char*)(reader->name.data),
                             &(namesize),
                             &(reader->state),
                             &(reader->protocol),
                             reader->atr.data,
                             &atr_len)) != SCARD_S_SUCCESS) {
    clean_data(&(reader->atr));
    return scarderr;
  }
  reader->atr.data_length = atr_len;

  reader->atr.data[reader->atr.data_length] = 0;

  if(reader->state == SCARD_ABSENT)  return scarderr;
  
  reader->is_containing_card = 1;

  return scarderr;
}



pcsc_error
connect_reader(service_t *service,
               unsigned char lock,
               reader_t *reader) {
  pcsc_error scarderr = SCARD_S_SUCCESS;

  if(reader->is_connected) {
    if((lock && !(reader->is_locked)) ||
       (scarderr = update_reader_content(reader)) == SCARD_W_RESET_CARD) {

      scarderr = SCardReconnect(reader->handle,
                                (lock ? SCARD_SHARE_EXCLUSIVE : SCARD_SHARE_SHARED),
                                SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                                SCARD_LEAVE_CARD,
                                &(reader->protocol));
    }
    
    if(scarderr != SCARD_S_SUCCESS) {
      if(reader->is_containing_card) clean_data(&(reader->atr));
      reader->is_containing_card = 0;
      reader->is_connected = 0;
      reader->is_locked = 0;
    } else {
      reader->is_locked = lock;
    }
  }
  
        
  if(!(reader->is_connected)) {
    if((scarderr = SCardConnect(service->context,
                                (char*)(reader->name.data),
                                (lock ? SCARD_SHARE_EXCLUSIVE : SCARD_SHARE_SHARED),
                                SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                                &(reader->handle),
                                &(reader->protocol))) != SCARD_S_SUCCESS) {
#ifdef DEBUG_READER
      log_debug("READER '%s' failed to connect : %s", reader->name.data, pcsc_stringify_error(scarderr));
#endif 
      
      reader->is_connected = 0;
      reader->is_locked = 0;
      reader->state = 0;
      reader->protocol = 0;
      (void)memset(&(reader->handle), 0, sizeof(reader->handle));
    } else {
#ifdef DEBUG_READER
      log_debug("READER '%s' is now connected", reader->name.data);
#endif
      reader->is_connected = 1;
      reader->is_locked = lock;
    }
  }
  
  return scarderr;
}



void
disconnect_reader(reader_t *reader,
                  unsigned int reset) {
  if(reader->is_connected) {
    (void)SCardDisconnect(reader->handle,
                          (reset == 2) ? SCARD_UNPOWER_CARD :
                          (reset == 1) ? SCARD_RESET_CARD :
                          SCARD_LEAVE_CARD);
#ifdef DEBUG_READER
    log_debug("READER '%s' disconnected %s",
              reader->name.data,
              (reset == 2) ? "and cold reset" :
              (reset == 1) ? "and warm reset" :
              "and leave card");
#endif
  }
  reader->is_connected = 0;
  reader->state = 0;
  reader->protocol = 0;
}













pcsc_error
update_service_content(service_t *service) {
  pcsc_error scarderr = SCARD_S_SUCCESS;
  reader_t *new_readers;
  unsigned int i;
  unsigned int new_nb_readers;
  DWORD prev_new_reader_string_length;


  prev_new_reader_string_length = 0;
  if(((scarderr = SCardListReaders(service->context,
                                   NULL,
                                   NULL,
                                   &prev_new_reader_string_length)) != SCARD_S_SUCCESS) && (scarderr != SCARD_E_NO_READERS_AVAILABLE)) {
    clean_readers(service);
    return scarderr;
  }

  scarderr = SCARD_S_SUCCESS;
  
  new_readers = NULL;
  new_nb_readers = 0;

  if(prev_new_reader_string_length) {
    char *new_reader_string, *ptr;
    DWORD new_reader_string_length;

    new_reader_string = (char *)malloc(prev_new_reader_string_length * sizeof(char));
    if(new_reader_string == NULL) {
      clean_readers(service);
      return SCARD_E_NO_MEMORY;
    }
    
    new_reader_string_length = prev_new_reader_string_length;
    if(((scarderr = SCardListReaders(service->context, NULL, new_reader_string, &new_reader_string_length)) != SCARD_S_SUCCESS) &&
       (scarderr != SCARD_E_NO_READERS_AVAILABLE)) {
      free(new_reader_string);
      clean_readers(service);
      return scarderr;
    }

    scarderr = SCARD_S_SUCCESS;

    if(prev_new_reader_string_length < new_reader_string_length) {
      free(new_reader_string);
      clean_readers(service);
      return SCARD_E_NO_MEMORY;
    }
      
    new_nb_readers = 0;
    if(new_reader_string_length) {
      for(i = 0; i < (new_reader_string_length - 1); ++i)
        if(new_reader_string[i] == 0) ++new_nb_readers;
    }
    
    if(new_nb_readers) {
      new_readers = (reader_t *)malloc(new_nb_readers * sizeof(reader_t));
      if(new_readers == NULL) {
        free(new_reader_string);
        clean_readers(service);
        return SCARD_E_NO_MEMORY;
      }
      
      ptr = new_reader_string;
      for(i = 0; i < new_nb_readers; ++i) {
        unsigned int len = strlen(ptr);
        init_reader(&(new_readers[i]));
        data_memcpy(&(new_readers[i].name), (unsigned char*)ptr, len);
        ptr += len + 1;
      }
    }
    
    free(new_reader_string);
  }



  if(scarderr == SCARD_S_SUCCESS) {

    if(new_nb_readers) {

      for(i = 0; i < new_nb_readers; ++i) {
        unsigned int j;
        reader_t *new_reader = &(new_readers[i]);
        
        j = 0;
        while((j < service->nb_readers) &&
              data_compare(new_reader->name, service->readers[j].name)) ++j;
        
        if(j < service->nb_readers) {
          reader_t *reader = &(service->readers[j]);
          new_reader->handle = reader->handle;
          new_reader->is_connected = reader->is_connected;
          new_reader->protocol = reader->state;

          reader->is_connected = 0;
          if(reader->is_containing_card) clean_data(&(reader->atr));
        }

        if(!(new_reader->is_connected)) {
          if(connect_reader(service, 0, new_reader) == SCARD_S_SUCCESS) {
            (void)update_reader_content(new_reader);
            (void)disconnect_reader(new_reader, 0);
          }
        } else {
          (void)update_reader_content(new_reader);
        }

      }

    }


    clean_readers(service);
    service->readers = new_readers;
    service->nb_readers = new_nb_readers;

  } else {

    if(new_nb_readers) {
      for(i = 0; i < new_nb_readers; ++i)
        clean_reader(&(new_readers[i]));
      free(new_readers);
    }

  }

  return scarderr;
}













pcsc_error
connect_service(service_t *service) {
  pcsc_error scarderr = SCARD_S_SUCCESS;

  if(service->is_available) {
    if((scarderr = SCardIsValidContext(service->context)) != SCARD_S_SUCCESS) {
#ifdef DEBUG_SERVICE
      log_debug("SERVICE context is not valid anymore : %s", pcsc_stringify_error(scarderr));
#endif
      (void)SCardReleaseContext(service->context);
      service->is_available = 0;
    }
  }

  if(!(service->is_available)) {
    if((scarderr = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &(service->context))) != SCARD_S_SUCCESS) {
#ifdef DEBUG_SERVICE
    log_debug("SERVICE failed to establish new context : %s", pcsc_stringify_error(scarderr));
#endif
      service->is_available = 0;
    } else {
#ifdef DEBUG_SERVICE
      log_debug("SERVICE new context established");
#endif
      service->is_available = 1;
    }
  }

  if(!(service->is_available))
    clean_readers(service);

  return scarderr;
}


void
disconnect_service(service_t *service) {
  if(service->is_available) {
    unsigned int i = 0;
    for(i = 0; i < service->nb_readers; ++i)
      disconnect_reader(&(service->readers[i]), 1);
#ifdef DEBUG_SERVICE
    log_debug("SERVICE context released");
#endif
    (void)SCardReleaseContext(service->context);
  }
  service->is_available = 0;
}





