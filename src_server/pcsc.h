// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
/*
 *  scdaemon
 *  Copyright (C) 2013 SGDSN/ANSSI
 *
 *  All rights reserved.
 *
 */

#ifndef __PCSC_H__
#define __PCSC_H__

#ifdef __APPLE__
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#else
#include <winscard.h>
#endif


typedef LONG pcsc_error;


#endif
