# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2013-2018 ANSSI. All Rights Reserved.
MAKEFILE_SERVER=Makefile.server
MAKEFILE_CLIENT=Makefile.client


.PHONY: server client clean mrproper

default: server

server:
	$(MAKE) -f $(MAKEFILE_SERVER)

client:
	$(MAKE) -f $(MAKEFILE_CLIENT)

clean:
	$(MAKE) -f $(MAKEFILE_SERVER) $@
	$(MAKE) -f $(MAKEFILE_CLIENT) $@

mrproper: clean
	$(MAKE) -f $(MAKEFILE_SERVER) $@
	$(MAKE) -f $(MAKEFILE_CLIENT) $@


