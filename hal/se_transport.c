/*
 * HardID Hardware Wallet — SE transport abstraction (impl)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 */

#include "se_transport.h"

static const se_transport_t *g_transport;

void se_transport_set(const se_transport_t *t) { g_transport = t; }
const se_transport_t *se_transport_get(void) { return g_transport; }
