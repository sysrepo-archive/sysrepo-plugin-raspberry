/**
 * @file raspberry-demo.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Demo Sysrepo plugin that allows Raspberry Pi management via NETCONF.
 *
 * @copyright
 * Copyright 2016 Cisco Systems, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include "sysrepo.h"

#define GPIO_PIN "18"
#define GPIO_EXPORT    "/sys/class/gpio/export"
#define GPIO_DIRECTION "/sys/class/gpio/gpio" GPIO_PIN "/direction"
#define GPIO_VALUE     "/sys/class/gpio/gpio" GPIO_PIN "/value"

/* logging macro for unformatted messages */
#define log_msg(MSG) \
    do { \
        fprintf(stderr, "raspberry-demo: " MSG "\n"); \
        syslog(LOG_INFO, "raspberry-demo: " MSG); \
    } while(0)

/* logging macro for formatted messages */
#define log_fmt(MSG, ...) \
    do { \
        fprintf(stderr, "raspberry-demo: " MSG "\n", __VA_ARGS__); \
        syslog(LOG_INFO, "raspberry-demo: " MSG, __VA_ARGS__); \
    } while(0)

static void
file_write(const char *filename, const char *content)
{
    FILE *fp = NULL;

    fp = fopen(filename, "w");
    if (NULL == fp) {
        log_fmt("Error opening file: %s", filename);
        return;
    }

    fprintf(fp, "%s\n", content);
    fclose(fp);
}

static void
gpio_init()
{
    file_write(GPIO_EXPORT, GPIO_PIN);
    file_write(GPIO_DIRECTION, "out");
}

static void
gpio_set_value(bool value)
{
    if (true == value) {
        file_write(GPIO_VALUE, "1");
    } else {
        file_write(GPIO_VALUE, "0");
    }
}

/* retrieves current configuration */
static void
retrieve_current_config(sr_session_ctx_t *session)
{
    sr_val_t *value = NULL;
    bool on = false;
    int rc = SR_ERR_OK;

    rc = sr_get_item(session, "/sysrepo-raspberry-demo:relay-switch", &value);
    if (SR_ERR_NOT_FOUND == rc) {
        on = false;
    } else if (SR_ERR_OK != rc) {
        log_fmt("error by retrieving configuration: %s", sr_strerror(rc));
        on = false;
    } else {
        if (true == value->data.bool_val) {
            on = true;
        } else {
            on = false;
        }
    }

    log_fmt("relay-switch=%s", on ? "ON" : "OFF");
    gpio_set_value(on);
}

static int
module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    log_msg("configuration has changed");

    retrieve_current_config(session);

    return SR_ERR_OK;
}

static int
dp_get_items_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    sr_val_t *value = NULL;

    value = calloc(1, sizeof(*value));
    if (NULL == value) {
        return SR_ERR_NOMEM;
    }

    value->xpath = strdup(xpath);
    value->type = SR_DECIMAL64_T;
    value->data.decimal64_val = 28.123;

    *values = value;
    *values_cnt = 1;
    return SR_ERR_OK;
}

int
sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;

    gpio_init();

    rc = sr_module_change_subscribe(session, "sysrepo-raspberry-demo", module_change_cb, NULL, 0,
            SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_dp_get_items_subscribe(session, "/sysrepo-raspberry-demo:temperature", dp_get_items_cb, NULL,
            SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    log_msg("plugin initialized successfully");

    retrieve_current_config(session);

    /* set subscription as our private context */
    *private_ctx = subscription;

    return SR_ERR_OK;

error:
    log_fmt("plugin initialization failed: %s", sr_strerror(rc));
    sr_unsubscribe(session, subscription);
    return rc;
}

void
sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
    /* subscription was set as our private context */
    sr_unsubscribe(session, private_ctx);

    log_msg("plugin cleanup finished");
}
