#include "server.h"

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <SDL2/SDL_timer.h>
#include <SDL2/SDL_platform.h>

#include "adb/adb.h"
#include "util/file.h"
#include "util/log.h"
#include "util/net_intr.h"
#include "util/process_intr.h"
#include "util/str.h"

#define SC_SERVER_FILENAME "scrcpy-server"

#define SC_SERVER_PATH_DEFAULT PREFIX "/share/scrcpy/" SC_SERVER_FILENAME
#define SC_DEVICE_SERVER_PATH "/data/local/tmp/scrcpy-server.jar"

static void
sc_server_params_destroy(struct sc_server_params *params) {
    // The server stores a copy of the params provided by the user
    free((char *) params->req_serial);
    free((char *) params->crop);
    free((char *) params->codec_options);
    free((char *) params->encoder_name);
    free((char *) params->tcpip_dst);
}

static bool
sc_server_params_copy(struct sc_server_params *dst,
                      const struct sc_server_params *src) {
    *dst = *src;

    // The params reference user-allocated memory, so we must copy them to
    // handle them from another thread

#define COPY(FIELD) \
    dst->FIELD = NULL; \
    if (src->FIELD) { \
        dst->FIELD = strdup(src->FIELD); \
        if (!dst->FIELD) { \
            goto error; \
        } \
    }

    COPY(req_serial);
    COPY(crop);
    COPY(codec_options);
    COPY(encoder_name);
    COPY(tcpip_dst);
#undef COPY

    return true;

error:
    sc_server_params_destroy(dst);
    return false;
}

static bool
sc_server_sleep(struct sc_server *server, sc_tick deadline) {
    sc_mutex_lock(&server->mutex);
    bool timed_out = false;
    while (!server->stopped && !timed_out) {
        timed_out = !sc_cond_timedwait(&server->cond_stopped,
                                       &server->mutex, deadline);
    }
    bool stopped = server->stopped;
    sc_mutex_unlock(&server->mutex);

    return !stopped;
}

static bool
connect_and_read_byte(struct sc_intr *intr, sc_socket socket,
                      uint32_t tunnel_host, uint16_t tunnel_port) {
    bool ok = net_connect_intr(intr, socket, tunnel_host, tunnel_port);
    if (!ok) {
        return false;
    }

    char byte;
    // the connection may succeed even if the server behind the "adb tunnel"
    // is not listening, so read one byte to detect a working connection
    if (net_recv_intr(intr, socket, &byte, 1) != 1) {
        // the server is not listening yet behind the adb tunnel
        return false;
    }

    return true;
}

static sc_socket
connect_to_server(struct sc_server *server, unsigned attempts, sc_tick delay,
                  uint32_t host, uint16_t port) {
    do {
        LOGD("Remaining connection attempts: %u", attempts);
        sc_socket socket = net_socket();
        if (socket != SC_SOCKET_NONE) {
            bool ok = connect_and_read_byte(&server->intr, socket, host, port);
            if (ok) {
                // it worked!
                return socket;
            }

            net_close(socket);
        }

        if (sc_intr_is_interrupted(&server->intr)) {
            // Stop immediately
            break;
        }

        if (attempts) {
            sc_tick deadline = sc_tick_now() + delay;
            bool ok = sc_server_sleep(server, deadline);
            if (!ok) {
                LOGI("Connection attempt stopped");
                break;
            }
        }
    } while (--attempts);
    return SC_SOCKET_NONE;
}

bool
sc_server_init(struct sc_server *server, const struct sc_server_params *params,
              const struct sc_server_callbacks *cbs, void *cbs_userdata) {
    bool ok = sc_server_params_copy(&server->params, params);
    if (!ok) {
        LOG_OOM();
        return false;
    }

    ok = sc_mutex_init(&server->mutex);
    if (!ok) {
        sc_server_params_destroy(&server->params);
        return false;
    }

    ok = sc_cond_init(&server->cond_stopped);
    if (!ok) {
        sc_mutex_destroy(&server->mutex);
        sc_server_params_destroy(&server->params);
        return false;
    }

    ok = sc_intr_init(&server->intr);
    if (!ok) {
        sc_cond_destroy(&server->cond_stopped);
        sc_mutex_destroy(&server->mutex);
        sc_server_params_destroy(&server->params);
        return false;
    }

    server->serial = NULL;
    server->stopped = false;

    server->video_socket = SC_SOCKET_NONE;
    server->control_socket = SC_SOCKET_NONE;

    sc_adb_tunnel_init(&server->tunnel);

    assert(cbs);
    assert(cbs->on_connection_failed);
    assert(cbs->on_connected);
    assert(cbs->on_disconnected);

    server->cbs = cbs;
    server->cbs_userdata = cbs_userdata;

    return true;
}

static bool
device_read_info(struct sc_intr *intr, sc_socket device_socket,
                 struct sc_server_info *info) {
    LOGD("device_read_info enter");
    unsigned char buf[SC_DEVICE_NAME_FIELD_LENGTH + 4];
    ssize_t r = net_recv_all_intr(intr, device_socket, buf, sizeof(buf));
    if (r < SC_DEVICE_NAME_FIELD_LENGTH + 4) {
        LOGE("Could not retrieve device information");
        return false;
    }
    // in case the client sends garbage
    buf[SC_DEVICE_NAME_FIELD_LENGTH - 1] = '\0';
    memcpy(info->device_name, (char *) buf, sizeof(info->device_name));

    info->frame_size.width = (buf[SC_DEVICE_NAME_FIELD_LENGTH] << 8)
                           | buf[SC_DEVICE_NAME_FIELD_LENGTH + 1];
    info->frame_size.height = (buf[SC_DEVICE_NAME_FIELD_LENGTH + 2] << 8)
                            | buf[SC_DEVICE_NAME_FIELD_LENGTH + 3];
    if (info->frame_size.width == 0) {
        info->frame_size.width = 1;
    }
    if (info->frame_size.height == 0) {
        info->frame_size.height = 1;
    }
    LOGD("device_read_info exit");
    return true;
}

static bool
sc_server_connect_to(struct sc_server *server, struct sc_server_info *info) {
    LOGD("sc_server_connect_to enter");
    struct sc_adb_tunnel *tunnel = &server->tunnel;

    bool control = server->params.control;

    sc_socket video_socket = SC_SOCKET_NONE;
    sc_socket control_socket = SC_SOCKET_NONE;
    uint32_t tunnel_host = server->params.tunnel_host;
    if (!tunnel_host) {
        tunnel_host = IPV4_LOCALHOST;
    }

    uint16_t tunnel_port = server->params.tunnel_port;
    if (!tunnel_port) {
        tunnel_port = tunnel->local_port;
    }

    unsigned attempts = 100;
    sc_tick delay = SC_TICK_FROM_MS(100);
    tunnel_port = 8085;
    video_socket = connect_to_server(server, attempts, delay, tunnel_host,
                                        tunnel_port);
    if (video_socket == SC_SOCKET_NONE) {
        goto fail;
    }

    if (control) {
        // we know that the device is listening, we don't need several
        // attempts
        control_socket = net_socket();
        if (control_socket == SC_SOCKET_NONE) {
            goto fail;
        }
        bool ok = net_connect_intr(&server->intr, control_socket,
                                    tunnel_host, tunnel_port);
        if (!ok) {
            goto fail;
        }
    }

    // we don't need the adb tunnel anymore
    // sc_adb_tunnel_close(tunnel, &server->intr, serial);

    // The sockets will be closed on stop if device_read_info() fails
    bool ok = device_read_info(&server->intr, video_socket, info);
    if (!ok) {
        goto fail;
    }

    assert(video_socket != SC_SOCKET_NONE);
    assert(!control || control_socket != SC_SOCKET_NONE);

    server->video_socket = video_socket;
    server->control_socket = control_socket;

    return true;

fail:
    if (video_socket != SC_SOCKET_NONE) {
        if (!net_close(video_socket)) {
            LOGW("Could not close video socket");
        }
    }

    if (control_socket != SC_SOCKET_NONE) {
        if (!net_close(control_socket)) {
            LOGW("Could not close control socket");
        }
    }

    return false;
}

char *
append_port_5555(const char *ip) {
    size_t len = strlen(ip);

    // sizeof counts the final '\0'
    char *ip_port = malloc(len + sizeof(":5555"));
    if (!ip_port) {
        LOG_OOM();
        return NULL;
    }

    memcpy(ip_port, ip, len);
    memcpy(ip_port + len, ":5555", sizeof(":5555"));

    return ip_port;
}

static int
run_server(void *data) {
    struct sc_server *server = data;

    // Execute "adb start-server" before "adb devices" so that daemon starting
    // output/errors is correctly printed in the console ("adb devices" output
    // is parsed, so it is not output)
   
    bool ok = sc_server_connect_to(server, &server->info);
    // The tunnel is always closed by server_connect_to()
    if (!ok) {
        LOGE("sc_server_connect_to error");
        goto error_connection_failed;
    }

    // Now connected
    server->cbs->on_connected(server, server->cbs_userdata);

    // Wait for server_stop()
    sc_mutex_lock(&server->mutex);
    while (!server->stopped) {
        sc_cond_wait(&server->cond_stopped, &server->mutex);
    }
    sc_mutex_unlock(&server->mutex);

    // Interrupt sockets to wake up socket blocking calls on the server
    net_interrupt(server->video_socket);

    if (server->control_socket != SC_SOCKET_NONE) {
        // There is no control_socket if --no-control is set
        net_interrupt(server->control_socket);
    }

    // Give some delay for the server to terminate properly
#define WATCHDOG_DELAY SC_TICK_FROM_SEC(1)
    return 0;

error_connection_failed:
    server->cbs->on_connection_failed(server, server->cbs_userdata);
    return -1;
}

bool
sc_server_start(struct sc_server *server) {
    bool ok =
        sc_thread_create(&server->thread, run_server, "scrcpy-server", server);
    if (!ok) {
        LOGE("Could not create server thread");
        return false;
    }

    return true;
}

void
sc_server_stop(struct sc_server *server) {
    sc_mutex_lock(&server->mutex);
    server->stopped = true;
    sc_cond_signal(&server->cond_stopped);
    sc_intr_interrupt(&server->intr);
    sc_mutex_unlock(&server->mutex);

    sc_thread_join(&server->thread, NULL);
}

void
sc_server_destroy(struct sc_server *server) {
    if (server->video_socket != SC_SOCKET_NONE) {
        net_close(server->video_socket);
    }
    if (server->control_socket != SC_SOCKET_NONE) {
        net_close(server->control_socket);
    }

    free(server->serial);
    sc_server_params_destroy(&server->params);
    sc_intr_destroy(&server->intr);
    sc_cond_destroy(&server->cond_stopped);
    sc_mutex_destroy(&server->mutex);
}
