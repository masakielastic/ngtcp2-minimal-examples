#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <inttypes.h>
#include <netdb.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define LOCAL_HOST "127.0.0.1"
#define LOCAL_PORT "4433"
#define ALPN "hq-interop"
#define CERT_FILE "/tmp/nghttp3-localhost.crt"
#define KEY_FILE "/tmp/nghttp3-localhost.key"
#define RESPONSE "server response\n"

struct server_config {
  const char *host;
  const char *port;
  const char *cert_file;
  const char *key_file;
  const char *alpn;
  const char *response;
  int exit_on_handshake;
};

struct server {
  struct server_config config;
  ngtcp2_crypto_conn_ref conn_ref;
  int fd;
  struct sockaddr_storage local_addr;
  socklen_t local_addrlen;
  struct sockaddr_storage remote_addr;
  socklen_t remote_addrlen;
  gnutls_certificate_credentials_t cred;
  gnutls_session_t session;
  ngtcp2_conn *conn;
  ngtcp2_ccerr last_error;
  int handshake_complete;
  int should_exit;

  struct {
    int64_t stream_id;
    const uint8_t *data;
    size_t datalen;
    size_t nwrite;
  } tx_stream;
};

static uint64_t timestamp(void) {
  struct timespec tp;

  if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
    fprintf(stderr, "clock_gettime: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

static int fill_random(void *dest, size_t destlen) {
  int rv = gnutls_rnd(GNUTLS_RND_RANDOM, dest, destlen);
  if (rv != 0) {
    fprintf(stderr, "gnutls_rnd: %s\n", gnutls_strerror(rv));
    return -1;
  }

  return 0;
}

static void rand_cb(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx) {
  (void)rand_ctx;

  if (fill_random(dest, destlen) != 0) {
    assert(0);
    abort();
  }
}

static int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                    uint8_t *token, size_t cidlen,
                                    void *user_data) {
  (void)conn;
  (void)user_data;

  if (fill_random(cid->data, cidlen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  cid->datalen = cidlen;

  if (fill_random(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static void log_printf(void *user_data, const char *fmt, ...) {
  va_list ap;
  (void)user_data;

  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);

  fputc('\n', stderr);
}

static int is_client_bidi_stream(int64_t stream_id) {
  return (stream_id & 0x3) == 0;
}

static void usage(const char *progname) {
  fprintf(stderr,
          "Usage: %s [--host HOST] [--port PORT] [--cert FILE] [--key FILE]\n"
          "          [--alpn ALPN] [--response TEXT | --no-response]\n"
          "          [--exit-on-handshake]\n",
          progname);
}

static int create_server_sock(struct sockaddr_storage *local_addr,
                              socklen_t *plocal_addrlen, const char *host,
                              const char *port) {
  struct addrinfo hints = {0};
  struct addrinfo *res = NULL, *rp;
  int fd = -1;
  int rv;
  int val = 1;

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;

  rv = getaddrinfo(host, port, &hints, &res);
  if (rv != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return -1;
  }

  for (rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd == -1) {
      continue;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) != 0) {
      close(fd);
      fd = -1;
      continue;
    }

    if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
      memcpy(local_addr, rp->ai_addr, rp->ai_addrlen);
      *plocal_addrlen = rp->ai_addrlen;
      break;
    }

    close(fd);
    fd = -1;
  }

  freeaddrinfo(res);

  if (fd == -1) {
    fprintf(stderr, "bind: %s\n", strerror(errno));
  }

  return fd;
}

static int server_send_packet(struct server *s, const uint8_t *data,
                              size_t datalen) {
  ssize_t nwrite = send(s->fd, data, datalen, 0);
  if (nwrite < 0) {
    fprintf(stderr, "send: %s\n", strerror(errno));
    return -1;
  }

  if ((size_t)nwrite != datalen) {
    fprintf(stderr, "short send: %zd != %zu\n", nwrite, datalen);
    return -1;
  }

  return 0;
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref) {
  struct server *s = conn_ref->user_data;
  return s->conn;
}

static int handshake_completed_cb(ngtcp2_conn *conn, void *user_data) {
  struct server *s = user_data;
  (void)conn;

  s->handshake_complete = 1;
  fprintf(stderr, "QUIC handshake completed\n");

  if (s->config.exit_on_handshake) {
    s->should_exit = 1;
  }

  return 0;
}

static int stream_open_cb(ngtcp2_conn *conn, int64_t stream_id,
                          void *user_data) {
  (void)conn;
  (void)user_data;
  fprintf(stderr, "stream %" PRId64 " opened\n", stream_id);
  return 0;
}

static int stream_close_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                           uint64_t app_error_code, void *user_data,
                           void *stream_user_data) {
  struct server *s = user_data;
  (void)conn;
  (void)stream_user_data;

  if (flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET) {
    fprintf(stderr, "stream %" PRId64 " closed app_error=%" PRIu64 "\n",
            stream_id, app_error_code);
  } else {
    fprintf(stderr, "stream %" PRId64 " closed\n", stream_id);
  }

  if (s->tx_stream.stream_id == stream_id) {
    s->tx_stream.stream_id = -1;
    s->tx_stream.data = NULL;
    s->tx_stream.datalen = 0;
    s->tx_stream.nwrite = 0;
  }

  return 0;
}

static int recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags,
                               int64_t stream_id, uint64_t offset,
                               const uint8_t *data, size_t datalen,
                               void *user_data, void *stream_user_data) {
  struct server *s = user_data;
  (void)conn;
  (void)stream_user_data;

  fprintf(stderr, "stream %" PRId64 " recv offset=%" PRIu64 " len=%zu\n",
          stream_id, offset, datalen);

  if (datalen) {
    fwrite(data, 1, datalen, stderr);
    fputc('\n', stderr);
  }

  if ((flags & NGTCP2_STREAM_DATA_FLAG_FIN) &&
      is_client_bidi_stream(stream_id) && s->config.response) {
    s->tx_stream.stream_id = stream_id;
    s->tx_stream.data = (const uint8_t *)s->config.response;
    s->tx_stream.datalen = strlen(s->config.response);
    s->tx_stream.nwrite = 0;
  }

  return 0;
}

static int acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id,
                                       uint64_t offset, uint64_t datalen,
                                       void *user_data,
                                       void *stream_user_data) {
  (void)conn;
  (void)stream_id;
  (void)offset;
  (void)datalen;
  (void)user_data;
  (void)stream_user_data;
  return 0;
}

static const char priority[] =
  "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:"
  "+CHACHA20-POLY1305:+AES-128-CCM:-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:"
  "+GROUP-SECP384R1:+GROUP-SECP521R1:%DISABLE_TLS13_COMPAT_MODE";

static int server_tls_init(struct server *s) {
  gnutls_datum_t alpn;
  int rv;

  rv = gnutls_certificate_allocate_credentials(&s->cred);
  if (rv != 0) {
    fprintf(stderr, "gnutls_certificate_allocate_credentials: %s\n",
            gnutls_strerror(rv));
    return -1;
  }

  rv = gnutls_certificate_set_x509_key_file(
    s->cred, s->config.cert_file, s->config.key_file, GNUTLS_X509_FMT_PEM);
  if (rv != 0) {
    fprintf(stderr, "gnutls_certificate_set_x509_key_file: %s\n",
            gnutls_strerror(rv));
    return -1;
  }

  rv = gnutls_init(&s->session,
                   GNUTLS_SERVER | GNUTLS_ENABLE_EARLY_DATA |
                     GNUTLS_NO_AUTO_SEND_TICKET | GNUTLS_NO_END_OF_EARLY_DATA);
  if (rv != 0) {
    fprintf(stderr, "gnutls_init: %s\n", gnutls_strerror(rv));
    return -1;
  }

  rv = gnutls_priority_set_direct(s->session, priority, NULL);
  if (rv != 0) {
    fprintf(stderr, "gnutls_priority_set_direct: %s\n", gnutls_strerror(rv));
    return -1;
  }

  if (ngtcp2_crypto_gnutls_configure_server_session(s->session) != 0) {
    fprintf(stderr, "ngtcp2_crypto_gnutls_configure_server_session failed\n");
    return -1;
  }

  rv = gnutls_credentials_set(s->session, GNUTLS_CRD_CERTIFICATE, s->cred);
  if (rv != 0) {
    fprintf(stderr, "gnutls_credentials_set: %s\n", gnutls_strerror(rv));
    return -1;
  }

  alpn.data = (unsigned char *)s->config.alpn;
  alpn.size = strlen(s->config.alpn);
  rv = gnutls_alpn_set_protocols(
    s->session, &alpn, 1, GNUTLS_ALPN_MANDATORY | GNUTLS_ALPN_SERVER_PRECEDENCE);
  if (rv != 0) {
    fprintf(stderr, "gnutls_alpn_set_protocols: %s\n", gnutls_strerror(rv));
    return -1;
  }

  gnutls_session_set_ptr(s->session, &s->conn_ref);
  gnutls_handshake_set_timeout(s->session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

  return 0;
}

static int server_quic_init(struct server *s, const ngtcp2_cid *client_dcid,
                            const ngtcp2_cid *client_scid, uint32_t version) {
  ngtcp2_callbacks callbacks = {
    .recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
    .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
    .handshake_completed = handshake_completed_cb,
    .encrypt = ngtcp2_crypto_encrypt_cb,
    .decrypt = ngtcp2_crypto_decrypt_cb,
    .hp_mask = ngtcp2_crypto_hp_mask_cb,
    .recv_stream_data = recv_stream_data_cb,
    .acked_stream_data_offset = acked_stream_data_offset_cb,
    .stream_open = stream_open_cb,
    .stream_close = stream_close_cb,
    .rand = rand_cb,
    .get_new_connection_id = get_new_connection_id_cb,
    .update_key = ngtcp2_crypto_update_key_cb,
    .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
    .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
  };
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  ngtcp2_path path = {
    .local =
      {
        .addr = (struct sockaddr *)&s->local_addr,
        .addrlen = s->local_addrlen,
      },
    .remote =
      {
        .addr = (struct sockaddr *)&s->remote_addr,
        .addrlen = s->remote_addrlen,
      },
  };
  ngtcp2_cid scid;
  int rv;

  scid.datalen = 18;
  if (fill_random(scid.data, scid.datalen) != 0) {
    return -1;
  }

  ngtcp2_settings_default(&settings);
  settings.initial_ts = timestamp();
  settings.log_printf = log_printf;

  ngtcp2_transport_params_default(&params);
  params.initial_max_stream_data_bidi_local = 64 * 1024;
  params.initial_max_stream_data_bidi_remote = 64 * 1024;
  params.initial_max_stream_data_uni = 64 * 1024;
  params.initial_max_data = 1024 * 1024;
  params.initial_max_streams_bidi = 16;
  params.initial_max_streams_uni = 16;
  params.max_idle_timeout = 30 * NGTCP2_SECONDS;
  params.active_connection_id_limit = 7;
  params.stateless_reset_token_present = 1;
  params.original_dcid = *client_dcid;
  params.original_dcid_present = 1;

  if (fill_random(params.stateless_reset_token,
                  sizeof(params.stateless_reset_token)) != 0) {
    return -1;
  }

  rv = ngtcp2_conn_server_new(&s->conn, client_scid, &scid, &path, version,
                              &callbacks, &settings, &params, NULL, s);
  if (rv != 0) {
    fprintf(stderr, "ngtcp2_conn_server_new: %s\n", ngtcp2_strerror(rv));
    return -1;
  }

  ngtcp2_conn_set_tls_native_handle(s->conn, s->session);
  return 0;
}

static int server_get_response(struct server *s, int64_t *pstream_id, int *pfin,
                               ngtcp2_vec *datav, size_t datavcnt) {
  if (datavcnt == 0) {
    return 0;
  }

  if (s->tx_stream.stream_id != -1 && s->tx_stream.nwrite < s->tx_stream.datalen) {
    *pstream_id = s->tx_stream.stream_id;
    *pfin = 1;
    datav->base = (uint8_t *)s->tx_stream.data + s->tx_stream.nwrite;
    datav->len = s->tx_stream.datalen - s->tx_stream.nwrite;
    return 1;
  }

  *pstream_id = -1;
  *pfin = 0;
  datav->base = NULL;
  datav->len = 0;
  return 0;
}

static int server_write_streams(struct server *s) {
  ngtcp2_tstamp ts = timestamp();
  ngtcp2_pkt_info pi;
  ngtcp2_ssize nwrite;
  uint8_t buf[1452];
  ngtcp2_path_storage ps;
  ngtcp2_vec datav;
  size_t datavcnt;
  int64_t stream_id;
  ngtcp2_ssize wdatalen;
  uint32_t flags;
  int fin;

  ngtcp2_path_storage_zero(&ps);

  for (;;) {
    datavcnt = server_get_response(s, &stream_id, &fin, &datav, 1);

    flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
    if (fin) {
      flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    }

    nwrite = ngtcp2_conn_writev_stream(s->conn, &ps.path, &pi, buf, sizeof(buf),
                                       &wdatalen, flags, stream_id, &datav,
                                       datavcnt, ts);
    if (nwrite < 0) {
      if (nwrite == NGTCP2_ERR_WRITE_MORE) {
        s->tx_stream.nwrite += (size_t)wdatalen;
        continue;
      }

      fprintf(stderr, "ngtcp2_conn_writev_stream: %s\n",
              ngtcp2_strerror((int)nwrite));
      ngtcp2_ccerr_set_liberr(&s->last_error, (int)nwrite, NULL, 0);
      return -1;
    }

    if (nwrite == 0) {
      return 0;
    }

    if (wdatalen > 0 && stream_id == s->tx_stream.stream_id) {
      s->tx_stream.nwrite += (size_t)wdatalen;
    }

    if (server_send_packet(s, buf, (size_t)nwrite) != 0) {
      return -1;
    }
  }
}

static int server_write(struct server *s) {
  if (!s->conn) {
    return 0;
  }

  return server_write_streams(s);
}

static int server_handle_expiry(struct server *s) {
  int rv = ngtcp2_conn_handle_expiry(s->conn, timestamp());
  if (rv != 0) {
    fprintf(stderr, "ngtcp2_conn_handle_expiry: %s\n", ngtcp2_strerror(rv));
    ngtcp2_ccerr_set_liberr(&s->last_error, rv, NULL, 0);
    return -1;
  }

  return 0;
}

static int server_read(struct server *s) {
  ngtcp2_path path = {
    .local =
      {
        .addr = (struct sockaddr *)&s->local_addr,
        .addrlen = s->local_addrlen,
      },
    .remote =
      {
        .addr = (struct sockaddr *)&s->remote_addr,
        .addrlen = s->remote_addrlen,
      },
  };
  ngtcp2_pkt_info pi;
  uint8_t buf[2048];
  ssize_t nread;
  int rv;

  nread = recv(s->fd, buf, sizeof(buf), 0);
  if (nread < 0) {
    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
      return 0;
    }

    fprintf(stderr, "recv: %s\n", strerror(errno));
    return -1;
  }

  rv = ngtcp2_conn_read_pkt(s->conn, &path, &pi, buf, (size_t)nread, timestamp());
  if (rv != 0) {
    fprintf(stderr, "ngtcp2_conn_read_pkt: %s\n", ngtcp2_strerror(rv));
    if (rv == NGTCP2_ERR_CRYPTO) {
      ngtcp2_ccerr_set_tls_alert(&s->last_error, ngtcp2_conn_get_tls_alert(s->conn),
                                 NULL, 0);
    } else {
      ngtcp2_ccerr_set_liberr(&s->last_error, rv, NULL, 0);
    }
    return -1;
  }

  return 0;
}

static void server_close(struct server *s) {
  ngtcp2_ssize nwrite;
  ngtcp2_pkt_info pi;
  ngtcp2_path_storage ps;
  uint8_t buf[1280];

  if (!s->conn) {
    return;
  }

  if (ngtcp2_conn_in_closing_period(s->conn) ||
      ngtcp2_conn_in_draining_period(s->conn)) {
    return;
  }

  ngtcp2_path_storage_zero(&ps);

  nwrite = ngtcp2_conn_write_connection_close(
    s->conn, &ps.path, &pi, buf, sizeof(buf), &s->last_error, timestamp());
  if (nwrite < 0) {
    fprintf(stderr, "ngtcp2_conn_write_connection_close: %s\n",
            ngtcp2_strerror((int)nwrite));
    return;
  }

  server_send_packet(s, buf, (size_t)nwrite);
}

static int server_accept_initial(struct server *s, uint8_t *buf, size_t buflen,
                                 size_t *pnread, ngtcp2_cid *client_dcid,
                                 ngtcp2_cid *client_scid, uint32_t *pversion) {
  for (;;) {
    ngtcp2_version_cid vc;
    ssize_t nread;
    int rv;

    s->remote_addrlen = sizeof(s->remote_addr);
    nread = recvfrom(s->fd, buf, buflen, 0, (struct sockaddr *)&s->remote_addr,
                     &s->remote_addrlen);
    if (nread < 0) {
      if (errno == EINTR) {
        continue;
      }

      fprintf(stderr, "recvfrom: %s\n", strerror(errno));
      return -1;
    }

    rv = ngtcp2_pkt_decode_version_cid(&vc, buf, (size_t)nread, 0);
    if (rv != 0 && rv != NGTCP2_ERR_VERSION_NEGOTIATION) {
      fprintf(stderr, "ignoring undecodable packet\n");
      continue;
    }

    if (!ngtcp2_is_supported_version(vc.version)) {
      fprintf(stderr, "ignoring unsupported version 0x%08x\n", vc.version);
      continue;
    }

    if (vc.dcidlen > NGTCP2_MAX_CIDLEN || vc.scidlen > NGTCP2_MAX_CIDLEN) {
      fprintf(stderr, "ignoring packet with unsupported CID length\n");
      continue;
    }

    ngtcp2_cid_init(client_dcid, vc.dcid, vc.dcidlen);
    ngtcp2_cid_init(client_scid, vc.scid, vc.scidlen);
    *pversion = vc.version;
    *pnread = (size_t)nread;

    if (connect(s->fd, (struct sockaddr *)&s->remote_addr, s->remote_addrlen) != 0) {
      fprintf(stderr, "connect: %s\n", strerror(errno));
      return -1;
    }

    s->local_addrlen = sizeof(s->local_addr);
    if (getsockname(s->fd, (struct sockaddr *)&s->local_addr, &s->local_addrlen) != 0) {
      fprintf(stderr, "getsockname: %s\n", strerror(errno));
      return -1;
    }

    return 0;
  }
}

static int server_init(struct server *s, const struct server_config *config) {
  memset(s, 0, sizeof(*s));
  s->config = *config;
  s->fd = -1;
  s->tx_stream.stream_id = -1;
  ngtcp2_ccerr_default(&s->last_error);

  s->fd = create_server_sock(&s->local_addr, &s->local_addrlen, s->config.host,
                             s->config.port);
  if (s->fd == -1) {
    return -1;
  }

  s->conn_ref.get_conn = get_conn;
  s->conn_ref.user_data = s;

  return 0;
}

static void server_free(struct server *s) {
  if (s->conn) {
    ngtcp2_conn_del(s->conn);
  }
  if (s->session) {
    gnutls_deinit(s->session);
  }
  if (s->cred) {
    gnutls_certificate_free_credentials(s->cred);
  }
  if (s->fd != -1) {
    close(s->fd);
  }
}

static int server_run(struct server *s) {
  ngtcp2_cid client_dcid, client_scid;
  uint32_t version;
  uint8_t buf[2048];
  size_t nread;
  ngtcp2_path path;
  ngtcp2_pkt_info pi;

  fprintf(stderr, "listening on %s:%s\n", s->config.host, s->config.port);

  if (server_accept_initial(s, buf, sizeof(buf), &nread, &client_dcid,
                            &client_scid, &version) != 0) {
    return -1;
  }

  if (server_tls_init(s) != 0) {
    return -1;
  }

  if (server_quic_init(s, &client_dcid, &client_scid, version) != 0) {
    return -1;
  }

  path.local.addr = (struct sockaddr *)&s->local_addr;
  path.local.addrlen = s->local_addrlen;
  path.remote.addr = (struct sockaddr *)&s->remote_addr;
  path.remote.addrlen = s->remote_addrlen;
  path.user_data = NULL;

  if (ngtcp2_conn_read_pkt(s->conn, &path, &pi, buf, nread, timestamp()) != 0) {
    fprintf(stderr, "ngtcp2_conn_read_pkt: initial packet failed\n");
    return -1;
  }

  if (server_write(s) != 0) {
    return -1;
  }

  for (;;) {
    struct pollfd pfd = {
      .fd = s->fd,
      .events = POLLIN,
    };
    ngtcp2_tstamp expiry;
    ngtcp2_tstamp now;
    int timeout_ms;
    int rv;

    if (s->should_exit || ngtcp2_conn_in_closing_period(s->conn) ||
        ngtcp2_conn_in_draining_period(s->conn)) {
      return 0;
    }

    expiry = ngtcp2_conn_get_expiry(s->conn);
    now = timestamp();
    timeout_ms = expiry <= now ? 0 : (int)((expiry - now) / NGTCP2_MILLISECONDS);

    rv = poll(&pfd, 1, timeout_ms);
    if (rv < 0) {
      if (errno == EINTR) {
        continue;
      }

      fprintf(stderr, "poll: %s\n", strerror(errno));
      return -1;
    }

    if (rv == 0) {
      if (server_handle_expiry(s) != 0) {
        return -1;
      }
    } else if (pfd.revents & POLLIN) {
      if (server_read(s) != 0) {
        return -1;
      }
    }

    if (server_write(s) != 0) {
      return -1;
    }
  }
}

int main(int argc, char **argv) {
  struct server s;
  struct server_config config = {
    .host = LOCAL_HOST,
    .port = LOCAL_PORT,
    .cert_file = CERT_FILE,
    .key_file = KEY_FILE,
    .alpn = ALPN,
    .response = RESPONSE,
    .exit_on_handshake = 0,
  };
  int rv;
  int i;

  for (i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
      config.host = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      config.port = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
      config.cert_file = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
      config.key_file = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--alpn") == 0 && i + 1 < argc) {
      config.alpn = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--response") == 0 && i + 1 < argc) {
      config.response = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--no-response") == 0) {
      config.response = NULL;
      continue;
    }
    if (strcmp(argv[i], "--exit-on-handshake") == 0) {
      config.exit_on_handshake = 1;
      continue;
    }
    if (strcmp(argv[i], "--help") == 0) {
      usage(argv[0]);
      return 0;
    }

    usage(argv[0]);
    return EXIT_FAILURE;
  }

  setbuf(stderr, NULL);

  rv = gnutls_global_init();
  if (rv != 0) {
    fprintf(stderr, "gnutls_global_init: %s\n", gnutls_strerror(rv));
    return EXIT_FAILURE;
  }

  if (server_init(&s, &config) != 0) {
    server_free(&s);
    gnutls_global_deinit();
    return EXIT_FAILURE;
  }

  rv = server_run(&s);
  if (rv != 0) {
    server_close(&s);
  }

  server_free(&s);
  gnutls_global_deinit();

  return rv == 0 ? 0 : EXIT_FAILURE;
}
