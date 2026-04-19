//! WebSocket connection utilities.
//!
//! `WsConnection` wraps `tokio-tungstenite` with three PIR-specific concerns:
//!
//! * **Large-frame support** — PIR responses can be tens of MB in a single
//!   binary frame (fresh-sync chunk batches against the `main` UTXO database
//!   run ~32 MiB). The default 16 MiB frame / 64 MiB message limits are
//!   bumped to 256 MiB to keep normal traffic well below the ceiling while
//!   still bounding memory use against a malicious server.
//!
//! * **Per-operation deadlines** — `connect`, `send`, `recv`, and `roundtrip`
//!   are all wrapped in `tokio::time::timeout`. Default deadlines are long
//!   enough for any legitimate PIR operation (server-side PIR responses can
//!   legitimately take several seconds) but prevent a wedged server from
//!   hanging a query indefinitely. Configurable via
//!   [`WsConnection::with_request_timeout`] and the
//!   [`connect_with_backoff`](WsConnection::connect_with_backoff) policy.
//!
//! * **Transport-level reconnect with exponential backoff** — once a
//!   connection fails, the higher-level PIR client state (Harmony hints,
//!   Onion FHE keys, in-flight round IDs) is *also* invalidated, so
//!   auto-reconnect isn't something that can happen transparently inside
//!   `roundtrip`. Instead, the connection layer exposes
//!   [`WsConnection::reconnect`] and
//!   [`WsConnection::connect_with_backoff`] so client-level reconnect
//!   code can rebuild its state on top of a retry loop that's already been
//!   tested.

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
// `Instant` is re-exported from pir_sdk (under the hood it's `web_time::Instant`,
// a drop-in for `std::time::Instant` that compiles to wasm32). Using the
// pir_sdk re-export keeps the timing source the same as the metrics callback's
// `Duration` argument across all transports.
use pir_sdk::{Instant, PirError, PirMetrics, PirResult};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

/// PIR responses can be very large — a fresh-sync chunk batch against the
/// live `main` database returns ~32 MiB in a single WebSocket frame, which
/// blows past `tungstenite`'s defaults (16 MiB frame / 64 MiB message).
/// Bumping both limits to 256 MiB keeps normal PIR traffic well below the
/// ceiling while still bounding memory use against a malicious server.
const MAX_WS_MESSAGE_SIZE: usize = 256 * 1024 * 1024;
const MAX_WS_FRAME_SIZE: usize = 256 * 1024 * 1024;

/// Default deadline for establishing a new WebSocket connection. A slow
/// TLS handshake over a stressed link can legitimately take several
/// seconds, but anything past 30s is almost certainly a wedged server
/// or a black-holed route.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default deadline for a single `send` / `recv` / `roundtrip` once a
/// connection is established. PIR responses can take several seconds to
/// compute server-side, and a fresh-sync chunk batch can be ~32 MiB —
/// a 90s budget is generous for both. `tungstenite` reads a whole binary
/// frame in one call, so this covers the full response, not just one
/// TCP segment.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(90);

/// Default starting delay between reconnect attempts. Doubles each try
/// (up to `DEFAULT_MAX_BACKOFF_DELAY`).
pub const DEFAULT_INITIAL_BACKOFF_DELAY: Duration = Duration::from_millis(250);

/// Cap on how long a single backoff sleep can get, to keep total
/// worst-case reconnect time bounded.
pub const DEFAULT_MAX_BACKOFF_DELAY: Duration = Duration::from_secs(5);

/// Default maximum number of connect attempts for
/// `connect_with_backoff` / `reconnect_with_backoff`. With the default
/// 250ms initial delay and 5s cap, 5 attempts spans roughly 0 + 0.25 +
/// 0.5 + 1.0 + 2.0 = ~3.75s of backoff plus up to 5 × connect_timeout
/// of work. Enough to ride out a brief server restart; short enough
/// that a truly-down server fails fast.
pub const DEFAULT_MAX_CONNECT_ATTEMPTS: u32 = 5;

/// Retry policy for connect + reconnect.
///
/// All four knobs are independent so callers can dial a gentle local-test
/// policy (one attempt, short timeout) or an aggressive production one
/// (many attempts, longer timeout) without reaching into the internals.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Maximum number of connect attempts (including the first one).
    /// Must be ≥ 1 — `with_max_attempts(0)` is clamped to 1 at runtime
    /// so a mis-configured client never silently skips connecting.
    pub max_attempts: u32,
    /// Starting delay between attempts. Doubles each retry, capped at
    /// `max_delay`. The *first* attempt fires immediately — the delay
    /// only applies between retries.
    pub initial_delay: Duration,
    /// Cap on how long a single backoff sleep can get.
    pub max_delay: Duration,
    /// Deadline for each individual WebSocket handshake.
    pub connect_timeout: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_CONNECT_ATTEMPTS,
            initial_delay: DEFAULT_INITIAL_BACKOFF_DELAY,
            max_delay: DEFAULT_MAX_BACKOFF_DELAY,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }
}

impl RetryPolicy {
    /// A single-attempt policy: no backoff, no retry, just one shot.
    /// Useful when the caller wants to implement its own retry loop
    /// around `connect_with_backoff`.
    pub fn single_attempt() -> Self {
        Self {
            max_attempts: 1,
            ..Self::default()
        }
    }

    /// Compute the backoff delay before the `attempt`-th retry (0-indexed,
    /// so `attempt=0` is the delay *before* the first retry, i.e. after
    /// attempt 1 has already failed). Clamped to `self.max_delay`.
    ///
    /// Separated out so unit tests can pin the schedule without needing
    /// a live server.
    pub(crate) fn backoff_delay(&self, attempt: u32) -> Duration {
        // 250ms, 500ms, 1s, 2s, 4s, 5s (capped), ...
        let doubled = self
            .initial_delay
            .checked_mul(1u32.checked_shl(attempt).unwrap_or(u32::MAX))
            .unwrap_or(self.max_delay);
        doubled.min(self.max_delay)
    }
}

/// A WebSocket connection to a PIR server.
pub struct WsConnection {
    sink: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    stream: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    url: String,
    request_timeout: Duration,
    retry_policy: RetryPolicy,
    /// Optional metrics recorder. Fires per-frame `on_bytes_sent` /
    /// `on_bytes_received` callbacks from `send` / `recv` / `roundtrip` once
    /// installed via [`set_metrics_recorder`](Self::set_metrics_recorder).
    /// `None` = silent (the default).
    ///
    /// Note: this field is *not* carried across `reconnect` — the reconnect
    /// path keeps the field value in place (we only replace the
    /// `sink`/`stream`), so a recorder installed before reconnect keeps
    /// firing afterwards.
    metrics_recorder: Option<Arc<dyn PirMetrics>>,
    /// Backend label passed to the recorder's callbacks. Defaults to the
    /// empty string; the owning client overrides via `set_metrics_recorder`.
    metrics_backend: &'static str,
}

/// Install the `ring` crypto provider for rustls exactly once per process.
///
/// rustls 0.23+ requires a process-wide default `CryptoProvider` before any
/// TLS handshake. We install `ring` (pure-Rust, no C toolchain). Multiple
/// threads calling `connect()` concurrently are serialized by `OnceLock`;
/// a pre-installed provider (e.g. by a consumer application) is left alone.
fn install_default_crypto_provider() {
    use std::sync::OnceLock;
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        // `install_default` returns `Err` if a provider was already installed
        // by a different crate (or a previous call). Either way the post-
        // condition "a provider is installed" holds, so the error is ignored.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Perform the raw WebSocket handshake against `url`, subject to
/// `connect_timeout`. Split out so `connect`, `connect_with_backoff`, and
/// `reconnect` share the same transport setup.
async fn raw_connect(
    url: &str,
    connect_timeout: Duration,
) -> PirResult<(
    SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
)> {
    install_default_crypto_provider();
    let config = WebSocketConfig {
        max_message_size: Some(MAX_WS_MESSAGE_SIZE),
        max_frame_size: Some(MAX_WS_FRAME_SIZE),
        ..Default::default()
    };
    let handshake =
        tokio_tungstenite::connect_async_with_config(url, Some(config), false);
    let (ws, _) = match tokio::time::timeout(connect_timeout, handshake).await {
        Ok(Ok(ok)) => ok,
        Ok(Err(e)) => {
            return Err(PirError::ConnectionFailed(format!("{}: {}", url, e)));
        }
        Err(_) => {
            return Err(PirError::Timeout(format!(
                "connect to {} took longer than {:?}",
                url, connect_timeout,
            )));
        }
    };
    Ok(ws.split())
}

impl WsConnection {
    /// Connect to a WebSocket URL using the default retry policy.
    ///
    /// Supports both `ws://` and `wss://` URLs. For `wss://` the rustls
    /// `ring` crypto provider is installed lazily on first call.
    ///
    /// The `tungstenite` 16 MiB default max frame size is bumped to
    /// [`MAX_WS_FRAME_SIZE`] so fresh-sync chunk batches (which can exceed
    /// 30 MiB against the main UTXO database) don't get rejected with
    /// `"Space limit exceeded: Message too long"`.
    ///
    /// Equivalent to `connect_with_backoff(url, RetryPolicy::default())`,
    /// which retries up to `DEFAULT_MAX_CONNECT_ATTEMPTS = 5` times with
    /// exponential backoff between failures. Use
    /// [`connect_once`](Self::connect_once) for a single-shot attempt,
    /// or [`connect_with_backoff`](Self::connect_with_backoff) to dial a
    /// custom policy.
    #[tracing::instrument(level = "info", skip_all, fields(url = %url))]
    pub async fn connect(url: &str) -> PirResult<Self> {
        Self::connect_with_backoff(url, RetryPolicy::default()).await
    }

    /// Connect with a single attempt — no retry, no backoff. Useful for
    /// tests and for callers that want to implement their own retry loop.
    #[tracing::instrument(level = "debug", skip_all, fields(url = %url))]
    pub async fn connect_once(url: &str) -> PirResult<Self> {
        Self::connect_with_backoff(url, RetryPolicy::single_attempt()).await
    }

    /// Connect with a custom retry policy.
    ///
    /// Retries only on connection-level failures
    /// ([`PirError::is_connection_error`]) — a 4xx/5xx HTTP response from
    /// the server bubbles up immediately, since those indicate a
    /// configuration bug rather than a transient outage.
    #[tracing::instrument(level = "debug", skip_all, fields(url = %url, max_attempts = policy.max_attempts))]
    pub async fn connect_with_backoff(
        url: &str,
        policy: RetryPolicy,
    ) -> PirResult<Self> {
        let max_attempts = policy.max_attempts.max(1);
        let mut last_err: Option<PirError> = None;
        for attempt in 0..max_attempts {
            if attempt > 0 {
                let delay = policy.backoff_delay(attempt - 1);
                log::debug!(
                    "[PIR-AUDIT] WsConnection retry {}/{} to {} after {:?}",
                    attempt + 1,
                    max_attempts,
                    url,
                    delay,
                );
                tokio::time::sleep(delay).await;
            }
            match raw_connect(url, policy.connect_timeout).await {
                Ok((sink, stream)) => {
                    return Ok(Self {
                        sink,
                        stream,
                        url: url.to_string(),
                        request_timeout: DEFAULT_REQUEST_TIMEOUT,
                        retry_policy: policy,
                        metrics_recorder: None,
                        metrics_backend: "",
                    });
                }
                Err(err) if err.is_connection_error() => {
                    last_err = Some(err);
                    // fall through to next retry
                }
                Err(err) => return Err(err),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            PirError::ConnectionFailed(format!(
                "{}: exhausted {} attempts",
                url, max_attempts,
            ))
        }))
    }

    /// Override the per-request deadline used by `send`, `recv`, and
    /// `roundtrip`. Builder-style so you can chain it after `connect`:
    /// `let conn = WsConnection::connect(url).await?.with_request_timeout(Duration::from_secs(30));`.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// The current per-request deadline.
    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// Get the URL this connection is connected to.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The retry policy in effect for [`reconnect`](Self::reconnect).
    pub fn retry_policy(&self) -> RetryPolicy {
        self.retry_policy
    }

    /// Replace this connection's underlying WebSocket with a fresh handshake
    /// to the same URL, using the retry policy that was in effect when the
    /// connection was originally established.
    ///
    /// Callers should treat a successful `reconnect` as "the transport is
    /// healthy again, but any server-side session state (Harmony hints,
    /// Onion FHE keys, in-flight round IDs) is gone — rebuild it." On
    /// failure the old sink/stream have already been dropped, so the
    /// `WsConnection` is no longer usable and the caller should surface the
    /// error or drop the connection.
    #[tracing::instrument(level = "info", skip_all, fields(url = %self.url))]
    pub async fn reconnect(&mut self) -> PirResult<()> {
        // Drop the old transport first so any half-open OS socket is
        // released before we start a fresh handshake. `connect_async`
        // doesn't care about lingering sockets, but leaving them open
        // across a retry storm could hit ulimit in pathological cases.
        let _ = self.sink.send(Message::Close(None)).await;
        let policy = self.retry_policy;
        let max_attempts = policy.max_attempts.max(1);
        let mut last_err: Option<PirError> = None;
        for attempt in 0..max_attempts {
            if attempt > 0 {
                let delay = policy.backoff_delay(attempt - 1);
                log::debug!(
                    "[PIR-AUDIT] WsConnection reconnect retry {}/{} to {} after {:?}",
                    attempt + 1,
                    max_attempts,
                    self.url,
                    delay,
                );
                tokio::time::sleep(delay).await;
            }
            match raw_connect(&self.url, policy.connect_timeout).await {
                Ok((sink, stream)) => {
                    self.sink = sink;
                    self.stream = stream;
                    return Ok(());
                }
                Err(err) if err.is_connection_error() => {
                    last_err = Some(err);
                }
                Err(err) => return Err(err),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            PirError::ConnectionFailed(format!(
                "{}: exhausted {} reconnect attempts",
                self.url, max_attempts,
            ))
        }))
    }

    /// Install (or replace) a metrics recorder. Once installed, every
    /// `send` / `recv` / `roundtrip` fires
    /// [`PirMetrics::on_bytes_sent`] / [`PirMetrics::on_bytes_received`]
    /// with the full wire-frame byte count (including the 4-byte length
    /// prefix on recv / the `recv`-half of `roundtrip`).
    ///
    /// `backend` is passed through to each callback so a single recorder
    /// can disambiguate which transport a byte count came from (a DPF
    /// client, for example, holds two `WsConnection`s and can label them
    /// both `"dpf"`; a Harmony client holds one `"harmony"` + one hint
    /// socket, etc.).
    ///
    /// Pass `None` to uninstall; pass a fresh `Arc` to replace. This is
    /// the inherent method the `PirTransport` trait impl delegates to.
    pub fn set_metrics_recorder(
        &mut self,
        recorder: Option<Arc<dyn PirMetrics>>,
        backend: &'static str,
    ) {
        self.metrics_recorder = recorder;
        self.metrics_backend = backend;
    }

    /// Fire `on_bytes_sent` on the installed recorder, if any. No-op when
    /// no recorder is installed — hot path, so the check is inline.
    fn fire_bytes_sent(&self, bytes: usize) {
        if let Some(rec) = &self.metrics_recorder {
            rec.on_bytes_sent(self.metrics_backend, bytes);
        }
    }

    /// Fire `on_bytes_received` on the installed recorder, if any. No-op
    /// when no recorder is installed.
    fn fire_bytes_received(&self, bytes: usize) {
        if let Some(rec) = &self.metrics_recorder {
            rec.on_bytes_received(self.metrics_backend, bytes);
        }
    }

    /// Fire `on_roundtrip_end` on the installed recorder, if any. No-op
    /// when no recorder is installed. Only called from the success path
    /// of `roundtrip` — partial-success is not surfaced as a roundtrip
    /// observation (see `PirMetrics::on_roundtrip_end` docs).
    fn fire_roundtrip_end(&self, bytes_out: usize, bytes_in: usize, duration: Duration) {
        if let Some(rec) = &self.metrics_recorder {
            rec.on_roundtrip_end(self.metrics_backend, bytes_out, bytes_in, duration);
        }
    }

    /// Send a binary message, subject to the per-request deadline.
    pub async fn send(&mut self, data: Vec<u8>) -> PirResult<()> {
        // Capture the read-only bits before `self.sink` is mutably
        // borrowed by `send(...)` — otherwise the borrow checker can't
        // tell the timeout/format fields don't alias the sink.
        let request_timeout = self.request_timeout;
        let url = self.url.clone();
        let bytes_out = data.len();
        let send_fut = self.sink.send(Message::Binary(data.into()));
        match tokio::time::timeout(request_timeout, send_fut).await {
            Ok(Ok(())) => {
                // Only fire after a confirmed successful send — a failed
                // send didn't put bytes on the wire from the caller's
                // perspective, so double-counting would be misleading.
                self.fire_bytes_sent(bytes_out);
                Ok(())
            }
            Ok(Err(e)) => Err(PirError::ConnectionClosed(format!("send: {}", e))),
            Err(_) => Err(PirError::Timeout(format!(
                "send to {} took longer than {:?}",
                url, request_timeout,
            ))),
        }
    }

    /// Receive a binary message, handling ping/pong automatically,
    /// subject to the per-request deadline.
    pub async fn recv(&mut self) -> PirResult<Vec<u8>> {
        let request_timeout = self.request_timeout;
        let url = self.url.clone();
        let recv_fut = self.recv_inner();
        match tokio::time::timeout(request_timeout, recv_fut).await {
            Ok(Ok(frame)) => {
                // Report the raw frame length (including any length
                // prefix the PIR protocol adds on top of the WebSocket
                // payload — matches what a wire-level observer would
                // see).
                self.fire_bytes_received(frame.len());
                Ok(frame)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(PirError::Timeout(format!(
                "recv from {} took longer than {:?}",
                url, request_timeout,
            ))),
        }
    }

    /// Inner recv loop — same behaviour as the old `recv`, no timeout.
    /// Wrapped by `recv` with `tokio::time::timeout`.
    async fn recv_inner(&mut self) -> PirResult<Vec<u8>> {
        loop {
            let msg = self
                .stream
                .next()
                .await
                .ok_or_else(|| PirError::ConnectionClosed("stream ended".into()))?
                .map_err(|e| PirError::ConnectionClosed(format!("recv: {}", e)))?;

            match msg {
                Message::Binary(b) => return Ok(b.into()),
                Message::Ping(p) => {
                    let _ = self.sink.send(Message::Pong(p)).await;
                }
                Message::Pong(_) => continue,
                Message::Close(_) => {
                    return Err(PirError::ConnectionClosed("server closed".into()))
                }
                Message::Text(_) => continue,
                Message::Frame(_) => continue,
            }
        }
    }

    /// Send a request and receive a response, subject to the per-request
    /// deadline **across both halves combined**.
    ///
    /// The request is encoded as: [4B length LE][payload]
    /// The response is: [4B length LE][payload]
    ///
    /// Using one combined deadline (rather than one per half) means a
    /// server that accepts the request quickly but then stalls on the
    /// response still fails in bounded time — which is the attack shape
    /// we're actually worried about.
    pub async fn roundtrip(&mut self, request: &[u8]) -> PirResult<Vec<u8>> {
        let request_timeout = self.request_timeout;
        let url = self.url.clone();
        // `request` length is observable *before* we enter the async block
        // — capturing it here lets us fire `on_bytes_sent` without having
        // to thread the count through the future.
        let bytes_out = request.len();
        // Capture `Instant::now()` only when a recorder is installed; the
        // `is_some().then(...)` branch elides the clock-read entirely
        // when no recorder is installed, preserving the "no recorder =
        // zero overhead" property for the no-roundtrip-metrics case
        // (and avoiding a `performance.now()` JS↔WASM boundary call on
        // the wasm transport via the same `pir_sdk::Instant`
        // re-export).
        let started_at: Option<Instant> = self.metrics_recorder.is_some().then(Instant::now);
        // Track whether the response future actually received something,
        // so we can fire `on_bytes_received` from outside the inner
        // `async` block (where we can't borrow `self.metrics_recorder`
        // while `self.sink`/`self.stream` are also mutably borrowed).
        let mut bytes_in: Option<usize> = None;
        let mut send_succeeded = false;
        let fut = async {
            // Send request (already includes length prefix from protocol
            // encoding).
            let send_fut = self.sink.send(Message::Binary(request.to_vec().into()));
            send_fut
                .await
                .map_err(|e| PirError::ConnectionClosed(format!("send: {}", e)))?;
            send_succeeded = true;

            // Receive response.
            let response = self.recv_inner().await?;
            if response.len() < 4 {
                return Err(PirError::Protocol("response too short".into()));
            }
            bytes_in = Some(response.len());
            Ok(response[4..].to_vec())
        };
        let result = match tokio::time::timeout(request_timeout, fut).await {
            Ok(result) => result,
            Err(_) => Err(PirError::Timeout(format!(
                "roundtrip to {} took longer than {:?}",
                url, request_timeout,
            ))),
        };
        // Fire byte-count callbacks *after* the future resolves so the
        // borrow of `self.sink`/`self.stream` is over. We fire on-send
        // only when the send half actually completed (a timeout before
        // the send future resolves means nothing hit the wire from the
        // caller's POV); we fire on-recv only when a full frame was
        // read (the raw frame length including prefix, matching `recv`).
        if send_succeeded {
            self.fire_bytes_sent(bytes_out);
        }
        if let Some(n) = bytes_in {
            self.fire_bytes_received(n);
        }
        // Fire `on_roundtrip_end` only on full success (both halves +
        // length prefix sanity check passed AND the result is `Ok`).
        // Using `result.is_ok()` here is the cleanest predicate: the
        // length-prefix check inside `fut` short-circuits with `Err`
        // before setting `bytes_in`, so a recorded "complete" roundtrip
        // implies a well-formed response. `started_at` being `Some`
        // implies a recorder is still installed (no install/uninstall
        // race in this single-threaded `&mut self` API).
        if let (true, Some(start), Some(n)) = (result.is_ok(), started_at, bytes_in) {
            self.fire_roundtrip_end(bytes_out, n, start.elapsed());
        }
        result
    }

    /// Close the connection.
    pub async fn close(&mut self) -> PirResult<()> {
        let _ = self.sink.send(Message::Close(None)).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_policy_default_matches_constants() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_attempts, DEFAULT_MAX_CONNECT_ATTEMPTS);
        assert_eq!(policy.initial_delay, DEFAULT_INITIAL_BACKOFF_DELAY);
        assert_eq!(policy.max_delay, DEFAULT_MAX_BACKOFF_DELAY);
        assert_eq!(policy.connect_timeout, DEFAULT_CONNECT_TIMEOUT);
    }

    #[test]
    fn retry_policy_single_attempt() {
        let policy = RetryPolicy::single_attempt();
        assert_eq!(policy.max_attempts, 1);
        // Other knobs should still match default so if the caller opts
        // back into retries via `with_max_attempts` they get sane values.
        assert_eq!(policy.initial_delay, DEFAULT_INITIAL_BACKOFF_DELAY);
    }

    #[test]
    fn backoff_delay_doubles_then_caps() {
        let policy = RetryPolicy {
            max_attempts: 10,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(800),
            connect_timeout: Duration::from_secs(5),
        };
        assert_eq!(policy.backoff_delay(0), Duration::from_millis(100));
        assert_eq!(policy.backoff_delay(1), Duration::from_millis(200));
        assert_eq!(policy.backoff_delay(2), Duration::from_millis(400));
        assert_eq!(policy.backoff_delay(3), Duration::from_millis(800));
        // Cap kicks in here — raw would be 1600ms but max_delay caps it.
        assert_eq!(policy.backoff_delay(4), Duration::from_millis(800));
        assert_eq!(policy.backoff_delay(5), Duration::from_millis(800));
    }

    #[test]
    fn backoff_delay_handles_large_attempts_without_overflow() {
        // A huge attempt count should saturate to max_delay, not panic
        // on `Duration::checked_mul(u32::MAX)`.
        let policy = RetryPolicy {
            max_attempts: 100,
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(5),
        };
        assert_eq!(policy.backoff_delay(64), policy.max_delay);
        assert_eq!(policy.backoff_delay(1_000), policy.max_delay);
    }

    /// Small helper: run `fut` and panic if it returns `Ok` — `WsConnection`
    /// itself doesn't implement `Debug` (the underlying `SplitSink`/`SplitStream`
    /// don't either), so `.unwrap_err()` doesn't typecheck. Match is fine.
    async fn expect_err<T>(fut: impl std::future::Future<Output = PirResult<T>>) -> PirError {
        match fut.await {
            Ok(_) => panic!("expected error, got Ok"),
            Err(e) => e,
        }
    }

    #[tokio::test]
    async fn connect_once_fails_on_unresolvable_host() {
        // `ws://invalid.pir-sdk-test.local:9/` should never resolve —
        // reserved TLD, reserved port. The error must be a connection
        // error (not a panic, not a hang).
        let err = expect_err(WsConnection::connect_once(
            "ws://invalid.pir-sdk-test.local:9/",
        ))
        .await;
        assert!(
            err.is_connection_error(),
            "expected connection error, got {:?}",
            err,
        );
    }

    #[tokio::test]
    async fn connect_respects_connect_timeout() {
        // 10.255.255.1 is RFC1918 unlikely-routable. Give it a
        // ridiculously short deadline; we should get a `Timeout` well
        // before any real TCP SYN retry would fire.
        //
        // On CI runners this may instead return ConnectionFailed if the
        // route is immediately unreachable (ICMP host-unreachable) —
        // both outcomes are fine, the point is it *doesn't hang*.
        let policy = RetryPolicy {
            max_attempts: 1,
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(1),
            connect_timeout: Duration::from_millis(50),
        };
        let err = expect_err(WsConnection::connect_with_backoff(
            "ws://10.255.255.1:9/",
            policy,
        ))
        .await;
        assert!(
            err.is_connection_error(),
            "expected connection error, got {:?}",
            err,
        );
    }

    #[tokio::test]
    async fn connect_with_backoff_retries_then_gives_up() {
        // Unresolvable host — every attempt will fail with a connection
        // error. The loop should make exactly `max_attempts` attempts
        // and then surface the last error. We can't easily assert the
        // attempt count from outside, but we CAN assert the total
        // elapsed time exceeds the sum of backoff delays. With
        // `initial_delay = 20ms` and 3 attempts, the floor is 20 + 40
        // = 60ms of sleep (plus up to 3 × connect_timeout of connect
        // work, which is irrelevant since DNS fails immediately).
        let policy = RetryPolicy {
            max_attempts: 3,
            initial_delay: Duration::from_millis(20),
            max_delay: Duration::from_millis(200),
            connect_timeout: Duration::from_millis(200),
        };
        let start = std::time::Instant::now();
        let err = expect_err(WsConnection::connect_with_backoff(
            "ws://invalid.pir-sdk-test.local:9/",
            policy,
        ))
        .await;
        let elapsed = start.elapsed();
        assert!(err.is_connection_error());
        // Floor: 20ms + 40ms = 60ms of backoff sleeps between 3 attempts.
        assert!(
            elapsed >= Duration::from_millis(60),
            "expected ≥60ms elapsed (3 attempts × backoff), got {:?}",
            elapsed,
        );
    }
}
