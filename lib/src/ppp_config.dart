import 'dart:typed_data';

import 'bytes.dart';
import 'frame_queue.dart';
import 'logging.dart';
import 'ppp_packets.dart';

/// Shared, mutable PPP session state threaded through the negotiators.
class PppState {
  // A single frame-identifier counter is shared across LCP, CHAP and IPCP, as
  // in the reference implementation.
  int _frameId = 0;

  int currentMru;
  final int desiredMru;

  // Chosen authentication protocol, set during LCP (only MSCHAPv2 supported).
  int? chosenAuthProtocol;

  // IPv4 address currently being requested / assigned via IPCP.
  Uint8List currentIpv4 = Uint8List(4); // 0.0.0.0 initially
  Uint8List? assignedDns;

  PppState({this.desiredMru = 1500}) : currentMru = 1500;

  int nextFrameId() {
    _frameId = (_frameId + 1) & 0xff;
    return _frameId;
  }
}

/// A parsed PPP configuration frame (LCP or IPCP): code, id, and options.
class ConfigFrame {
  final int code;
  final int id;
  final List<PppOption> options;

  ConfigFrame(this.code, this.id, this.options);

  static ConfigFrame fromView(PppFrameView v) {
    final r = ByteReader(v.body);
    final options = PppOption.readAll(r, v.body.length);
    return ConfigFrame(v.code, v.id, options);
  }
}

/// Outcome of reviewing the server's Configure-Request.
class ServerReview {
  final List<PppOption>? reject; // options to Configure-Reject
  final List<PppOption>? nak; // options to Configure-Nak
  final List<PppOption> ackEcho; // full option list to echo in Configure-Ack

  ServerReview.reject(List<PppOption> opts)
      : reject = opts,
        nak = null,
        ackEcho = const [];
  ServerReview.nak(List<PppOption> opts)
      : reject = null,
        nak = opts,
        ackEcho = const [];
  ServerReview.ack(this.ackEcho)
      : reject = null,
        nak = null;
}

/// The generic RFC 1661 configure-request/ack/nak/reject convergence loop,
/// specialized by subclasses for LCP and IPCP.
///
/// Success requires both directions to be satisfied: the server acks our
/// request (isClientReady) and we ack the server's request (isServerReady).
abstract class ConfigNegotiator {
  final String name;
  final int protocol;
  final PppState state;
  final Logger log;
  final void Function(Uint8List framed) send;
  final FrameQueue<PppFrameView> inbox;

  static const Duration requestInterval = Duration(seconds: 3);
  static const int maxRequests = 10;

  int _requestId = 0;
  bool _clientReady = false;
  bool _serverReady = false;

  ConfigNegotiator({
    required this.name,
    required this.protocol,
    required this.state,
    required this.log,
    required this.send,
    required this.inbox,
  });

  // -- subclass hooks ------------------------------------------------------

  /// Options for our outbound Configure-Request.
  List<PppOption> buildRequestOptions();

  /// Reviews the server's Configure-Request options.
  ServerReview reviewServerRequest(List<PppOption> options);

  /// Applies a Configure-Nak the server sent for our request (adopt suggested
  /// values). Return false to abort negotiation.
  bool onNak(List<PppOption> options);

  /// Applies a Configure-Reject the server sent for our request (drop rejected
  /// options). Return false to abort negotiation.
  bool onReject(List<PppOption> options);

  // -- driver --------------------------------------------------------------

  bool get _isOpen => _clientReady && _serverReady;

  void _sendRequest() {
    _requestId = state.nextFrameId();
    final opts = buildRequestOptions();
    final body = PppOption.writeAll(opts);
    final framed = buildPppFrame(
      protocol: protocol,
      code: lcpCodeConfigureRequest,
      id: _requestId,
      body: body,
    );
    log.debug(name,
        'send Configure-Request id=$_requestId with ${opts.length} option(s)');
    send(framed);
  }

  void _sendResponse(int code, int id, List<PppOption> opts) {
    final framed = buildPppFrame(
      protocol: protocol,
      code: code,
      id: id,
      body: PppOption.writeAll(opts),
    );
    log.debug(name, 'send ${configCodeName(code)} id=$id');
    send(framed);
  }

  /// Runs the negotiation to convergence. Throws on timeout/exhaustion or an
  /// aborting Nak/Reject.
  Future<void> run() async {
    log.stage('$name negotiation');
    var requestsLeft = maxRequests;
    _sendRequest();

    while (true) {
      PppFrameView view;
      try {
        view = await inbox.next(requestInterval);
      } on Object {
        // Timeout: resend our request.
        _clientReady = false;
        requestsLeft--;
        if (requestsLeft < 0) {
          throw StateError('$name negotiation timed out (no response)');
        }
        log.trace(name, 'timeout, resending request ($requestsLeft left)');
        _sendRequest();
        continue;
      }

      final frame = ConfigFrame.fromView(view);

      if (frame.code == lcpCodeConfigureRequest) {
        _serverReady = false;
        final review = reviewServerRequest(frame.options);
        if (review.reject != null) {
          _sendResponse(lcpCodeConfigureReject, frame.id, review.reject!);
        } else if (review.nak != null) {
          _sendResponse(lcpCodeConfigureNak, frame.id, review.nak!);
        } else {
          _sendResponse(lcpCodeConfigureAck, frame.id, review.ackEcho);
          _serverReady = true;
        }
      } else {
        // Response to our request. Ignore stale ids.
        if (_clientReady) {
          // Server re-opened; restart our side.
          _clientReady = false;
          _sendRequest();
          continue;
        }
        if (frame.id != _requestId) {
          log.trace(name,
              'ignoring ${configCodeName(frame.code)} id=${frame.id} (want $_requestId)');
          continue;
        }
        switch (frame.code) {
          case lcpCodeConfigureAck:
            log.debug(name, 'received Configure-Ack for our request');
            _clientReady = true;
            break;
          case lcpCodeConfigureNak:
            log.debug(name, 'received Configure-Nak');
            if (!onNak(frame.options)) {
              throw StateError('$name negotiation aborted by Nak');
            }
            _sendRequest();
            break;
          case lcpCodeConfigureReject:
            log.debug(name, 'received Configure-Reject');
            if (!onReject(frame.options)) {
              throw StateError('$name negotiation aborted by Reject');
            }
            _sendRequest();
            break;
          case lcpCodeTerminateRequest:
            throw StateError('$name: server sent Terminate-Request');
          default:
            log.trace(name,
                'ignoring PPP ${configCodeName(frame.code)} during $name');
        }
      }

      if (_isOpen) {
        log.info(name, 'negotiation complete (both directions ready)');
        return;
      }
    }
  }
}
