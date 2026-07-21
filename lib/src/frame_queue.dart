import 'dart:async';

/// A minimal single-consumer awaitable queue.
///
/// Frames pushed via [add] are buffered; [next] returns the oldest buffered
/// frame or awaits the next one. Used to bridge the framer's broadcast stream
/// into the sequential request/response loops of PPP negotiation without
/// pulling in an external dependency.
class FrameQueue<T> {
  final _buffer = <T>[];
  Completer<T>? _waiter;
  bool _closed = false;
  Object? _error;

  void add(T item) {
    if (_closed) return;
    final w = _waiter;
    if (w != null && !w.isCompleted) {
      _waiter = null;
      w.complete(item);
    } else {
      _buffer.add(item);
    }
  }

  void addError(Object error) {
    _error = error;
    final w = _waiter;
    if (w != null && !w.isCompleted) {
      _waiter = null;
      w.completeError(error);
    }
  }

  /// Returns the next frame, or throws [TimeoutException] if none arrives
  /// within [timeout]. A `null` return is never produced; timeouts throw so
  /// callers can distinguish "no frame" from a real frame.
  Future<T> next(Duration timeout) {
    if (_buffer.isNotEmpty) {
      return Future.value(_buffer.removeAt(0));
    }
    if (_error != null) {
      final e = _error!;
      _error = null;
      return Future.error(e);
    }
    if (_closed) {
      return Future.error(StateError('queue closed'));
    }
    final w = Completer<T>();
    _waiter = w;
    return w.future.timeout(timeout);
  }

  void close() {
    _closed = true;
    final w = _waiter;
    if (w != null && !w.isCompleted) {
      _waiter = null;
      w.completeError(StateError('queue closed'));
    }
  }
}
