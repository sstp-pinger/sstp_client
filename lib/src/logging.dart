/// Minimal leveled logger. The CLI harness constructs one and threads it
/// through every layer so a stalled handshake can be debugged without adding
/// print statements by hand.
enum LogLevel { trace, debug, info, warn, error }

class Logger {
  final LogLevel level;
  final void Function(String line) sink;

  Logger({this.level = LogLevel.info, void Function(String)? sink})
      : sink = sink ?? print;

  bool get isTrace => level.index <= LogLevel.trace.index;

  void _log(LogLevel l, String tag, String msg) {
    if (l.index < level.index) return;
    final ts = DateTime.now().toIso8601String().substring(11, 23);
    sink('$ts ${l.name.toUpperCase().padRight(5)} [$tag] $msg');
  }

  void trace(String tag, String msg) => _log(LogLevel.trace, tag, msg);
  void debug(String tag, String msg) => _log(LogLevel.debug, tag, msg);
  void info(String tag, String msg) => _log(LogLevel.info, tag, msg);
  void warn(String tag, String msg) => _log(LogLevel.warn, tag, msg);
  void error(String tag, String msg) => _log(LogLevel.error, tag, msg);

  /// Logs a full stage banner so progress is easy to scan.
  void stage(String msg) => _log(LogLevel.info, 'STAGE', '=== $msg ===');
}
