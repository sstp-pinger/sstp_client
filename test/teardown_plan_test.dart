import 'dart:io';

import 'package:sstp_client/sstp_client.dart';
import 'package:test/test.dart';

/// A command that appends [word] to [file], on either shell.
TeardownCommand append(File file, String word) => Platform.isWindows
    ? TeardownCommand('cmd', ['/c', 'echo $word>>${file.path}'], word)
    : TeardownCommand('sh', ['-c', 'echo $word >> "${file.path}"'], word);

void main() {
  final log = Logger(level: LogLevel.error, sink: (_) {});

  test('an empty plan is empty, and a held handle is not', () {
    expect(const TeardownPlan().isEmpty, isTrue);
    expect(const TeardownPlan(wintunAdapter: 1).isEmpty, isFalse);
    expect(const TeardownPlan(tunFd: 3).isEmpty, isFalse);
    expect(
      const TeardownPlan(commands: [TeardownCommand('x', [], 'x')]).isEmpty,
      isFalse,
    );
  });

  test('undoes the newest change first and keeps going past a failure',
      () async {
    final dir = await Directory.systemTemp.createTemp('teardown_plan_test');
    addTearDown(() => dir.delete(recursive: true));
    final file = File('${dir.path}${Platform.pathSeparator}order.txt');

    await runTeardownPlan(
      TeardownPlan(commands: [
        append(file, 'first'),
        const TeardownCommand('no-such-command-sstp', [], 'missing'),
        append(file, 'last'),
      ]),
      log,
    );

    final lines = (await file.readAsLines()).map((l) => l.trim()).toList();
    expect(lines, ['last', 'first']);
  });
}
