import hashlib
import json
import re
from collections import Counter
from pathlib import Path

H = Path.home()
CAP = H / 'darm-e3e1-t6-q5-q2-q4-4-p2-full-trace-001'
RUN = H / 'darm-e3e1-t6-q5-q2-q4-4-p2-001'
OUT = H / 'darm-e3e1-t6-q5-q2-q4-4-p2-event-audit-v2-001'
OLD = H / 'darm-e3e1-t6-q5-q2-q4-3-p1-trace-002/p1_trace_runner.py'
NEW = CAP / 'p2_runner.py'

P1_SHA = '558695ef0f18c55df6601e9f42600bd47b41a3a75eabb53b2fc529a6aecdecff'
P2_SHA = '57407f1a7c1281c5e7ade02c32d0c95557fe6603f147afad03d87f514a2c0744'

PINS = {
    'DARM-E3E1-T6-Q5-Q2-Q4-3-P1-002-evidence-lock-001.tar.gz':
        'abdcaca19deba360d8917f53f5bb056e9f51203d95ae4d3a634111b9c8f51d4b',
    'DARM-E3E1-T6-Q5-Q2-Q4-3-P1-002-v2-SUPPLEMENT-evidence-lock-001.tar.gz':
        '322fa8788cff17dac8127b037ffba0cf4e831b03c6adb278eef03e7059a58abb'
}

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for piece in iter(lambda: f.read(1048576), b''):
            h.update(piece)
    return h.hexdigest()

def load(path):
    return json.loads(path.read_text())

CALL = re.compile(
    r'^\d+(?:\.\d+)?\s+([a-zA-Z_]\w*)\('
)
EXEC = re.compile(
    r'^\d+(?:\.\d+)?\s+execve\("([^"\n]+)".*\)\s+=\s+0(?:\s|$)'
)
RANGE = re.compile(
    r'\bclose_range\((\d+),\s*(\d+),\s*0\)\s+=\s+0(?:\s|$)'
)
DUP2 = re.compile(
    r'\bdup2\((\d+)(?:<[^,\n]*>)?,\s*(\d+)(?:<[^,\n]*>)?\)\s+=\s+(\d+)(?:\b|<)'
)
CLOSE = re.compile(
    r'\bclose\((\d+)(?:<[^>]*>)?\)\s+=\s+0(?:\s|$)'
)
PIPE = re.compile(
    r'\bpipe2\(\[(\d+)(?:<[^>]*>)?,\s*(\d+)(?:<[^>]*>)?\],\s*O_CLOEXEC\)\s+=\s+0(?:\s|$)'
)
VFORK = re.compile(
    r'\bvfork\(\)\s+=\s+(\d+)\b'
)
DEVNULL = re.compile(
    r'\bopenat\([^,\n]+,\s*"/dev/null",\s*O_RDWR\|O_CLOEXEC\)\s+=\s+(\d+)(?:\b|<)'
)

BAD = (
    '<unfinished ...>',
    'resumed>',
    'syscall_0x',
    '???(',
    'strace:'
)

EXPECTED = Counter({
    'close': 3,
    'dup2': 3,
    'close_range': 2,
    'rt_sigaction': 64,
    'rt_sigprocmask': 1
})


def classify_terminal_trace(lines, is_kernel=False, exec_index=None):
    if not lines:
        return False, []

    exceptions = []

    for i, line in enumerate(lines):
        if any(flag in line for flag in BAD):
            return False, exceptions

        if not line.rstrip().endswith('= ?'):
            continue

        # Only the penultimate record may be a terminal exception.
        if i != len(lines) - 2:
            return False, exceptions

        last = lines[-1]
        kind = None

        if (
            re.search(r'\b(?:exit|exit_group)\(0\)\s+=\s+\?\s*$', line)
            and '+++ exited with 0 +++' in last
        ):
            kind = 'NORMAL_TERMINAL_EXIT'

        elif (
            is_kernel
            and exec_index is not None
            and i > exec_index
            and re.search(r'\bfutex\(', line)
            and '+++ killed by SIGKILL +++' in last
        ):
            kind = 'POSTEXEC_FUTEX_TERMINATED'

        if kind is None:
            return False, exceptions

        exceptions.append({
            'kind': kind,
            'line_number': i + 1,
            'record': line.strip(),
            'termination': last.strip()
        })

    return len(exceptions) <= 1, exceptions

def analyze(case, evidence, traces):
    checks = {}
    details = {'mode': case.get('mode')}

    try:
        mode = case['mode']
        broker = case['broker_pid']
        kernel = case['snapshots']['child_after']['kernel']
        child = kernel['pid']

        before = [
            x['fd'] for x in
            case['snapshots']['broker_before']['canary_matches']
        ]
        after = [
            x['fd'] for x in
            case['snapshots']['broker_after']['canary_matches']
        ]

        lines = traces[child]
        required = [3] if mode == 'explicit_pass' else []

        checks['BROKER_CANARY_PROFILE'] = (
            before == after == required
        )
        checks['KERNEL_SNAPSHOT_NO_CANARY'] = (
            kernel['canary']['canary_matches'] == []
            and kernel['sha256']
                == evidence['expected_kernel_sha256']
        )
        checks['Q41_SESSION_PASSED'] = (
            case['q41_exit'] == 0
            and case['q41_verdict']
                == 'REAL_BROKER_RESPONSE_NO_FD_TRANSFER_IN_TESTED_SESSION'
            and case['audit']['exit'] == 0
        )

        execs = [
            (i, m.group(1))
            for i, line in enumerate(lines)
            if (m := EXEC.search(line))
        ]

        checks['UNIQUE_PINNED_KERNEL_EXEC'] = (
            len(execs) == 1
            and execs[0][1] == kernel['exe']
        )

        if not checks['UNIQUE_PINNED_KERNEL_EXEC']:
            return checks, details

        boundary = execs[0][0]
        pre = lines[:boundary]

        calls = [
            (i, m.group(1), line)
            for i, line in enumerate(pre)
            if (m := CALL.match(line))
        ]

        checks['ALL_PREEXEC_LINES_DECODED'] = (
            len(calls) == len(pre)
            and not any(
                any(flag in x for flag in BAD)
                or x.rstrip().endswith('= ?')
                for x in pre
            )
        )

        counts = Counter(name for _, name, _ in calls)

        checks['EXACT_PREEXEC_SYSCALL_PROFILE'] = (
            counts == EXPECTED
        )

        checks['SIGNAL_RECORDS_HAVE_RETURNS'] = all(
            re.search(r'\)\s+=\s+-?\d+(?:\s|$)', line)
            for _, name, line in calls
            if name in ('rt_sigaction', 'rt_sigprocmask')
        )

        closes = [
            (i, int(m.group(1)))
            for i, name, line in calls
            if name == 'close'
            and (m := CLOSE.search(line))
        ]

        checks['THREE_SUCCESSFUL_NONSTDIO_CLOSES'] = (
            len(closes) == 3
            and all(fd >= 3 for _, fd in closes)
        )

        dup = [
            (i, tuple(map(int, m.groups())), line)
            for i, name, line in calls
            if name == 'dup2'
            and (m := DUP2.search(line))
        ]

        checks['EXACT_SUCCESSFUL_STDIO_DUP2'] = (
            len(dup) == 3
            and sorted(
                destination
                for _, (source, destination, result), _ in dup
            ) == [0, 1, 2]
            and all(
                destination == result
                and source >= 3
                and source not in before
                for _, (source, destination, result), _ in dup
            )
        )

        ranges = [
            (i, int(m.group(1)), int(m.group(2)))
            for i, name, line in calls
            if name == 'close_range'
            and (m := RANGE.search(line))
        ]

        checks['SUCCESSFUL_CONTIGUOUS_CLOSE_RANGES'] = (
            len(ranges) == 2
            and ranges[0][1] == 3
            and ranges[1][1] == ranges[0][2] + 2
            and ranges[1][2] == 2147483647
        )

        if not checks['SUCCESSFUL_CONTIGUOUS_CLOSE_RANGES']:
            return checks, details

        gap = ranges[0][2] + 1

        checks['CANARY_CLOSED_BEFORE_EXEC'] = all(
            any(
                lo <= fd <= hi
                for _, lo, hi in ranges
            )
            for fd in before
        )

        checks['CLOSURE_AFTER_STDIO_SETUP'] = (
            all(i < ranges[0][0] for i, _ in closes)
            and all(i < ranges[0][0] for i, _, _ in dup)
            and ranges[0][0] < ranges[1][0] < boundary
        )

        spawns = [
            (tid, i)
            for tid, contents in traces.items()
            for i, line in enumerate(contents)
            if (m := VFORK.search(line))
            and int(m.group(1)) == child
        ]

        checks['UNIQUE_VFORK_FROM_TRACED_PARENT'] = (
            len(spawns) == 1
        )

        if not checks['UNIQUE_VFORK_FROM_TRACED_PARENT']:
            return checks, details

        tid, position = spawns[0]

        checks['BROKER_THREAD_ANCESTRY'] = (
            tid == broker
            or sum(
                'CLONE_THREAD' in line
                and 'CLONE_FILES' in line
                and re.search(r'\bclone3?\(', line) is not None
                and re.search(
                    r'=\s*' + str(tid) + r'\b', line
                ) is not None
                for line in traces[broker]
            ) == 1
        )

        parent = traces[tid]
        setup = parent[:position]

        pipes = [
            tuple(map(int, m.groups()))
            for line in setup
            if (m := PIPE.search(line))
        ]

        devnull = [
            int(m.group(1))
            for line in setup
            if (m := DEVNULL.search(line))
        ]

        checks['THREE_CLOEXEC_SETUP_PIPES'] = (
            len(pipes) >= 3
            and pipes[-1][1] == gap
        )

        if (
            checks['THREE_CLOEXEC_SETUP_PIPES']
            and checks['EXACT_SUCCESSFUL_STDIO_DUP2']
        ):
            latest = pipes[-3:]
            sources = {
                destination: source
                for _, (source, destination, result), _ in dup
            }

            checks['STDIO_SOURCES_ACCOUNTED'] = (
                sources == {
                    0: latest[0][0],
                    1: latest[1][1],
                    2: devnull[-1] if devnull else -1
                }
            )
        else:
            checks['STDIO_SOURCES_ACCOUNTED'] = False

        checks['PARENT_CLOSES_CLOEXEC_PIPE'] = any(
            re.search(
                r'\bclose\(' + str(gap)
                + r'(?:<[^>]*>)?\)\s+=\s+0(?:\s|$)',
                line
            )
            for line in parent[position + 1:]
        )

        critical = {broker, tid, child}

        classified = {
            pid: classify_terminal_trace(
                traces.get(pid, []),
                is_kernel=(pid == child),
                exec_index=(boundary if pid == child else None)
            )
            for pid in critical
        }

        checks['NO_CRITICAL_TRACE_ANOMALIES'] = all(
            value[0] for value in classified.values()
        )

        details['terminal_record_exceptions'] = {
            str(pid): value[1]
            for pid, value in classified.items()
            if value[1]
        }

        details.update({
            'broker_pid': broker,
            'spawning_tid': tid,
            'kernel_pid': child,
            'canary_fds': before,
            'gap_fd': gap,
            'close_ranges': [
                [lo, hi] for _, lo, hi in ranges
            ],
            'preexec_syscalls': dict(counts),
            'preexec_lines': len(pre)
        })

    except (KeyError, TypeError, IndexError, ValueError) as exc:
        checks['STRUCTURE_VALID'] = False
        details['parse_error'] = repr(exc)

    return checks, details

def main():
    if OUT.exists() or OUT.is_symlink():
        raise SystemExit('REFUSE_EXISTING_AUDIT_OUTPUT')

    checks = {}

    for name, pin in PINS.items():
        checks['LOCK_' + str(len(checks) + 1)] = (
            (H / name).is_file()
            and sha(H / name) == pin
        )

    checks['PINNED_PARENT_RUNNER'] = (
        OLD.is_file() and sha(OLD) == P1_SHA
    )
    checks['PINNED_P2_RUNNER'] = (
        NEW.is_file() and sha(NEW) == P2_SHA
    )

    if (
        checks['PINNED_PARENT_RUNNER']
        and checks['PINNED_P2_RUNNER']
    ):
        old = OLD.read_text()
        new = NEW.read_text()

        old_out = "OUT = H / 'darm-e3e1-t6-q5-q2-q4-3-p1-002'"
        new_out = "OUT = H / 'darm-e3e1-t6-q5-q2-q4-4-p2-001'"

        checks['ONLY_OUTPUT_DIRECTORY_CHANGED'] = (
            old.count(old_out) == 1
            and new == old.replace(old_out, new_out, 1)
        )
    else:
        checks['ONLY_OUTPUT_DIRECTORY_CHANGED'] = False

    summary = load(CAP / 'capture_summary.json')
    evidence = load(RUN / 'evidence.json')

    checks['CAPTURE_PRECHECK'] = (
        summary.get('verdict')
        == 'Q44_P2_FULLSYSCALL_CAPTURE_RECORDED_PENDING_AUDIT'
        and len(summary.get('checks', {})) >= 10
        and all(
            value is True
            for value in summary['checks'].values()
        )
    )

    checks['EVIDENCE_INTEGRITY'] = (
        sha(RUN / 'evidence.json') + '  evidence.json'
        in (RUN / 'sha256.txt').read_text().splitlines()
    )

    checks['REPLAY_VERDICT'] = (
        evidence.get('verdict')
        == 'REAL_KERNEL_CHILD_FD_CUSTODY_P0_OBSERVED'
        and not evidence.get('errors')
        and len(evidence.get('checks', {})) == 7
        and all(
            value is True
            for value in evidence['checks'].values()
        )
    )

    cases = evidence.get('cases', [])

    checks['TWO_CASES'] = (
        len(cases) == 2
        and [c.get('mode') for c in cases]
        == ['normal', 'explicit_pass']
    )

    traces = {
        int(p.name.split('.')[-1]):
            p.read_text(errors='replace').splitlines()
        for p in CAP.glob('trace.*')
        if p.name.split('.')[-1].isdigit()
    }

    checks['TRACE_COUNT'] = (
        len(traces)
        == summary.get('counts', {}).get('trace_files')
        == 287
    )

    checks['TRACER_SCOPE_ALL'] = (
        load(CAP / 'provenance.json').get('trace_profile')
        == 'ALL_SYSCALLS'
    )

    checks['NO_STRUCTURAL_DETACH'] = not any(
        re.search(
            r'strace:\s*Process\s+\d+\s+detached'
            r'|\+\+\+\s+detached\s+\+\+',
            line,
            re.IGNORECASE
        )
        for lines in traces.values()
        for line in lines
    )

    results = {}

    if checks['TWO_CASES']:
        for case in cases:
            c, details = analyze(case, evidence, traces)

            results[case['mode']] = {
                'checks': c,
                'details': details
            }

            print(
                'Q44_P2_' + case['mode'].upper() + '_CHECKS=',
                json.dumps(c, sort_keys=True)
            )

    passed = (
        all(checks.values())
        and len(results) == 2
        and all(
            all(result['checks'].values())
            for result in results.values()
        )
    )

    verdict = (
        'Q44_P2_FULLTRACE_KERNEL_EXEC_BOUNDARY_CORROBORATED'
        if passed else 'NOT_QUALIFIED'
    )

    report = {
        'schema': 'DARM-Q44-P2-FULLTRACE-EVENT-AUDIT-v1',
        'verdict': verdict,
        'global_checks': checks,
        'cases': results,
        'trace_counts': summary.get('counts', {}),
        'scope': {
            'two_kernel_exec_transitions_only': True,
            'full_syscall_profile_requested': True,
            'complete_event_history_proven': False,
            'independent_kernel_witness': False,
            'transient_preexec_inheritance_excluded': False,
            'untested_fd_transfer_paths_excluded': False
        },
        'auditor_sha256': sha(Path(__file__).resolve())
    }

    OUT.mkdir(mode=0o700, exist_ok=False)

    target = OUT / 'audit.json'
    target.write_text(
        json.dumps(report, indent=2, sort_keys=True) + '\n'
    )

    (OUT / 'sha256.txt').write_text(
        sha(target) + '  audit.json\n'
    )

    print(
        'Q44_P2_GLOBAL_CHECKS=',
        json.dumps(checks, sort_keys=True)
    )
    print('Q44_P2_AUDIT_VERDICT=', verdict)
    print('Q44_P2_AUDIT_PATH=', target)

    raise SystemExit(0 if passed else 2)

if __name__ == '__main__':
    main()
