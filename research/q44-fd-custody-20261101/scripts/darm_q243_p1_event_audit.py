import hashlib
import json
import re
import sys
from pathlib import Path

H = Path.home()
CAP = H / 'darm-e3e1-t6-q5-q2-q4-3-p1-trace-002'
RUN = H / 'darm-e3e1-t6-q5-q2-q4-3-p1-002'
AUD = H / 'darm-e3e1-t6-q5-q2-q4-3-p1-event-audit-001'

SUCCESS = 'P1_002_TRACE_CAPTURE_RECORDED_PENDING_EVENT_AUDIT'
P0_VERDICT = 'REAL_KERNEL_CHILD_FD_CUSTODY_P0_OBSERVED'

def sha(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for block in iter(lambda: f.read(1048576), b''):
            h.update(block)
    return h.hexdigest()

def load(p):
    return json.loads(p.read_text())

def traces_by_tid():
    result = {}
    for p in CAP.glob('trace.*'):
        try:
            tid = int(p.name.rsplit('.', 1)[1])
        except ValueError:
            continue
        result[tid] = p.read_text(errors='replace').splitlines()
    return result

rx_exec = re.compile(
    r'\bexecve\("([^"\n]+)".*\)\s+=\s+0(?:\s|$)'
)
rx_range = re.compile(
    r'\bclose_range\((\d+),\s*(\d+),\s*0\)\s+=\s+0(?:\s|$)'
)
rx_pipe = re.compile(
    r'\bpipe2\(\[(\d+)(?:<[^>]*>)?,\s*'
    r'(\d+)(?:<[^>]*>)?\],\s*O_CLOEXEC\)\s+=\s+0(?:\s|$)'
)

def analyze_case(c, evidence, traces):
    mode = c.get('mode')
    result = {}
    snapshots = c.get('snapshots', {})
    kernel = snapshots.get('child_after', {}).get('kernel', {})
    broker = c.get('broker_pid')
    child = kernel.get('pid')

    result['VALID_PROCESSES'] = (
        type(broker) is int and broker > 1
        and type(child) is int and child > 1
        and child != broker
    )
    if not result['VALID_PROCESSES']:
        return result, {}

    before = snapshots.get('broker_before', {}).get(
        'canary_matches', []
    )
    after = snapshots.get('broker_after', {}).get(
        'canary_matches', []
    )
    fds = [x.get('fd') for x in before]
    after_fds = [x.get('fd') for x in after]

    required = [3] if mode == 'explicit_pass' else []
    result['BROKER_CANARY_CUSTODY'] = (
        fds == required and after_fds == required
    )
    result['CHILD_SNAPSHOT_NO_CANARY'] = (
        kernel.get('canary', {}).get('canary_matches') == []
        and kernel.get('sha256')
            == evidence.get('expected_kernel_sha256')
    )

    lines = traces.get(child, [])
    result['CHILD_TRACE_PRESENT'] = bool(lines)

    execs = [
        (i, m)
        for i, line in enumerate(lines)
        if (m := rx_exec.search(line))
    ]
    result['PINNED_KERNEL_EXEC'] = (
        len(execs) == 1
        and execs[0][1].group(1) == kernel.get('exe')
    )
    if not result['PINNED_KERNEL_EXEC']:
        return result, {}

    boundary = execs[0][0]
    pre = lines[:boundary]

    result['PREEXEC_SYSCALLS_COMPLETE_IN_RECORD'] = not any(
        '<unfinished ...>' in line or 'resumed>' in line
        for line in pre
    )

    ranges = [
        (int(m.group(1)), int(m.group(2)), i)
        for i, line in enumerate(pre)
        if (m := rx_range.search(line))
    ]

    valid_ranges = (
        len(ranges) == 2
        and ranges[0][0] == 3
        and ranges[1][0] == ranges[0][1] + 2
        and ranges[1][1] == 2147483647
        and ranges[0][2] < ranges[1][2]
    )
    result['SUCCESSFUL_PREEXEC_CLOSE_RANGES'] = valid_ranges
    if not valid_ranges:
        return result, {}

    gap = ranges[0][1] + 1
    result['CANARY_FD_COVERED'] = all(
        any(lo <= fd <= hi for lo, hi, _ in ranges)
        for fd in fds
    )

    between = pre[ranges[1][2] + 1:]
    fd_op = re.compile(
        r'\b(?:open|openat|openat2|creat|dup|dup2|dup3|'
        r'fcntl|pipe|pipe2|socket|socketpair|recvmsg|'
        r'sendmsg|pidfd_getfd|close|close_range)\('
    )
    result['NO_NEW_FD_SYSCALLS_BEFORE_EXEC'] = not any(
        fd_op.search(line) for line in between
    )

    spawns = [
        (tid, i)
        for tid, entries in traces.items()
        for i, line in enumerate(entries)
        if re.search(
            r'\bvfork\(\)\s+=\s+' + str(child) + r'\b',
            line
        )
    ]
    result['UNIQUE_VFORK_SPAWN'] = len(spawns) == 1
    if not result['UNIQUE_VFORK_SPAWN']:
        return result, {}

    tid, index = spawns[0]
    broker_lines = traces.get(broker, [])

    result['BROKER_THREAD_ANCESTRY'] = (
        tid == broker or any(
            'CLONE_THREAD' in line
            and re.search(r'\bclone3?\(', line)
            and re.search(
                r'=\s*' + str(tid) + r'\b', line
            )
            for line in broker_lines
        )
    )

    parent = traces[tid]
    pipes = [
        (int(m.group(1)), int(m.group(2)))
        for line in parent[:index]
        if (m := rx_pipe.search(line))
    ]

    result['EXCEPTION_IS_CLOEXEC_PIPE'] = (
        bool(pipes) and pipes[-1][1] == gap
    )
    result['PARENT_CLOSED_PIPE'] = any(
        re.search(
            rf'\bclose\({gap}(?:<[^>]*>)?\)'
            rf'\s+=\s+0(?:\s|$)',
            line
        )
        for line in parent[index + 1:]
    )

    details = {
        'broker_pid': broker,
        'kernel_pid': child,
        'spawning_tid': tid,
        'broker_canary_fds': fds,
        'preexec_closed_ranges': [
            [lo, hi] for lo, hi, _ in ranges
        ],
        'cloexec_exception_fd': gap
    }
    return result, details

def main():
    if AUD.exists() or AUD.is_symlink():
        raise SystemExit('REFUSE_EXISTING_AUDIT')

    if not CAP.is_dir() or not RUN.is_dir():
        raise SystemExit('MISSING_CAPTURE')

    checks = {}
    evidence_file = RUN / 'evidence.json'

    checks['EVIDENCE_HASH'] = (
        (RUN / 'sha256.txt').read_text().splitlines()
        == [sha(evidence_file) + '  evidence.json']
    )

    provenance = load(CAP / 'provenance.json')

    checks['RUNNER_SOURCE_PIN'] = (
        provenance.get('experimental_sha256')
        == sha(CAP / 'p1_trace_runner.py')
        == '558695ef0f18c55df6601e9f42600bd47b41a3a75eabb53b2fc529a6aecdecff'
        and provenance.get('original_sha256')
        == sha(H / 'darm_q243_kernel_child_p0.py')
        == '2963e278a2673174eaded020f81d00f10a4fdd6d2878b023934fc205033e8e5d'
    )

    checks['TRACER_STDERR_EMPTY'] = (
        (CAP / 'strace_stderr.log').read_text().strip() == ''
    )

    evidence = load(evidence_file)
    summary = load(CAP / 'capture_summary.json')

    checks['CAPTURE_PASSED'] = (
        summary.get('verdict') == SUCCESS
        and all(
            x is True
            for x in summary.get('checks', {}).values()
        )
    )

    checks['P0_REPLAY_PASSED'] = (
        evidence.get('verdict') == P0_VERDICT
        and evidence.get('errors') == []
        and len(evidence.get('checks', {})) == 7
        and all(
            x is True for x in evidence['checks'].values()
        )
    )

    cases = evidence.get('cases', [])
    checks['TWO_CASES'] = (
        len(cases) == 2
        and [c.get('mode') for c in cases]
        == ['normal', 'explicit_pass']
    )

    traces = traces_by_tid()
    checks['TRACE_FILES_PRESENT'] = len(traces) >= 6

    details = {}
    if checks['TWO_CASES']:
        for case in cases:
            case_checks, info = analyze_case(
                case, evidence, traces
            )
            mode = case['mode'].upper()
            details[mode] = info
            for name, passed in case_checks.items():
                checks[mode + '_' + name] = passed

    passed = bool(checks) and all(
        value is True for value in checks.values()
    )

    verdict = (
        'Q43_P1_002_EXEC_BOUNDARY_TRACE_CORROBORATED'
        if passed else 'NOT_QUALIFIED'
    )

    report = {
        'verdict': verdict,
        'checks': checks,
        'details': details,
        'auditor_source_sha256': sha(
            Path(__file__).resolve()
        ),
        'scope': {
            'two_tested_exec_transitions_only': True,
            'canary_fd_number_closed_before_exec': passed,
            'all_fd_transitions_complete': False,
            'no_preexec_child_exposure_proven': False,
            'external_witness': False,
            'all_product_launchers_qualified': False
        }
    }

    AUD.mkdir(mode=0o700, exist_ok=False)
    target = AUD / 'audit.json'
    target.write_text(
        json.dumps(report, indent=2, sort_keys=True) + '\n'
    )
    (AUD / 'sha256.txt').write_text(
        sha(target) + '  audit.json\n'
    )

    print('Q43_P1_EVENT_CHECKS=',
          json.dumps(checks, sort_keys=True))
    print('Q43_P1_EVENT_DETAILS=',
          json.dumps(details, sort_keys=True))
    print('Q43_P1_EVENT_VERDICT=', verdict)
    print('Q43_P1_EVENT_AUDIT_PATH=', AUD)

    return 0 if passed else 2

if __name__ == '__main__':
    sys.exit(main())
