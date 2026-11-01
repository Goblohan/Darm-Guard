import copy
import hashlib
import json
import re
import runpy
from pathlib import Path

H = Path.home()
CAP = H / 'darm-e3e1-t6-q5-q2-q4-4-p2-full-trace-001'
RUN = H / 'darm-e3e1-t6-q5-q2-q4-4-p2-001'
AUD = H / 'darm-e3e1-t6-q5-q2-q4-4-p2-event-audit-v2-001'
SRC = H / 'darm_q244_p2_event_audit_v2.py'
OUT = H / 'darm-e3e1-t6-q5-q2-q4-4-p2-mutation-002'

SRC_SHA = '3c4deccc559a041b14c53c694726583b923f1dbaa7dd267da311e66d7fe449f2'
BASE_SHA = 'abdcaca19deba360d8917f53f5bb056e9f51203d95ae4d3a634111b9c8f51d4b'
SUP_SHA = '322fa8788cff17dac8127b037ffba0cf4e831b03c6adb278eef03e7059a58abb'

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1048576), b''):
            h.update(block)
    return h.hexdigest()

def require(ok, label):
    print(label + '=', 'PASS' if ok else 'NOT_QUALIFIED', flush=True)
    if not ok:
        raise SystemExit('REFUSE:' + label)

def checked_json(directory, filename):
    p = directory / filename
    manifest = directory / 'sha256.txt'
    require(p.is_file() and manifest.is_file(), 'FILE_' + filename)
    require(
        sha(p) + '  ' + filename in manifest.read_text().splitlines(),
        'HASH_' + filename
    )
    return json.loads(p.read_text())

def rewrite(t, pid, predicate, action, label):
    lines = list(t[pid])
    hits = [i for i, line in enumerate(lines) if predicate(line)]
    if len(hits) != 1:
        raise ValueError(label + ':ANCHOR_COUNT=' + str(len(hits)))
    i = hits[0]
    new = action(lines[i])
    if new is not None and new == lines[i]:
        raise ValueError(label + ':NO_CHANGE')
    if new is None:
        del lines[i]
    else:
        lines[i] = new
    t[pid] = lines

def insert_before_range(t, pid, event):
    lines = list(t[pid])
    indexes = [i for i, x in enumerate(lines) if 'close_range(3,' in x]
    if len(indexes) != 1:
        raise ValueError('INSERT_RANGE_ANCHOR_INVALID')
    lines.insert(indexes[0], '1793489127.808000 ' + event)
    t[pid] = lines

def main():
    require(not OUT.exists() and not OUT.is_symlink(),
            'NEW_MUTATION_OUTPUT')
    require(SRC.is_file() and sha(SRC) == SRC_SHA,
            'AUDITOR_V2_SOURCE_PIN')

    require(
        sha(H / 'DARM-E3E1-T6-Q5-Q2-Q4-3-P1-002-evidence-lock-001.tar.gz') == BASE_SHA,
        'Q43_PARENT_LOCK'
    )
    require(
        sha(H / 'DARM-E3E1-T6-Q5-Q2-Q4-3-P1-002-v2-SUPPLEMENT-evidence-lock-001.tar.gz') == SUP_SHA,
        'Q43_SUPPLEMENT_LOCK'
    )

    report = checked_json(AUD, 'audit.json')
    require(
        report['verdict']
        == 'Q44_P2_FULLTRACE_KERNEL_EXEC_BOUNDARY_CORROBORATED'
        and report['auditor_sha256'] == SRC_SHA
        and len(report['global_checks']) == 12
        and all(v is True for v in report['global_checks'].values())
        and all(
            len(x['checks']) == 18
            and all(v is True for v in x['checks'].values())
            for x in report['cases'].values()
        ),
        'BASELINE_V2_REPORT'
    )

    evidence = checked_json(RUN, 'evidence.json')
    require(
        evidence['verdict']
        == 'REAL_KERNEL_CHILD_FD_CUSTODY_P0_OBSERVED',
        'REAL_SESSION_VERDICT'
    )

    summary = json.loads((CAP / 'capture_summary.json').read_text())
    require(
        summary['verdict']
        == 'Q44_P2_FULLSYSCALL_CAPTURE_RECORDED_PENDING_AUDIT',
        'CAPTURE_PIN'
    )

    module = runpy.run_path(
        str(SRC), run_name='__mutation_suite_import__'
    )
    analyze = module['analyze']
    pipe_rx = module['PIPE']

    traces = {
        int(p.name.rsplit('.', 1)[1]):
            p.read_text(errors='replace').splitlines()
        for p in CAP.glob('trace.*')
        if p.name.rsplit('.', 1)[-1].isdigit()
    }

    cases = {x['mode']: x for x in evidence['cases']}
    require(set(cases) == {'normal', 'explicit_pass'}, 'TWO_CASES')

    info = {}
    for mode, case in cases.items():
        checks, details = analyze(case, evidence, traces)
        require(
            len(checks) == 18
            and all(v is True for v in checks.values()),
            'BASELINE_RECOMPUTED_' + mode.upper()
        )
        info[mode] = details

    x = info['explicit_pass']
    child = x['kernel_pid']
    parent = x['spawning_tid']
    broker = x['broker_pid']
    gap = x['gap_fd']
    normal_child = info['normal']['kernel_pid']

    def edit_child(t, predicate, action, label):
        rewrite(t, child, predicate, action, label)

    def mutate_dup_source(t, destination):
        def patch(line):
            pattern = (
                r'\bdup2\(\d+[^,\n]*,\s*'
                + str(destination) + r'(?=<|\))'
            )
            changed, count = re.subn(
                pattern,
                'dup2(3</tmp/Q44_SYNTHETIC_CANARY>, '
                + str(destination),
                line,
                count=1
            )
            if count != 1:
                raise ValueError('DUP_SOURCE_REWRITE_FAILED')
            return changed

        edit_child(
            t,
            lambda line: re.search(
                r'\bdup2\(.*?,\s*'
                + str(destination) + r'<',
                line
            ) is not None,
            patch,
            'CANARY_TO_STDIO_' + str(destination)
        )

    def mutate_pipe(t):
        rewrite(
            t, parent,
            lambda line: (
                (m := pipe_rx.search(line)) is not None
                and int(m.group(2)) == gap
            ),
            lambda line: line.replace('O_CLOEXEC', '0', 1),
            'PIPE_CLOEXEC'
        )

    def mutate_parent_close(t):
        pattern = re.compile(
            r'\bclose\(' + str(gap)
            + r'<[^\n]*\)\s+=\s+0(?:\s|$)'
        )
        rewrite(
            t, parent,
            lambda line: pattern.search(line) is not None,
            lambda line: line.replace(' = 0', ' = -1 EBADF', 1),
            'PARENT_CLOSE'
        )

    def mutate_vfork(t):
        pattern = re.compile(
            r'\bvfork\(\)\s+=\s+' + str(child) + r'\b'
        )
        rewrite(
            t, parent,
            lambda line: pattern.search(line) is not None,
            lambda line: re.sub(
                r'(=\s+)' + str(child) + r'\b',
                r'\g<1>999999', line, count=1
            ),
            'VFORK'
        )

    def mutate_clone(t):
        pattern = re.compile(r'=\s*' + str(parent) + r'\b')
        rewrite(
            t, broker,
            lambda line: (
                'CLONE_THREAD' in line
                and pattern.search(line) is not None
            ),
            lambda line: pattern.sub('= 999999', line, count=1),
            'CLONE_THREAD'
        )

    def mutate_dup_order(t):
        lines = list(t[child])
        duplicates = [
            i for i, line in enumerate(lines)
            if re.search(r'\bdup2\(', line)
        ]
        ranges = [
            i for i, line in enumerate(lines)
            if 'close_range(3,' in line
        ]
        if len(duplicates) != 3 or len(ranges) != 1:
            raise ValueError('DUP_ORDER_ANCHORS')

        moved = lines.pop(duplicates[-1])
        index = next(
            i for i, line in enumerate(lines)
            if 'close_range(3,' in line
        )
        lines.insert(index + 1, moved)
        t[child] = lines

    def mutate_terminal(t, pid, original, replacement):
        rewrite(
            t, pid,
            lambda line: (
                original in line and line.rstrip().endswith('= ?')
            ),
            lambda line: line.replace(original, replacement, 1),
            'TERMINAL_' + original
        )

    def omit_sigaction(t):
        lines = list(t[child])
        boundary = next(
            i for i, line in enumerate(lines)
            if 'execve("' in line
            and 'darmkernel' in line
            and ' = 0' in line
        )
        indexes = [
            i for i, line in enumerate(lines[:boundary])
            if 'rt_sigaction(' in line
        ]
        if len(indexes) != 64:
            raise ValueError('EXPECTED_64_PREEXEC_SIGACTION_RECORDS')
        del lines[indexes[0]]
        t[child] = lines

    def mutate_preexec_sigmask(t):
        lines = list(t[child])

        execs = [
            i for i, line in enumerate(lines)
            if 'execve("' in line
            and 'darmkernel' in line
            and re.search(r'\)\s+=\s+0(?:\s|$)', line)
        ]

        if len(execs) != 1:
            raise ValueError(
                'PREEXEC_KERNEL_BOUNDARY_COUNT=' + str(len(execs))
            )

        boundary = execs[0]

        positions = [
            i for i, line in enumerate(lines[:boundary])
            if re.search(r'\brt_sigprocmask\(', line)
        ]

        if len(positions) != 1:
            raise ValueError(
                'PREEXEC_SIGMASK_COUNT=' + str(len(positions))
            )

        index = positions[0]
        original_event = lines[index]

        changed, count = re.subn(
            r'(\)\s+=\s+)-?\d+\s*$',
            r'\g<1>?',
            original_event,
            count=1
        )

        if count != 1 or changed == original_event:
            raise ValueError('SIGMASK_RETURN_REWRITE_FAILED')

        lines[index] = changed
        t[child] = lines

    # Every mutation must fail its specifically targeted predicate.
    tests = [
        ('CANARY_TO_STDERR', 'explicit_pass',
         lambda t,c: mutate_dup_source(t, 2),
         'EXACT_SUCCESSFUL_STDIO_DUP2'),

        ('CANARY_TO_STDOUT', 'explicit_pass',
         lambda t,c: mutate_dup_source(t, 1),
         'EXACT_SUCCESSFUL_STDIO_DUP2'),

        ('CLOSE_RANGE_FAILED', 'explicit_pass',
         lambda t,c: edit_child(
             t, lambda z: 'close_range(3,' in z,
             lambda z: z.replace(' = 0', ' = -1 EBADF', 1),
             'CLOSE_RANGE_FAILED'),
         'SUCCESSFUL_CONTIGUOUS_CLOSE_RANGES'),

        ('CLOSE_RANGE_OMITTED', 'explicit_pass',
         lambda t,c: edit_child(
             t, lambda z: 'close_range(3,' in z,
             lambda z: None, 'CLOSE_RANGE_OMITTED'),
         'EXACT_PREEXEC_SYSCALL_PROFILE'),

        ('FORGED_EXEC_PATH', 'explicit_pass',
         lambda t,c: edit_child(
             t,
             lambda z: 'execve("' in z and 'darmkernel' in z
             and ' = 0' in z,
             lambda z: re.sub(
                 r'\bexecve\("[^"]+',
                 'execve("/tmp/Q44_SYNTHETIC_KERNEL',
                 z, count=1),
             'EXEC_PATH'),
         'UNIQUE_PINNED_KERNEL_EXEC'),

        ('BROKEN_VFORK', 'explicit_pass',
         lambda t,c: mutate_vfork(t),
         'UNIQUE_VFORK_FROM_TRACED_PARENT'),

        ('ORPHAN_THREAD', 'explicit_pass',
         lambda t,c: mutate_clone(t),
         'BROKER_THREAD_ANCESTRY'),

        ('REMOVE_PIPE_CLOEXEC', 'explicit_pass',
         lambda t,c: mutate_pipe(t),
         'THREE_CLOEXEC_SETUP_PIPES'),

        ('PARENT_CLOSE_FAILED', 'explicit_pass',
         lambda t,c: mutate_parent_close(t),
         'PARENT_CLOSES_CLOEXEC_PIPE'),

        ('NEW_PREEXEC_OPENAT', 'explicit_pass',
         lambda t,c: insert_before_range(
             t, child,
             'openat(AT_FDCWD, "/tmp/Q44_SYNTHETIC", O_RDONLY) = 14'),
         'EXACT_PREEXEC_SYSCALL_PROFILE'),

        ('PREEXEC_SCM_RIGHTS', 'explicit_pass',
         lambda t,c: insert_before_range(
             t, child,
             'recvmsg(5, {msg_control=[{cmsg_level=SOL_SOCKET, '
             'cmsg_type=SCM_RIGHTS, cmsg_data=[14]}]}, 0) = 1'),
         'EXACT_PREEXEC_SYSCALL_PROFILE'),

        ('PREEXEC_DUP3', 'explicit_pass',
         lambda t,c: insert_before_range(
             t, child,
             'dup3(3, 2, 0) = 2'),
         'EXACT_PREEXEC_SYSCALL_PROFILE'),

        ('PREEXEC_CLOEXEC_CLEARED', 'explicit_pass',
         lambda t,c: insert_before_range(
             t, child,
             f'fcntl({gap}, F_SETFD, 0) = 0'),
         'EXACT_PREEXEC_SYSCALL_PROFILE'),

        ('SIGACTION_OMITTED', 'explicit_pass',
         lambda t,c: omit_sigaction(t),
         'EXACT_PREEXEC_SYSCALL_PROFILE'),

        ('PREEXEC_SIGMASK_UNKNOWN', 'explicit_pass',
         lambda t,c: mutate_preexec_sigmask(t),
         'ALL_PREEXEC_LINES_DECODED'),

        ('DUP2_AFTER_CLOSE_RANGE', 'explicit_pass',
         lambda t,c: mutate_dup_order(t),
         'CLOSURE_AFTER_STDIO_SETUP'),

        ('TERMINAL_BROKER_EXIT_FORGED', 'explicit_pass',
         lambda t,c: mutate_terminal(
             t, broker, 'exit_group(0)',
             'openat(AT_FDCWD, "/tmp/Q44_SYNTHETIC", O_RDONLY)'),
         'NO_CRITICAL_TRACE_ANOMALIES'),

        ('TERMINAL_KERNEL_FUTEX_FORGED', 'explicit_pass',
         lambda t,c: mutate_terminal(
             t, child, 'futex(', 'openat('),
         'NO_CRITICAL_TRACE_ANOMALIES'),

        ('NORMAL_CANARY_SPOOF', 'normal',
         lambda t,c: c['snapshots']['broker_before']
             ['canary_matches'].append({'fd':3}),
         'BROKER_CANARY_PROFILE'),

        ('NORMAL_PREEXEC_EXTRA_FD', 'normal',
         lambda t,c: insert_before_range(
             t, normal_child,
             'memfd_create("Q44_SYNTHETIC", MFD_CLOEXEC) = 14'),
         'EXACT_PREEXEC_SYSCALL_PROFILE')
    ]

    results = {}

    for name, mode, mutate, expected_failure in tests:
        altered = dict(traces)
        changed_case = copy.deepcopy(cases[mode])

        try:
            mutate(altered, changed_case)
            checks, _ = analyze(
                changed_case, evidence, altered
            )

            failed = sorted(
                k for k, v in checks.items()
                if v is not True
            )

            if expected_failure in failed:
                status = 'REJECTED_EXPECTED'
            elif failed:
                status = 'REJECTED_OTHER'
            else:
                status = 'ESCAPED'

            results[name] = {
                'case': mode,
                'status': status,
                'required_failed_check': expected_failure,
                'failed_checks': failed,
                'auditor_accepted': (
                    bool(checks)
                    and all(v is True for v in checks.values())
                )
            }

        except Exception as exc:
            status = 'INVALID_MUTATION'
            results[name] = {
                'case': mode,
                'status': status,
                'error': repr(exc)
            }

        print('MUTATION_' + name + '=', status, flush=True)

    rejected = sum(
        item['status'] == 'REJECTED_EXPECTED'
        for item in results.values()
    )

    passed = rejected == len(tests)

    verdict = (
        'Q44_P2_V2_MUTATION_SUITE_PASS'
        if passed else 'NOT_QUALIFIED'
    )

    result = {
        'schema': 'DARM-Q44-P2-V2-OFFLINE-MUTATIONS-v1',
        'verdict': verdict,
        'mutations': results,
        'total_mutations': len(tests),
        'rejected_expected': rejected,
        'auditor_sha256': SRC_SHA,
        'mutation_suite_sha256': sha(Path(__file__).resolve()),
        'real_darm_exploitation_proven': False,
        'complete_event_history_proven': False,
        'independent_kernel_witness': False,
        'synthetic_trace_changes_only': True,
        'mutations_performed_in_memory': True,
        'original_capture_modified': False
    }

    OUT.mkdir(mode=0o700, exist_ok=False)
    dest = OUT / 'mutation_report.json'

    dest.write_text(
        json.dumps(result, indent=2, sort_keys=True) + '\n'
    )

    (OUT / 'sha256.txt').write_text(
        sha(dest) + '  mutation_report.json\n'
    )

    print('Q44_P2_V2_MUTATIONS_REJECTED=',
          rejected, '/', len(tests))
    print('Q44_P2_V2_MUTATION_VERDICT=', verdict)
    print('Q44_P2_V2_MUTATION_REPORT=', dest)

    raise SystemExit(0 if passed else 2)

if __name__ == '__main__':
    main()
