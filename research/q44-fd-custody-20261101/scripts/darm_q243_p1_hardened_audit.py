import copy
import hashlib
import json
import re
import runpy
from pathlib import Path

H = Path.home()
CAP = H / 'darm-e3e1-t6-q5-q2-q4-3-p1-trace-002'
RUN = H / 'darm-e3e1-t6-q5-q2-q4-3-p1-002'
AUD = H / 'darm-e3e1-t6-q5-q2-q4-3-p1-event-audit-001'
MUT = H / 'darm-e3e1-t6-q5-q2-q4-3-p1-mutation-probe-001'
OUT = H / 'darm-e3e1-t6-q5-q2-q4-3-p1-hardened-audit-001'
V1 = H / 'darm_q243_p1_event_audit.py'
FROZEN = H / 'DARM-E3E1-T6-Q5-Q2-Q4-3-P1-002-evidence-lock-001.tar.gz'

PINS = {
    'archive': 'abdcaca19deba360d8917f53f5bb056e9f51203d95ae4d3a634111b9c8f51d4b',
    'auditor_v1': '9ceac2912825057cac103b02cb5d36b21138f0dc73b0070c300516c8290c91e6',
    'mutation_v1': '8345110053647b24107a9288bbf4c89cd9bb41156111fa783aa6fa1afa98c3f6',
}

FD_OP = re.compile(
    r'\b(open|openat|openat2|creat|dup|dup2|dup3|fcntl|'
    r'pipe|pipe2|socket|socketpair|recvmsg|sendmsg|sendmmsg|'
    r'pidfd_getfd|close|close_range|memfd_create|accept|'
    r'accept4|eventfd|eventfd2|io_uring_setup)\('
)
DUP2 = re.compile(
    r'\bdup2\((\d+)[^,\n]*,\s*(\d+)[^)\n]*\)\s+=\s+(\d+)(?:\b|<)'
)
CLOSE = re.compile(
    r'\bclose\((\d+)(?:<[^\n]*>)?\)\s+=\s+0(?:\b|<)'
)
EXEC = re.compile(r'\bexecve(?:at)?\(')
PROCESS_CREATION = re.compile(r'\b(?:fork|vfork|clone|clone3)\(')


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def checked_json(directory, filename):
    path = directory / filename
    manifest = directory / 'sha256.txt'
    assert path.is_file() and manifest.is_file(), 'MISSING_HASHED_' + filename
    assert manifest.read_text().splitlines() == [
        digest(path) + '  ' + filename
    ], 'HASH_MISMATCH_' + filename
    return json.loads(path.read_text())


def validate_child(case, evidence, traces):
    kernel = case['snapshots']['child_after']['kernel']
    child = kernel['pid']
    lines = traces[child]

    successes = [
        i for i, line in enumerate(lines)
        if EXEC.search(line)
        and re.search(r'\)\s+=\s+0(?:\b|$)', line)
    ]

    checks = {
        'ONE_SUCCESSFUL_EXEC': len(successes) == 1
    }

    if len(successes) != 1:
        return checks, {}

    pre = lines[:successes[0]]

    # Bounded to the syscall classes selected by the tracer.
    operations = [
        (i, m.group(1), line)
        for i, line in enumerate(pre)
        if (m := FD_OP.search(line))
    ]

    dup = [
        (i, DUP2.search(line), line)
        for i, op, line in operations
        if op == 'dup2'
    ]

    parsed = [
        (i, tuple(map(int, m.groups())), line)
        for i, m, line in dup
        if m
    ]

    canary_fds = [
        x['fd']
        for x in case['snapshots']['broker_before']['canary_matches']
    ]

    first_range = next(
        (i for i, op, line in operations if op == 'close_range'),
        None
    )

    checks['STRICT_PREEXEC_FD_SYSCALL_PROFILE'] = all(
        op in ('close', 'close_range', 'dup2')
        for i, op, line in operations
    )

    checks['ALL_DUP2_RECORDS_PARSED'] = (
        len(dup) == len(parsed)
    )

    checks['EXACT_STDIO_DUP2_TARGETS'] = (
        len(parsed) == 3
        and sorted(
            dest for _, (_, dest, ret), _ in parsed
        ) == [0, 1, 2]
    )

    checks['STDIO_DUP2_SUCCESS_AND_PRECEDES_CLOSURE'] = (
        first_range is not None
        and all(
            dest == ret and i < first_range
            for i, (src, dest, ret), line in parsed
        )
    )

    checks['CANARY_NOT_DUPLICATED_PREEXEC'] = all(
        src not in canary_fds
        for _, (src, dest, ret), line in parsed
    )

    checks['NO_DUP2_INTO_CLOEXEC_GAP'] = all(
        dest != case.get('_gap', -1)
        for _, (src, dest, ret), line in parsed
    )

    checks['EXPECTED_STDIO_ORIGINS'] = (
        len(parsed) == 3
        and all(
            (
                '<pipe:' in line.split(',', 1)[0]
                if dest in (0, 1)
                else '</dev/null' in line.split(',', 1)[0]
            )
            for _, (src, dest, ret), line in parsed
        )
    )

    checks['CLOSE_EVENTS_SUCCEEDED_AND_NOT_STDIO'] = all(
        CLOSE.search(line) is not None
        and int(CLOSE.search(line).group(1)) >= 3
        for _, op, line in operations
        if op == 'close'
    )

    checks['NO_PREEXEC_NESTED_PROCESS_SPAWN'] = not any(
        PROCESS_CREATION.search(line)
        for line in pre
    )

    checks['ONE_EXEC_SYSCALL_TOTAL'] = (
        sum(EXEC.search(line) is not None for line in lines) == 1
    )

    details = {
        'child': child,
        'canary_fds': canary_fds,
        'dup2': [
            {
                'source': src,
                'destination': dest,
                'result': ret
            }
            for _, (src, dest, ret), _ in parsed
        ],
        'preexec_fd_ops': [
            op for _, op, _ in operations
        ]
    }

    return checks, details


def insert_one(traces, pid, needle, event):
    lines = traces[pid]

    indexes = [
        i for i, line in enumerate(lines)
        if needle in line
    ]

    if len(indexes) != 1:
        raise ValueError(
            'BAD_MUTATION_ANCHOR:' + needle
            + ':' + str(len(indexes))
        )

    lines.insert(indexes[0], event)


def run():
    if OUT.exists() or OUT.is_symlink():
        raise SystemExit('REFUSE_EXISTING_AUDIT')

    print('=== VERIFY FROZEN SOURCES ===')

    sources = [
        (FROZEN, PINS['archive'], 'ARCHIVE'),
        (V1, PINS['auditor_v1'], 'FROZEN_V1_AUDITOR'),
        (
            H / 'darm_q243_p1_mutation_probe.py',
            PINS['mutation_v1'],
            'MUTATION_PROBE'
        )
    ]

    for file, expected, label in sources:
        assert file.is_file() and digest(file) == expected, (
            label + '_PIN_FAIL'
        )
        print(label + '_PIN=PASS')

    recorded = checked_json(AUD, 'audit.json')
    original_mutation = checked_json(
        MUT, 'mutation_report.json'
    )

    assert (
        recorded['verdict']
        == 'Q43_P1_002_EXEC_BOUNDARY_TRACE_CORROBORATED'
        and len(recorded['checks']) == 33
        and all(recorded['checks'].values())
    ), 'BAD_PREVIOUS_AUDIT'

    assert (
        original_mutation['verdict']
        == 'AUDITOR_COVERAGE_GAP_REPRODUCED'
    ), 'BAD_NEGATIVE_RESULT'

    original_results = original_mutation['results']

    prior_controls = (
        'CLOSE_RANGE_FAILURE',
        'FORGED_KERNEL_EXEC',
        'BROKEN_VFORK_ANCESTRY',
        'ORPHAN_SPAWNING_THREAD',
        'REMOVE_CLOEXEC_FLAG',
        'PARENT_PIPE_CLOSE_FAILURE'
    )

    prior_escapes = (
        'SYNTHETIC_CANARY_TO_STDERR',
        'SYNTHETIC_CANARY_TO_GAP_FD'
    )

    original_controls_rejected = (
        set(original_results) == set(prior_controls + prior_escapes)
        and all(
            original_results[n]['auditor_accepted'] is False
            for n in prior_controls
        )
        and all(
            original_results[n]['auditor_accepted'] is True
            for n in prior_escapes
        )
    )

    assert original_controls_rejected, 'BAD_PREVIOUS_MUTATION_FINDINGS'

    evidence = checked_json(RUN, 'evidence.json')

    assert (
        evidence['verdict']
        == 'REAL_KERNEL_CHILD_FD_CUSTODY_P0_OBSERVED'
    ), 'BAD_REAL_SESSION_VERDICT'

    summary = json.loads(
        (CAP / 'capture_summary.json').read_text()
    )

    assert (
        summary['verdict']
        == 'P1_002_TRACE_CAPTURE_RECORDED_PENDING_EVENT_AUDIT'
    ), 'BAD_TRACE_CAPTURE'

    old = runpy.run_path(
        str(V1),
        run_name='__supplementary_audit_import__'
    )

    analyze = old['analyze_case']
    traces = old['traces_by_tid']()

    cases = evidence['cases']

    assert (
        len(cases) == 2
        and [c['mode'] for c in cases]
        == ['normal', 'explicit_pass']
    ), 'BAD_CASE_STRUCTURE'

    print('=== HARDENED REAL-TRACE REPLAY ===')

    outcomes = {}

    for case in cases:
        base, info = analyze(case, evidence, traces)

        assert all(
            v is True for v in base.values()
        ), 'ORIGINAL_CASE_NOT_QUALIFIED:' + case['mode']

        fixed_case = {
            **case,
            '_gap': info['cloexec_exception_fd']
        }

        controls, detail = validate_child(
            fixed_case, evidence, traces
        )

        outcomes[case['mode']] = {
            'checks': controls,
            'detail': detail
        }

        print(
            'V2_' + case['mode'].upper() + '_CHECKS=',
            json.dumps(controls, sort_keys=True)
        )

    positive_pass = all(
        all(x['checks'].values())
        for x in outcomes.values()
    )

    print(
        'V2_BASELINE=',
        'PASS' if positive_pass else 'NOT_QUALIFIED'
    )

    print('=== ADVERSARIAL MUTATION REPLAY ===')

    target = next(
        c for c in cases
        if c['mode'] == 'explicit_pass'
    )

    _, info = analyze(target, evidence, traces)

    child = info['kernel_pid']
    gap = info['cloexec_exception_fd']

    def inject(traces_copy, event):
        insert_one(
            traces_copy,
            child,
            'close_range(3,',
            '1793483204.233700 ' + event
        )

    mutations = [
        (
            'CANARY_TO_STDERR',
            'dup2(3</tmp/DARM_SYNTHETIC_CANARY>, '
            '2</dev/null>) = 2</tmp/DARM_SYNTHETIC_CANARY>'
        ),
        (
            'CANARY_TO_GAP',
            f'dup2(3</tmp/DARM_SYNTHETIC_CANARY>, '
            f'{gap}<pipe:[synthetic]>) = '
            f'{gap}</tmp/DARM_SYNTHETIC_CANARY>'
        ),
        (
            'CANARY_TO_STDOUT',
            'dup2(3</tmp/DARM_SYNTHETIC_CANARY>, '
            '1<pipe:[synthetic]>) = 1</tmp/DARM_SYNTHETIC_CANARY>'
        ),
        (
            'CANARY_TO_STDIN',
            'dup2(3</tmp/DARM_SYNTHETIC_CANARY>, '
            '0<pipe:[synthetic]>) = 0</tmp/DARM_SYNTHETIC_CANARY>'
        ),
        (
            'DUP3_TO_STDERR',
            'dup3(3</tmp/DARM_SYNTHETIC_CANARY>, '
            '2</dev/null>, 0) = 2</tmp/DARM_SYNTHETIC_CANARY>'
        ),
        (
            'GAP_CLOEXEC_CLEARED',
            f'fcntl({gap}<pipe:[synthetic]>, F_SETFD, 0) = 0'
        ),
        (
            'UNEXPECTED_OPENAT',
            'openat(AT_FDCWD, "/tmp/DARM_SYNTHETIC_CANARY", '
            'O_RDONLY) = 14</tmp/DARM_SYNTHETIC_CANARY>'
        ),
        (
            'SCM_RIGHTS_RECEIVE',
            'recvmsg(5<socket:[synthetic]>, '
            '{msg_control=[{cmsg_level=SOL_SOCKET, '
            'cmsg_type=SCM_RIGHTS, cmsg_data=[14]}]}, 0) = 1'
        )
    ]

    mutation_results = {}

    for name, event in mutations:
        altered = copy.deepcopy(traces)
        inject(altered, event)

        previous_checks, _ = analyze(
            target, evidence, altered
        )

        v1_accept = (
            bool(previous_checks)
            and all(previous_checks.values())
        )

        strict_case = {
            **target,
            '_gap': gap
        }

        v2_checks, _ = validate_child(
            strict_case, evidence, altered
        )

        v2_accept = (
            v1_accept
            and all(v2_checks.values())
        )

        mutation_results[name] = {
            'v1_accepted': v1_accept,
            'v2_accepted': v2_accept,
            'v2_failed': sorted(
                k for k, value in v2_checks.items()
                if value is not True
            )
        }

        print(
            'MUTATION_' + name + '=',
            'ESCAPED' if v2_accept else 'REJECTED'
        )

    negative_pass = all(
        not m['v2_accepted']
        for m in mutation_results.values()
    )

    regression_pass = (
        mutation_results['CANARY_TO_STDERR']['v1_accepted']
        and mutation_results['CANARY_TO_GAP']['v1_accepted']
    )

    rejected = sum(
        not m['v2_accepted']
        for m in mutation_results.values()
    )

    print(
        'V2_MUTATION_REJECTED=',
        rejected, '/', len(mutation_results)
    )

    print('V1_GAP_REPRODUCED=', regression_pass)

    verdict = (
        'Q43_P1_002_SUPPLEMENTAL_FD_FLOW_AUDIT_PASS'
        if positive_pass and negative_pass and regression_pass
        else 'NOT_QUALIFIED'
    )

    report = {
        'verdict': verdict,
        'checks': {
            'BASELINE_BOTH_SESSIONS': positive_pass,
            'ALL_EIGHT_NEW_MUTATIONS_REJECTED': negative_pass,
            'ORIGINAL_TWO_ESCAPES_REPRODUCED': regression_pass,
            'ORIGINAL_SIX_CONTROLS_REJECTED':
                original_controls_rejected
        },
        'positive': outcomes,
        'mutations': mutation_results,
        'auditor_v1_sha256': PINS['auditor_v1'],
        'frozen_archive_sha256': PINS['archive'],
        'source_sha256': digest(Path(__file__).resolve()),
        'scope': {
            'actual_darm_exploit': False,
            'mutations_synthetic': True,
            'whitelisted_fd_syscall_profile': True,
            'all_syscalls_observed': False,
            'preexec_child_never_inherited_canary': False,
            'all_processes_and_launchers_qualified': False,
            'no_product_changes': True
        }
    }

    OUT.mkdir(mode=0o700, exist_ok=False)

    path = OUT / 'audit.json'
    path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + '\n'
    )

    (OUT / 'sha256.txt').write_text(
        digest(path) + '  audit.json\n'
    )

    print('Q43_P1_V2_VERDICT=', verdict)
    print('Q43_P1_V2_REPORT=', path)

    return 0 if verdict.endswith('_PASS') else 2


if __name__ == '__main__':
    raise SystemExit(run())
