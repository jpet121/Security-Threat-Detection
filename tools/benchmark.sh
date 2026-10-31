#!/usr/bin/env bash
# Run from the repository root with the auditor virtualenv activated.
set -euo pipefail
python - <<'PY'
import json, os, platform, subprocess, sys, tempfile, time
from pathlib import Path
dense = os.environ.get('AUDITOR_BENCH_DENSE') == '1'
results=[]
with tempfile.TemporaryDirectory(prefix='auditor-bench-') as temporary:
    base=Path(temporary)
    for count in ((400,1600,6400) if dense else (20000,200000)):
        logs=base/str(count); logs.mkdir()
        for host in range(40):
            with (logs/f'host-{host}.log').open('w') as f:
                for i in range(count//40):
                    if dense or i % 100 == 0:
                        f.write(f'2026-10-17T02:03:04Z edge-{host} sshd[12]: Failed password for user{host} from 198.51.100.{host+1} port 55522 ssh2\n')
                    else:
                        f.write('198.51.100.5 - - [17/Oct/2026:02:05:00 +0000] "GET /search?q=hello%3Bworld HTTP/1.1" 200 45\n')
        metrics=base/f'time-{count}.json'
        output=base/f'out-{count}'
        measure = 'import sys,time,resource,json; from pathlib import Path; from security_log_auditor.cli import main; start=time.perf_counter(); code=main(sys.argv[2:]); r=resource.getrusage(resource.RUSAGE_SELF); Path(sys.argv[1]).write_text(json.dumps(dict(elapsed_seconds=time.perf_counter()-start,peak_rss_kib=r.ru_maxrss,user_seconds=r.ru_utime,system_seconds=r.ru_stime))); sys.exit(code)'
        cmd=[sys.executable,'-c',measure,str(metrics),'--input',str(logs),'--output',str(output)]
        result=subprocess.run(cmd,capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError(f'benchmark failed with code {result.returncode}: {result.stderr}')
        manifest=json.loads((output/'manifest.json').read_text())
        assert manifest['records_examined']==count and manifest['unique_matched_events']==(count if dense else count//100)
        results.append(json.loads(metrics.read_text()) | {'records':count,'input_bytes':sum(p.stat().st_size for p in logs.iterdir()),'hosts':40,'matched_events':manifest['unique_matched_events'],'run_state':manifest['run_state']})
report={'kind':'dense_authentication_windows' if dense else 'synthetic_scaling_not_customer_weekend_acceptance','python':platform.python_version(),'platform':platform.platform(),'cpu_count':os.cpu_count(),'runs':results,'limitations':['Synthetic data and current container, not a client busy-weekend corpus or a standard independently specified investigation host.','No customer throughput or memory target was provided.']}
Path('evidence').mkdir(exist_ok=True)
Path('evidence/dense-benchmark.json' if dense else 'evidence/benchmark.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
PY
