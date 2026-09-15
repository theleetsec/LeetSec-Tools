#!/usr/bin/env python3
"""Optional installed-tool compatibility check; DNS traffic stays on loopback."""
import ipaddress
import json
import os
import shutil
import tempfile
from pathlib import Path
import socket
import struct
import subprocess
import threading

puredns_bin = shutil.which('puredns')
dnsx_bin = shutil.which('dnsx')
assert puredns_bin and dnsx_bin and shutil.which('massdns'), 'Install puredns, massdns and dnsx before this optional check'
out = Path(os.environ.get('LEETENUM_TEST_OUTPUT_DIR') or tempfile.mkdtemp(prefix='leetenum-local-dns-'))
out.mkdir(exist_ok=True)
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(('127.0.0.1', 0))
port = server.getsockname()[1]
server.settimeout(0.2)
stop = threading.Event()
recover = threading.Event()
queries = []
def serve():
    while not stop.is_set():
        try:
            data, address = server.recvfrom(4096)
        except socket.timeout:
            continue
        cursor = 12
        labels = []
        while data[cursor]:
            length = data[cursor]
            labels.append(data[cursor+1:cursor+1+length].decode('ascii').lower())
            cursor += length+1
        cursor += 1
        name = '.'.join(labels)
        kind = struct.unpack('!H', data[cursor:cursor+2])[0]
        question = data[12:cursor+4]
        queries.append((name, kind))
        value = None
        if kind == 1 and name in ('address.example.invalid', '_service.example.invalid'):
            value = ipaddress.ip_address('192.0.2.8').packed
        if kind == 1 and name == 'miss.example.invalid' and recover.is_set():
            value = ipaddress.ip_address('192.0.2.10').packed
        if kind == 28 and name == 'ipv6.example.invalid':
            value = ipaddress.ip_address('2001:db8::8').packed
        response = data[:2] + struct.pack('!HHHHH', 0x8180, 1, int(value is not None), 0, 0) + question
        if value is not None:
            response += b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, 60, len(value)) + value
        server.sendto(response, address)
thread = threading.Thread(target=serve, daemon=True)
thread.start()
names = {'address.example.invalid', '_service.example.invalid', 'ipv6.example.invalid', 'miss.example.invalid'}
inp = out / 'candidates.txt'
inp.write_text(''.join(h+'\n' for h in sorted(names)))
resolvers = out / 'resolvers.txt'
resolvers.write_text(f'127.0.0.1:{port}\n')
def run(label, command):
    completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    (out / (label+'.log')).write_bytes(completed.stdout)
    assert completed.returncode == 0, (label, completed.returncode, completed.stdout[-1000:])
def read_names(path):
    return set(path.read_text().splitlines())
try:
    old = out / 'old-bulk.txt'
    common = [puredns_bin, 'resolve', str(inp), '-r', str(resolvers), '--rate-limit', '100', '--skip-wildcard-filter', '--skip-validation']
    run('old-bulk', common+['-w', str(old)])
    old_set = read_names(old)
    assert old_set == {'address.example.invalid'}, old_set
    new = out / 'new-bulk.txt'
    run('new-bulk', common+['--skip-sanitize', '-w', str(new)])
    new_set = read_names(new)
    assert new_set == {'address.example.invalid', '_service.example.invalid'}, new_set
    missed = out / 'missed.txt'
    missed.write_text(''.join(h+'\n' for h in sorted(names-new_set)))
    recover.set()
    recovered = out / 'recovered.txt'
    run('recovery', [dnsx_bin, '-l', str(missed), '-r', f'127.0.0.1:{port}', '-a', '-aaaa', '-silent', '-no-color', '-disable-update-check', '-threads', '2', '-rate-limit', '5', '-retry', '3', '-o', str(recovered)])
    recovered_set = read_names(recovered)
    assert new_set | recovered_set == names, (new_set, recovered_set)
    (out / 'queries.json').write_text(json.dumps(queries, indent=2)+'\n')
    assert all(kind == 0 or h in names for h, kind in queries), queries
    summary = {'result':'PASS', 'server':'loopback only', 'candidate_count':len(names), 'old_bulk_accepted':len(old_set), 'new_bulk_accepted':len(new_set), 'independently_recovered':len(recovered_set), 'final_accepted':len(new_set|recovered_set), 'checks':['real puredns default sanitization omits underscore service labels', 'real bulk resolver uses A lookups and misses AAAA-only records', 'real dnsx A/AAAA recovery repairs omissions and simulated transient first-pass loss'], 'queries':queries}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k!='queries'}), flush=True)
finally:
    stop.set()
    thread.join(1)
    server.close()
