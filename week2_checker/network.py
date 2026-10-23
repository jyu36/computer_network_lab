#!/usr/bin/env python3
"""Linux/Mininet integration checker. Each case gets a fresh controller + switch."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent
STAGES = ['base', 'blocklist', 'movement', 'runtime']
HOSTS = ['h1', 'h2', 'h3']


def mac(host):
    return '00:00:00:00:00:%02x' % int(host[1:])


def load_cases(path, stage):
    cases = json.loads(Path(path).read_text())
    if len({c['id'] for c in cases}) != len(cases):
        raise ValueError('Duplicate case IDs')
    return [c for c in cases if STAGES.index(c['stage']) <= STAGES.index(stage)]


def wait_until(fn, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = fn()
        if value:
            return value
        time.sleep(0.05)
    raise TimeoutError('Readiness/observation deadline exceeded')


def run(command, check=True):
    return subprocess.run(command, capture_output=True, text=True, timeout=15, check=check).stdout


def stop(process):
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


class Lab:
    def __init__(self, args, case, directory):
        self.args, self.case, self.directory = args, case, directory
        self.net = self.controller = None
        self.tag = 100
        self.events = []
        self.captures = []
        self.log = None

    def request(self, method, path, data=None, expected=200):
        body = None if data is None else json.dumps(data).encode()
        req = urllib.request.Request('http://127.0.0.1:%d/rain/%s' % (self.args.api_port, path),
            data=body, method=method, headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=6) as response:
                status, raw = response.status, response.read()
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read()
        self.events.append({'method': method, 'path': path, 'body': data,
                            'status': status, 'response': raw.decode(errors='replace')})
        assert status == expected, '%s %s returned %s, expected %s' % (method, path, status, expected)
        return json.loads(raw) if raw else None

    def sync(self):
        if self.args.stock_base:
            return  # Base observations use packet/flow evidence; no invented API acknowledgement.
        result = self.request('POST', 'sync')
        assert result.get('complete') is True, result

    def status(self):
        result = self.request('GET', 'status')
        assert not result.get('errors'), result
        return result

    def start(self):
        from mininet.net import Mininet
        from mininet.node import OVSSwitch, RemoteController
        env = os.environ.copy()
        initially_blocked = ([mac(self.case['blocked'])]
                             if self.case['scenario'] in {'static', 'static_unknown', 'move_block'} else [])
        if 'initial_blocked' in self.case:
            initially_blocked = [mac(n) for n in self.case['initial_blocked']]
        env.update(RAIN_BLOCKED=json.dumps(initially_blocked))
        env.pop('RAIN_BUG', None)
        self.log = (self.directory / 'controller.log').open('w')
        command = [self.args.ryu_manager, '--ofp-listen-host', '127.0.0.1',
                   '--ofp-tcp-listen-port', str(self.args.of_port),
                   '--wsapi-host', '127.0.0.1', '--wsapi-port', str(self.args.api_port),
                   str(Path(self.args.controller).resolve())]
        (self.directory / 'launch.json').write_text(json.dumps({'command': command,
            'RAIN_BLOCKED': initially_blocked}, indent=2))
        self.controller = subprocess.Popen(command, env=env, stdout=self.log, stderr=subprocess.STDOUT)

        def api_up():
            if self.controller.poll() is not None:
                raise RuntimeError('Controller exited; inspect controller.log')
            try:
                return self.request('GET', 'status')
            except (OSError, TimeoutError):
                return False
        if not self.args.stock_base:
            wait_until(api_up, 15)
        self.net = Mininet(controller=None, switch=OVSSwitch, build=False)
        self.net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=self.args.of_port)
        switch = self.net.addSwitch('s1', protocols='OpenFlow13', failMode='secure', dpid='0000000000000001')
        for i, name in enumerate(HOSTS, 1):
            host = self.net.addHost(name, ip='10.0.0.%s/24' % i, mac=mac(name))
            self.net.addLink(host, switch, port2=i)
        self.net.build()
        for host in self.net.hosts:
            host.cmd('sysctl -qw net.ipv6.conf.all.disable_ipv6=1')
            host.cmd('sysctl -qw net.ipv6.conf.default.disable_ipv6=1')
        self.net.start()
        if self.args.stock_base:
            def connected():
                if self.controller.poll() is not None:
                    raise RuntimeError('Controller exited; inspect controller.log')
                flows = run(['ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', 's1'])
                return 'CONTROLLER' in flows and 'priority=0' in flows
            wait_until(connected, 15)
        else:
            wait_until(lambda: self.status().get('switches') == [1])
        self.sync()
        self.snapshot('initial')

    def snapshot(self, label):
        # Save switch evidence even if the controller API has stopped responding.
        for suffix, command in [('flows', ['ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', 's1']),
                                ('ports', ['ovs-ofctl', '-O', 'OpenFlow13', 'show', 's1'])]:
            try:
                text = run(command, check=False)
            except Exception as exc:
                text = repr(exc)
            (self.directory / (label + '.' + suffix + '.txt')).write_text(text)
        if self.args.stock_base:
            return
        try:
            (self.directory / (label + '.status.json')).write_text(json.dumps(self.status(), indent=2))
        except Exception as exc:
            (self.directory / (label + '.api-error.txt')).write_text(repr(exc))

    def send(self, source, destination, kind='icmp', count=3):
        host = self.net.get(source)
        command = ['python3', str(ROOT / 'probe.py'), '--interface', str(host.defaultIntf()),
            '--src-mac', mac(source), '--dst-mac', mac(destination),
            '--src-ip', host.IP(), '--dst-ip', self.net.get(destination).IP(),
            '--tag', str(self.tag), '--kind', kind, '--count', str(count)]
        process = host.popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate(timeout=5)
        if process.returncode:
            raise RuntimeError('Probe failed: %s %s' % (out, err))

    def learn(self, names=HOSTS):
        for name in names:
            self.send(name, 'h1' if name != 'h1' else 'h2', kind='arp')
        if not self.args.stock_base:
            wait_until(lambda: all(mac(n) in self.status().get('learned', {}).get('1', {}) for n in names))
        self.sync()

    def observe(self, source, destination, receivers, allowed=True, count=3):
        self.tag += 1
        sniffers = []
        try:
            for receiver in receivers:
                host = self.net.get(receiver)
                stem = '%03d_%s_to_%s_at_%s' % (self.tag, source, destination, receiver)
                pcap, log = self.directory / (stem + '.pcap'), self.directory / (stem + '.tcpdump.log')
                capture_log = log.open('w')
                filt = 'icmp and icmp[0] = 8 and icmp[4:2] = %d and ether dst %s' % (self.tag, mac(destination))
                process = host.popen(['tcpdump', '-U', '-n', '-i', str(host.defaultIntf()),
                                     '-w', str(pcap), filt], stdout=subprocess.DEVNULL, stderr=capture_log)
                sniffers.append((process, capture_log, pcap, log, receiver))
                self.captures.append(process)

                def listening():
                    if process.poll() is not None:
                        raise RuntimeError('tcpdump exited: ' + log.read_text())
                    return 'listening on' in log.read_text()
                wait_until(listening, 4)
            self.send(source, destination, count=count)
            time.sleep(self.args.observe_seconds)  # Observation bound, not update synchronization.
        finally:
            for process, handle, *_ in sniffers:
                stop(process)
                handle.close()
        for process, _, pcap, log, receiver in sniffers:
            if process.returncode not in (0, -signal.SIGINT):
                raise RuntimeError('Capture process failed: ' + log.read_text())
            dropped = re.search(r'(?m)^(\d+) packets dropped by kernel\s*$', log.read_text())
            if not dropped or int(dropped.group(1)) != 0:
                raise RuntimeError('Unreliable capture: ' + log.read_text())
            decoded = run(['tcpdump', '-nn', '-r', str(pcap)])
            pcap.with_suffix('.packets.txt').write_text(decoded)
            received = len(decoded.splitlines())
            expected_delivery = allowed[receiver] if isinstance(allowed, dict) else allowed
            self.events.append({'source': source, 'destination': destination, 'receiver': receiver,
                                'sent': count, 'received': received, 'allowed': expected_delivery})
            assert received == (count if expected_delivery else 0), (
                '%s -> %s at %s: expected %s packets, observed %s; see %s' %
                (source, destination, receiver, count if expected_delivery else 0, received, pcap.name))

    def delivery(self, source, destination, allowed=True):
        self.observe(source, destination, [destination], allowed)

    def cached(self, source, destination):
        self.delivery(source, destination)
        self.sync()
        flows = run(['ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', 's1'])
        port = int(source[1:])
        matches = [line for line in flows.splitlines() if 'dl_dst=' + mac(destination) in line
                   and ('in_port=' not in line or 'in_port=%d,' % port in line)
                   and re.search(r'actions=(?:output:)?%d(?:,|$)' % int(destination[1:]), line)]
        assert matches, 'Required cached forwarding rule absent: ' + flows
        self.snapshot('cached_%s_%s' % (source, destination))

    def policy(self, blocked):
        result = self.request('PUT', 'policy', {'blocked': [mac(n) for n in blocked]})
        assert result.get('complete') is True, 'Policy response must acknowledge BarrierReply'

    def move(self, name):
        # Change only the OVS ingress/output port number; host interface, MAC and IP stay fixed.
        interface = 's1-eth' + name[1:]
        run(['ovs-vsctl', 'set', 'Interface', interface, 'ofport_request=4'])
        wait_until(lambda: run(['ovs-vsctl', 'get', 'Interface', interface, 'ofport']).strip() == '4')
        # The controller must actually observe the new source location first.
        self.send(name, 'h1', kind='arp')
        try:
            wait_until(lambda: self.status().get('learned', {}).get('1', {}).get(mac(name)) == 4)
        except TimeoutError as exc:
            raise AssertionError('Moved source was not learned on port 4') from exc
        self.sync()
        self.snapshot('after_move')
        flows = run(['ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', 's1'])
        stale = [line for line in flows.splitlines() if 'dl_dst=' + mac(name) in line
                 and 'actions=output:' + name[1:] in line]
        assert not stale, 'Stale destination rules survived move: ' + '\n'.join(stale)

    def exercise(self):
        scenario = self.case['scenario']
        if scenario == 'trace':
            for step in self.case['steps']:
                operation = step['op']
                if operation == 'learn':
                    self.learn()
                elif operation == 'cache':
                    self.cached(step['source'], step['destination'])
                elif operation == 'observe':
                    self.observe(step['source'], step['destination'], list(step['expect']), step['expect'])
                elif operation == 'move':
                    self.move(step['host'])
                elif operation == 'policy':
                    self.policy(step['blocked'])
                else:
                    raise ValueError('Unknown trace operation: ' + operation)
        elif scenario == 'unknown':
            if not self.args.stock_base:
                assert self.status()['learned']['1'] == {}, 'Fresh controller was not empty'
            self.observe('h1', 'h2', ['h2', 'h3'], count=1)
        elif scenario == 'ping':
            loss = self.net.pingAll(timeout='1')
            self.events.append({'pingall_loss_percent': loss})
            assert loss == 0, 'ARP/ICMP pingall loss: %s%%' % loss
        elif scenario == 'static_unknown':
            self.delivery('h1', self.case['blocked'], False)
            other = next(n for n in ['h2', 'h3'] if n != self.case['blocked'])
            self.delivery('h1', other)
        else:
            self.learn()
            if scenario == 'known':
                for source in HOSTS:
                    for destination in HOSTS:
                        if source == destination:
                            continue
                        other = next(n for n in HOSTS if n not in {source, destination})
                        self.cached(source, destination)
                        self.observe(source, destination, [destination, other],
                                     {destination: True, other: False})
            elif scenario == 'static':
                blocked = self.case['blocked']
                other = next(n for n in ['h2', 'h3'] if n != blocked)
                self.delivery('h1', other)  # Live allowed path, even under policy.
                self.delivery('h1', blocked, False)
                self.delivery(blocked, 'h1')  # Source is allowed: destination-only policy.
            elif scenario in {'move', 'move_block'}:
                moved = self.case['moved']
                self.cached('h1', moved)
                self.move(moved)
                self.delivery('h1', moved)
                self.delivery(moved, 'h1')
                if scenario == 'move_block':
                    self.delivery('h1', self.case['blocked'], False)
            elif scenario == 'runtime':
                blocked = self.case['blocked']
                other = next(n for n in ['h2', 'h3'] if n != blocked)
                self.cached('h1', blocked)
                self.policy([blocked])
                self.snapshot('after_block')
                self.delivery('h1', other)
                self.delivery('h1', blocked, False)  # Existing cached path.
                self.delivery(other, blocked, False)  # New ingress/destination pair.
                self.delivery(blocked, 'h1')
                self.policy([])
                self.delivery('h1', blocked)
                # Repeat to expose stale state across successive updates.
                self.policy([blocked])
                self.delivery('h1', blocked, False)
                self.policy([])
                self.delivery('h1', blocked)
            elif scenario == 'invalid':
                self.policy(['h2'])
                before = self.status()['blocked']
                for body in [{'blocked': ['invalid']}, {'blocked': 'not-a-list'}, {},
                             {'blocked': [12]}, {'blocked': [], 'extra': True}, [], None]:
                    self.request('PUT', 'policy', body, expected=400)
                    assert self.status()['blocked'] == before, 'Invalid input mutated policy'
                self.delivery('h1', 'h2', False)
                self.delivery('h1', 'h3')
            else:
                raise ValueError('Unknown scenario: ' + scenario)
        self.sync()

    def close(self):
        for process in self.captures:
            stop(process)
        try:
            if self.net is not None:
                self.snapshot('final')
                self.net.stop()
        finally:
            if self.controller is not None:
                stop(self.controller)
            if self.log is not None:
                self.log.close()
            (self.directory / 'events.json').write_text(json.dumps(self.events, indent=2))


def preflight(args):
    if platform.system() != 'Linux' or os.geteuid() != 0:
        raise RuntimeError('Run in your Ubuntu Mininet VM as root; see README.md')
    for tool in ['ovs-vsctl', 'ovs-ofctl', 'tcpdump', 'python3']:
        if not shutil.which(tool):
            raise RuntimeError('Missing command: ' + tool)
    if not shutil.which(args.ryu_manager):
        raise RuntimeError('Provide --ryu-manager /absolute/path/to/venv/bin/ryu-manager')
    if not Path(args.controller).is_file():
        raise RuntimeError('Controller file not found')
    bridges = run(['ovs-vsctl', 'list-br']).splitlines()
    if 's1' in bridges:
        raise RuntimeError('s1 already exists. Exit your manual Mininet session before testing.')
    for port in ([args.of_port] if args.stock_base else [args.of_port, args.api_port]):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', port))
    import mininet.net  # noqa: F401


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', choices=STAGES, default='base')
    parser.add_argument('--controller', required=True, help='Path to the actual controller source')
    parser.add_argument('--stock-base', action='store_true', help='Base tests without the custom HTTP API')
    parser.add_argument('--ryu-manager', default=shutil.which('ryu-manager') or 'ryu-manager')
    parser.add_argument('--cases', default=str(ROOT / 'cases.json'))
    parser.add_argument('--case', help='Run one case by exact ID')
    parser.add_argument('--of-port', type=int, default=6653)
    parser.add_argument('--api-port', type=int, default=8080)
    parser.add_argument('--output', default=str(ROOT / 'results'))
    parser.add_argument('--observe-seconds', type=float, default=1.0)
    parser.add_argument('--list', action='store_true')
    args = parser.parse_args()
    if not 0 < args.observe_seconds <= 60:
        parser.error('--observe-seconds must be in (0, 60]')
    if args.stock_base and args.stage != 'base':
        parser.error('--stock-base only supports --stage base; later stages need the agreed update interface')
    if not __debug__:
        parser.error('Assertions are required: do not use python -O or PYTHONOPTIMIZE')
    cases = load_cases(args.cases, args.stage)
    if args.case:
        cases = [c for c in cases if c['id'] == args.case]
    if not cases:
        parser.error('No matching cases; check --stage and --case')
    if args.list:
        print(json.dumps(cases, indent=2))
        return 0
    preflight(args)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    directory = Path(args.output).resolve() / (stamp + '_' + Path(args.controller).stem)
    directory.mkdir(parents=True)
    environment = {'platform': platform.platform(), 'python': sys.version, 'arguments': vars(args)}
    source = Path(args.controller).read_bytes()
    environment['controller_sha256'] = hashlib.sha256(source).hexdigest()
    (directory / 'controller_source.py').write_bytes(source)
    for name, command in [('ovs', ['ovs-vsctl', '--version']), ('tcpdump', ['tcpdump', '--version']),
                          ('mininet', ['mn', '--version']), ('ryu', [args.ryu_manager, '--version'])]:
        try:
            environment[name] = run(command, check=False)
        except Exception as exc:
            environment[name] = repr(exc)
    (directory / 'environment.json').write_text(json.dumps(environment, indent=2))
    results = []
    for case in cases:
        case_dir = directory / case['id']
        case_dir.mkdir()
        lab = Lab(args, case, case_dir)
        result = {'id': case['id'], 'status': 'PASS'}
        try:
            lab.start()
            lab.exercise()
        except AssertionError as exc:
            result.update(status='FAIL', error=str(exc), traceback=traceback.format_exc())
        except Exception as exc:
            result.update(status='ERROR', error=str(exc), traceback=traceback.format_exc())
        finally:
            try:
                lab.close()
            except Exception as exc:
                result.update(status='ERROR', cleanup_error=repr(exc))
        (case_dir / 'result.json').write_text(json.dumps(result, indent=2))
        results.append(result)
        print('%s %s %s' % (result['status'], case['id'], result.get('error', '')), flush=True)
    (directory / 'summary.json').write_text(json.dumps(results, indent=2))
    print('Evidence:', directory)
    return 0 if all(r['status'] == 'PASS' for r in results) else 1


if __name__ == '__main__':
    sys.exit(main())
