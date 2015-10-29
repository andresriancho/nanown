#-*- mode: Python;-*-

import sys
import time
import socket
import subprocess
import tempfile

import netifaces


def getLocalIP(remote_host, remote_port):
    connection = socket.create_connection((remote_host, remote_port))
    ret_val = connection.getsockname()[0]
    connection.close()

    return ret_val


def getIfaceForIP(ip):
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, None)
        if addrs:
            for a in addrs:
                if a.get('addr', None) == ip:
                    return iface


class snifferProcess(object):
    my_ip = None
    my_iface = None
    target_ip = None
    target_port = None
    _proc = None
    _spool = None

    def __init__(self, target_ip, target_port):
        self.target_ip = target_ip
        self.target_port = target_port
        self.my_ip = getLocalIP(target_ip, target_port)
        self.my_iface = getIfaceForIP(self.my_ip)
        print(self.my_ip, self.my_iface)

    def start(self):
        self._spool = tempfile.NamedTemporaryFile('w+t')
        self._proc = subprocess.Popen(['chrt', '-r', '99', 'nanown-listen',
                                       self.my_iface, self.my_ip,
                                       self.target_ip, "%d" % self.target_port,
                                       self._spool.name, '0'])
        time.sleep(0.25)

    def openPacketLog(self):
        return open(self._spool.name, 'rt')

    def stop(self):
        if self._proc:
            self._proc.terminate()
            self._proc.wait(2)
            if self._proc.poll() is None:
                self._proc.kill()
                self._proc.wait(1)
            self._proc = None

    def is_running(self):
        return self._proc.poll() is None

    def __del__(self):
        self.stop()


def startSniffer(target_ip, target_port, output_file):
    my_ip = getLocalIP(target_ip, target_port)
    my_iface = getIfaceForIP(my_ip)
    return subprocess.Popen(
        ['chrt', '-r', '99', 'nanown-listen', my_iface, my_ip,
                             target_ip, "%d" % target_port, output_file, '0'])


def stopSniffer(sniffer):
    sniffer.terminate()
    sniffer.wait(2)
    if sniffer.poll() is None:
        sniffer.kill()
        sniffer.wait(1)


def removeDuplicatePackets(packets):
    # return packets
    suspect = ''
    seen = {}
    # XXX: Need to review this deduplication algorithm and make sure it is
    # correct
    for p in packets:
        key = (p['sent'], p['tcpseq'], p['tcpack'], p['payload_len'])
        if key not in seen:
            seen[key] = p
            continue
        if p['sent'] == 1 and (seen[key]['observed'] > p['observed']):  # earliest sent
            seen[key] = p
            suspect += 's'  # duplicated sent packets
            continue
        if p['sent'] == 0 and (seen[key]['observed'] > p['observed']):  # earliest rcvd
            seen[key] = p
            suspect += 'r'  # duplicated received packets
            continue

    # if len(seen) < len(packets):
    # sys.stderr.write("INFO: removed %d duplicate packets.\n" % (len(packets)
    # - len(seen)))

    return suspect, seen.values()


def analyzePackets(packets, timestamp_precision, trim_sent=0, trim_rcvd=0):
    suspect, packets = removeDuplicatePackets(packets)

    sort_key = lambda d: (d['observed'], d['tcpseq'])
    alt_key = lambda d: (d['tcpseq'], d['observed'])
    sent = sorted(
        (p for p in packets if p['sent'] == 1 and p['payload_len'] > 0), key=sort_key)
    rcvd = sorted(
        (p for p in packets if p['sent'] == 0 and p['payload_len'] > 0), key=sort_key)
    rcvd_alt = sorted(
        (p for p in packets if p['sent'] == 0 and p['payload_len'] > 0), key=alt_key)

    s_off = trim_sent
    if s_off >= len(sent):
        suspect += 'd'  # dropped packet?
        s_off = -1
    last_sent = sent[s_off]

    r_off = len(rcvd) - trim_rcvd - 1
    if r_off < 0:
        suspect += 'd'  # dropped packet?
        r_off = 0
    last_rcvd = rcvd[r_off]
    if last_rcvd != rcvd_alt[r_off]:
        suspect += 'R'  # reordered received packets

    last_sent_ack = None
    try:
        last_sent_ack = min(((p['tcpack'], p['observed'], p) for p in packets
                             if p['sent'] == 0 and p['payload_len'] + last_sent['tcpseq'] >= p['tcpack']))[2]

    except Exception as e:
        sys.stderr.write("WARN: Could not find last_sent_ack.\n")

    packet_rtt = last_rcvd['observed'] - last_sent['observed']
    tsval_rtt = None
    if None not in (timestamp_precision, last_sent_ack):
        tsval_rtt = int(
            round((last_rcvd['tsval'] - last_sent_ack['tsval']) * timestamp_precision))

    if packet_rtt < 0 or (tsval_rtt != None and tsval_rtt < 0):
        # sys.stderr.write("WARN: Negative packet or tsval RTT.
        # last_rcvd=%s,last_sent=%s\n" % (last_rcvd, last_sent))
        suspect += 'N'

    return {'packet_rtt': packet_rtt,
            'tsval_rtt': tsval_rtt,
            'suspect': suspect,
            'sent_trimmed': trim_sent,
            'rcvd_trimmed': trim_rcvd}, len(sent), len(rcvd)
