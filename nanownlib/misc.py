import sys
import json
import time
import datetime
import statistics
import pprint

from .network import analyzePackets
from .stats import septasummary, mad, quadsummary


def evaluateTrim(db, unusual_case, strim, rtrim):
    """
    septasummary and mad for each dist of differences
    """
    cursor = db.conn.cursor()
    #query = """
    #  SELECT packet_rtt-(SELECT avg(packet_rtt) FROM probes,trim_analysis
    #                     WHERE sent_trimmed=:strim AND rcvd_trimmed=:rtrim AND trim_analysis.probe_id=probes.id AND probes.test_case!=:unusual_case AND sample=u.s AND probes.type in ('train','test'))
    #  FROM (SELECT probes.sample s,packet_rtt FROM probes,trim_analysis WHERE sent_trimmed=:strim AND rcvd_trimmed=:rtrim AND trim_analysis.probe_id=probes.id AND probes.test_case=:unusual_case AND probes.type in ('train','test') AND 1 NOT IN (select 1 from probes p,trim_analysis t WHERE p.sample=s AND t.probe_id=p.id AND t.suspect LIKE '%R%')) u
    #"""

    query = """
      SELECT packet_rtt-(SELECT avg(packet_rtt) FROM probes,trim_analysis
                         WHERE sent_trimmed=:strim AND rcvd_trimmed=:rtrim AND trim_analysis.probe_id=probes.id AND probes.test_case!=:unusual_case AND sample=u.s AND probes.type in ('train','test'))
      FROM (SELECT probes.sample s,packet_rtt FROM probes,trim_analysis WHERE sent_trimmed=:strim AND rcvd_trimmed=:rtrim AND trim_analysis.probe_id=probes.id AND probes.test_case=:unusual_case AND probes.type in ('train','test')) u
    """
    # TODO: check for "N" in suspect field and return a flag

    params = {"strim": strim, "rtrim": rtrim, "unusual_case": unusual_case}
    cursor.execute(query, params)
    differences = [row[0] for row in cursor]

    return septasummary(differences), mad(differences)


def analyzeProbes(db, trim=None, recompute=False):
    db.conn.execute(
        "CREATE INDEX IF NOT EXISTS packets_probe ON packets (probe_id)")
    db.conn.commit()

    pcursor = db.conn.cursor()
    pcursor.execute("SELECT tcpts_mean FROM meta")
    try:
        timestamp_precision = pcursor.fetchone()[0]
    except:
        timestamp_precision = None

    pcursor.execute("DELETE FROM trim_analysis")
    db.conn.commit()
    if recompute:
        pcursor.execute("DELETE FROM analysis")
        db.conn.commit()

    def loadPackets(db):
        print('Loading packets...')

        cursor = db.conn.cursor()
        # cursor.execute("SELECT * FROM packets ORDER BY probe_id")
        cursor.execute(
            "SELECT * FROM packets WHERE probe_id NOT IN (SELECT probe_id FROM analysis) ORDER BY probe_id")

        probe_id = None
        entry = []
        ret_val = []
        for p in cursor:
            if probe_id is None:
                probe_id = p['probe_id']
            if p['probe_id'] != probe_id:
                ret_val.append((probe_id, entry))
                probe_id = p['probe_id']
                entry = []
            entry.append(dict(p))
        ret_val.append((probe_id, entry))

        print('Done!')
        return ret_val

    def processPackets(packet_cache, strim, rtrim):
        print('Processing packets...')

        sent_tally = []
        rcvd_tally = []
        analyses = []
        for probe_id, packets in packet_cache:
            try:
                analysis, s, r = analyzePackets(packets, timestamp_precision)
                analysis['probe_id'] = probe_id
                analyses.append(analysis)
                sent_tally.append(s)
                rcvd_tally.append(r)
            except Exception:
                # traceback.print_exc()
                msg = "WARN: couldn't find enough packets for probe_id=%s\n"
                sys.stderr.write(msg % probe_id)

        db.addTrimAnalyses(analyses)
        db.conn.commit()

        result = statistics.mode(sent_tally), statistics.mode(rcvd_tally)
        print('Done!')
        return result

    # start = time.time()
    packet_cache = loadPackets(db)
    # print("packets loaded in: %f" % (time.time()-start))

    if trim is not None:
        best_strim, best_rtrim = trim
        processPackets(packet_cache, best_strim, best_rtrim)
    else:
        num_sent, num_rcvd = processPackets(packet_cache, 0, 0)
        args = (num_sent, num_rcvd)
        print("Process packet output num_sent: %d, num_rcvd: %d" % args)

        for strim in range(0, num_sent):
            for rtrim in range(0, num_rcvd):
                args = (strim, rtrim)
                print('Processing packets strim: %s | rtrim %s' % args)

                if strim == 0 and rtrim == 0:
                    # no point in doing 0,0 again
                    continue
                processPackets(packet_cache, strim, rtrim)

        unusual_case, delta = findUnusualTestCase(db, (0, 0))
        evaluations = {}

        for strim in range(0, num_sent):
            for rtrim in range(0, num_rcvd):
                evaluations[(strim, rtrim)] = evaluateTrim(db, unusual_case,
                                                           strim, rtrim)

        pprint.pprint(evaluations)

        delta_margin = 0.15
        best_strim = 0
        best_rtrim = 0
        good_delta, good_mad = evaluations[(0, 0)]

        for strim in range(1, num_sent):
            delta, mad = evaluations[(strim, 0)]
            if delta * good_delta > 0.0 and (abs(good_delta) - abs(delta)) < abs(delta_margin * good_delta) and mad < good_mad:
                best_strim = strim
            else:
                break

        good_delta, good_mad = evaluations[(best_strim, 0)]
        for rtrim in range(1, num_rcvd):
            delta, mad = evaluations[(best_strim, rtrim)]
            if delta * good_delta > 0.0 and (abs(good_delta) - abs(delta)) < abs(delta_margin * good_delta) and mad < good_mad:
                best_rtrim = rtrim
            else:
                break

        print("selected trim parameters:", (best_strim, best_rtrim))

    pcursor.execute("""INSERT OR IGNORE INTO analysis
                         SELECT id,probe_id,suspect,packet_rtt,tsval_rtt
                           FROM trim_analysis
                           WHERE sent_trimmed=? AND rcvd_trimmed=?""",
                    (best_strim, best_rtrim))
    db.conn.commit()

    return len(packet_cache)


def parseJSONLines(fp):
    for line in fp:
        yield json.loads(line)


def associatePackets(sniffer_fp, db):
    sniffer_fp.seek(0)

    # now combine sampler data with packet data
    buffered = []

    cursor = db.conn.cursor()
    cursor.execute(
        "SELECT count(*) count,min(time_of_day) start,max(time_of_day+userspace_rtt) end from probes")
    ptimes = cursor.fetchone()
    window_size = 100 * \
        int((ptimes['end'] - ptimes['start']) / ptimes['count'])
    # print("associate window_size:", window_size)

    db.addPackets(parseJSONLines(sniffer_fp), window_size)

    cursor.execute("SELECT count(*) count FROM packets WHERE probe_id is NULL")
    unmatched = cursor.fetchone()['count']
    if unmatched > 0:
        sys.stderr.write(
            "WARNING: %d observed packets didn't find a home...\n" % unmatched)

    return None


def enumStoredTestCases(db):
    cursor = db.conn.cursor()
    cursor.execute("SELECT test_case FROM probes GROUP BY test_case")
    return [tc[0] for tc in cursor]


def findUnusualTestCase(db, trim=None):
    test_cases = enumStoredTestCases(db)
    if trim is not None:
        params = {'strim': trim[0], 'rtrim': trim[1]}
        qsuffix = " AND sent_trimmed=:strim AND rcvd_trimmed=:rtrim"
        table = "trim_analysis"
    else:
        params = {}
        qsuffix = ""
        table = "analysis"

    cursor = db.conn.cursor()
    cursor.execute("SELECT packet_rtt FROM probes," + table +
                   " a WHERE probes.id=a.probe_id AND probes.type in ('train','test')" + qsuffix, params)
    global_tm = quadsummary([row['packet_rtt'] for row in cursor])

    tm_abs = []
    tm_map = {}

    # XXX: if more speed needed, percentile extension to sqlite might be
    # handy...
    for tc in test_cases:
        params['test_case'] = tc
        query = """SELECT packet_rtt FROM probes,""" + table + """ a
                   WHERE probes.id=a.probe_id AND probes.type in ('train','test')
                   AND probes.test_case=:test_case""" + qsuffix
        cursor.execute(query, params)
        tm_map[tc] = quadsummary([row['packet_rtt'] for row in cursor])
        tm_abs.append((abs(tm_map[tc] - global_tm), tc))

    magnitude, tc = max(tm_abs)
    params['test_case'] = tc
    query = """SELECT packet_rtt FROM probes,""" + table + """ a
               WHERE probes.id=a.probe_id AND probes.type in ('train','test')
               AND probes.test_case<>:test_case""" + qsuffix
    cursor.execute(query, params)
    remaining_tm = quadsummary([row['packet_rtt'] for row in cursor])

    delta = tm_map[tc] - remaining_tm
    # Hack to make the chosen unusual_case more intuitive to the user
    if len(test_cases) == 2 and delta < 0.0:
        tc = [t for t in test_cases if t != tc][0]
        delta = abs(delta)

    return tc, delta


def reportProgress(db, sample_types, start_time):
    cursor = db.conn.cursor()
    output = ''
    total_completed = 0
    total_requested = 0
    for st in sample_types:
        cursor.execute(
            "SELECT count(id) c FROM (SELECT id FROM probes WHERE type=? AND time_of_day>? GROUP BY sample)", (st[0], int(start_time * 1000000000)))
        count = cursor.fetchone()[0]
        output += " | %s remaining: %6d" % (st[0], st[1] - count)
        total_completed += count
        total_requested += st[1]

    rate = total_completed / (time.time() - start_time)
    total_time = total_requested / rate
    eta = datetime.datetime.fromtimestamp(start_time + total_time)
    print("STATUS:", output[3:], "| est. total_time: %s | ETA: %s" %
          (str(datetime.timedelta(seconds=total_time)), eta.strftime("%Y-%m-%d %X")))


def evaluateTestResults(db):
    cursor = db.conn.cursor()
    query = """
      SELECT classifier FROM classifier_results GROUP BY classifier ORDER BY classifier;
    """
    cursor.execute(query)
    classifiers = []
    for c in cursor:
        classifiers.append(c[0])

    best_obs = []
    best_error = []
    max_obs = 0
    for classifier in classifiers:
        query = """
        SELECT classifier,params,num_observations,(false_positives+false_negatives)/2 error
        FROM classifier_results
        WHERE trial_type='test'
         AND classifier=:classifier
         AND (false_positives+false_negatives)/2.0 < 5.0
        ORDER BY num_observations,(false_positives+false_negatives)
        LIMIT 1
        """
        cursor.execute(query, {'classifier': classifier})
        row = cursor.fetchone()
        if row is None:
            query = """
            SELECT classifier,params,num_observations,(false_positives+false_negatives)/2 error
            FROM classifier_results
            WHERE trial_type='test' and classifier=:classifier
            ORDER BY (false_positives+false_negatives),num_observations
            LIMIT 1
            """
            cursor.execute(query, {'classifier': classifier})
            row = cursor.fetchone()
            if row is None:
                sys.stderr.write(
                    "WARN: couldn't find test results for classifier '%s'.\n" % classifier)
                continue
            row = dict(row)

            best_error.append(dict(row))
        else:
            best_obs.append(dict(row))

    return best_obs, best_error

