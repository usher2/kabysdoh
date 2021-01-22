#!/usr/bin/python3

import ctypes
import json
import random
import threading
import time

DUMP_PATH = '/srv/kabysdoh/kabydump.pyjson'
# MGMT_ADDR = ('::1', 24066)
# MGMT_METRICS_ACL = []
# MGMT_API_ACL = []

# take a look at /usr/lib/python3.5/http/server.py and do a MGMG HTTP IFACE with verify_request() cb.

DUMP = None

NET_TYPE_A = ntohs(RR_TYPE_A)
NET_TYPE_AAAA = ntohs(RR_TYPE_AAAA)
NET_CLASS_IN = ntohs(RR_CLASS_IN)

class query_info_head(ctypes.Structure):
    _fields_ = [
        ('qname', ctypes.c_char_p), # qname, in wireformat, actually defined as (uint8_t*).
        ('qname_len', ctypes.c_size_t), # length of qname including last 0 octet
        ('qtype', ctypes.c_uint16), # qtype, host byte order
        ('qclass', ctypes.c_uint16), # qclass, host byte order
        ('local_alias', ctypes.c_void_p), # actually defined as (struct local_rrset*).
    ]

query_info_head_p = ctypes.POINTER(query_info_head)
c_void_pp = ctypes.POINTER(ctypes.c_void_p)

# int (*attach_sub)(struct module_qstate* qstate, struct query_info* qinfo, uint16_t qflags, int prime, int valrec, struct module_qstate** newq);
ATTACH_SUB_T = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, query_info_head_p, ctypes.c_uint16, ctypes.c_int, ctypes.c_int, ctypes.c_void_p)

LOCK = object()

def strAsDname(s):
    l = []
    for label in s.encode('ascii').split(b'.'):
        if len(label) > 0:
            l.append(bytes((len(label),)))
            l.append(label)
    l.append(bytes((0,)))
    return b''.join(l)

def load_dump(fpath):
    # It takes ~150 ms to load & parse the dump dated 2020-12-26.
    with open(fpath, 'rt') as fd:
        d = json.load(fd)
    if d['uint128'] != 0xffffffffffffffffffffffffffffffff:
        raise RuntimeError('Bad uint128 marker. Was pyjson re-encoded with floats?', d['uint128'])
    d['ip'] = set(d['ip'])
    d['ipv6'] = set(d['ipv6'])
    for (nbits, setname) in ((32, 'ipSubnet'), (128, 'ipv6Subnet')):
        common_mask = 2 ** nbits - 1
        for (_, netmask) in d[setname]:
            common_mask &= netmask
        t1 = {}
        for (netaddr, netmask) in d[setname]:
            if netmask != common_mask:
                t1.setdefault(netaddr & common_mask, []).append((netaddr, netmask))
            else:
                t1[netaddr] = None
        d['{}TrieMask'.format(setname)] = common_mask
        d[setname] = t1
    d['cdn'], d['cdnv6'] = {LOCK: threading.Lock()}, {LOCK: threading.Lock()}
    for (nbits, setname) in ((32, 'cdnSubnet'), (128, 'cdnv6Subnet')):
        common_mask = 2 ** nbits - 1
        for (_, netmask, _) in d[setname]:
            common_mask &= netmask
        t1 = {}
        for (netaddr, netmask, cdn) in d[setname]:
            if cdn not in d['cdn']:
                d['cdn'][cdn], d['cdnv6'][cdn] = [], []
            if netmask != common_mask:
                t1.setdefault(netaddr & common_mask, []).append((netaddr, netmask, cdn))
            else:
                t1[netaddr] = cdn
        d['{}TrieMask'.format(setname)] = common_mask
        d[setname] = t1
    for cdn in list(d['cdnDomains']):
        d['cdnDomains'][cdn] = [strAsDname(_) for _ in d['cdnDomains'][cdn]]
    return d

def init_standard(id, env):
    # Let's ensure that query_info_head and query_info memory layout is the same.
    qi = query_info()
    assert qi.qname == b'' and qi.qtype == 0 and qi.qclass == 0 # %immutable fields.
    qip = ctypes.cast(int(qi.this), query_info_head_p)
    qiwr = qip[0]
    assert qiwr.qname == None and qiwr.qname_len == 0 and qiwr.qtype == 0 and qiwr.qclass == 0
    qname_buf = b'\x07invalid\x00'
    qiwr.qname = qname_buf # does it allocate a copy? who knows... Let's hold a ref for safety.
    qiwr.qname_len = len(qname_buf)
    qiwr.qclass = RR_CLASS_CH
    qiwr.qtype = RR_TYPE_AAAA
    assert qi.qname == b'\x07invalid\x00' and qi.qtype == RR_TYPE_AAAA and qi.qclass == RR_CLASS_CH # %immutable, huh
    # If it crashes, it crashes here. If it does not, it is not expected to crash further.
    global DUMP
    DUMP = load_dump(DUMP_PATH) # should I rather use `mod_env` global?...

def deinit(id):
    DUMP = None

def parse_reply_info(rep):
    d = DUMP
    # rep points to `struct reply_info`
    good, unwanted, rrcdn, goodcdn = 0, set(), set(), []

    now = time.monotonic()
    rrconf = {
        NET_TYPE_A: (
            6, d['ip'],
            d['ipSubnet'], d['ipSubnetTrieMask'],
            d['cdnSubnet'], d['cdnSubnetTrieMask'],
        ),
        NET_TYPE_AAAA: (
            18, d['ipv6'],
            d['ipv6Subnet'], d['ipv6SubnetTrieMask'],
            d['cdnv6Subnet'], d['cdnv6SubnetTrieMask'],
        )
    }

    for keyi in range(rep.an_numrrsets):
        ub_packed_rrset_key = rep.rrsets[keyi] # struct ub_packed_rrset_key
        rk = ub_packed_rrset_key.rk # struct packed_rrset_key
        rk_conf = rrconf.get(rk.type)
        if rk_conf is not None and rk.rrset_class == NET_CLASS_IN:
            data = ub_packed_rrset_key.entry.data # struct packed_rrset_data
            rr_len, ipset, t1, common_mask, cdnt1, cdn_mask = rk_conf
            for rri in range(data.count):
                blob = data.rr_data[rri]
                if not (rr_len == data.rr_len[rri] == len(blob) == blob[1] + 2 and blob[0] == 0):
                    # continue # broken RR?! Other plugins do this check as well...
                    raise RuntimeError('RR with malformed rr_len', rk.dname_str)
                ip = int.from_bytes(blob[2:], 'big')

                netlist = t1.get(ip & common_mask, False)
                if ip in ipset or (
                    netlist is not False and (
                        netlist is None # netmask == common_mask
                        or any((ip & netmask) == netaddr for netaddr, netmask in netlist)
                )):
                    unwanted.add(blob)
                    rr_good = False
                else:
                    good += 1
                    rr_good = True

                netlist = cdnt1.get(ip & cdn_mask, False)
                if netlist is not False: # it _might_ be known CDN
                    if isinstance(netlist, str): # netmask == common_mask
                        cdn = netlist
                    else:
                        for netaddr, netmask, cdn in netlist:
                            if (ip & netmask) == netaddr:
                                break
                        else:
                            cdn = None
                    if cdn is not None:
                        rrcdn.add(cdn)
                        if rr_good and data.rr_ttl[rri] > 0:
                            exp = now + data.rr_ttl[rri]
                            rrtxt = 'CLASS{:d} TYPE{:d} \\# {:d} {:s}'.format(
                                ntohs(rk.rrset_class), ntohs(rk.type),
                                blob[1],
                                ''.join('{:02X}'.format(c) for c in blob[2:]))
                            goodcdn.append((exp, rrtxt, rr_len, cdn))
    return good, unwanted, rrcdn, goodcdn

def set_crafted_return_msg(qstate, unwanted, stash=None):
    qinfo, rep = qstate.return_msg.qinfo, qstate.return_msg.rep # current `return_msg`

    flags, security = rep.flags, rep.security # copy before set_return_msg()
    # NB: only TTL might be updated in-place. `resmod.py' is an example for TTL case.
    msg = DNSMessage(qinfo.qname_str, qinfo.qtype, qinfo.qclass,
        (PKT_QR if flags & QF_BIT_QR else 0) |
        (PKT_AA if flags & QF_BIT_AA else 0) |
        (PKT_TC if flags & QF_BIT_TC else 0) |
        (PKT_RD if flags & QF_BIT_RD else 0) |
        (PKT_CD if flags & QF_BIT_CD else 0) |
        (PKT_RA if flags & QF_BIT_RA else 0) |
        (PKT_AD if flags & QF_BIT_AD else 0))
    fitness = {}
    now = time.monotonic()
    for keyi in range(rep.an_numrrsets):
        ub_packed_rrset_key = rep.rrsets[keyi]
        rk = ub_packed_rrset_key.rk
        is_ip = rk.type in (NET_TYPE_A, NET_TYPE_AAAA) and rk.rrset_class == NET_CLASS_IN
        data = ub_packed_rrset_key.entry.data # struct packed_rrset_data
        fitness[(rk.dname, rk.type, rk.rrset_class)] = data.trust, data.security
        for rri in range(data.count):
            blob = data.rr_data[rri]
            if not is_ip or blob not in unwanted:
                # RFC3597 format
                msg.answer.append('{:s} {:d} CLASS{:d} TYPE{:d} \\# {:d} {:s}'.format(
                    rk.dname_str, data.rr_ttl[rri],
                    ntohs(rk.rrset_class), ntohs(rk.type),
                    data.rr_len[rri] - 2,
                    ''.join('{:02X}'.format(c) for c in blob[2:])))
            elif stash: # is_ip and (blob in unwanted) and (non-empty stash)
                exp, rrtxt = stash.pop()
                msg.answer.append('{:s} {:d} {:s}'.format(
                    rk.dname_str, int(min(data.rr_ttl[rri], exp - now)), rrtxt))
                log_info('****** {}'.format(msg.answer[-1]))

    # TODO: account for ECS. ECS cache is tricky.
    # TODO: understand if `authority` and `additional` should be copied.
    # TODO: understand why is `explanation.invalid` dropped from reply. Is it "minimal-responses"?
    #   msg.additional.append('explanation.invalid. 0 IN TXT "Deleted unwanted RRs"')
    invalidateQueryInCache(qstate, qinfo)

    # NB: set_return_msg() updates qstate.return_msg.rep.authoritative using PKT_AA.
    if not msg.set_return_msg(qstate):
        log_info('set_return_msg() failed')
        return False

    # Old `rep` points to pointless point at this point.
    qinfo, rep = qstate.return_msg.qinfo, qstate.return_msg.rep # new `return_msg`

    # And let the UGLY hack begin. I hope, it does not crash Unbound.
    # It is needed to put the answer to cache, otherwise the query can't be replied
    # from cache and the "Cache reply: secure entry changed status" msg is logged.
    rep.security = security
    for keyi in range(rep.an_numrrsets):
        ub_packed_rrset_key = rep.rrsets[keyi]
        rk = ub_packed_rrset_key.rk
        data = ub_packed_rrset_key.entry.data
        data.trust, data.security = fitness[(rk.dname, rk.type, rk.rrset_class)] # KeyError here is a bug
    # End of the UGLY hack. Much trust. Very verify_request. Lots security. Wow!

    is_referral = 0
    # Both raw msg and rrset is stored for non-referral queries, bare rrset for referral.
    if not storeQueryInCache(qstate, qinfo, rep, is_referral):
        log_info('storeQueryInCache() failed')
        return False

    return True

def launch_subquery(qstate, qname, qtype):
    attach_sub = qstate.env.attach_sub
    if attach_sub is None:
        # NULL pointer here is not lack of memory, it looks like logic error
        raise RuntimeError('qstate.env.attach_sub is None')

    # Oh the roskomnadzor is frightful!
    # And the SWIG is not so delightful. :-(
    # Since we've no way to __call__()...
    # Let it blow! Let it blow! Let it blow!
    attach_sub = ATTACH_SUB_T(int(attach_sub)) # `attach_sub` is a pointer, not a SWIG-wrapped function.

    qi = query_info() # SWIG proxy is used as sizeof(query_info) _might_ change across versions.
    qiwr = ctypes.cast(int(qi.this), query_info_head_p)[0] # query_info is %immutable
    qiwr.qname = qname
    qiwr.qname_len = len(qname)
    qiwr.qclass = RR_CLASS_IN
    qiwr.qtype = qtype

    newq = ctypes.c_void_p()

    if not attach_sub(int(qstate.this), qiwr, qstate.query_flags, qstate.is_priming, qstate.is_valrec, ctypes.pointer(newq)):
        log_info('attach_sub failed')
        return False

    return True

"""
MODULE_STATE_INITIAL initial state - new query
MODULE_WAIT_REPLY    waiting for reply to outgoing network query. It's for `iterator' module.
MODULE_WAIT_MODULE   module is waiting for another module. In the `module-config' chain.
MODULE_RESTART_NEXT  module is waiting for another module; that other is restarted. E.g. restarting a query on bad answer.
MODULE_WAIT_SUBQUERY module is waiting for sub-query.
MODULE_ERROR         module could not finish the query.
MODULE_FINISHED      module is finished with query. The query is done & finished.
"""

# Following events seems to be relevant just for `iterator`:
#   MODULE_EVENT_REPLY    reply inbound from server
#   MODULE_EVENT_NOREPLY  no reply, timeout or other error
#   MODULE_EVENT_CAPSFAIL reply is there, but capitalisation check failed
# And this one is a generic error:
#   MODULE_EVENT_ERROR    error

SUBQUERY, STASH_QTYPE, UNWANTED, RRCDN = object(), object(), object(), object()

def operate(id, event, qstate, qdata):
    if event in (MODULE_EVENT_PASS, MODULE_EVENT_NEW): # query passed by other module OR new query
        # MODULE_EVENT_PASS is either "new" query or module wake-up after sub-query.
        # MODULE_EVENT_NEW does not happen if `subnetcache` is called before `python`.
        # _If I understand Unbound state machine correctly._
        if SUBQUERY not in qdata:
            qstate.ext_state[id] = MODULE_WAIT_MODULE # down to validator & iterator
            return True
        else:
            return operate_on_subquery_results(id, qstate, qdata)
    elif event != MODULE_EVENT_MODDONE: # next module is done, and its reply is awaiting you
        qstate.ext_state[id] = MODULE_ERROR
        return True

    assert SUBQUERY not in qdata

    # qstate.reply is None in all the cases I've tested. It makes sense in presence of mesh_info.
    is_external = qstate.mesh_info.reply_list is not None # reply_list.query_reply.addr points to client
    has_reply = qstate.return_msg is not None
    qinfo = qstate.qinfo
    qtype, qclass = qinfo.qtype, qinfo.qclass
    # log_query_info(NO_VERBOSE, 'operate(): event:{} qdata:{} has_reply:{} is_external:{} qinfo:'.format(
    #     strmodulevent(event), qdata, has_reply, is_external), qinfo)
    if not is_external or qtype not in (RR_TYPE_A, RR_TYPE_AAAA) or qclass != RR_CLASS_IN:
        # These are not the queries you are looking for.
        qstate.ext_state[id] = MODULE_FINISHED
        return True

    if not has_reply:
        log_query_info(NO_VERBOSE, 'Dead NS? operate(): event:{} qdata:{} has_reply:{} is_external:{} qinfo:'.format(
            strmodulevent(event), qdata, has_reply, is_external), qinfo)
        qstate.ext_state[id] = MODULE_FINISHED
        return True

    rep = qstate.return_msg.rep # `rep` for `reply`, struct reply_info
    if qstate.return_rcode != RCODE_NOERROR or rep.an_numrrsets == 0:
        # We do not touch faulty and/or empty replies.
        qstate.ext_state[id] = MODULE_FINISHED
        return True

    # The goal is to:
    # 1. drop unwanted IP addresses; deduce CDN of the domain; log affected domains
    # 2. start a sub-query for a CDN'ed domain if no IP addresses left
    # 3. TODO: learn domains for CDN'ed IP addresses if some IP addresses left for external queries.
    #    TODO: understand if malicious user may harm this heuristics and only sub-queries are good.
    #    Only external queries are considered as internal queries resolve A/AAAA for NSes and such.
    good, unwanted, rrcdn, _ = parse_reply_info(rep)
    if len(rrcdn) == 1:
        rrcdn = rrcdn.pop()
    else:
        if len(rrcdn) > 1:
            log_info('ambiguous CDN for {}: {}'.format(qinfo.qname_str, rrcdn))
        rrcdn = None

    if not unwanted: # all is good
        pass
    elif good > 0: # just drop some RRs
        if not set_crafted_return_msg(qstate, unwanted):
            qstate.ext_state[id] = MODULE_ERROR
            return True
    elif rrcdn is not None:
        unwanted_rr_len = {len(blob) for blob in unwanted}
        if len(unwanted_rr_len) > 1:
            raise RuntimeError('Mixture of unwanted RR types in answer', unwanted)
        qdata[SUBQUERY] = 0
        qdata[STASH_QTYPE] = {6: RR_TYPE_A, 18: RR_TYPE_AAAA}[unwanted_rr_len.pop()]
        qdata[UNWANTED] = unwanted
        qdata[RRCDN] = rrcdn
        return operate_on_subquery_results(id, qstate, qdata)
    else:
        log_info('****** TODO: BLOCKPAGE SERVER, good:{} unwanted:{}'.format(good, unwanted))
    qstate.ext_state[id] = MODULE_FINISHED
    return True

def operate_on_subquery_results(id, qstate, qdata):
    d = DUMP
    stashgrp = d['cdn' if qdata[STASH_QTYPE] == RR_TYPE_A else 'cdnv6']
    now = time.monotonic()
    with stashgrp[LOCK]: # it may be per-CDN, but it does not make sense with just ~two CDNs
        stash = stashgrp[qdata[RRCDN]]
        while stash and stash[-1][0] < now: # drop expired
            stash.pop()
        stash = stash.copy()
    if stash:
        random.shuffle(stash)
        if set_crafted_return_msg(qstate, qdata[UNWANTED], stash):
            qstate.ext_state[id] = MODULE_FINISHED
        else:
            qstate.ext_state[id] = MODULE_ERROR
    else:
        if qdata[SUBQUERY] >= 3:
            raise RuntimeError('too many sub-queries', rrcdn)
        # TODO: is invalidateQueryInCache needed here before sub-query?
        sqname = random.choice(d['cdnDomains'][qdata[RRCDN]])
        if launch_subquery(qstate, sqname, qdata[STASH_QTYPE]):
            qdata[SUBQUERY] += 1
            qstate.ext_state[id] = MODULE_WAIT_SUBQUERY
        else:
            qstate.ext_state[id] = MODULE_ERROR
    return True

def inform_super(module_id, qstate, superq, qdata):
    log_query_info(NO_VERBOSE, 'inform_super(): qdata:{} qstate.qinfo:'.format(qdata), qstate.qinfo)
    log_query_info(NO_VERBOSE, 'inform_super(): qdata:{} superq.qinfo:'.format(qdata), superq.qinfo)
    # qdata is attached to qstate, writhing there is not reflected in superq, it's not a postbox.
    #
    # Following has no visible effect as well:
    #   qstate.ext_state[module_id] = MODULE_ERROR
    #   superq.ext_state[module_id] = MODULE_ERROR
    #
    # What is the goal of inform_super() in python? How should it be used to modify superq state?...

    # qstate.env.{now,now_tv} point to gettimeogday() structures without wrappers. ctypes once more?
    d = DUMP
    _, _, _, good = parse_reply_info(qstate.return_msg.rep)
    g4 = [_ for _ in good if _[2] == 6]
    g6 = [_ for _ in good if _[2] == 18]
    if not g4 and not g6:
        log_query_info(NO_VERBOSE, 'NO GOOD?! WTF?! inform_super(): qdata:{} qstate.qinfo:'.format(qdata), qstate.qinfo)
        return True
    now = time.monotonic()
    for key, good in (('cdn', g4), ('cdnv6', g6)):
        if not good:
            continue
        stashgrp = d[key]
        with stashgrp[LOCK]:
            known = {}
            for exp, rrtxt, rr_len, cdn in good:
                stash = stashgrp[cdn]
                stash.append((exp, rrtxt))
                known[id(stash)] = stash
            for stash in known.values():
                stash.sort(reverse=True)
                while stash and stash[-1][0] < now: # drop expired
                    stash.pop()
                while len(stash) > 42: # prevent unbounded growth
                    stash.pop()
    return True
