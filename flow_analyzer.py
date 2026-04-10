"""
Multi-Switch Flow Table Analyzer - POX Controller
Author: Anshul Poovaiah K | PES1UG24CS071
"""
from pox.core import core
from pox.lib.util import dpid_to_str
from pox.lib.recoco import Timer
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *

log = core.getLogger()

HEAVY_BYTES_THRESHOLD = 500
SUSPICIOUS_PKT_THRESHOLD = 10
BLOCKED_SRC = "00:00:00:00:00:01"
BLOCKED_DST = "00:00:00:00:00:06"

class FlowTableAnalyzer(EventMixin):
    def __init__(self):
        self.mac_to_port = {}
        self.connections = {}
        self.listenTo(core.openflow)
        Timer(10, self._poll_stats, recurring=True)
        log.info("FlowTableAnalyzer started")
        log.info("Blocked pair: %s -> %s", BLOCKED_SRC, BLOCKED_DST)

    def _poll_stats(self):
        log.info("\n" + "="*65)
        log.info("FLOW TABLE SNAPSHOT - Switches: %d", len(self.connections))
        log.info("="*65)
        for dpid, con in self.connections.items():
            con.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

    def _handle_ConnectionUp(self, event):
        self.connections[event.dpid] = event.connection
        self.mac_to_port.setdefault(event.dpid, {})
        log.info("[+] Switch connected: %s", dpid_to_str(event.dpid))

    def _handle_ConnectionDown(self, event):
        self.connections.pop(event.dpid, None)
        log.info("[-] Switch disconnected: %s", dpid_to_str(event.dpid))

    def _handle_PacketIn(self, event):
        packet = event.parsed
        dpid = event.dpid
        in_port = event.port
        if not packet.parsed:
            return
        src = str(packet.src)
        dst = str(packet.dst)

        if src == BLOCKED_SRC and dst == BLOCKED_DST:
            log.info("[BLOCKED] %s -> %s (policy enforcement)", src, dst)
            msg = of.ofp_flow_mod()
            msg.match.dl_src = packet.src
            msg.match.dl_dst = packet.dst
            msg.priority = 20
            msg.idle_timeout = 60
            event.connection.send(msg)
            return

        self.mac_to_port[dpid][src] = in_port
        log.info("PacketIn dpid=%s src=%s dst=%s port=%d",
                 dpid_to_str(dpid), src, dst, in_port)

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            msg = of.ofp_flow_mod()
            msg.match.dl_src = packet.src
            msg.match.dl_dst = packet.dst
            msg.match.in_port = in_port
            msg.idle_timeout = 30
            msg.hard_timeout = 120
            msg.priority = 10
            msg.actions.append(of.ofp_action_output(port=out_port))
            event.connection.send(msg)
            log.info("FlowInstalled: %s -> %s out_port=%d", src, dst, out_port)
        else:
            out_port = of.OFPP_FLOOD

        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.in_port = in_port
        msg.actions.append(of.ofp_action_output(port=out_port))
        event.connection.send(msg)

    def _handle_FlowStatsReceived(self, event):
        dpid = dpid_to_str(event.connection.dpid)
        stats = event.stats
        if not stats:
            log.info("Switch %s: no rules", dpid)
            return

        log.info("\n--- Switch %s (%d rules) ---", dpid, len(stats))
        log.info("  %-8s %-6s %-24s %-12s %-12s NOTE",
                 "Priority","IdleTO","Match","Packets","Bytes")
        log.info("  " + "-"*75)

        heavy = []
        suspicious = []

        for f in sorted(stats, key=lambda x: x.byte_count, reverse=True):
            note = ""
            if f.byte_count >= HEAVY_BYTES_THRESHOLD:
                note = "HEAVY TRAFFIC"
                heavy.append(f)
            if f.packet_count >= SUSPICIOUS_PKT_THRESHOLD:
                note += " HIGH PACKET RATE"
                suspicious.append(f)
            log.info("  %-8s %-6s %-24s %-12s %-12s %s",
                     f.priority, f.idle_timeout,
                     str(f.match)[:24], f.packet_count, f.byte_count, note)

        log.info("\n  [TOP 3 FLOWS by Bytes] Switch %s", dpid)
        for i, f in enumerate(sorted(stats, key=lambda x: x.byte_count, reverse=True)[:3], 1):
            log.info("    #%d match=%s bytes=%s packets=%s",
                     i, str(f.match)[:30], f.byte_count, f.packet_count)

        if heavy:
            log.info("  [!] HEAVY TRAFFIC: %d flow(s)", len(heavy))
        if suspicious:
            log.info("  [!] SUSPICIOUS FLOWS: %d flow(s)", len(suspicious))
        if not heavy and not suspicious:
            log.info("  [OK] Traffic normal on switch %s", dpid)

def launch():
    core.registerNew(FlowTableAnalyzer)
