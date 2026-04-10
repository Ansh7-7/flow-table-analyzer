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

class FlowTableAnalyzer(EventMixin):
    def __init__(self):
        self.mac_to_port = {}
        self.connections = {}
        self.listenTo(core.openflow)
        # Poll flow stats every 10 seconds
        Timer(10, self._poll_stats, recurring=True)
        log.info("FlowTableAnalyzer started")

    def _poll_stats(self):
        log.info("\n" + "="*60)
        log.info("FLOW TABLE SNAPSHOT - Switches: %d", len(self.connections))
        log.info("="*60)
        for dpid, con in self.connections.items():
            con.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

    def _handle_ConnectionUp(self, event):
        dpid = dpid_to_str(event.dpid)
        self.connections[event.dpid] = event.connection
        self.mac_to_port.setdefault(event.dpid, {})
        log.info("[+] Switch connected: %s", dpid)

    def _handle_ConnectionDown(self, event):
        self.connections.pop(event.dpid, None)
        log.info("[-] Switch disconnected: %s", dpid_to_str(event.dpid))

    def _handle_PacketIn(self, event):
        packet  = event.parsed
        dpid    = event.dpid
        in_port = event.port

        if not packet.parsed:
            return

        src = str(packet.src)
        dst = str(packet.dst)

        self.mac_to_port[dpid][src] = in_port
        log.info("PacketIn dpid=%s src=%s dst=%s port=%d",
                 dpid_to_str(dpid), src, dst, in_port)

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]

            # Install flow rule
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

        # Forward packet
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.in_port = in_port
        msg.actions.append(of.ofp_action_output(port=out_port))
        event.connection.send(msg)

    def _handle_FlowStatsReceived(self, event):
        dpid = dpid_to_str(event.connection.dpid)
        log.info("\n--- Switch %s (%d rules) ---", dpid, len(event.stats))
        log.info("  %-8s %-6s %-20s %-12s %-12s",
                 "Priority","IdleTO","Match","Packets","Bytes")
        log.info("  " + "-"*62)
        for f in sorted(event.stats, key=lambda x: x.priority, reverse=True):
            log.info("  %-8s %-6s %-20s %-12s %-12s",
                     f.priority,
                     f.idle_timeout,
                     str(f.match)[:20],
                     f.packet_count,
                     f.byte_count)

def launch():
    core.registerNew(FlowTableAnalyzer)

