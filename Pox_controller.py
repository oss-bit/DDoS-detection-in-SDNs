from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp
import time
import threading
import numpy as np
import pickle
import os

log = core.getLogger()

WINDOW_SIZE = 5

class FlowFeature:
    """Store featres for a specific flow"""
    def __initi__(self):
        self.packet_count = 0
        self.byte_count = 0
        self.start_time = time.time()
        self.last_time = time.time()
        self.intervals = []
        self.packet_sizes = []
    
    def add_packet(self, packet_size):
        current_time = time.time()
        if self.packet_count > 0:
            self.intervals.append(current_time - self.last_time)
        self.packet_count += 1
        self.byte_count += packet_size
        self.packet_sizes.append(packet_size)
        self.last_time = current_time

    def get_features(self):
        duration = time.time() - self.start_time
        packet_rate = self.packet_count/duration if duration > 0 else 0
        byte_rate = self.byte_count/duration if duration > 0 else 0
        avg_packet_size = np.mean(self.packet_sizes) if self.packet_sizes else 0 
        var_packet_size = np.var(self.packet_sizes) if len(self.packet_sizes) > 1 else 0
        avg_interval = np.mean(self.intervals) if self.intervals else 0
        var_interval = np.var(self.intervals) if len(self.intervals) > 1 else 0
        return [packet_rate, byte_rate, avg_packet_size, var_packet_size, avg_interval, var_interval]
    
class DDoSDetector:
    """ML based DDos detector for POX"""
    def __init__(self, model_path="ml_model.pkl"):
        try:
            with open(model_path,'rb') as f:
                self.model = pickle.load(f)
            log.info("Successfully loaded Ml model from %s", model_path)
        except Exception as e:
            log.error("Failed to load ML model: %s", e)
            self.model = None
        self.flow_table = {}
        self.blacklist = set()
        self.running = True
        self.thread = threading.Thread(target=self._analyze_flows)
    
    def process_packet(self, packet, parsed_packet):
        if isinstance(parsed_packet.next, ipv4):
            ip_packet = parsed_packet.next
            src_ip = ip_packet.srcip
            dst_ip = ip_packet.dstip
            protocol = ip_packet.protocol
            src_port = 0
            dst_port = 0
            if protocol ==6 and isinstance(ip_packet.next, tcp):
                tcp_packet = ip_packet.next
                src_port = tcp_packet.srcport
                dst_port = tcp_packet.dstport
            elif protocol == 17 and isinstance(ip_packet.next, udp):
                udp_packet = ip_packet.next
                src_port = udp_packet.srcport
                dst_port = udp_packet.dstport

            flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
            if src_ip in self.blacklist:
                return True
            if flow_key not in self.flow_table:
                self.flow_table[flow_key] = FlowFeature()
            self.flow_table[flow_key].add_packet(len(packet))
        return False
    def _analyze_flows(self):

        while self.running:
            time.sleep(WINDOW_SIZE)
            if not self.model:
                continue
            current_time = time.time()
            dst_ip_flows = {}
            for (src_ip, dst_ip, _, _, _), flow in list(self.flow_table.items()):
                if current_time - flow.last_time > WINDOW_SIZE*2:
                    del self.flow_table[(src_ip, dst_ip, _, _, _)]
                    continue
                if dst_ip not in dst_ip_flows:
                    dst_ip_flows[dst_ip] = []
                dst_ip_flows[dst_ip].append((src_ip, flow))
            for dst_ip, flows in dst_ip_flows.items():
                if len(flows) <3:
                    continue
                all_features = []
                for _, flow in flows:
                    all_features.append(flow.get_features())
                X = np.array(all_features)
                agg_features = [
                    np.mean(X[:, 0]),
                    np.mean(X[:, 1]),
                    np.std(X[:,0]),
                    len(flows),
                    np.mean(X[:,4]),
                ]
                try:
                    is_attack = self.model.predict([agg_features])[0]
                    if is_attack == 1:
                        log.warning("DDoS attack detected targeting %s", dst_ip)
                        packet_rates = [(src_ip, flow.get_features()[0]) for src_ip, flow in flows]
                        packet_rates.sort(key=lambda x: x[1], reverse=True)
                        num_to_blacklist = max(1, int(len(packet_rates)*0.7))
                        for i in range(num_to_blacklist):
                            src_ip = packet_rates[i][0]
                            self.blacklist.add(src_ip)
                            log.warning("Blacklisted %s (packet rate: %.2f pps)",src_ip, packet_rates[i][1])
                except Exception as e:
                    log.error("Error during prediction: %s", e)
    def shutdown(self):
        self.running = False
        self.thread.join()

class DDosDefender(object):
    def __init__(self, connection, detector):
        self.connection = connection
        self.detector = detector
        connection.addListeners(self)
        self.mac_to_port = {}
        log.debug("DDos defender initialized for %s", dpid_to_str(connection.dpid))
    def _handle_packet_in(self, event):
        packet = event.parsed
        is_blacklisted = self.detector.process_packet(event.data, packet)
        if is_blacklisted:
            log.debug("Dropping packet from blacklisted soruce")
            return
        self.mac_to_port[packet.src] = event.port
        
        if packet.dst in self.mac_to_port:
            port = self.mac_to_port[packet.dst]
            log.debug("Installing flow for %s.%i -> %s.%i", packet.src, event.port, packet.dst, port)
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match.from_packet(packet, event.port)
            msg.idle_timeout = 10
            msg.hard_timeout = 30
            msg.actions.append(of.ofp_action_output(port=port))
            msg.data = event.ofp
            self.connection.send(msg)
        else:
            log.debug("Flooding %s -> %s", packet.src, packet.dst)
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            msg.data = event.ofp
            self.connection.send(msg)

detector = None

def launch(model="ml_model.pkl"):
    global detector
    detector = DDoSDetector(model_path=model)

    def start_defender(event):
        log.debug("Controlling %s", dpid_to_str(event.dpid))
        DDosDefender(event.connection, detector)
    
    core.openflow.addListnerByName("ConnectionUp", start_defender)
    
    def shutdown():
        if detector:
            detector.shutdown()
    core.addListnerByName("GoingDownEvent", lambda _: shutdown())




