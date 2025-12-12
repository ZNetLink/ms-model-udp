import logging
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import miaosuan as ms
from miaosuan.engine.engine import INTRPT_TYPE_REMOTE, INTRPT_TYPE_STRM, Stream
from miaosuan.engine.simobj import SimObj
from miaosuan.mms.process_registry import AttrType, pr_attr_set, pr_register
from ipv4 import ip_support

logger = logging.getLogger(__name__)

UDP_PACKET_FORMAT = "udp_dgram"
UDP_INDICATION_ICI = "udp_ind"
UDP_COMMAND_ICI = "udp_command"
IP_INDICATION_ICI = "ip_ind"

IP_PROTOCOL_UDP = 17
UDP_PORT_MIN = 1
UDP_PORT_MAX = 65535
UDP_DYNAMIC_PORT_MIN = 49152
UDP_DYNAMIC_PORT_MAX = 65535
UDP_HEADER_LENGTH = 8

def _iter_streams(streams: Optional[Dict[int, Stream]]) -> Tuple[Stream, ...]:
    if not streams:
        return ()
    return tuple(streams.values())


@dataclass
class UdpSocket:
    local_port: int
    stream_to_app: int
    stream_from_app: int
    app_module: Optional[SimObj] = None
    remote_port: Optional[int] = None


@dataclass
class UdpHeader:
    SrcPort: int
    DstPort: int
    Length: int
    Checksum: int


@ms.process_model("udp")
class UdpProcess:
    def __init__(self) -> None:
        self.my_module: Optional[SimObj] = None
        self.my_node: Optional[SimObj] = None
        self.ip_module: Optional[SimObj] = None
        self.pr_handle = None

        self.stream_to_ip: int = -1
        self.stream_from_ip: int = -1
        self.stream_to_ip_obj: Optional[Stream] = None
        self.stream_from_ip_obj: Optional[Stream] = None

        self.sockets: Dict[int, UdpSocket] = {}
        self.next_dynamic_port: int = UDP_DYNAMIC_PORT_MIN

        self._stats_handle_recv_pps: ms.StatHandle = None
        self._stats_handle_send_pps: ms.StatHandle = None
        self._stats_handle_recv_bps: ms.StatHandle = None
        self._stats_handle_send_bps: ms.StatHandle = None

    @ms.transition("Wait", "Init", "c60aae4d-01b0-4884-844b-fac9c6bdb77f")
    def from_wait_to_init(self):
        return True

    @ms.transition("Init", "Idle", "92353864-2543-49a3-905d-4dd0b8e6c0bc")
    def from_init_to_idle(self):
        return True

    @ms.transition("Idle", "Idle", "7b11ea08-2ff8-438e-ae15-464e02b0609b")
    def from_idle_to_idle(self):
        return True

    # --------------------------------------------------------------- States --
    @ms.state_enter("Wait", begin=True)
    def enter_wait(self) -> None:
        module = ms.self_obj()
        if module is None:
            raise RuntimeError("UDP: missing module context during wait state")

        self.my_module = module
        self.my_node = ms.topo_parent(module)

        process = ms.pro_self()
        if process is None:
            raise RuntimeError("UDP: missing process context during registration")

        if self.my_node is None:
            raise RuntimeError("UDP: failed to resolve parent node for module registration")

        try:
            self.pr_handle = pr_register(
                self.my_node.get_id(),
                module.get_id(),
                process,
                "udp",
            )
            pr_attr_set(self.pr_handle, "protocol", AttrType.STRING, "udp")
        except Exception as exc:
            logger.warning("UDP: process registry registration failed: %s", exc)

        # 初始化统计量
        self._setup_stats()

        ms.intrpt_schedule_self(ms.sim_time(), 0)

    @ms.state_enter("Init")
    def enter_init(self) -> None:
        self.sockets.clear()
        self.next_dynamic_port = UDP_DYNAMIC_PORT_MIN
        self.stream_to_ip = -1
        self.stream_from_ip = -1
        self.ip_module = self._resolve_ip_module()

        ms.intrpt_schedule_self(ms.sim_time(), 0)

    @ms.state_exit("Init")
    def exit_init(self) -> None:
        if self.ip_module is None:
            logger.info("UDP: IP module not resolved; skipping protocol registration")
            return

        out_streams = ms.get_out_streams()
        self.stream_to_ip_obj = None
        for stream in _iter_streams(out_streams):
            if stream.dst is self.ip_module:
                self.stream_to_ip = stream.src_index
                self.stream_to_ip_obj = stream
                break

        in_streams = ms.get_in_streams()
        self.stream_from_ip_obj = None
        for stream in _iter_streams(in_streams):
            if stream.src is self.ip_module:
                self.stream_from_ip = stream.dst_index
                self.stream_from_ip_obj = stream
                break

        if self.stream_to_ip < 0 or self.stream_from_ip < 0:
            logger.warning(
                "UDP: failed to locate streams connected to IP module (to_ip=%s, from_ip=%s)",
                self.stream_to_ip,
                self.stream_from_ip,
            )
            return

        self._register_protocol_with_ip()

    @ms.state_enter("Idle")
    def enter_idle(self) -> None:
        return

    @ms.state_exit("Idle")
    def exit_idle(self) -> None:
        intr_type = ms.intrpt_type()
        if intr_type == INTRPT_TYPE_STRM:
            self._handle_stream_interrupt()
        elif intr_type == INTRPT_TYPE_REMOTE:
            self._handle_remote_interrupt()
        else:
            logger.debug("UDP: ignoring unexpected interrupt type %s", intr_type)

    # ---------------------------------------------------------- Interrupts --
    def _handle_stream_interrupt(self) -> None:
        stream_index = ms.intrpt_strm()
        try:
            packet = ms.pk_get(stream_index)
        except Exception as exc:
            logger.warning("UDP: failed to retrieve packet from stream %s: %s", stream_index, exc)
            return

        if packet is None:
            logger.warning("UDP: received empty packet from stream %s", stream_index)
            return

        if stream_index == self.stream_from_ip:
            self._handle_packet_from_ip(packet)
        else:
            self._handle_packet_from_app(packet, stream_index)

    def _handle_packet_from_ip(self, packet) -> None:
        ici = ms.intrpt_ici()
        if ici is None:
            logger.warning("UDP: missing ICI from IP layer; dropping packet")
            ms.pk_destroy(packet)
            return

        try:
            src_addr = int(ici.get_int("src address"))
        except Exception:
            logger.warning("UDP: missing src address in ICI; dropping packet")
            ms.pk_destroy(packet)
            return

        pkt_format = ms.pk_format(packet)
        if pkt_format != UDP_PACKET_FORMAT:
            logger.warning("UDP: unexpected packet format %s", pkt_format)
            ms.pk_destroy(packet)
            return

        try:
            header_obj = ms.pk_nfd_get_pointer(packet, "header")
            if not isinstance(header_obj, UdpHeader):
                raise TypeError(f"unexpected header object type {type(header_obj)!r}")
        except Exception as exc:
            logger.warning("UDP: failed to read UDP header: %s", exc)
            ms.pk_destroy(packet)
            return

        try:
            data_packet = ms.pk_nfd_get_packet(packet, "data")
        except Exception as exc:
            logger.warning("UDP: UDP packet missing data payload: %s", exc)
            ms.pk_destroy(packet)
            return

        src_port = header_obj.SrcPort
        dst_port = header_obj.DstPort

        if src_port <= 0 or dst_port <= 0:
            logger.warning("UDP: invalid ports src=%s dst=%s", src_port, dst_port)
            ms.pk_destroy(packet)
            return

        socket = self.sockets.get(dst_port)
        if socket is None:
            logger.debug("UDP: no socket bound to port %s; dropping packet", dst_port)
            ms.pk_destroy(packet)
            return

        if data_packet is None:
            logger.warning("UDP: packet missing payload; dropping")
            ms.pk_destroy(packet)
            return
        in_intf_idx = ici.get_int("in intf idx")
        self._forward_to_application(socket, data_packet, src_addr, src_port, in_intf_idx)
        ms.pk_destroy(packet)

    def _handle_packet_from_app(self, packet, stream_index: int) -> None:
        ici = ms.intrpt_ici()
        if ici is None:
            logger.warning("UDP: missing ICI from application; destroying packet")
            ms.pk_destroy(packet)
            return

        dst_addr = ici.get_int("remote address")
        dst_port = ici.get_int("remote port")
        if dst_addr is None or dst_port is None:
            logger.warning("UDP: missing remote address/port in ICI")
            ms.pk_destroy(packet)
            return

        local_port = ici.get_int("local port")
        if local_port is None or local_port < 0:
            local_port = 0
        else:
            socket = self._socket_by_stream(stream_index)
            if socket is not None:
                local_port = socket.local_port

        self._send_to_ip(packet, local_port, dst_addr, dst_port)

    def _handle_remote_interrupt(self) -> None:
        ici = ms.intrpt_ici()
        if ici is None:
            logger.warning("UDP: remote interrupt without ICI")
            return

        try:
            command = ici.get_string("command")
        except Exception as exc:
            logger.warning("UDP: failed to read command from ICI: %s", exc)
            return

        if command == "listen":
            self._handle_listen_command(ici)
        elif command == "close":
            self._handle_close_command(ici)
        else:
            logger.warning("UDP: unknown command %s", command)

    # ----------------------------------------------------------- Operations --
    def _handle_listen_command(self, ici) -> None:
        try:
            app_module_id = int(ici.get_int("app module id"))
        except Exception as exc:
            logger.warning("UDP: listen command without app module id: %s", exc)
            return

        app_module = ms.get_sim_obj(app_module_id)
        if app_module is None:
            logger.warning("UDP: listen command references unknown module id %s", app_module_id)
            return

        try:
            requested_port = int(ici.get_int("local port"))
        except Exception:
            requested_port = 0

        if requested_port <= 0:
            requested_port = self._allocate_dynamic_port()

        if requested_port in self.sockets:
            logger.warning("UDP: port %s already in use", requested_port)
            return

        to_app, from_app = self._streams_with_app(app_module)
        if to_app < 0 or from_app < 0:
            logger.warning("UDP: failed to resolve streams for app module %s", app_module_id)
            return

        socket = UdpSocket(
            local_port=requested_port,
            stream_to_app=to_app,
            stream_from_app=from_app,
            app_module=app_module,
        )
        self.sockets[requested_port] = socket
        logger.info("UDP: listening on port %s for module %s", requested_port, app_module_id)

    def _handle_close_command(self, ici) -> None:
        try:
            local_port = int(ici.get_int("local port"))
        except Exception as exc:
            logger.warning("UDP: close command without local port: %s", exc)
            return

        if local_port in self.sockets:
            del self.sockets[local_port]
            logger.info("UDP: closed socket on port %s", local_port)
        else:
            logger.debug("UDP: close command received for unused port %s", local_port)

    def _forward_to_application(
            self,
            socket: UdpSocket,
            packet,
            src_addr: int,
            src_port: int,
            in_intf_id: int,
    ) -> None:
        try:
            ici = ms.ici_create(UDP_INDICATION_ICI)
        except Exception as exc:
            logger.warning("UDP: failed to create UDP indication ICI: %s", exc)
            ms.pk_destroy(packet)
            return

        ici.set_int("remote address", int(src_addr))
        ici.set_int("remote port", int(src_port))
        ici.set_int("local port", int(socket.local_port))
        ici.set_int("in intf idx", in_intf_id)

        # 记录统计量
        self._stats_handle_recv_pps.record(1)
        self._stats_handle_recv_bps.record(ms.pk_total_size_get(packet))

        ms.ici_install(ici)
        ms.pk_send(packet, socket.stream_to_app)
        ms.ici_install(None)

    def _send_to_ip(self, packet, local_port: int, dst_addr: int, dst_port: int) -> None:
        if dst_port <= 0 or dst_port > UDP_PORT_MAX:
            logger.warning("UDP: invalid destination port %s; dropping packet", dst_port)
            ms.pk_destroy(packet)
            return

        if local_port <= 0 or local_port > UDP_PORT_MAX:
            local_port = self._allocate_dynamic_port()

        data_size_bits = int(ms.pk_total_size_get(packet) or 0)
        data_size_bytes = max(0, data_size_bits // 8)

        udp_packet = ms.pk_create_fmt(UDP_PACKET_FORMAT)
        header = UdpHeader(
            SrcPort=int(local_port),
            DstPort=int(dst_port),
            Length=UDP_HEADER_LENGTH + data_size_bytes,
            Checksum=0,
        )
        ms.pk_nfd_set_pointer(udp_packet, "header", header)
        ms.pk_nfd_set_packet(udp_packet, "data", packet)
        ms.pk_stamp(udp_packet)

        try:
            ici = ms.ici_create(IP_INDICATION_ICI)
        except Exception as exc:
            logger.warning("UDP: failed to create IP indication ICI: %s", exc)
            ms.pk_destroy(udp_packet)
            ms.pk_destroy(packet)
            return

        ici.set_int("dest address", int(dst_addr))
        ici.set_int("protocol", IP_PROTOCOL_UDP)

        if self.stream_to_ip < 0:
            logger.warning("UDP: stream to IP not ready; dropping outgoing packet")
            ms.pk_destroy(udp_packet)
            ms.pk_destroy(packet)
            return

        # 记录统计量
        self._stats_handle_send_pps.record(1)
        self._stats_handle_send_bps.record(ms.pk_total_size_get(udp_packet))

        ms.ici_install(ici)
        ms.pk_send(udp_packet, self.stream_to_ip)
        ms.ici_install(None)

    # ------------------------------------------------------- Helper Methods --
    def _streams_with_app(self, module: SimObj) -> Tuple[int, int]:
        to_app = -1
        from_app = -1

        for stream in _iter_streams(ms.get_out_streams()):
            if stream.dst is module:
                to_app = stream.src_index
                break

        for stream in _iter_streams(ms.get_in_streams()):
            if stream.src is module:
                from_app = stream.dst_index
                break

        return to_app, from_app

    def _socket_by_stream(self, stream_index: int) -> Optional[UdpSocket]:
        for socket in self.sockets.values():
            if socket.stream_from_app == stream_index:
                return socket
        return None

    def _allocate_dynamic_port(self) -> int:
        start = max(UDP_DYNAMIC_PORT_MIN, self.next_dynamic_port)
        for port in range(start, UDP_DYNAMIC_PORT_MAX + 1):
            if port not in self.sockets:
                self.next_dynamic_port = port + 1
                return port

        for port in range(UDP_DYNAMIC_PORT_MIN, start):
            if port not in self.sockets:
                self.next_dynamic_port = port + 1
                return port

        logger.error("UDP: no available dynamic ports")
        return UDP_DYNAMIC_PORT_MIN

    def _resolve_ip_module(self) -> Optional[SimObj]:
        module = self.my_module
        if module is None:
            return None

        parent = ms.topo_parent(module)
        if parent is None:
            return None

        try:
            return ip_support.find_node_ip_module(parent)
        except Exception as exc:
            logger.warning("UDP: failed to resolve IP module via helper: %s", exc)
            return None

    def _register_protocol_with_ip(self) -> None:
        try:
            ip_support.register_protocol(IP_PROTOCOL_UDP, "udp", self.stream_to_ip_obj, self.stream_from_ip_obj)
        except Exception as exc:
            logger.warning("UDP: failed to register protocol with IP: %s", exc)


    def _setup_stats(self):
        mode = ms.StatMode(
            mode=ms.StatCaptureMode.BUCKET,
            total_captures=100,
            agg=ms.StatAgg.SUM_PER_TIME
        )
        self._stats_handle_recv_bps = ms.register_stat("UDP.<plt_name>.<device_name>.recv_bps", mode)
        self._stats_handle_send_bps = ms.register_stat("UDP.<plt_name>.<device_name>.sent_bps", mode)
        self._stats_handle_recv_pps = ms.register_stat("UDP.<plt_name>.<device_name>.recv_pps", mode)
        self._stats_handle_send_pps = ms.register_stat("UDP.<plt_name>.<device_name>.send_pps", mode)



