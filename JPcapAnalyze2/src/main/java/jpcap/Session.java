package main.java.jpcap;

import java.util.ArrayList;
import java.util.List;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

public class Session {
	private SessionFeatures m_sFeatures;
	private List<PacketFeatures> m_packets;
	private String m_filePath;

	public Session() {
		m_sFeatures = null;
		m_packets = new ArrayList<PacketFeatures>();
	}

	public Session(String filePath){
		m_sFeatures = null;
		m_packets = new ArrayList<PacketFeatures>();
		m_filePath = filePath;
	}

	public void addPacket(PacketFeatures pf){
		m_packets.add(pf);
	}

	public List<PacketFeatures> getPacketsFeatures() {
		return m_packets;
	}

	public SessionFeatures getsFeatures() {
		return m_sFeatures;
	}

	public void setsFeatures(SessionFeatures sFeatures) {
		this.m_sFeatures = sFeatures;
	}

	public String getFilePath() {
		return m_filePath;
	}

	public void setFilePath(String m_filePath) {
		this.m_filePath = m_filePath;
	}

	public void setServerName(String serverName){
		m_sFeatures.setServername(serverName);
	}

	public void execute() throws Exception {
		PcapHandle handle=null;
		try {
			handle = Pcaps.openOffline(m_filePath, TimestampPrecision.NANO);
		} catch (PcapNativeException e) {
			try {
				handle = Pcaps.openOffline(m_filePath);
			} catch (Exception e1) {
				System.out.println("reading file: "+ m_filePath+ " failed");
				return;
			}
		}
		Packet packet = handle.getNextPacketEx();
		SessionFeatures sf  = getServerDetails(packet);
		m_sFeatures = sf;

		while (true) {
			try {
				packet = handle.getNextPacketEx();
				PacketFeatures pf = new PacketFeatures();		
				pf.setSessionFeaturs(sf);
				pf.addFeaturs(packet);
				addPacket(pf);
			} catch (Exception e) {
				break;
			}
		}
		handle.close();
	}

	private SessionFeatures getServerDetails(Packet packet) {
		SessionFeatures sf = new SessionFeatures();
		TcpPacket tcpPacket = packet.get(TcpPacket.class);
		if (tcpPacket == null) {
			String port1 = packet.get(UdpPacket.class).getHeader().getSrcPort().toString();
			String port2 = packet.get(UdpPacket.class).getHeader().getDstPort().toString();
			sf.setUdpSrcPort(port1);
			sf.setUdpDstPort(port2);

			sf.setProtocol("Udp");
		} else {
			String port1 = packet.get(TcpPacket.class).getHeader().getSrcPort().toString();
			String port2 = packet.get(TcpPacket.class).getHeader().getDstPort().toString();
			sf.setTcpSrcPort(port1);
			sf.setTcpDstPort(port2);

			sf.setProtocol("Tcp");
		}

		String ip1 = packet.get(IpV4Packet.class).getHeader().getSrcAddr().toString();
		if (ip1.startsWith("/")) {
			ip1 = ip1.substring(1);
		}
		String ip2 = packet.get(IpV4Packet.class).getHeader().getDstAddr().toString();
		if (ip2.startsWith("/")) {
			ip2 = ip2.substring(1);
		}			
		sf.setSrcIP(ip1);
		sf.setDstIP(ip2);
		return sf;
	}

}
