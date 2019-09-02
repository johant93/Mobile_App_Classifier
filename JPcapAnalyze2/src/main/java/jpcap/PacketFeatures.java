package main.java.jpcap;

import java.util.List;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.TcpPacket.TcpHeader;
import org.pcap4j.packet.TcpPacket.TcpOption;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.TcpOptionKind;

public class PacketFeatures {

	SessionFeatures sessionFeaturs ;

	public SessionFeatures get_sessionFeaturs() {
		return sessionFeaturs;
	}
	
	public void setSessionFeaturs(SessionFeatures sf) {
		this.sessionFeaturs = sf;
	}

	private int tls_handshake_session_id_length; //
	private int tls_handshake_comp_methods_length; //
	private int tls_handshake_extension_len; //
	private int tls_handshake_cipher_suites_length; //
	private double tls_handshake_version; //
	private String tls_handshake_extensions_server_name; //

	private int ip_ttl; //

	private int tcp_window_size; //
	private int tcp_options_mss_val;   //
	private int tcp_options_wscale_shift;  //

	private boolean tcp_flags_ack; //
	private boolean tcp_flags_syn;  //
	private boolean tcp_flags_reset; //


	//TODO fix udp problem
	public void addFeaturs(Packet packet) {
		TcpPacket tcpPacket = packet.get(TcpPacket.class);
		if (tcpPacket == null) {
			UdpPacket udpPacket = packet.get(UdpPacket.class);
			return;
		}

		TcpHeader tcpHeader = tcpPacket.getHeader();
		tcp_flags_ack = tcpHeader.getAck();
		tcp_flags_syn = tcpHeader.getSyn();
		tcp_flags_reset = tcpHeader.getRst();
		tcp_window_size = tcpHeader.getWindowAsInt();
		tcp_window_size = tcpHeader.getWindow() & 0xffff;
		setOptions(tcpHeader.getOptions());
		if(packet.get(IpV4Packet.class) != null){
			ip_ttl = packet.get(IpV4Packet.class).getHeader().getTtlAsInt(); 
		}
		try {
			setTls(packet);
		} catch (Exception e) {
			
		}
	}

	private void setOptions(List<TcpOption> options){
		for(TcpOption option: options){
			TcpOptionKind kind = option.getKind();
			byte[] data = option.getRawData();
			if(kind == TcpOptionKind.WINDOW_SCALE){
				tcp_options_wscale_shift = (int) data[2] & 0xff;
			}else if(kind == TcpOptionKind.MAXIMUM_SEGMENT_SIZE){
				tcp_options_mss_val = (int) (data[2] & 0xff) * 256 + (data[3] & 0xff);
			}
		}
	}

	private void setTls(Packet packet) throws Exception {
		try {
			TcpPacket tcpPacket = packet.get(TcpPacket.class);
			if (tcpPacket == null) {
				return;
			}
			byte[] tcpData = tcpPacket.getRawData();
			if (tcpData == null || tcpData.length < 32 + 32) {
				return;
			}
			int offset = ((tcpData[12] & 0xF0) >> 4) * 4;
			// start of TLS
			if (tcpData[offset] != 0x16 || tcpData[offset + 1] != 0x03) {
				return;
			}
			double dv = (double)( tcpData[offset+2] & 0xff ) -1 ;
			double d = dv / 10;
			tls_handshake_version = 1 + d;
			// encrypted packet
			offset += 5;
			if (tcpData[offset] != 0x01) {
				return;
			}
			// ClientHello
			offset += 6; // random number
			offset += 32;
			// session ID
			int sLen = tcpData[offset] & 0xff;
			tls_handshake_session_id_length = sLen;
			offset += 1 + sLen;
			// Cipher suites
			sLen = getShort(tcpData, offset);
			tls_handshake_cipher_suites_length = sLen;
			offset += 2 + sLen;
			sLen = tcpData[offset] & 0xff;
			tls_handshake_comp_methods_length =sLen;
			offset += 1 + sLen;
			// Extensions
			sLen = getShort(tcpData, offset);
			if (sLen <= 0 || offset + sLen > tcpData.length) {
				return;
			}
			tls_handshake_extension_len = sLen;
			offset += 2;
			while (offset < tcpData.length) {
				int type = getShort(tcpData, offset);
				int length = getShort(tcpData, offset + 2);
				offset += 4;
				if (type == 0) {
					// server name
					offset += 2; // server list name
					offset++; // server type
					length = getShort(tcpData, offset);
					offset += 2;
					tls_handshake_extensions_server_name = new String(tcpData, offset, length);
					break;
				}
				offset += length;
			}
		} catch (Exception e) {
		}
	}

	private int getShort(byte[] data, int offset) {
		int b1 = data[offset] & 0xff;
		int b2 = data[offset + 1] & 0xff;
		int ret = b1 * 256 + b2;
		return ret;
	}

	public int getTlsSessionIdLength() {
		return tls_handshake_session_id_length;
	}

	public int getTlsCompMethodsLength() {
		return tls_handshake_comp_methods_length;
	}

	public int getTlsHandshakeExtensionLen() {
		return tls_handshake_extension_len;
	}

	public int getTlsHandshakeCipherSuitesLength() {
		return tls_handshake_cipher_suites_length;
	}

	public double getTlsHandshakeVersion() {
		return tls_handshake_version;
	}

	public String getServerName() {
		return tls_handshake_extensions_server_name;
	}

	public int getIpTtl() {
		return ip_ttl;
	}

	public int getTcpWindowSize() {
		return tcp_window_size;
	}

	public int getTcpOptionsMssVal() {
		return tcp_options_mss_val;
	}

	public int getTcp_optionsWscaleShift() {
		return tcp_options_wscale_shift;
	}

	public boolean isTcpFlagsAck() {
		return tcp_flags_ack;
	}

	public boolean isTcpFlagsSyn() {
		return tcp_flags_syn;
	}

	public boolean isTcpFlagsReset() {
		return tcp_flags_reset;
	}
}
