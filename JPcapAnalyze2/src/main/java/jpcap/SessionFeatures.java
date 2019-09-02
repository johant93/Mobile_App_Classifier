package main.java.jpcap;

public class SessionFeatures {

	private String servername;
	private String src_IP;
	private String dst_IP;
	String tcp_src_port;
	String tcp_dst_port;
	String udp_src_port;
	String udp_dst_port;
	private String protocol;
	
	public SessionFeatures() {
	}
	
	public SessionFeatures(SessionFeatures sf){
		this.servername = sf.servername;
		this.src_IP = sf.src_IP;
		this.dst_IP = sf.dst_IP;
		this.tcp_src_port = sf.tcp_src_port;
		this.tcp_dst_port = sf.tcp_dst_port;
		this.udp_src_port = sf.udp_src_port;
		this.udp_dst_port = sf.udp_dst_port;
		this.protocol =sf.protocol;
	}

	public String getSrcIP() {
		return src_IP;
	}

	public void setSrcIP(String src_IP) {
		this.src_IP = src_IP;
	}

	public String getDstIP() {
		return dst_IP;
	}

	public void setDstIP(String dst_IP) {
		this.dst_IP = dst_IP;
	}

	public void setTcpSrcPort(String tcp_src_port) {
		this.tcp_src_port = tcp_src_port;
	}

	public void setTcpDstPort(String tcp_dst_port) {
		this.tcp_dst_port = tcp_dst_port;
	}

	public void setUdpSrcPort(String udp_src_port) {
		this.udp_src_port = udp_src_port;
	}

	public void setUdpDstPort(String udp_dst_port) {
		this.udp_dst_port = udp_dst_port;
	}

	public String getProtocol() {
		return protocol;
	}

	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}

	public String getServername() {
		return servername;
	}

	public void setServername(String servername) {
		this.servername = servername;
	}

	//TODO fix protocol 
	public String getDstPort(){
		if(protocol == null){
			return null;
		}
		if(protocol.equals("Tcp")){
			return  this.tcp_dst_port;
		}else{
			return  this.udp_dst_port;
		}
	}

	public String getSrPort(){
		if(protocol == null){
			return null;
		}
		if(protocol.equals("Tcp")){
			return  this.tcp_src_port;
		}else{
			return  this.udp_src_port;
		}
	}
}
