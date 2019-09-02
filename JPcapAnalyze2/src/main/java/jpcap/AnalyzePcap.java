package main.java.jpcap;

public class AnalyzePcap {

	public AnalyzePcap() {

	}

	public String run(String pcapFile) throws Exception{
		Session session = new Session(pcapFile);
		session.execute();

		boolean found = false;
		String serverName = null;
		for(PacketFeatures pf : session.getPacketsFeatures()){
			serverName = pf.getServerName();
			if(serverName != null){
				found = true;
				serverName = CheckAndSetServerName(serverName);
				session.setServerName(serverName);
				break;
			}
		}
		//TODO write to different list all the rest of the servers names
		if(! found || serverName == null){
			return null;
		}
		StatisticalFeatures stats = new StatisticalFeatures(session);
		String line;
		line = stats.getStat();
		return String.format("%s,%s,\n", line,serverName);

		//		SessionFeatures sf = session.getsFeatures();
		//		line = String.format("%s,%s,%s,%s,%s,%s,\n", sf.getSrcIP(), sf.getSrPort(),
		//				sf.getDstIP(), sf.getDstPort(), sf.getProtocol(), sf.getServername());
		//		return line;
	}

	private String CheckAndSetServerName(String serverName) {
		String result = null;
		if(serverName.contains("facebook")||serverName.contains("fbcdn")){
			result = "facebook";
		}else if(serverName.contains("cnn")){
			result = "cnn";
		}else if (serverName.contains("amazon")) {
			result = "amazon";
		}
		return result;
	}

}