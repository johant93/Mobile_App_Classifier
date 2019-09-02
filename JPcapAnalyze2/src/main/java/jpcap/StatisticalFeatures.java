package main.java.jpcap;

import org.apache.commons.math3.stat.descriptive.moment.Kurtosis;
import org.apache.commons.math3.stat.descriptive.moment.Mean;
import org.apache.commons.math3.stat.descriptive.moment.Skewness;
import org.apache.commons.math3.stat.descriptive.moment.StandardDeviation;
import org.apache.commons.math3.stat.descriptive.moment.Variance;
import org.apache.commons.math3.stat.descriptive.rank.Max;
import org.apache.commons.math3.stat.descriptive.rank.Min;
import org.apache.commons.math3.stat.descriptive.rank.Percentile;

public class StatisticalFeatures {
	private int numOfElements;
	private double[] session_id_length;
	private double[] comp_methods_length;
	private double[] extension_len;
	private double[] cipher_suites_length;
	private double[] handshake_version;
	private double[] ip_ttl;
	private double[] window_size;
	private double[] mss_val;
	private double[] wscale_shift;
	private double[] flags_ack; 
	private double[] flags_syn;  
	private double[] flags_reset;
	
	public StatisticalFeatures(Session session) {
		numOfElements = session.getPacketsFeatures().size();
		session_id_length = new double[numOfElements];
		comp_methods_length = new double[numOfElements];
		extension_len = new double[numOfElements];
		cipher_suites_length = new double[numOfElements];
		handshake_version = new double[numOfElements];
		ip_ttl = new double[numOfElements];
		window_size = new double[numOfElements];
		mss_val = new double[numOfElements];
		wscale_shift = new double[numOfElements];
		flags_ack = new double[numOfElements];
		flags_syn = new double[numOfElements];
		flags_reset = new double[numOfElements];

		int i=0;
		for(PacketFeatures pf: session.getPacketsFeatures()){
			session_id_length[i] = pf.getTlsSessionIdLength();
			comp_methods_length[i] = pf.getTlsCompMethodsLength();
			extension_len[i] = pf.getTlsCompMethodsLength();
			cipher_suites_length[i] = pf.getTlsHandshakeCipherSuitesLength();
			handshake_version[i] = pf.getTlsHandshakeVersion();
			ip_ttl[i] = pf.getIpTtl();
			window_size[i] = pf.getTcpWindowSize();
			mss_val[i] = pf.getTcpOptionsMssVal();
			wscale_shift[i] = pf.getTcp_optionsWscaleShift();
			flags_ack[i]  = pf.isTcpFlagsAck() ? 1 : 0;
			flags_syn[i]  = pf.isTcpFlagsSyn() ? 1 : 0;
			flags_reset[i]  = pf.isTcpFlagsReset() ? 1 : 0;
			i++;
		}
	}

	public String getStat() {
		String line;
		line = String.format("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s", calculate(session_id_length), calculate(comp_methods_length),
				calculate(extension_len), calculate(cipher_suites_length), calculate(handshake_version),
				calculate(ip_ttl), calculate(window_size), calculate(mss_val),calculate(flags_ack), calculate(flags_syn), calculate(flags_reset) ,
				calculate(wscale_shift));
		return line;
	}

//	private String calculate(double[] array) {
//		String result;
//		result = String.format("%s,%s,%s,%s,%s,%s,%s,%s", calcMean(array), calcVariance(array),
//				calcMax(array), calcMin(array), calcStandardDeviation(array),calcSkew(array),
//				calcKurtosis(array), calcPercentiles(array));
//		return result;
//	}

	private String calculate(double[] array) {
		String result;
		result = String.format("%s,%s,%s,%s,%s", calcMean(array), calcVariance(array),
				calcStandardDeviation(array),calcSkew(array),
				calcKurtosis(array));
		return result;
	}
	
	private double calcMean(double[] values) {
		Mean mean = new Mean();
		return isNaNFix(mean.evaluate(values));
	}

	private double calcVariance(double[] values) {
		Variance variance = new Variance();
		return isNaNFix(variance.evaluate(values));		
	}

	private double calcStandardDeviation(double[] values) {
		StandardDeviation sd = new StandardDeviation();
		return isNaNFix(sd.evaluate(values));		
	}

	private double calcSkew(double[] values) {
		Skewness skew = new Skewness();
		return isNaNFix(skew.evaluate(values));
	}

	private double calcKurtosis(double[] values) {
		Kurtosis kurtosis = new Kurtosis();
		return isNaNFix(kurtosis.evaluate(values));
	}

	private double isNaNFix(double val){
		return Double.isNaN(val) ? 1 : val;		
	}

}
