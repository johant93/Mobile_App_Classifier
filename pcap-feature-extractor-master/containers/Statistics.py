import sys
from containers.PacketContainer import PacketContainer
from utils.read_pcap import gen_data_frame, gen_flows_up_down, read_pcap
from containers.Flow import Flow
import numpy as np
import statistics as stat
from scipy.stats import skew, kurtosis
from containers.Session import Session

import pandas as pd

"""
FIX:
"""

"""
Class fields:
sess - Session DataFrame
"""

class Statistics(PacketContainer):

    def __init__(self):
        pass
        #session = Session()
        #self.sess = session.get_sess()


# compute mean, variance, standard deviation, skew and kurtosis statistics for packets feature.
    def calcul_stats(self,packets_feature):
        mean = stat.mean(packets_feature)
        if len(packets_feature)>2:
            var = stat.variance(packets_feature,mean)
            std = stat.stdev(packets_feature)
            kurt = kurtosis(packets_feature)
            ske = skew(packets_feature)
        else:
            var = 1
            std = 1
            kurt = 1
            ske = 1
        stats = np.array([mean, var, std, kurt, ske])
        return stats

    def get_all_statistics(self,sess):
        stats_features = np.array([])
        features = ['frame.len','frame.time_delta','frame.time_epoch','ip.len','ip.ttl','tcp.len','tcp.hdr_len','tcp.flags.push',
                    'tcp.flags.syn','tcp.flags.ack','tcp.flags.reset','tcp.window_size']
        for feature in features:
            newFeatures = self.calcul_stats(sess[feature])
            stats_features = np.append(stats_features,newFeatures)

        return stats_features
