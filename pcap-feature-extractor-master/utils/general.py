import os
from path import Path as path
from os import listdir
from os.path import isfile, join
from utils.read_pcap import read_pcap
import numpy as np
import csv

def cleanup_pyc(DIRECTORY):
    d = path(DIRECTORY)
    files = d.walkfiles("*.pyc")
    for file in files:
        file.remove()
        print ("Removed {} file").format(file)


"""
Assuming a relevant pcap directory contains a .hcl file with label details.
This allows a non strict folder hierarchy i.e.
data/
    any_folder_order/
        relevant_folder1/
            label_data.hcl
            *.pcap
    dummy_folder_name/
        relevant_folder2/
            label_data.hcl
            *.pcap

-----------------
Currently assuming that if a single pcap file in a directory is a session
pcap, all other pcap files in the directory are also session pcaps.
Therefor the if clause checks if any of the pcap files in a given
directory is a session pcap. If true the directory is added to the list
of relevant directories.
"""
def gen_data_folders(PARENT_DIRECTORY):
    d = path(PARENT_DIRECTORY)
    l = []
    for root, dirs, files in os.walk(d):
        # if any(file.endswith('.hcl') for file in files) and any(is_pcap_session(file) for file in files):
        if any(is_pcap_session(join(root, file)) for file in files):
            l.append(path.abspath(root))
    return l

""" Returns a list of pcap file names from a given folder """
def gen_pcap_filenames(folder_name):
        # return [join(folder_name, f) for f in listdir(folder_name) if (isfile(join(folder_name, f)) and ('hcl' not in f) and ('pcap' in f)) ]
        file_names = [join(folder_name, f) for f in listdir(folder_name) if (isfile(join(folder_name, f)) and ('hcl' not in f) and (f.endswith('pcap'))) ]
        # print file_names
        return file_names


"""
Write a list of pcap file names to a given filename
DOES NOT WORK YET
"""
def write_pcap_filenames(filename_list, file_name):
        with open(file_name, "wb") as f:
            writer = csv.writer(f)
            writer.writerow(filename_list)




"""
generate label per server_name groupe

0 = facebook app (serveur name group from facebook app)
1 = amazon app
2 = CNN app
"""
def gener_label(pcap_path):
    facebook_ssl_list = np.array(['www.facebook.com','edge-mqtt.facebook.com','scontent-frx5-1.xx.fbcdn.net','video-frx5-1.xx.fbcdn.net',
                                  'static.xx.fbcdn.net','m.facebook.com','graph.facebook.com','lithium.facebook.com','b-graph.facebook.com',
                                  'scontent-lhr3-1.xx.fbcdn.net','video-lhr3-1.xx.fbcdn.net','external-lhr3-1.xx.fbcdn.net','api.facebook.com'])


    amazon_ssl_list = np.array(['www.amazon.com','msh.amazon.com','api.amazon.com','images-na.ssl-images-amazon.com'
                               's.amazon-adsystem.com','aax-us-east.amazon-adsystem.com','fls-na.amazon.com','unagi-na.amazon.com',
                               'transient.amazon.com','mads.amazon-adsystem.com','m.media-amazon.com','arcus-uswest.amazon.com','completion.amazon.com',
                               'cognito-identity.us-east-1.amazonaws.com','mobileanalytics.us-east-1.amazonaws.com'
                               ])
    cnn_ssl_list = np.array(['www.cnn.com','smetrics.cnn.com','data.cnn.com','tvem.cdn.turner.com','cnnios-f.akamaihd.net','edition.cnn.com',
                             'agility.cnn.com','cdn.cnn.com','cnn.sdk.beemray.com','edition.i.cdn.cnn.com','cnn.bounceexchange.com',
                             ])

    if pcap_path.endswith('.pcap'):
        df = read_pcap(pcap_path, fields=['ssl.handshake.extensions_server_name'])
        sni_count = len(df[df['ssl.handshake.extensions_server_name'].notnull()])
        if sni_count == 1:
            server_name = df.iloc[0]['ssl.handshake.extensions_server_name']

            if "facebook" in server_name or "fbcdn" in server_name:
                return 0

            elif "amazon" in server_name :
                return 1

            elif "cnn" in server_name:
                return 2

    return -1


def remove_UnknowSSL(df):
    df = df[df['label'] != -1]
    return df

"""
Labels per combination:
    os = { Linux, Windows, OSX }
    browser = { Chrome, FireFox, IExplorer }
    application = { , }
    service = { , }

    0 = (Linux, Chrome)
    1 = (Linux, FireFox)
    2 = (Windows, Chrome)
    3 = (Windows, FireFox)
    4 = (Windows, IExplorer)
    5 = (OSX, Safari)

"""
def gen_label(device, browser, application, service):
    """
    if os == 'Linux':
        if browser == 'Chrome':
            return 0
        elif browser == 'FireFox':
            return 1
    elif os == 'Windows':
        if browser == 'Chrome':
            return 2
        elif browser == 'FireFox':
            return 3
        elif browser == 'IExplorer':
            return 4
    elif os == 'OSX':
        if browser == 'Safari':
            return 5
    """
    if device == 'iphone7':
        return 0
    elif device == 'OnePlus':
        return 1


"""
Parse a folder name and return the os + browser
Currently returns os only.
Assumes the following format:
L_cyber_chrome_09-17__11_38_11
"""
def parse_folder_name(folder_name):
    temp = folder_name.split(os.sep)
    temp.reverse()
    tokens = temp[0].split('_')
    if tokens[0] == 'face':
        return 'facebook'
    elif tokens[0] == 'am':
        return 'amazon'
    elif tokens[0] == 'cnn':
        return 'cnn'
    elif tokens[0] == 'iphone7':
        return 'iphone7'
    elif tokens[0] == 'OnePlus':
        return 'OnePlus'

""" Return True if the given pcap is a session """
def is_pcap_session(pcap_path):
    if pcap_path.endswith('.pcap'):
        df = read_pcap(pcap_path, fields=['frame.time_epoch','ssl.handshake.extensions_server_name'])
        sni_count = len(df[df['ssl.handshake.extensions_server_name'].notnull()])
        if sni_count == 1:
            return True
    return False

""" Replace space with underscore for all folder and file names """
def space_to_underscore(ROOT_FOLDER):
        d = path(ROOT_FOLDER)


        for root, dirs, files in os.walk(d):
            # print 'In ' + repr(str(root))
            # print '================='

            for filename in os.listdir(root): # parse through file list in the current directory
                # print 'Filename: ' + repr(str(filename))
                # print '================='

            	if filename.find(" ") > 0: # if an underscore is found
                    newfilename = filename.replace(' ','_')
                    # print 'newfilename: ' + repr(str(newfilename))

                    os.rename(join(root, filename), join(root, newfilename))
