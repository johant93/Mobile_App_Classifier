# pcap-feature-extractor
A code package which transforms pcap files into ML feature vectors.


Data folder structure:

Assuming a relevant pcap directory contains a .hcl file with label details.
This allows a non strict folder hierarchy i.e.  
data/  
----any_folder_order/  
--------relevant_folder1/  
------------label_data.hcl  
------------*.pcap  
----dummy_folder_name/  
--------relevant_folder2/  
------------label_data.hcl  
------------*.pcap  
