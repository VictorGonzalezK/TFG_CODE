#from asyncore import write
#from subprocess import STARTF_USESTDHANDLES
from zipfile import ZipFile
from io import TextIOWrapper
import csv
import pandas as pd
from FeatureExtraction import *
from SQL_Manager import *
import time
from collections import Counter
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#Set file name
file_name = "../Data/Webpages_Classification_train_data.csv.zip"

#Create the SQL table for tokens
tokens_table = "Tokens1"
create_table(tokens_table)
#Create the SQL Table
table_name = "Table1"
create_table(table_name)
start_time = time.time()
u_counter = 0
cont  = True
#Open the zip file in READ mode
with ZipFile(file_name, 'r') as zip:
    #Open the csv file inside
    with zip.open('Webpages_Classification_train_data.csv', mode='r') as file:
        #Get the reader
        reader = csv.DictReader(TextIOWrapper(file,"utf-8"))
        for i in range(30000):
            row = next(reader)
            #To recuperate at some point in a known url
                        
            if u_counter >150:
                break
            
            if i<1177:
                continue

            url = row["url"]
            if url == "http://www.roxyrivera.com/": cont=False
            if cont: continue
            

            malicious = 1 if row["label"]=="bad" else 0
            if malicious == 0: continue
            checker = check_table(url, table_name)
            if checker == 1:
                print("Already in table")
                continue
            
            dict = {}
            dict["url"] = url
            dict["malicious"] = malicious
            print("\n"+url)
            
            feature_start = time.time()
            #Connection Features
            dict.update(get_networkInfo(url))
            if len(dict)>2:
                #Content Features
                dict.update(get_webContentInfo(url))
            
                #Lexical Features
                tokens_dict={}
                tokens_dict["url"] = url
                tokens_dict["malicious"] = malicious
                lexical_dict, t_dict = get_lexicalf(url)
                tokens_dict.update(t_dict)
                dict.update(lexical_dict)
                
                #DNS Features
                ns_list = []
                dns_dict = get_DNSinfo(url)
                if "ns_list" in dns_dict.keys():
                    ns_list = dns_dict.pop("ns_list")
                if "ipaddrlist" in dns_dict.keys():
                    ip_Addr = dns_dict.pop("ipaddrlist")
                    count = 0
                    for addr in ip_Addr:
                        count+=1
                        dns_dict["IP_Adrr_"+str(count)]=addr
                
                dict.update(dns_dict)
                w_ns = []
                #Whois Features
                w_dict = get_whoisinfo(url)
                if "name_servers" in w_dict.keys():
                    w_ns = w_dict.pop("name_servers")
                if "w_status" in w_dict.keys():
                    w_status = w_dict.pop("w_status")
                    if w_status!=None:
                        count = 0
                        for stat in w_status:
                            count+=1
                            dns_dict["w_status_"+str(count)]=stat
                try:
                    if len(w_ns)>0 and len(ns_list)>0:
                        dict["NameServers_coherence"] = 1 if (Counter(w_ns)==Counter(ns_list)) else 0
                except:
                    pass
                dict.update(w_dict)
                
                u_counter +=1
                print("Added: ", u_counter)

                #Make insertion
                res = make_insertion(dict, table_name)
                if res==1:
                    table_name = table_name[:5]+str(int(table_name[5])+1)
                    create_table(table_name)
                    res = make_insertion(dict, table_name)
                
                
                tres = make_insertion(tokens_dict, tokens_table)
                if tres==1:
                    tokens_table = tokens_table[:6]+str(int(tokens_table[6])+1)
                    create_table(tokens_table)
                    tres = make_insertion(tokens_dict, tokens_table)
                
                feature_end = time.time()

                if (feature_end - feature_start)>30:
                    print("Enought time go next")
                    continue
                
                print("\n5s Pause")
                time.sleep(5)

                if i>1 and i%10 == 0:
                    print("\n30s Pause")
                    time.sleep(30)
            
            
        file.close()
    zip.close()

end_time = time.time()

temp = (end_time - start_time)
hours = temp//3600
temp = temp - 3600*hours
minutes = temp//60
seconds = temp - 60*minutes

print("\nTime spend: %d:%d:%d" % (hours, minutes, seconds))
print("Last url: ", url)
print("Url position: ", i)