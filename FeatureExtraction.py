from tkinter.messagebox import NO
import whois                #Module to produce parsed WHOIS data
import tldextract           #Separate the domain subdomain and top-level
import time                 #timer
import socket               #Get the ip of an url
import json                 #Used to load data as a dictionary
from collections import Counter #Counter function
import re                   #Library for string management
import requests             #Manage HTTP packets

from urllib.parse import urlsplit
import dns.resolver
import datetime
from bs4 import BeautifulSoup
import geoip2.database
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_lexicalf (url):
    
    #print("Splitting URL in hostname/path")

    ext = tldextract.extract(url)
    subdomain = ext.subdomain
    domain = ext.domain
    TLD = ext.suffix

    url_split= urlsplit(url, allow_fragments=False)
    scheme = url_split.scheme
    if (re.sub("[^a-zA-Z]+","",scheme)=="") and (url[:2]!="//"):
        url_correction = "//"+url
        url_split = urlsplit(url_correction, allow_fragments=False)
        scheme = url_split.scheme
    netloc = url_split.netloc
    path = url_split.path
    query = url_split.query
    num_param = len(query.split("&"))
    complete_path = path
    if query != "":
        complete_path += "?"+query
    else:
        query = "No Query"
    
    
    
    #print("Domain and URL lenghts")
    len_hostname = len(netloc)
    len_TLD = len(TLD)
    len_subdomain = len(subdomain)
    len_domain = len(domain)
    len_domtld = len(domain+"."+TLD)
    len_url = len(url)
    len_path = len(complete_path)
    #Length of the first subdirectory in path
    len_fsubdir = 0
    if len(path) > 1:
        first_subdirectory = path.split("/")[1]
        len_fsubdir = len(first_subdirectory)

    #print("Tokenize Hostname")
    tokens_host= list(filter(None,re.split(r'\W+',netloc)))
    num_tokens_host = len(tokens_host)
    average_tokenslenhost = 0
    if num_tokens_host>0:
        tokens_lenhhost = [len(i) for i in tokens_host]
        average_tokenslenhost = sum(tokens_lenhhost)/len(tokens_lenhhost)
        average_tokenslenhost = round(average_tokenslenhost, 3)
    
    #print("Tokenize Path")
    tokens_path = list(filter(None,re.split(r'\W+',complete_path)))
    num_tokenspath = len(tokens_path)
    average_tokenslenpath = 0
    if num_tokenspath>0:
        tokens_lenpath = [len(i) for i in tokens_path]
        average_tokenslenpath = sum(tokens_lenpath)/len(tokens_lenpath)
        average_tokenslenpath = round(average_tokenslenpath, 3)

    #print("Characterss frequency")
    #frequency of each char in url
    char_freq = Counter(url.lower())

    #print("Number of characters")
    #number of dots in url
    num_dotsurl = url.count(".")
    #replace by an empty space all non-alphabet in a string
    alphabetic_url = re.sub("[^a-zA-Z]+","",url) 
    alphabetic_domain = re.sub("[^a-zA-Z]+","",domain)
    #Number of alphas in url/domain
    num_letters_url = len(alphabetic_url)
    num_letters_domain = len(alphabetic_domain)
    #number of unique letters/characters in url
    num_uniqletters_url = len(set(alphabetic_url))
    num_uniqchar_url = len(set(url))
    #number of unique letters/characters in domain
    num_uniqletters_domain = len(set(alphabetic_domain))
    num_uniqchar_domain = len(set(domain))
    #Number of digits in url/domain
    num_digits_url = len(re.sub("[^0-9]", "", url))
    num_digits_domain = len(re.sub("[^0-9]", "", domain)) 
    #Number of slashes / in path 
    num_slash_path = path.count("/")
    #Number of non-alpha non-digit char in url
    num_otherchar_url = len_url-(num_letters_url+num_digits_url)
    #Ratios of the URL char types
    pc_letters = num_letters_url/len_url
    pc_letters = round(pc_letters, 3)
    pc_digits = num_digits_url/len_url
    pc_digits = round(pc_digits, 3)
    pc_other = num_otherchar_url/len_url
    pc_other = round(pc_other, 3)

    #print("Booleans")
    #If domain is an IPv4
    bool_ip = 1 if re.fullmatch('\d+\.\d+\.\d+\.\d+\.*', domain) else 0
    #If protocol is https
    bool_https = 1 if (scheme == "https") else 0
    #Does hostname contains server or client
    bool_server = 1 if "server" in netloc else 0
    bool_client = 1 if "client" in netloc else 0
    
    
    dict= {"subdomain":subdomain, "domain":domain, "TLD":TLD, "scheme":scheme, "netloc":netloc, "path":path, "complete_path":complete_path, 
    "num_param":num_param, "len_hostname":len_hostname, "len_TLD":len_TLD, "len_subdomain":len_subdomain, "len_domain":len_domain, "len_domtld":len_domtld, "len_url":len_url, 
    "len_path":len_path, "len_fsubdir":len_fsubdir, "num_tokens_host":num_tokens_host, "average_tokenslenhost":average_tokenslenhost, "num_tokenspath":num_tokenspath,
    "average_tokenslenpath":average_tokenslenpath, "num_dotsurl":num_dotsurl, "num_letters_url":num_letters_url, "num_letters_domain":num_letters_domain,
    "num_uniqletters_url":num_uniqletters_url, "num_uniqchar_url":num_uniqchar_url, "num_uniqletters_domain":num_uniqletters_domain, "num_uniqchar_domain":num_uniqchar_domain,
    "num_digits_url":num_digits_url, "num_digits_domain":num_digits_domain, "num_slash_path":num_slash_path, "num_otherchar_url":num_otherchar_url, "pc_letters":pc_letters,
    "pc_digits":pc_digits, "pc_other":pc_other, "bool_ip":bool_ip, "bool_https":bool_https, "bool_server":bool_server, "bool_client":bool_client}
    
    if query != "No Query":
        dict["query"]=query
    
    dict_tokens = {}
    for i in tokens_host:
        var_name = "host_"+i
        dict_tokens[var_name] = 1 if var_name not in dict_tokens.keys() else dict_tokens[var_name]+1
    
    for i in tokens_path:
        var_name = "path_"+i
        dict_tokens[var_name] = 1 if var_name not in dict_tokens.keys() else dict_tokens[var_name]+1
    
    #just alphanumeric on the name
    transformdict = {"~":"tilde", "`":"graveAccent", "!":"exclamationMark", "@":"at", "#":"pound", "(":"oParenthesis", ")":"cParenthesis", "_":"underscore",
    "$":"dollar", "%":"percent", "^":"carat", "&":"ampersand", "*":"asterisk", "-":"hyphen", "+":"plus", "=":"equals", "{":"oBrace", "}":"cBrace", 
    "[":"oBracket", "]":"cBracket", "|":"pipe", ":":"colon", ";":"semicolon", "<":"less", ",":"comma", ">":"greater", ".":"dot", "?":"question", "/":"fSlash", "\\":"bSlash"}
    
    for i in char_freq.keys():
        if i.isalnum():
            var_name = "freq_"+i
        else:
            var_name = "freq_"+transformdict[i]
        dict[var_name] = char_freq[i]
    
    return dict, dict_tokens
    
def get_whoisinfo(url):
    #Get whois information
    #Sometimes fails to detect the data if not in the crrect format ex:"upf"
    #Can have more than one dates being then an array
    dict={}
    try:
        dict["w_completeness"] = 0
        w = whois.whois(url)
        dict["w_country"] = w.get("country")
        if type(w.creation_date) == list:
                dict["reg_date"] = w.creation_date[0]
        else:
            dict["reg_date"] = w.creation_date
        
        if type(w.updated_date) == list:
                dict["lst_update"] = w.updated_date[0]
        else:
            dict["lst_update"] = w.updated_date
        
        if type(w.expiration_date) == list:
                dict["exp_date"] = w.expiration_date[0]
        else:
            dict["exp_date"] = w.expiration_date
        
        dict["resgistrar"] = w.get("registrar")
        dict["name_servers"] = w.name_servers
        dict["c_nameserver"]= len(w.name_servers)
        dict["w_status"] = w.get("status")              #multiple status check https://www.icann.org/resources/pages/epp-status-codes-2014-06-16-en
        # registrant = 
        dict["w_completeness"] = 1
    except:
        print("whois Failed")
        pass
    return dict

def get_DNSinfo(url):
    ext = tldextract.extract(url)
    url_split= urlsplit(url, allow_fragments=False)
    domain = url_split.netloc
    hostname = ext.registered_domain
    asn_database = geoip2.database.Reader('GeoLite2-ASN.mmdb')
    country_database = geoip2.database.Reader('GeoLite2-Country.mmdb')
    dict={}
    try:
        dns_start = time.time()
        result = dns.resolver.resolve(domain, "A", lifetime = 5)                 #return all known IPv4 addresses
        dns_end = time.time()
        t_dnslookup = (dns_end - dns_start)                         #dns lookup time in ms
        dict["t_dnslookup"]=t_dnslookup             
        ttl_a = result.rrset.ttl                                    #ttl of a record
        dict["ttl_a"]=ttl_a
        
        n_ips =0
        ipaddrlist  = []
        for ipval in result:
            ipaddrlist.append(ipval.to_text())
            n_ips +=1                                                #number of resolved ips for domain
        dict["n_ips"] = n_ips
        dict["ipaddrlist"] = ipaddrlist                        
        ip_resolve = 1
    except:
        ip_resolve = 0
        pass
    #asn
    try:
        ASN = set()
        for ip in ipaddrlist:
            response = asn_database.asn(ip)
            ASN.add(response.autonomous_system_number) 
        dict["same_ASN"] = 1 if len(ASN)==1 else 0
        dict["ASN"] = list(ASN)[0]
    except:
        pass
    try:
        response = country_database.country(ipaddrlist[0])
        dict["host_iso"] = response.country.iso_code
        dict["host_country"] = response.country.name
    except:
        pass
    #if ip_resolve == 1:
        #check fluxiness
        """
        try:
            print("Fluxiness Calculation Time: "+str(ttl_a)+"s")
            time.sleep(ttl_a)
            result2 = dns.resolver.resolve(domain, "A", lifetime = 5)
            fluxiness_IP = []
            for ipval2 in result2:
                fluxiness_IP.append(ipval2.to_text())
            total_numIPs = len(set(fluxiness_IP).union(set(ipaddrlist)))
            dict["IP_Fluxiness"] = round(total_numIPs / n_ips, 3)
        except:
            pass
        """
    try:
        aresult = dns.resolver.resolve_address(ipaddrlist[0], lifetime = 5)              #PTR
        c=0
        for addr in aresult:
            a=addr.to_text()
            c+=1
            dict["PTR_Addr"+str(c)] = a
        dict["bool_PTR"] = 1
    except:
        dict["bool_PTR"] = 0
        pass

    try:
        nameservers = dns.resolver.resolve(hostname,'NS', lifetime = 5)
        ttl_ns = nameservers.rrset.ttl                              #ttl of ns lookup
        dict["ttl_ns"] = ttl_ns
        num_ns=0
        ns_list=[]
        for server in nameservers:
            ns = server.target.to_text()
            ns_list.append(ns)
            host,alias,nsiplist = socket.gethostbyname_ex(ns)
            num_ip_ns = len(nsiplist)
            num_ns+=1
            dict["num_ip_NS"+str(num_ns)] = num_ip_ns
        dict["num_ns"] = num_ns
        dict["ns_list"] = ns_list
    except:
        pass

               
    return dict
    
def get_networkInfo(url):
    dict={}
    try:
        print("Send HTML Request")
        r = requests.get(url,timeout=5, verify=False) #use parameter timeout=1 to stop waiting for a response verify to ignore ssl certificate in https
        r.raise_for_status()            #gets the status  200=ok 4xx=client error 5xx= server error raise error
        dict["download_sec"] = r.elapsed.total_seconds()    #time between request and response
        if "server" in r.headers.keys():
            dict["server_OS"] = r.headers["server"]
        if "content-length" in r.headers.keys():
            dict["h_contlen"] = r.headers["content-length"]
        if "last-modified" in r.headers.keys():
            dict["h_lastmod"] = r.headers["last-modified"]
        if "transfer-encoding" in r.headers.keys():
            dict["h_tranenc"] = r.headers["transfer-encoding"]
        dict["final_contlen"] = len(r.content)  #len of bytes content decompressed
        dict["times_redirect"] = len(r.history)        #track redirection, list of all redirections
        dict["final_url"] = r.url
        
    except requests.exceptions.RequestException as e:
        print(e)
        print("Connection not established")
        pass

    return dict

def get_webContentInfo(url):
    dict={}
    try:
        print("Send Content Request")
        r = requests.get(url,timeout=5,verify=False) #use parameter timeout=1 to stop waiting for a response
        r.raise_for_status()            #gets the status  200=ok 4xx=client error 5xx= server error raise error
        web_content = r.text              #get web content
        #parsing the web content
        #web_content = open("text.txt", "r", encoding="utf8").read()
        dict["c_script"] = (web_content.count("</script>"))       #num java scripts
        dict["c_htmlTag"] = (web_content.count("</html>"))          #number of html tags
        dict["c_nlines"] = (len(web_content.split("\n")))        #numer of lines
        dict["c_iframe"] = (web_content.count("</iframe>"))      #number of iframes
        dict["c_object"] = (web_content.count("</object>"))      #number of objects
        dict["c_hyperlink"] = (web_content.count("</a>"))            #number of Hyperlynk
        dict["c_wopen"] = (web_content.count("window.open("))    #count window.open
        dict["c_embed"] = (web_content.count("<embed"))          #count external objects in the web
        dict["c_jredirect"] = (web_content.count("location.replace("))    #search for redirections in the web
        #Search for suspicious Java Script functions
        dict["c_escape"] = (web_content.count("escape("))
        dict["c_eval"] = (web_content.count("eval("))
        dict["c_link"] = (web_content.count("link("))
        dict["c_unescape"] = (web_content.count("unescape("))
        dict["c_exec"] = (web_content.count("exec("))
        dict["c_search"] = (web_content.count("search("))

        #Get text
        soup = BeautifulSoup(web_content, features="html.parser")
        # kill all script and style elements
        for script in soup(["script", "style"]):
            script.extract()    # rip it out
        # get text
        text = soup.get_text()
        # break into lines and remove leading and trailing space on each
        lines = (line.strip() for line in text.splitlines())
        # break multi-headlines into a line each
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        # drop blank lines
        text = '\n'.join(chunk for chunk in chunks if chunk)
        if len(text)<15530:
            dict["full_text"] = text
        else:
            dict["full_text"] = text[0:15530]

    except:
        print("Can't access the content")
        pass

    return dict
