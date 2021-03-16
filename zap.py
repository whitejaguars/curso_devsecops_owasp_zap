#!/usr/bin/python
'''
[properties]
@author: Mario Robles
@name: OWASP ZAP
@id: zap
@description: Run OWASP ZAP
@syntax: zap
@type: integration
@impact: intrusive
@service: [http,https]
@return_type: vuln
[properties]
type = [function,exploit,integration,tool]
impact = [safe,intrusive,dos]
service = [ssh,ftp,smtp,pop,imap,web,http,https,smb,tcp-##,udp-##]
return_type = [vuln,asset,boolean,null]
'''
try:
    import subprocess,re,platform, sys, time, pickle , os, random
    from datetime import datetime, timedelta
    from zapv2 import ZAPv2
except ImportError as e:
    print("[ X ] Missing libraries need to be installed: "+str(e))
    print("      Installing python ZAP")
    print("      pip install python-owasp-zap-v2.4")

class bcolors:
    WHITE = '\033[1;37m'
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    ORANGE = '\033[93m'
    RED = '\033[91m'
    YELLOW = '\033[1;33m'
    PURPLE = '\033[0;35m'
    ENDC = '\033[0m'
    BOLD = "\033[;1m"
    black='\033[30m'
    red='\033[31m'
    green='\033[32m'
    orange='\033[33m'
    blue='\033[34m'
    purple='\033[35m'
    cyan='\033[36m'
    lightgrey='\033[37m'
    darkgrey='\033[90m'
    lightred='\033[91m'
    lightgreen='\033[92m'
    yellow='\033[93m'
    lightblue='\033[94m'
    pink='\033[95m'
    lightcyan='\033[96m'
    
def Print(txt,col=None):
    ccolor = bcolors.ENDC
    if col == None or platform.system() == 'Windows':
        print(txt)
        return
    elif col == 'red':
        ccolor = bcolors.RED
    elif col == 'green':
        ccolor = bcolors.GREEN
    elif col == 'orange':
        ccolor = bcolors.ORANGE
    elif col == 'blue':
        ccolor = bcolors.cyan
    print(ccolor+txt+bcolors.ENDC)


# Module Integration
mod_requirements = [{'name': 'url', 'description': 'URL ZAP will be scanning', 'type': 'url', 'required': True,
                     'value': None},
                    {'name': 'args', 'description': 'Send custom arguments for running ZAP (override other parameters)',
                     'type': 'string', 'required': False, 'value': None},
                    {'name': 'port', 'description': 'The port used by ZAP for running the local proxy', 'type': 'port',
                     'required': False, 'value': 9995},
                    {'name': 'apikey',
                     'description': 'Setup a custom API key for ZAP, if not provided JaguarScan will generate one for' +
                                    ' you',
                     'type': 'string', 'required': False, 'value': None},
                    {'name': 'path',
                     'description': 'Custom path for locating the zap.bat or zap.sh script, if not provided the ' +
                                    'module will use the default based on the current OS',
                     'type': 'string', 'required': False, 'value': None},
                    {'name': 'scantype', 'description': 'What scan type do you want ZAP to run: spider,active,full',
                     'type': ['spider', 'active', 'full'], 'required': True, 'value': 'full'}]


def requirements():
    return mod_requirements


def req_validations(reqs):
    try:
        mod_config = {}
        if isinstance(reqs, list):
            for req in reqs:
                mod_found = False
                for mod_req in mod_requirements:
                    if mod_req["name"] == req["name"]:
                        mod_found = True
                        if mod_req["required"] == True and req["value"] == None:
                            Print("[ X ] Parameter "+req["name"]+" is required","red")
                            return False
                        if mod_req["type"] == 'port' or mod_req["type"] == 'integer':
                            mod_config[req["name"]] = int(req['value'])
                        else:
                            mod_config[req["name"]] = req['value']
                
                if mod_found == False:
                    Print("[ X ] Parameter "+req["name"]+" is not defined in module","red")
                    return False
            return mod_config
        else:
            if mod_requirements["required"] == True and reqs["value"] == None:
                Print("[ X ] Parameter "+reqs["name"]+" is required","red")
                return False
            if mod_requirements["type"] == 'port' or mod_requirements["type"] == 'integer':
                mod_config[reqs["name"]] = int(reqs['value'])
            else:
                mod_config[reqs["name"]] = reqs['value']
            return mod_config
    except Exception as e:
        Print("[ X ] Unhandled Validation Error: "+str(e),"red")
        return False


def run(reqs):
    try:
        zap_config = req_validations(reqs)
        if zap_config == False:
            return {'description': 'Errors found in the data provided', 'status': 'error'}
        Print("[ ! ] Parameters validated", "green")
        # Generate token
        if zap_config["apikey"] is None:
            zap_config["apikey"] = gen_token()
        Print("[ ! ] Loading ZAP", "green")
        # Testing code
        zap_results = None
        if zap_config["port"] == 9995:
            zap_config["port"] = random.randint(19000, 19999)
        if load_zap(zap_path=zap_config["path"],
                    zap_args=zap_config["args"],
                    api_token=zap_config["apikey"],
                    port=zap_config["port"]):
            Print("[ ! ] ZAP successfully loaded!","green")
            zap_results = zap_scan(zap_config["url"],
                                   apikey=zap_config["apikey"],
                                   zap_port=zap_config["port"],
                                   scan_type=zap_config["scantype"])
            if zap_results is None:
                return {'description': "ZAP scan didn't completed correctly, see the event log for details",
                        'status': 'error'}
        else:
            return {'description': "ZAP didn't started correctly, make sure the path is correct", 'status': 'error'}
        
        return {'results': zap_results, 'status': True}
    
    except Exception as e:
        Print("[ X ] Error: "+str(e), "red")
        return {'description': 'Error: '+str(e), 'status': 'error'}


# Module Integration
def load_zap(zap_path=None, zap_args=None, api_token=None, port=None):
    if zap_args is None:
        if api_token is None:
            api_string = "api.disablekey=true"
        else:
            api_string = 'api.key="'+api_token+'"'
        if port is None:
            zap_port = "-port 9999"
        else:
            zap_port = "-port "+str(port)
            
        if zap_args is None:
            zap_args = ' -daemon -config '+api_string+' '+zap_port
        
    if zap_path is None:
        zap_path = ''
        if platform.system() == "Darwin":
            zap_path = '"/Applications/OWASP ZAP.app/Contents/MacOS/"./"OWASP ZAP.sh"'
        elif platform.system() == "Linux":
            zap_path = "/opt/zap/zap.sh"
        elif platform.system() == "Windows":
            zap_path = "%programfiles%\OWASP\Zed Attack Proxy\zap.bat"
        
    if zap_path != "":
        return run_shell_command(zap_path + zap_args)
    else:
        Print("[ X ] Operating system not recognized", "red")
        return False 


def zap_scan(target, apikey=None, zap_port='9999', scan_type='full'):
    zap = ZAPv2(apikey=apikey,
                proxies={'http': 'http://127.0.0.1:'+str(zap_port),
                         'https': 'http://127.0.0.1:'+str(zap_port)})
    
    # Create new context
    Print('[ ! ] Creating a new context', "green")
    contextname = "JaguarScan"
    contextid = zap.context.new_context(contextname=contextname)
    zap.context.remove_context(contextname='Default Context')
    zap.context.include_in_context(contextname=contextname, regex="{0}{1}".format(target, ".*"))
    zap.context.set_context_in_scope(contextname=contextname, booleaninscope=True)
    Print('[ ! ] Accessing target {}'.format(target), "green")
    zap.urlopen(target)
    # Give the sites tree a chance to get updated
    time.sleep(2)

    Print('[ ! ] Spidering target {}'.format(target), "green")
    #scanid = zap.spider.scan(target)
    scanid = zap.spider.scan(contextname=contextname, recurse=True, subtreeonly=True)
    # Give the Spider a chance to start
    time.sleep(2)
    while (int(zap.spider.status(scanid)) < 100):
        # Loop until the spider has finished
        Print('[ ! ] Spider progress %: {}'.format(zap.spider.status(scanid)), "green")
        time.sleep(5)
    Print('[ ! ] Spider progress %: {}'.format(zap.spider.status(scanid)), "green")
    Print('[ ! ] Spider completed', "green")
    
    while (int(zap.pscan.records_to_scan) > 0):
        Print('[ ! ] Records to passive scan : {}'.format(zap.pscan.records_to_scan), 'green')
        time.sleep(2)
    
    Print('[ ! ] Passive Scan completed', 'green')
    
    if scan_type == 'active' or scan_type == 'full':
        Print('[ ! ] Active Scanning target {}'.format(target), 'green')
        #scanid = zap.ascan.scan(target)
        #zap.ascan.enable_all_scanners(scanpolicyname='Default Policy')
        scanners = zap.ascan.scanners()
        disabled = []
        for scanner in scanners:
            if scanner["quality"] == "alpha":
                disabled.append(scanner["id"])
        if len(disabled) > 0:
            zap.ascan.disable_scanners(disabled)
        scanid = zap.ascan.scan(target, recurse=True, inscopeonly=True)
        started = datetime.now()
        lastp = ""
        expiration = started + timedelta(minutes=10)
        while (int(zap.ascan.status(scanid)) < 100):
            # Loop until the scanner has finished
            pcompleted = zap.ascan.status(scanid)
            if lastp != pcompleted:
                lastp = pcompleted
                expiration = started + timedelta(minutes=10)
            sys.stdout.write(u"\u001b[1000D"+'[ ! ] Scan progress : '+ pcompleted +"%")
            sys.stdout.flush()
            time.sleep(1)
            sys.stdout.flush()
            if datetime.now() > expiration:
                Print('\n[ X ] Aborting the scan, ZAP is not responding', 'red')
                zap.ascan.stop_all_scans()
                time.sleep(10)
                break

        Print('[ ! ] Scan progress %: {}'.format(zap.ascan.status(scanid)), 'green')
        
        Print('[ ! ] Active Scan completed', 'green')
    
    # Report the results
    
    Print('[ ! ] Hosts: {}'.format(', '.join(zap.core.hosts)), 'green')
    Print('[ ! ] Collecting alerts', 'green')
    results = zap.core.alerts()
    Print('[ ! ] Total results found: '+str(len(results)), 'orange')
    jaguarscan_results = []
    
    for each_vuln in results:
        message_data = zap.core.message(each_vuln['messageId'])
        if each_vuln['url'].startswith( 'https://' ):
            prot = "https"
        else:
            prot = "http"
        # TODO: ZSS-1 Base64 Encode Request and response data
        # TODO: Convert data into safe JSON
        # TODO: Error: 'ascii' codec can't encode character u'\u2014' in position 448: ordinal not in range(128)
        tmp = {"issue_type": "vulnerability",
               "type": each_vuln['name'],
               "scan_type": "dynamic",
               'severity':each_vuln['risk'],
               'confidence':each_vuln['confidence'],
               'evidence':'Method:'+each_vuln['method']+' Evidence:'+each_vuln['evidence']+' Parameters:'+each_vuln['param'],
               'target':target,
               'details':each_vuln['description'],
               'url':each_vuln['url'],
               'port':'',
               'transport':'tcp',
               'protocol':prot,
               'attack':each_vuln['attack'],
               'cve':'',
               'cvss':'',
               'cvss_string':'',
               'cwe':each_vuln['cweid'],
               'wasc':each_vuln['wascid'],
               'remediation':each_vuln['solution'],
               'screenshot':None,
               'references': each_vuln['reference'],
               'request': message_data['requestHeader']+message_data['requestBody'],
               'response': message_data['responseHeader']+message_data['responseBody'],
               'tool': 'zap'
               }
        jaguarscan_results.append(tmp)
    
    Print('[ ! ] Shutting down ZAP','orange')
    zap.core.shutdown()
    time.sleep(5)
    return jaguarscan_results


def run_shell_command(cmd):
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    # Poll process for new output until finished
    while True:
        nextline = process.stdout.readline()
        if nextline == '' and process.poll() is not None:
            break
        otxt = str(nextline)
        otxt = re.sub("[^0-9a-zA-Z%$&#@!+-_?(){}\[]<=>.,\'\":;\\\/\s]+", '', otxt)
        otxt = otxt.replace("\n", "")
        otxt = otxt.strip(" ")
        if otxt != "":
            Print(otxt,"orange")
            if "ZAP is now listening" in otxt:
                return True
            elif "Cannot listen on port" in otxt:
                Print('[ X ] The port specified is probably being used by another application','red')
                Print('      Select another port in your configuration and try again','red')
                return False
        sys.stdout.flush()

    #output = process.communicate()[0]
    #exitCode = process.returncode
    return False
    #if (exitCode == 0):
    #    Print("Command completed","blue")
    #    return output
        
def save_obj(obj, name ):
    with open(name + '.pkl', 'wb') as f:
        pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)

def load_obj(name ):
    with open(name + '.pkl', 'rb') as f:
        return pickle.load(f)
    
def gen_token(length=20, charset="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"):
    random_bytes = os.urandom(length)
    len_charset = len(charset)
    indices = [int(len_charset * (ord(byte) / 256.0)) for byte in random_bytes]
    return "".join([charset[index] for index in indices])

    
if __name__ == '__main__':
    try:
        if len(sys.argv) < 2 or len(sys.argv) > 3:
            print("Usage:")
            print(" zap.py http://the-url [/path/to/zap.sh]")
            exit(1)
        target = sys.argv[1]
        zap_path = sys.argv[2] if len(sys.argv) == 3 else None
        if load_zap(zap_path=zap_path):
            zap_results = zap_scan(target)
            count = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
            for issue in zap_results:
                if issue["severity"] in ["High", "Medium", "Low", "Informational"]:
                    count[issue["severity"]] += 1
            print("Total {}, High {}, Medium {}, Low {}, Info {}".format(len(zap_results),
                                                                         count["High"],
                                                                         count["Medium"],
                                                                         count["Low"],
                                                                         count["Informational"]))
            print("Process completed")
        else:
            Print("[ X ] ZAP didn't started correctly, make sure ZAP is installed and the executable path is correct")
        
    except Exception as e:
        Print("[ X ] Error: "+str(e), "red")