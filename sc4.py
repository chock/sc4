'''
Security Center 4 JSON API wrapper
CGG 9/2010 (charles.griebel@gmail.com)
'''

import sys, httplib2, urllib, json, time
import getpass
from pprint import pprint

# *************** SET THIS TO YOUR SC4 HOST FQDN ***************** 
SC4HOST = 'sc4.your.com'
# ****************************************************************

class SC4Error(Exception):
    '''
    Basic exception thrown if someone gives us a bogus asset list name
    '''
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

if not SC4HOST:
    raise SC4Error('*** You need to set SC4HOST at the top of %s. ***' % __file__)


_URL = 'https://%s/sc4/request.php' % SC4HOST
DEBUG = False

SEVERITIES = ('low', 'medium', 'high', 'critical')
_severity = dict( [ (b, a) for a, b in enumerate(SEVERITIES)])
_ASSET_LISTS = dict()

assetFieldstr = ("id type name description visibility group definedIPs creatorID ownerID "
                "modifiedTime createdTime")

# These are valid actions for modules
module_actions = {
        'asset': ('init','edit','getIPs'),
        'auth': ('login', 'logout'),
        'plugin': ('getDetails', 'getPage','init'),
        'system': ('init',),
        'vuln': ('init', 'getIP', 'query'),
        'acceptRiskRule': ('getRules','add'),
        'scan': ('init',),
        'user': ('init',),
        }

def _getSc4Username():
    '''
    helper function to get SC4 login username
    '''
    userdefault = getpass.getuser()
    saveout = sys.stdout
    sys.stdout = sys.stderr
    sc4user = raw_input("SC4 username [%s]: " % userdefault)
    if not sc4user:
        sc4user = userdefault
    sys.stdout = saveout
    return sc4user

def _getSc4Password():
    '''
    helper function to get SC4 login username
    '''
    return getpass.getpass('Enter password: ')

def _dateFromStamp(stamp):
    from datetime import date
    return str(date.fromtimestamp(stamp))

class connection():
    '''
    Provides a connection to SC4 which, in turn, provides the methods to pull
    data from SC4.
    '''

    def __init__(self, user=None, passwd=None):
        self.url = _URL
        self.headers = {"Content-type": "application/x-www-form-urlencoded"}
        if not user:
            user = _getSc4Username()
            sys.stderr.write("Authenticating with username '%s'\n" % user)
        if not passwd:
            passwd = _getSc4Password()
        self.user = user
        self.passwd = passwd
        self._token = None
        self.__connect()

    def __connect(self):
        input = {'password': self.passwd,
                 'username': self.user}
        response,result = self.__send('auth','login',input)
        if result["error_code"] == 0:
            #print "SC4 Login Successful"
            self._token = result['response']['token']
        else:
            raise SC4Error(("Error " + str(result["error_code"]) + ": %s" %
            (result["error_msg"])))

    def __send(self, module, action, input=None, request_id=1):
        if module not in module_actions:
            sys.exit("Bad module '%s'" % module)
        if action not in module_actions[module]:
            sys.exit("Bad action '%s' for module '%s'" % (action, module))
        data = {'request_id': str(request_id),
                'module': module,
                'action': action,
                }

        if module != 'auth':
            data['token'] = self._token

        if input:
            if DEBUG: pprint(input)
            data['input'] = json.dumps(input)

        http = httplib2.Http()
        response, content = http.request(self.url, 'POST', 
                headers=self.headers,
        body=urllib.urlencode(data))
        if 'set-cookie' in response:
            self.headers['Cookie'] = response['set-cookie']
        #print response.status, response.reason
        return response, json.loads(content)

    def __vulnquery(self, tool, vfilters, pluginType='all', sortField=None, sortDir='asc'):
        #XXX debug
        '''
        vfilters.append( { 'filterName' : 'repositoryIDs',
                          'value' : 1,
                          'operator' : '='
                        }
                       )
        '''
        # we don't want compliance or passive results
        vfilters.append( { 'filterName' : 'pluginType',
                          'value' : pluginType,
                          'operator' : '='
                        }
                       )

        input = {'tool' : tool, 
                'startOffset' : 0,
                'endOffset' : 99999,
                'sortField' : 'ip',
                'sortDir' : 'asc',
                'sourceType' : 'cumulative',    #XXX debug (not documented)
                'filters' : vfilters,
                }

        response, results = self.__send('vuln', 'query', input)
        if DEBUG:
            pprint(results)
        return response, results

    def __rulesQuery(self, repID, pluginID=None, pluginType='all'):
        #'sourceType' : 'cumulative',    #XXX debug (not documented)
        input = {
                'repID' : repID,
                }
        if pluginID:
            input['pluginID'] = pluginID
        response, results = self.__send('acceptRiskRule', 'getRules', input)
        if DEBUG:
            pprint(results)
        return response, results

    def __buildFilters(self, assetListId=None, ip=None, pluginID=None, severity=None, 
            pluginText=None, age=None, acceptedRisk=None, mitigated=False):
        '''
        valid filters:
            repositoryIDs,assetIDs,pluginType,familyID,ip,port,
            tcpport,udpport,pluginID,pluginText,firstSeen,lastSeen,lastMitigated,
            severity,protocol,policyID,assetID,acceptedRisk,wasMitigated,recastRisk
        '''
        
        vfilters = []
        vfilter = dict()
        if assetListId:
            vfilter['filterName'] = 'assetID'
            vfilter['value'] = str(assetListId)
            vfilter['operator'] = '='
        elif ip:
            vfilter['filterName'] = 'ip'
            vfilter['value'] = ip
            vfilter['operator'] = '='

        if vfilter:
            vfilters.append(vfilter)

        if pluginID:
            vfilters.append( { 'filterName' : 'pluginID',
                              'value' : pluginID,
                              'operator' : '='
                            }
                           )

        if severity:
            vfilters.append( { 'filterName' : 'severity',
                              'value' : _severity[severity],
                              'operator' : '='
                            }
                           )

        if pluginText:
            vfilters.append( { 'filterName' : 'pluginText',
                              'value' : pluginText,
                              'operator' : '='
                            }
                           )
        if age:
            agefilt = { 'filterName' : 'firstSeen',
                              'value' : abs(age),
                              'operator' : '<='
                      }
            if age < 0:
                agefilt['operator'] = '>='
            vfilters.append(agefilt)       
        if acceptedRisk:
            vfilters.append( { 'filterName' : 'acceptedRisk',
                              'value' : 'true',
                              'operator' : '='
                            }
                          )       
        if mitigated:
            vfilters.append( { 'filterName' : 'wasMitigated',
                              'value' : mitigated,
                              'operator' : '='
                            }
                           )
        return vfilters

    def getSeveritySummary(self, assetListId=None, ip=None, age=None, acceptedRisk=False, 
            mitigated=False, pluginType='active'):
        '''
        return: hash keyed on SEVERITIES
        '''
        tool = 'sumseverity'
        vfilters = self.__buildFilters(assetListId=assetListId, ip=ip, age=age, 
                acceptedRisk=acceptedRisk, mitigated=mitigated)
        response, results = self.__vulnquery(tool, vfilters, pluginType)
        return dict([ (SEVERITIES[int(f['severity'])], int(f['count'])) 
                for f in results['response']['results']])
    
    def getIp(self, ip): 
        '''
        get information about ip asset
        return {'macAddress': '', 'repositoryName': 'Compliance',
        'hasCompliance': 'Yes', 'severityHigh': '2', 'severityMedium': '0',
        'ip': '1.2.3.4', 'lastScan': '1294427 459', 'netbiosName': '',
        'repositoryID': '2', 'severityCritical': '0', 'score': '105', 'assets':
        [{'id': '1', 'name': 'My Servers'}, {'id': '10', 'name': 'My HPUX Servers'
        }, {'id': '22', 'name': 'My Unix Servers'}], 'os': '',
        'severityLow': '85', 'total': 0, 'dnsName': '', 'hasPassive': 'Yes'}
        '''

        input = {
                'ip' : ip,
                }
        response, results = self.__send('vuln', 'getIP', input)
        '''
        this is never used
        fields = ('ip','lastScan','dnsName','netbiosName','os',
                'repositoryID', 'repositoryName', 'severityCritical',
                'severityHigh', 'severityMedium', 'severityLow', 
                'assets')
        '''

        #NOT USED data = {}
        if len(results['response']['records']) != 0:
            return results['response']['records'][0]    # return first record
        else:
            return None
        

    def getAssetListCount(self, assetListId):
        '''
        return: number of devices in asset list (int)
        '''
        tool = 'sumip'
        vfilters = self.__buildFilters(assetListId=assetListId)
        response, results = self.__vulnquery(tool, vfilters)
        return int(results['response']['totalRecords'])

    def getAssetListIps(self, assetListId):
        '''
        return: ips of devices in asset list
        '''
        tool = 'sumip'
        vfilters = self.__buildFilters(assetListId=assetListId)
        response, results = self.__vulnquery(tool, vfilters)
        return [ r['ip'] for r in results['response']['results'] ]

    def getIpsWithVulns(self, pluginid):
        '''
        accept: pluginid (comma separated list of singles or ranges)
        return: list of IPs with vuln
        '''
        tool = 'sumip'
        vfilters = self.__buildFilters(pluginID=pluginid)
        response, results = self.__vulnquery(tool, vfilters)

        return [ r['ip'] for r in results['response']['results'] ]
        #return results['response']['results']

    def getAcceptRiskRules(self, repID, pluginType='all', pluginID=None):
        '''
        return data related to accept risk rule
        '''
        response, results = self.__rulesQuery(repID, pluginID, pluginType)
        return results['response']['acceptRiskRules']

    def getVulnDetail(self, assetListId=None, ip=None, pluginID=None, 
            severity=None, pluginText=None, age=None, acceptedRisk=False, pluginType='active'):
        '''
        accept:
            assetlist (num) (optional)
               - OR-
            ip (comma sep. list of IPs string) (optional)

            pluginID (optional)
            severity <'low' | 'medium' | 'high' | 'critical'> (optional)
            age (number of days since discovered - num) (optional)
        return:
            list of vulns (see below for format)
        '''
        tool = 'vulndetails'
        vfilters = self.__buildFilters(assetListId=assetListId, ip=ip, 
                pluginID=pluginID, severity=severity, pluginText=pluginText,
                age=age, acceptedRisk=acceptedRisk)
        response, results = self.__vulnquery(tool, vfilters, pluginType)

        '''
        sample vuln. fields
                                    {u'acceptRisk': u'0',
                                     u'dnsName': u'foo.bar.com',
                                     u'familyID': u'2',
                                     u'firstSeen': u'1284001810',
                                     u'hasBeenMitigated': u'0',
                                     u'ip': u'1.2.3.5',
                                     u'lastSeen': u'1284346924',
                                     u'macAddress': u'',
                                     u'netbiosName': u'',
                                     u'pluginID': u'49113',
                                     u'pluginName': u'HP-UX Security patch : PHCO_41202
        ,
                                     u'pluginText': u'\\nSynopsis :\\n\\nThe remote hos
         is missing HP-UX PHCO_41202 security update\\n\\nDescription :\\n\\n11.31 Soft
        are Distributor Cumulative Patch\\n\\nSolution :\\n\\nftp://ftp.itrc.hp.com//hp
        ux_patches/11.X/PHCO_41202\\n\\nRisk factor :\\n\\nHigh\\n\\n',
                                     u'port': u'0',
                                     u'protocol': u'6',
                                     u'recastRisk': u'0',
                                     u'repositoryID': u'1',
                                     u'severity': u'2'}],

        '''
        return results['response']['results']

    def getPluginDetail(self, pluginID):
        '''
            plugin::getDetails
            Returns metadata specific to the Plugin ID.
                name = <string>
                description = <string>
                familyID = <num>
                family = <string>
                modifiedTime = <num>
                version = <string>
                cvebid = <num>
                md5 = <string>
                copyright = <string>
                sourceFile = <string>
                type = <string>
        '''
        input = {
                'pluginID' : pluginID,
                }
        response, results = self.__send('plugin', 'getDetails', input)
        if DEBUG:
            pprint(results)
        return results['response']['plugin']

    def getAssetLists(self, type='all'):
        '''
        accept: type ('all' | 'static' | 'dynamic')
        return: dicts of assetList keyed on asset list name
            ['group', 'description', 'modifiedTime', 'definedIPs', 'visibility', 
            'creatorID' , 'createdTime', 'ownerID', 'type', 'id', 'name']
        '''
        global _ASSET_LISTS
        if not _ASSET_LISTS:
            response, results = self.__send('asset', 'init')
            assets = dict()
            #debug
            #pprint(results)
            #if 'assets' in results['response'] and len(results['response']['assets']) != 0:
            if len(results['response']['assets']) != 0:
                for assetres in results['response']['assets']:
                    asset = dict()
                    for field in [ f for f in assetFieldstr.split() if f in assetres]:
                        #print field,
                        if 'Time' in field:
                            val = time.ctime(int(assetres[field]))
                        else:
                            val = assetres[field]
                        asset[field] = val
                    atype = asset['type']
                    asset['id'] = int(asset['id'])
                    if type == 'all' or type == atype:
                        assets[asset['name']] = asset
            else:
                raise SC4Error('Could not get asset lists.')
            _ASSET_LISTS = assets
        return _ASSET_LISTS

    def getAssetListId(self, name):
        assetLists = self.getAssetLists()
        if name in assetLists:
            return assetLists[name]['id']
        else:
            return None

    def getAssetListName(self, id):
        id = int(id)
        assetLists = self.getAssetLists()
        for name in assetLists:
            if assetLists[name]['id'] == id:
                return name
        return None

    def getScanJobs(self):
        '''
        Get summary information about scheduled scan jobs
        accept: org id
        return: hash of jobrecord hashed on jobname
                description, target, targetday, targettime, frequency,
        '''
        from collections import namedtuple

        jobfields = 'description,target,targetday,targettime,frequency'
        jobrecord = namedtuple('jobrecord', jobfields)

        '''
        sample time format (scheduleDefinition)

        'every 00:40 America/New_York'
        'Wednesday 05:30 America/New_York'
        '''

        jobs = {}
        response, results = self.__send('scan', 'init')
        for s in [s for s in results['response']['scans'] if s['scheduleFrequency'] != 'template']:
            name = s['name']
            description = s['description']
            target = self.getAssetListName(s['assets'][0]['id'])
            targetday, targettime = s['scheduleDefinition'].split(' ')[0:2]
            if targetday == 'every': targetday = 'daily'
            frequency = s['scheduleFrequency']
            #pprint((description, target, targetday, targettime, frequency))
            jobs[name] = jobrecord._make((description, target, targetday, targettime, frequency))
            
        return jobs

    '''
    ******************************************
    * Methods below here make changes in SC4 *
    ******************************************
    '''
    def acceptRisk(self, repID, hostType, hostValue, pluginID, comments=None, 
            port='any', protocol='any'):
        '''
        repID must be repository where rule is to be placed
            Vuln db. is '1' and Compliance is '2'
        hostType is 'asset' for asset lists
        hostValue is id of asset list for asset lists
        '''
        if hostType not in ('asset', 'ip'):
            raise SC4Error("sc4::acceptRisk - bad hostType '%s'" % hostType)

        input = {
                'repIDs' : [{"id":repID}],
                'hostType' : hostType,
                'hostValue' : hostValue,
                'pluginID' : pluginID,
                'comments' : comments,
                'port' : port,
                'protocol' : protocol,
                }

        #debug
        if DEBUG:
            pprint (input)

        response, results = self.__send('acceptRiskRule', 'add', input)
        pprint(results)
        return results  #debug

    def updateAssetList(self, listname, ips):
        assetLists = self.getAssetLists()
        if not listname in assetLists:
            raise SC4Error("Could not find a matching asset list for '%s'" % listname)

        asset = assetLists[listname]

        assetStr = "\n".join(ips)

        # update the asset record with the new IP list
        asset['definedIPs'] = assetStr
        response, results = self.__send('asset', 'edit', asset)

        fieldstr = ("id type name description visibility group definedIPs creatorID "
                    "ownerID modifiedTime createdTime")
        print "Updated asset list as follows:"
        if len(results['response']) != 0:
            asset = results['response']
            # NOT USED type = asset['type']
            for field in [ f for f in fieldstr.split() if f in asset]:
                print "\t%s" % field,
                if 'Time' in field:
                    print time.ctime(int(asset[field]))
                else:
                    print asset[field]
        else:
            print "Problem"

# BEGIN MAIN
if __name__ == '__main__':
    user = _getSc4Username()
    passwd = _getSc4Password()

    conn = connection(user, passwd)
    assetLists = conn.getAssetLists()

    def getRandomAsset():
        # return name and id of a random asset list
        from random import choice
        name = choice(assetLists.keys())
        assetdetail = assetLists.pop(name)
        id = assetdetail['id']
        return name, id

    name, id = getRandomAsset()
    print "Random asset list '%s' has id: %s" % (name, id)
    vulns = conn.getVulnDetail(assetListId=id, severity='high', acceptedRisk=False)
    print "\t...and it has %s high vulns" % len(vulns)

    vulnlimit = 50
    myfields = ('ip', 'dnsName', 'pluginName', 'pluginID')
    vulncount = 0
    for v in vulns:
        vulncount+=1
        print "\t",
        for f in myfields:
            print v[f], 
        print
        if vulncount==vulnlimit:
            print "breaking at %d results" % vulnlimit
            break

    name, id = getRandomAsset()
    print "\nRandom asset list '%s' has id: %s" % (name, id)

    age = 10
    vulns = conn.getVulnDetail(assetListId=id, severity='high', age=age, acceptedRisk=False)
    print "\t...and it has %s high vulns >= %d days old" % (len(vulns), age)

    age = 7
    sevs = conn.getSeveritySummary(assetListId=id, age=age)
    #XXX debug 
    print "\t...and it has %s high vulns >= %d days old" % (sevs['high'], age)
    print "\there are all the sevs:"
    for sev in SEVERITIES:
        print "\t\t" + sev, sevs[sev]

    import socket
    ip = socket.gethostbyname(socket.gethostname())
    vulns = conn.getVulnDetail(ip=ip, severity='low', acceptedRisk=True)
    print "\nThis local device (%s) has %s low vulns" % (ip, len(vulns))
    vulncount = 0
    for v in vulns:
        for f in myfields:
            print "\t", v[f], 
        print
        if vulncount==vulnlimit:
            print "breaking at %d results" % vulnlimit
            break


'''
NOTE: this stuff not used but is useful information

classResults = ('ip', 'repositoryID', 'score', 'total', 'low',
          'medium', 'high', 'critical')

serviceResults = ('count', 'detectionMethod', 'name')

sumtools = { 'sumasset':('assetList', 'total', 'low', 'medium', 'high', 
                        'critical', 'score'),

             'sumip':('ip', 'repositoryID', 'score', 'total', 'low', 'medium',
                      'high', 'critical', 'macAddress', 'netbiosName', 
                      'dnsName'),
             'sumclassc':classResults,
             'sumclassb':classResults,
             'sumclassa':classResults,
             'sumport':('port', 'total', 
                        'low', 'medium', 'high', 'critical'),
             'sumprot':('protocol', 'total', 
                        'low', 'medium', 'high', 'critical'),
             'sumplugin':('pluginID', 'total', 'severity', 'name', 'familyID'),
             'sumsev':('severity', 'count'),
             }
servicetools = {
             'listwebservers':serviceResults,
             'listwebclients':serviceResults,
             'listmailclients':serviceResults,
             'listsshservers':serviceResults,
             'listservices':serviceResults,
             'listos':serviceResults,
             }

detailtools = {
             'listvuln':('pluginId', 'repositoryID', 'severity', 'ip', 'port',
                         'protocol', 'name', 'familyID', 'dnsName', 
                         'macAddress', 'netbiosName'),
             'vulndetails':('pluginID', 'repositoryID', 'severity', 'ip',
                            'port', 'protocol', 'name', 'familyID', 'firstSeen',
                            'lastSeen', 'pluginText', 'dnsName', 'macAddress', 
                            'netbiosName'),
             }

tools = dict()
for d in (sumtools, servicetools, detailtools):
    tools.update(d)

filternames = ('familyID', 'pluginType', 'ip', 'port', 'tcpport', 'udpport', 'pluginID', 'pluginText',
           'firstSeen', 'lastSeen', 'severity', 'protocol', 'repositoryIDs', 'assetID', 'policyID')
pluginTypes = ('active', 'passive', 'compliance')

'''

