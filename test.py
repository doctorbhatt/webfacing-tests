#!/usr/bin/python

'''

Author Chetan Bhatt
email chetan.bhatt@warnerbros.com
Version: DRAFTv1.0
Python Support: 2.7
Configlet: DEV_R12-BUILD-PRODUCTION-ARUBA-MM

Changes
---------
012423 - First Draft


'''

#from cvplibrary import Form
from cvplibrary import CVPGlobalVariables,GlobalVariableNames
from cvplibrary import Device
import requests,json
import urllib3
import pprint

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_mm_session_id(mm,u,pw):
  url ='https://{}:4343/v1/api/login'.format(mm)
  credentials = "username={}&password={}".format(u,pw)
  try:
    r = requests.post(url, verify=False, data=credentials, timeout=2)
    session_id = r.json()['_global_result']['UIDARUBA']
    print ('Logged into Mobility Controller')
    print ('Session ID is {}'.format(session_id))
    print '-------'
    return session_id
  except:
    print 'Error Logging into Mobility Controller'
  return 401
  
def query_mm_post(session_id,mm,url):
  aos_session_id_cookie = dict(SESSION=session_id)
  fullurl='https://{}:4343/v1/{}'.format(mm,url)
  
  payload = json.dumps({
    "rname": "StudioNet220-ROLE",
    "role__acl": [
      {
        "acl_type": "session",
        "pname": "global-sacl",
        "_flags": {
          "readonly": True,
          "system": True
        }
      },
      {
        "acl_type": "session",
        "pname": "apprf-studionet220-role-sacl",
        "_flags": {
          "readonly": True,
          "system": True
        }
      },
      {
        "acl_type": "session",
        "pname": "studionet-post-auth-common-policies"
      }
    ],
    "role__cp_acc": {
      "_present": True,
      "_flags": {
        "default": True
      }
    },
    "role__openflow": {
      "_present": True,
      "_flags": {
        "default": True
      }
    },
    "role__vlan": {
      "vlanstr": "1640"
    },
    "role__reauth": {
      "_flags": {
        "default": True
      },
      "reauthperiod": 0
    },
    "role__max_sess": {
      "_flags": {
        "default": True
      },
      "max_sess": 65535
    }
  })
  #print fullurl
  #print aos_session_id_cookie
  try:
    r = requests.post(fullurl,verify=False,cookies=aos_session_id_cookie,data=payload )
    print '-----'
    return r.json()
  except:
    r = "No Data"
  return r
  
def query_mm_get(session_id,mm,url):
  aos_session_id_cookie = dict(SESSION=session_id)
  fullurl='https://{}:4343/v1/{}'.format(mm,url)
  #print fullurl
  #print aos_session_id_cookie
  try:
    r = requests.get(fullurl,verify=False,cookies=aos_session_id_cookie )
    print '-----'
    return r.json()
  except:
    r = "No Data"
  return r

def logout_mm(mm):
  url='https://{}:4343/vi/api/logout'.format(mm)
  try:
    response = requests.post(url,verify=False, timeout=2)
    print
    print("Logged out from Mobility Master")
  except:
    print("Error logging out of Mobility Master")

#--------------

def main():
  
  u = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_USERNAME)
  pw = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_PASSWORD)
  mm = 'wblburpvarubamm.net.warnerbros.com'
  #mm = '10.145.247.250'
  

  session_id = get_mm_session_id(mm,u,pw)
  
  if session_id is not "401":
    '''
    # List of all the Containers
    #url = 'configuration/container?UIDARUBA={}'.format(session_id)
    #pprint.pprint(query_mm_get(session_id,mm,url))

    
    #url2 = 'configuration/object?UIDARUBA={}'.format(session_id)
    #url2 = 'configuration/object/ctrl_ip?config_path=%2Fmd&UIDARUBA={}'.format(session_id)
    
    print "Hiearchy"
    url6 = 'configuration/object/node_hierarchy?UIDARUBA={}'.format(session_id)
    #pprint.pprint(query_mm_get(session_id,mm,url6)['childnodes'][1])
    pprint.pprint(query_mm_get(session_id,mm,url6)['childnodes'][1]['childnodes'][0]['name'])
    #pprint.pprint(query_mm_get(session_id,mm,url6)['childnodes'][1]['childnodes'][0]['devices'])
    print
    
    
    print 'Group WB_BUR Containers'
    url3 = 'configuration/container?UIDARUBA={}&config_path=/md/wb_bur'.format(session_id)
    pprint.pprint(query_mm_get(session_id,mm,url3))
    
    
    print 'Banner in WB_BUR Containers'
    url4 = 'configuration/object/banner_motd?UIDARUBA={}&config_path=/md/wb_bur'.format(session_id)
    pprint.pprint(query_mm_get(session_id,mm,url4))
    
    print 'Roles'
    #filter_parameter = '[{"OBJECT" : {"$eq" : "apprf-studionet410-role-sacl" }}]'
    filter_parameter = ''
    url5 = 'configuration/object/role?UIDARUBA={}&config_path=/md/wb_bur&filter={}'.format(session_id,filter_parameter)
    dict_query_results = query_mm_get(session_id,mm,url5)
    list_query_results = dict_query_results['_data']['role']

    for key in list_query_results:
      print key['rname']
    
    
    print 'Policies'
    #filter_parameter = '[{"OBJECT" : {"$eq" : "apprf-studionet410-role-sacl" }}]'
    filter_parameter = ''
    url6 = 'configuration/object/role?UIDARUBA={}&config_path=/md/wb_bur&filter={}'.format(session_id,filter_parameter)
    dict_query_results = query_mm_get(session_id,mm,url6)
    print dict_query_results
    list_query_results = dict_query_results['_data']['role']

    for key in list_query_results:
      print key['rname']
    '''
   
    #print 'Push to role'
    #url7 = 'configuration/object/role?UIDARUBA={}&config_path=/md/wb_bur_sn'.format(session_id)
    #pprint.pprint(json.dumps(query_mm_post(session_id,mm,url7)['_global_result']['status_str']))
    
    
    logout_mm(mm)
  else:
    print('Cannot Obtain information from the Mobility Master')
  
  
  
#--------------

if __name__ == '__main__':
  main()
