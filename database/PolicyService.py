from database.DBService import DBService as dbs
from PolicyUtil import Policy
import uuid

class PolicyService:
    def addPolicy(self, policy):
        policy.attri_permit = str(policy.attri_permit).replace("'", "\"")
        policy.time_condition = str(policy.time_condition).replace("'", "\"")
        policy.attri_condition = str(policy.attri_condition).replace("'", "\"")
        sql = "insert into policy(id,name,user,device,capability,status_permit,action_permit,attri_permit,time_condition,location_condition,attri_condition,level,submitter,state) values('{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}')".\
            format(policy.id, policy.name, policy.user, policy.device, policy.capability, policy.status_permit, policy.action_permit, policy.attri_permit, policy.time_condition, policy.location_condition, policy.attri_condition, policy.level, policy.submitter, policy.state)
        return dbs.execute_update(sql)
    
    def updatePolicy(self, policy):
        policy.attri_permit = str(policy.attri_permit).replace("'", "\"")
        policy.time_condition = str(policy.time_condition).replace("'", "\"")
        policy.attri_condition = str(policy.attri_condition).replace("'", "\"")
        sql = "update policy set name='{}',user='{}',device='{}',capability='{}',status_permit='{}',action_permit='{}',attri_permit='{}',time_condition='{}',location_condition='{}',attri_condition='{}',level='{}',submitter='{}',state='{}' where id='{}'".\
            format(policy.name, policy.user, policy.device, policy.capability, policy.status_permit, policy.action_permit, policy.attri_permit, policy.time_condition, policy.location_condition, policy.attri_condition, policy.level, policy.submitter, policy.state, policy.id)
        return dbs.execute_update(sql)

    def deletePolicy(self, policy):
        sql = "delete from policy where id='{}'".format(policy.id)
        return dbs.execute_update(sql)
    
    def deletePolicyById(self, id):
        sql = "delete from policy where id='{}'".format(id)
        return dbs.execute_update(sql)
    
    def getPolicyById(self, id):
        sql = "select id,name,user,device,capability,status_permit,action_permit,attri_permit,time_condition,location_condition,attri_condition,level,submitter,state from policy where id='{}'".format(id)
        record = dbs.execute_query(sql)
        policy_ = Policy()
        policy_.id = record[0][0]
        policy_.name = record[0][1]
        policy_.user = record[0][2]
        policy_.device = record[0][3]
        policy_.capability = record[0][4]
        policy_.status_permit = True if record[0][5]=="True" else False
        policy_.action_permit = True if record[0][6]=="True" else False
        policy_.attri_permit = eval(record[0][7])
        policy_.time_condition = eval(record[0][8])
        policy_.location_condition = record[0][9]
        policy_.attri_condition = eval(record[0][10])
        policy_.level = record[0][11]
        policy_.submitter = record[0][12]
        policy_.state = record[0][13]
        return policy_
    
    def getPolicy(self, name,user,device,capability,status_permit,action_permit,attri_permit,time_condition,location_condition,attri_condition,level,submitter,state):
        sql = "select id,name,user,device,capability,status_permit,action_permit,attri_permit,time_condition,location_condition,attri_condition,level,submitter,state from policy where 1=1"
        if name:
            sql += " and name like '%{}%'".format(name)
        if user:
            sql += " and user like '%{}%'".format(user)
        if device:
            sql += " and device like '%{}%'".format(device)
        if capability:
            sql += " and capability like '%{}%'".format(capability)
        if status_permit:
            sql += " and status_permit like '%{}%'".format(status_permit)
        if action_permit:
            sql += " and action_permit like '%{}%'".format(action_permit)
        if attri_permit:
            sql += " and attri_permit like '%{}%'".format(attri_permit)
        if time_condition:
            sql += " and time_condition like '%{}%'".format(time_condition)
        if location_condition:
            sql += " and location_condition like '%{}%'".format(location_condition)
        if attri_condition:
            sql += " and attri_condition like '%{}%'".format(attri_condition)
        if level:
            sql += " and level like '%{}%'".format(level)
        if submitter:
            sql += " and submitter like '%{}%'".format(submitter)
        if state:
            sql += " and state like '%{}%'".format(state)
        record = dbs.execute_query(sql)
        if record:
            policy_ = Policy()
            policy_.id = record[0][0]
            policy_.name = record[0][1]
            policy_.user = record[0][2]
            policy_.device = record[0][3]
            policy_.capability = record[0][4]
            policy_.status_permit = True if record[0][5]=="True" else False
            policy_.action_permit = True if record[0][6]=="True" else False
            policy_.attri_permit = eval(record[0][7])
            policy_.time_condition = eval(record[0][8])
            policy_.location_condition = record[0][9]
            policy_.attri_condition = eval(record[0][10])
            policy_.level = record[0][11]
            policy_.submitter = record[0][12]
            policy_.state = record[0][13]
            return policy_
        else:
            return None
    
    def getAllPolicyDatagrid(self, name,user,device,capability,status_permit,action_permit,attri_permit,time_condition,location_condition,attri_condition,level,submitter,state, page, rows):
        sql = "select id,name,user,device,capability,status_permit,action_permit,attri_permit,time_condition,location_condition,attri_condition,level,submitter,state from policy where 1=1"
        if name:
            sql += " and name like '%{}%'".format(name)
        if user:
            sql += " and user like '%{}%'".format(user)
        if device:
            sql += " and device like '%{}%'".format(device)
        if capability:
            sql += " and capability like '%{}%'".format(capability)
        if status_permit:
            sql += " and status_permit like '%{}%'".format(status_permit)
        if action_permit:
            sql += " and action_permit like '%{}%'".format(action_permit)
        if attri_permit:
            sql += " and attri_permit like '%{}%'".format(attri_permit)
        if time_condition:
            sql += " and time_condition like '%{}%'".format(time_condition)
        if location_condition:
            sql += " and location_condition like '%{}%'".format(location_condition)
        if attri_condition:
            sql += " and attri_condition like '%{}%'".format(attri_condition)
        if level:
            sql += " and level like '%{}%'".format(level)
        if submitter:
            sql += " and submitter like '%{}%'".format(submitter)
        if state:
            sql += " and state like '%{}%'".format(state)
        records = dbs.execute_query(sql)
        records_page = records[(page-1)*rows:page*rows]
        result = {}
        record_json = []
        for rec in records_page:
            record_json.append({"id":rec[0], "name":rec[1], "user":rec[2], "device":rec[3], "capability":rec[4], "status_permit":rec[5], "action_permit":rec[6], "attri_permit":rec[7], "time_condition":rec[8], "location_condition":rec[9], "attri_condition":rec[10], "level":rec[11], "submitter":rec[12], "state":rec[13]})
        result["total"] = len(records)
        result["rows"] = record_json
        return result
    
    def getAllPolicyJson(self, name,user,device,capability,status_permit,action_permit,attri_permit,time_condition,location_condition,attri_condition,level,submitter,state):
        sql = "select id,name,user,device,capability,status_permit,action_permit,attri_permit,time_condition,location_condition,attri_condition,level,submitter,state from policy where 1=1"
        if name:
            sql += " and name like '%{}%'".format(name)
        if user:
            sql += " and user like '%{}%'".format(user)
        if device:
            sql += " and device like '%{}%'".format(device)
        if capability:
            sql += " and capability like '%{}%'".format(capability)
        if status_permit:
            sql += " and status_permit like '%{}%'".format(status_permit)
        if action_permit:
            sql += " and action_permit like '%{}%'".format(action_permit)
        if attri_permit:
            sql += " and attri_permit like '%{}%'".format(attri_permit)
        if time_condition:
            sql += " and time_condition like '%{}%'".format(time_condition)
        if location_condition:
            sql += " and location_condition like '%{}%'".format(location_condition)
        if attri_condition:
            sql += " and attri_condition like '%{}%'".format(attri_condition)
        if level:
            sql += " and level like '%{}%'".format(level)
        if submitter:
            sql += " and submitter like '%{}%'".format(submitter)
        if state:
            sql += " and state like '%{}%'".format(state)
        records = dbs.execute_query(sql)
        result = []
        for rec in records:
            result.append({"id":rec[0], "name":rec[1], "user":rec[2], "device":rec[3], "capability":rec[4], "status_permit":rec[5], "action_permit":rec[6], "attri_permit":rec[7], "time_condition":rec[8], "location_condition":rec[9], "attri_condition":rec[10], "level":rec[11], "submitter":rec[12], "state":rec[13]})
        return result
    
    def getPolicyList(self, name,user,device,capability,status_permit,action_permit,attri_permit,time_condition,location_condition,attri_condition,level,submitter,state):
        sql = "select id,name,user,device,capability,status_permit,action_permit,attri_permit,time_condition,location_condition,attri_condition,level,submitter,state from policy where 1=1"
        if name:
            sql += " and name like '%{}%'".format(name)
        if user:
            sql += " and user like '%{}%'".format(user)
        if device:
            sql += " and device like '%{}%'".format(device)
        if capability:
            sql += " and capability like '%{}%'".format(capability)
        if status_permit:
            sql += " and status_permit like '%{}%'".format(status_permit)
        if action_permit:
            sql += " and action_permit like '%{}%'".format(action_permit)
        if attri_permit:
            sql += " and attri_permit like '%{}%'".format(attri_permit)
        if time_condition:
            sql += " and time_condition like '%{}%'".format(time_condition)
        if location_condition:
            sql += " and location_condition like '%{}%'".format(location_condition)
        if attri_condition:
            sql += " and attri_condition like '%{}%'".format(attri_condition)
        if level:
            sql += " and level like '%{}%'".format(level)
        if submitter:
            sql += " and submitter like '%{}%'".format(submitter)
        if state:
            sql += " and state like '%{}%'".format(state)
        records = dbs.execute_query(sql)
        policy_list = []
        for rec in records:
            policy_ = Policy()
            policy_.id = rec[0]
            policy_.name = rec[1]
            policy_.user = rec[2]
            policy_.device = rec[3]
            policy_.capability = rec[4]
            policy_.status_permit = True if rec[5]=="True" else False
            policy_.action_permit = True if rec[6]=="True" else False
            policy_.attri_permit = eval(rec[7])
            policy_.time_condition = eval(rec[8])
            policy_.location_condition = rec[9]
            policy_.attri_condition = eval(rec[10])
            policy_.level = rec[11]
            policy_.submitter = rec[12]
            policy_.state = rec[13] 

            policy_list.append(policy_)
        return policy_list