from database.DBService import DBService as dbs
import uuid

class Capability:
    def __init__(self, id="", name="", device=""):
        if id:
            self.id = id
        else:
            self.id = uuid.uuid1()
        self.name = name
        self.device = device

class CapabilityService:
    def addCapability(self, capability):
        sql = "insert into capability(id,name,device) values('{}','{}','{}')".\
            format(capability.id, capability.name, capability.device)
        return dbs.execute_update(sql)
    
    def updateCapability(self, capability):
        sql = "update capability set name='{}',device='{}' where id='{}'".\
            format(capability.name, capability.device, capability.id)
        return dbs.execute_update(sql)

    def deleteCapability(self, capability):
        sql = "delete from capability where id='{}'".format(capability.id)
        return dbs.execute_update(sql)
    
    def deleteCapabilityById(self, id):
        sql = "delete from capability where id='{}'".format(id)
        return dbs.execute_update(sql)
    
    def getCapabilityById(self, id):
        sql = "select id,name,device from capability where id='{}'".format(id)
        record = dbs.execute_query(sql)
        id_ = record[0][0]
        name_ = record[0][1]
        device_ = record[0][2]
        return Capability(id_, name_, device_)
    
    def getCapabilityid(self, name, device):
        sql = "select id from capability where name='{}' and device='{}'".format(name, device)
        record = dbs.execute_query(sql)
        id_ = record[0][0]
        return id_
    
    def getCapability(self, name, device):
        sql = "select id,name,device from capability where 1=1"
        if name:
            sql += " and name like '%{}%'".format(name)
        if device:
            sql += " and device like '%{}%'".format(device)
        record = dbs.execute_query(sql)
        if record:
            id_ = record[0][0]
            name_ = record[0][1]
            device_ = record[0][2]
            return Capability(id_, name_, device_)
        else:
            return None
    
    def getAllCapabilityDatagrid(self, name, device, page, rows):
        sql = "select id,name,device from capability where 1=1"
        if name:
            sql += " and name like '%{}%'".format(name)
        if device:
            sql += " and device like '%{}%'".format(device)
        records = dbs.execute_query(sql)
        records_page = records[(page-1)*rows:page*rows]
        result = {}
        record_json = []
        for rec in records_page:
            record_json.append({"id":rec[0], "name":rec[1], "attribute":rec[2], "value":rec[3], "platform":rec[4], "device":rec[5], "remark":rec[6]})
        result["total"] = len(records)
        result["rows"] = record_json
        return result
    
    def getAllCapabilityFullDatagrid(self, name, device, page, rows):
        sql = "select c.id as id,p.name as platform,d.name as device,c.name as capability from platform p, device d,capability c where d.platform=p.id and c.device=d.id"
        if name:
            sql += " and c.name like '%{}%'".format(name)
        if device:
            sql += " and c.device like '%{}%'".format(device)
        records = dbs.execute_query(sql)
        records_page = records[(page-1)*rows:page*rows]
        result = {}
        record_json = []
        for rec in records_page:
            record_json.append({"id":rec[0], "platform":rec[1], "device":rec[2], "capability":rec[3]})
        result["total"] = len(records)
        result["rows"] = record_json
        return result
    
    def getAllCapabilityJson(self, name, device):
        sql = "select id,name,device from capability where 1=1"
        if name:
            sql += " and name like '%{}%'".format(name)
        if device:
            sql += " and device like '%{}%'".format(device)
        records = dbs.execute_query(sql)
        result = []
        for rec in records:
            result.append({"id":rec[0], "name":rec[1], "device":rec[2]})
        return result