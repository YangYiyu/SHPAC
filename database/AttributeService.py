from database.DBService import DBService as dbs
import uuid

class Attribute:
    def __init__(self, id="", name="", control="", capability=""):
        if id:
            self.id = id
        else:
            self.id = uuid.uuid1()
        self.name = name
        self.control = control
        self.capability = capability

class AttributeService:
    def addAttribute(self, attribute):
        sql = "insert into attribute(id,name,control,capability) values('{}','{}','{}','{}')".\
            format(attribute.id, attribute.name, attribute.control, attribute.capability)
        return dbs.execute_update(sql)
    
    def updateAttribute(self, attribute):
        sql = "update attribute set name='{}',control='{}',capability='{}' where id='{}'".\
            format(attribute.name, attribute.control, attribute.capability, attribute.id)
        return dbs.execute_update(sql)

    def deleteAttribute(self, attribute):
        sql = "delete from attribute where id='{}'".format(attribute.id)
        return dbs.execute_update(sql)
    
    def deleteAttributeById(self, id):
        sql = "delete from attribute where id='{}'".format(id)
        return dbs.execute_update(sql)
    
    def getAttributeById(self, id):
        sql = "select id,name,control,capability from attribute where id='{}'".format(id)
        record = dbs.execute_query(sql)
        id_ = record[0][0]
        name_ = record[0][1]
        control_ = record[0][2]
        capability_ = record[0][3]
        return Attribute(id_, name_, control_, capability_)
    
    def getAttributeid(self, name, capability):
        sql = "select id from attribute where name='{}' and capability='{}'".format(name, capability)
        record = dbs.execute_query(sql)
        id_ = record[0][0]
        return id_
    
    def getAttributeidByPlatformDeviceCapabilityAttribute(self, platform, device, capability, attribute):
        sql = "select a.id from platform p, device d, capability c, attribute a where d.platform=p.id and c.device=d.id and a.capability=c.id and p.name='{}' and d.name='{}' and c.name='{}' and a.name='{}'".format(platform, device, capability, attribute)
        record = dbs.execute_query(sql)
        id_ = record[0][0]
        return id_

    def getAttribute(self, name, control, capability):
        sql = "select id,name,control,capability from attribute where 1=1"
        if name:
            sql += " and name like '%{}%'".format(name)
        if control:
            sql += " and control like '%{}%'".format(control)
        if capability:
            sql += " and capability like '%{}%'".format(capability)
        record = dbs.execute_query(sql)
        if record:
            id_ = record[0][0]
            name_ = record[0][1]
            control_ = record[0][2]
            capability_ = record[0][3]
            return Attribute(id_, name_, control_, capability_)
        else:
            return None

    def getAllAttributeDatagrid(self, name, control, capability, page, rows):
        sql = "select id,name,control,capability from attribute where 1=1"
        if name:
            sql += " and name like '%{}%'".format(name)
        if control:
            sql += " and control like '%{}%'".format(control)
        if capability:
            sql += " and capability like '%{}%'".format(capability)
        records = dbs.execute_query(sql)
        records_page = records[(page-1)*rows:page*rows]
        result = {}
        record_json = []
        for rec in records_page:
            record_json.append({"id":rec[0], "name":rec[1], "control":rec[2], "capability":rec[3]})
        result["total"] = len(records)
        result["rows"] = record_json
        return result
    
    def getAllAttributeFullDatagrid(self, name, control, capability, page, rows):
        sql = "select a.id as id,p.name as platform,p.package as package,p.activity as activity,d.name as device,c.name as capability,a.name as attribute,a.control from platform p, device d,capability c,attribute a where d.platform=p.id and c.device=d.id and a.capability=c.id"
        if name:
            sql += " and a.name like '%{}%'".format(name)
        if control:
            sql += " and control like '%{}%'".format(control)
        if capability:
            sql += " and a.capability like '%{}%'".format(capability)
        records = dbs.execute_query(sql)
        records_page = records[(page-1)*rows:page*rows]
        result = {}
        record_json = []
        for rec in records_page:
            record_json.append({"id":rec[0], "platform":rec[1], "package":rec[2], "activity":rec[3], "device":rec[4], "capability":rec[5], "attribute":rec[6], "control":rec[7]})
        result["total"] = len(records)
        result["rows"] = record_json
        return result
    
    def getAllAttributeJson(self, name, control, capability):
        sql = "select id,name,control,capability from attribute where 1=1"
        if name:
            sql += " and name like '%{}%'".format(name)
        if control:
            sql += " and control like '%{}%'".format(control)
        if capability:
            sql += " and capability like '%{}%'".format(capability)
        records = dbs.execute_query(sql)
        result = []
        for rec in records:
            result.append({"id":rec[0], "name":rec[1], "control":rec[2], "capability":rec[3]})
        return result