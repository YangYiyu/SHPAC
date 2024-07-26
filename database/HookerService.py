from database.DBService import DBService as dbs
import uuid

class Hooker:
    def __init__(self, id="", script="", type="", capability="", method=""):
        if id:
            self.id = id
        else:
            self.id = uuid.uuid1()
        self.script = script
        self.type = type
        self.capability = capability
        self.method = method

class HookerService:
    def addHooker(self, hooker):
        sql = "insert into hooker(id,script,type,capability,method) values('{}','{}','{}','{}','{}')".\
            format(hooker.id, hooker.script, hooker.type, hooker.capability, hooker.method)
        return dbs.execute_update(sql)
    
    def updateHooker(self, hooker):
        sql = "update hooker set script='{}',type='{}',capability='{}',method='{}' where id='{}'".\
            format(hooker.script, hooker.type, hooker.capability, hooker.method, hooker.id)
        return dbs.execute_update(sql)

    def deleteHooker(self, hooker):
        sql = "delete from hooker where id='{}'".format(hooker.id)
        return dbs.execute_update(sql)
    
    def deleteHookerById(self, id):
        sql = "delete from hooker where id='{}'".format(id)
        return dbs.execute_update(sql)
    
    def getHookerById(self, id):
        sql = "select id,script,type,capability,method from hooker where id='{}'".format(id)
        record = dbs.execute_query(sql)
        id_ = record[0][0]
        script_ = record[0][1]
        type_ = record[0][2]
        capability_ = record[0][3]
        method_ = record[0][4]
        return Hooker(id_, script_, type_, capability_, method_)
    
    def getHookerByCapability(self, type, capaid):
        sql = "select id,script,type,capability,method from hooker where type='{}' and capability='{}'".format(type, capaid)
        record = dbs.execute_query(sql)
        if len(record)>0:
            id_ = record[0][0]
            script_ = record[0][1]
            type_ = record[0][2]
            capability_ = record[0][3]
            method_ = record[0][4]
            return Hooker(id_, script_, type_, capability_, method_)
        else:
            return None
        
    def getAllMethodsByPlatform(self, platform):
        method_array = []
        sql = "select distinct method from hooker h,capability c where h.capability=c.id and c.platform='{}'".format(platform)
        record = dbs.execute_query(sql)
        for m in record:
            method_array.append(m[0])
        return method_array
    
    def getScriptByPlatformMethod(self, platform, method):
        script_array = []
        sql = "select c.platform,c.device,c.name,c.attribute,h.type,h.script from hooker h,capability c where h.capability=c.id and c.platform='{}' and h.method='{}'".format(platform, method)
        record = dbs.execute_query(sql)
        for r in record:
            script_array.append({"platform":r[0],"device":r[1],"capability":r[2],"attribute":r[3],"type":r[4],"script":r[5]})
        return script_array