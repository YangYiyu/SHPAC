from database.DBService import DBService as dbs
import uuid

class Script:
    def __init__(self, id="", path="", platform=""):
        if id:
            self.id = id
        else:
            self.id = uuid.uuid1()
        self.path = path
        self.platform = platform

class ScriptService:
    def addScript(self, script):
        sql = "insert into script(id,path,platform) values('{}','{}','{}')".\
            format(script.id, script.path, script.platform)
        return dbs.execute_update(sql)
    
    def updateScript(self, script):
        sql = "update script set path='{}',platform='{}' where id='{}'".\
            format(script.path, script.platform, script.id)
        return dbs.execute_update(sql)

    def deleteScript(self, script):
        sql = "delete from script where id='{}'".format(script.id)
        return dbs.execute_update(sql)
    
    def deleteScriptById(self, id):
        sql = "delete from script where id='{}'".format(id)
        return dbs.execute_update(sql)
    
    def getScriptById(self, id):
        sql = "select id,path,platform from script where id='{}'".format(id)
        record = dbs.execute_query(sql)
        id_ = record[0][0]
        path_ = record[0][1]
        platform_ = record[0][2]
        return Script(id_, path_, platform_)
    
    def getScript(self, path, platform):
        sql = "select id,path,platform from script where 1=1"
        if path:
            sql += " and path like '%{}%'".format(path)
        if platform:
            sql += " and platform like '%{}%'".format(platform)
        record = dbs.execute_query(sql)
        if record:
            id_ = record[0][0]
            path_ = record[0][1]
            platform_ = record[0][2]
            return Script(id_, path_, platform_)
        else:
            return None
    
    def getAllScriptDatagrid(self, path, platform, page, rows):
        sql = "select id,path,platform from script where 1=1"
        if path:
            sql += " and path like '%{}%'".format(path)
        if platform:
            sql += " and platform like '%{}%'".format(platform)
        records = dbs.execute_query(sql)
        records_page = records[(page-1)*rows:page*rows]
        result = {}
        record_json = []
        for rec in records_page:
            record_json.append({"id":rec[0], "path":rec[1], "platform":rec[2]})
        result["total"] = len(records)
        result["rows"] = record_json
        return result
    
    def getAllScriptJson(self, path, platform):
        sql = "select id,path,platform from script where 1=1"
        if path:
            sql += " and path like '%{}%'".format(path)
        if platform:
            sql += " and platform like '%{}%'".format(platform)
        records = dbs.execute_query(sql)
        result = []
        for rec in records:
            result.append({"id":rec[0], "path":rec[1], "platform":rec[2]})
        return result