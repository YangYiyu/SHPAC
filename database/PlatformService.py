from database.DBService import DBService as dbs
import uuid

class Platform:
    def __init__(self, id="", name="", package="", activity="", modulename=""):
        if id:
            self.id = id
        else:
            self.id = uuid.uuid1()
        self.name = name
        self.package = package
        self.activity = activity
        self.modulename = modulename

class PlatformService:
    def addPlatform(self, platform):
        sql = "insert into platform(id,name,package,activity,modulename) values('{}', '{}','{}','{}','{}')".\
            format(platform.id, platform.name, platform.package, platform.activity, platform.modulename)
        return dbs.execute_update(sql)
    
    def updatePlatform(self, platform):
        sql = "update platform set name='{}',package='{}',activity='{}',modulename='{}' where id='{}'".\
            format(platform.name, platform.package, platform.activity, platform.modulename, platform.id)
        return dbs.execute_update(sql)

    def deletePlatform(self, platform):
        sql = "delete from platform where id='{}'".format(platform.id)
        return dbs.execute_update(sql)
    
    def deletePlatformById(self, id):
        sql = "delete from platform where id='{}'".format(id)
        return dbs.execute_update(sql)
    
    def getPlatformById(self, id):
        sql = "select id,name,package,activity,modulename from platform where id='{}'".format(id)
        record = dbs.execute_query(sql)
        id_ = record[0][0]
        name_ = record[0][1]
        package_ = record[0][2]
        activity_ = record[0][3]
        modulename_ = record[0][3]
        return Platform(id_, name_, package_, activity_, modulename_)
    
    def getPlatform(self, name, package, activity, modulename):
        sql = "select id,name,package,activity,modulename from platform where 1=1"
        if name:
            sql += " and name like '%{}%'".format(name)
        if package:
            sql += " and package like '%{}%'".format(package)
        if activity:
            sql += " and activity like '%{}%'".format(activity)
        if modulename:
            sql += " and modulename like '%{}%'".format(modulename)
        record = dbs.execute_query(sql)
        if record:
            id_ = record[0][0]
            name_ = record[0][1]
            package_ = record[0][2]
            activity_ = record[0][3]
            modulename_ = record[0][4]
            return Platform(id_, name_, package_, activity_, modulename_)
        else:
            return None
    
    def getAllPlatformDatagrid(self, name, package, activity, modulename, page, rows):
        sql = "select id,name,package,activity,modulename from platform where 1=1"
        if name:
            sql += " and name like '%{}%'".format(name)
        if package:
            sql += " and package like '%{}%'".format(package)
        if activity:
            sql += " and activity like '%{}%'".format(activity)
        if modulename:
            sql += " and modulename like '%{}%'".format(modulename)
        records = dbs.execute_query(sql)
        records_page = records[(page-1)*rows:page*rows]
        result = {}
        record_json = []
        for rec in records_page:
            record_json.append({"id":rec[0], "name":rec[1], "package":rec[2], "activity":rec[3], "modulename":rec[4]})
        result["total"] = len(records)
        result["rows"] = record_json
        return result
    
    def getAllPlatformJson(self, name, package, activity, modulename):
        sql = "select id,name,package,activity,modulename from platform where 1=1"
        if name:
            sql += " and name like '%{}%'".format(name)
        if package:
            sql += " and package like '%{}%'".format(package)
        if activity:
            sql += " and activity like '%{}%'".format(activity)
        if modulename:
            sql += " and modulename like '%{}%'".format(modulename)
        records = dbs.execute_query(sql)
        result = []
        for rec in records:
            result.append({"id":rec[0], "name":rec[1], "package":rec[2], "activity":rec[3], "modulename":rec[4]})
        return result