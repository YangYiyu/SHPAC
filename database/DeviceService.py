from database.DBService import DBService as dbs
import uuid

class Device:
    def __init__(self, id="", name="", deviceid="", virtualid="", platform=""):
        if id:
            self.id = id
        else:
            self.id = uuid.uuid1()
        self.name = name
        self.deviceid = deviceid
        self.virtualid = virtualid
        self.platform = platform

class DeviceService:
    def addDevice(self, device):
        sql = "insert into device(id,name,deviceid,virtualid,platform) values('{}', '{}', '{}', '{}', '{}')".\
            format(device.id, device.name, device.deviceid, device.virtualid, device.platform)
        return dbs.execute_update(sql)
    
    def updateDevice(self, device):
        sql = "update device set name='{}',deviceid='{}',virtualid='{}',platform='{}' where id='{}'".\
            format(device.name, device.deviceid, device.virtualid, device.platform, device.id)
        return dbs.execute_update(sql)

    def deleteDevice(self, device):
        sql = "delete from device where id='{}'".format(device.id)
        return dbs.execute_update(sql)
    
    def deleteDeviceById(self, id):
        sql = "delete from device where id='{}'".format(id)
        return dbs.execute_update(sql)
    
    def getDeviceById(self, id):
        sql = "select id,name,deviceid,virtualid,platform from device where id='{}'".format(id)
        record = dbs.execute_query(sql)
        id_ = record[0][0]
        name_ = record[0][1]
        deviceid_ = record[0][2]
        virtualid_ = record[0][3]
        platform_ = record[0][4]
        return Device(id_, name_, deviceid_, virtualid_, platform_)
    
    def getDevice(self, name, deviceid, virtualid, platform):
        sql = "select id,name,deviceid,virtualid,platform from device where 1=1"
        if name:
            sql += " and name like '%{}%'".format(name)
        if deviceid:
            sql += " and deviceid like '%{}%'".format(deviceid)
        if virtualid:
            sql += " and virtualid like '%{}%'".format(virtualid)
        if platform:
            sql += " and platform like '%{}%'".format(platform)
        record = dbs.execute_query(sql)
        if record:
            id_ = record[0][0]
            name_ = record[0][1]
            deviceid_ = record[0][2]
            virtualid_ = record[0][3]
            platform_ = record[0][4]
            return Device(id_, name_, deviceid_, virtualid_, platform_)
        else:
            return None
    
    def getAllDeviceDatagrid(self, name, deviceid, virtualid, platform, page, rows):
        sql = "select id,name,deviceid,virtualid,platform from device where 1=1"
        if name:
            sql += " and name like '%{}%'".format(name)
        if deviceid:
            sql += " and deviceid like '%{}%'".format(deviceid)
        if virtualid:
            sql += " and virtualid like '%{}%'".format(virtualid)
        if platform:
            sql += " and platform like '%{}%'".format(platform)
        records = dbs.execute_query(sql)
        records_page = records[(page-1)*rows:page*rows]
        result = {}
        record_json = []
        for rec in records_page:
            record_json.append({"id":rec[0], "name":rec[1], "deviceid":rec[2], "virtualid":rec[3], "platform":rec[4]})
        result["total"] = len(records)
        result["rows"] = record_json
        return result
    
    def getAllDeviceFullDatagrid(self, name, deviceid, virtualid, platform, page, rows):
        sql = "select d.id,d.name,d.deviceid,d.virtualid,p.name as platform from device d, platform p where d.platform=p.id"
        if name:
            sql += " and name like '%{}%'".format(name)
        if deviceid:
            sql += " and deviceid like '%{}%'".format(deviceid)
        if virtualid:
            sql += " and virtualid like '%{}%'".format(virtualid)
        if platform:
            sql += " and platform like '%{}%'".format(platform)
        records = dbs.execute_query(sql)
        records_page = records[(page-1)*rows:page*rows]
        result = {}
        record_json = []
        for rec in records_page:
            record_json.append({"id":rec[0], "name":rec[1], "deviceid":rec[2], "virtualid":rec[3], "platform":rec[4]})
        result["total"] = len(records)
        result["rows"] = record_json
        return result
    
    def getAllDeviceJson(self, name, deviceid, virtualid, platform):
        sql = "select id,name,deviceid,virtualid,platform from device where 1=1"
        if name:
            sql += " and name like '%{}%'".format(name)
        if deviceid:
            sql += " and deviceid like '%{}%'".format(deviceid)
        if virtualid:
            sql += " and virtualid like '%{}%'".format(virtualid)
        if platform:
            sql += " and platform like '%{}%'".format(platform)
        records = dbs.execute_query(sql)
        result = []
        for rec in records:
            result.append({"id":rec[0], "name":rec[1], "deviceid":rec[2], "virtualid":rec[3], "platform":rec[4]})
        return result
    
    def getDeviceidByVirtualid(self, virtualid, platform):
        sql = "select deviceid from device where 1=1"
        if virtualid:
            sql += " and virtualid like '%{}%'".format(virtualid)
        if platform:
            sql += " and platform like '%{}%'".format(platform)
        record = dbs.execute_query(sql)
        if record:
            deviceid_ = record[0][0]
            return deviceid_
        else:
            return ""
        
    def getVirtualidByDeviceid(self, deviceid, platform):
        sql = "select virtualid from device where 1=1"
        if deviceid:
            sql += " and deviceid like '%{}%'".format(deviceid)
        if platform:
            sql += " and platform like '%{}%'".format(platform)
        record = dbs.execute_query(sql)
        if record:
            virtualid_ = record[0][0]
            return virtualid_
        else:
            return ""