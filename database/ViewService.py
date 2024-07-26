from database.DBService import DBService as dbs
import uuid

class View:
    def __init__(self, id="", xpath="", type="", attribute="", idx=""):
        if id:
            self.id = id
        else:
            self.id = uuid.uuid1()
        self.type = type
        self.xpath = xpath
        self.attribute = attribute
        self.idx = idx

class ViewService:
    def addView(self, view):
        sql = "insert into view(id,xpath,type,attribute,idx) values('{}','{}','{}','{}',{})".\
            format(view.id, view.xpath, view.type, view.attribute, view.idx)
        return dbs.execute_update(sql)
    
    def updateView(self, view):
        sql = "update view set xpath='{}',type='{}',attribute='{}',idx={} where id='{}'".\
            format(view.xpath, view.type, view.attribute, view.idx, view.id)
        return dbs.execute_update(sql)

    def deleteView(self, view):
        sql = "delete from view where id='{}'".format(view.id)
        return dbs.execute_update(sql)
    
    def deleteViewById(self, id):
        sql = "delete from view where id='{}'".format(id)
        return dbs.execute_update(sql)
    
    def deleteViewByAttribute(self, attribute):
        sql = "delete from view where attribute='{}'".format(attribute)
        return dbs.execute_update(sql)
    
    def getViewById(self, id):
        sql = "select id,xpath,type,attribute,idx from view where id='{}'".format(id)
        record = dbs.execute_query(sql)
        id_ = record[0][0]
        xpath_ = record[0][1]
        type_ = record[0][2]
        attribute_ = record[0][3]
        idx_ = record[0][4]
        return View(id_, xpath_, type_, attribute_, idx_)
    
    def getView(self, type, xpath, attribute):
        sql = "select id,type,xpath,attribute,idx from view where 1=1"
        if type:
            sql += " and type like '%{}%'".format(type)
        if xpath:
            sql += " and xpath like '%{}%'".format(xpath)
        if attribute:
            sql += " and attribute like '%{}%'".format(attribute)
        record = dbs.execute_query(sql)
        if record:
            id_ = record[0][0]
            xpath_ = record[0][1]
            type_ = record[0][2]
            attribute_ = record[0][3]
            idx_ = record[0][4]
            return View(id_, xpath_, type_, attribute_, idx_)
        else:
            return None
    
    def getAllViewDatagrid(self, type, xpath, attribute, page, rows):
        sql = "select id,xpath,type,attribute,idx from view where 1=1"
        if type:
            sql += " and type like '%{}%'".format(type)
        if xpath:
            sql += " and xpath like '%{}%'".format(xpath)
        if attribute:
            sql += " and attribute like '%{}%'".format(attribute)
        records = dbs.execute_query(sql)
        records_page = records[(page-1)*rows:page*rows]
        result = {}
        record_json = []
        for rec in records_page:
            record_json.append({"id":rec[0], "xpath":rec[1], "type":rec[2], "attribute":rec[3], "idx":rec[4]})
        result["total"] = len(records)
        result["rows"] = record_json
        return result
    
    def getViewXpathArrayByAttribute(self, attributeid):
        sql = "select xpath from view where attribute='{}' order by idx".format(attributeid)
        xpathArray = []
        records = dbs.execute_query(sql)
        for rec in records:
            xpathArray.append(rec[0])
        return xpathArray