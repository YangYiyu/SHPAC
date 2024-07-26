from database.DBService import DBService as dbs
import uuid

class User:
    def __init__(self, id="", username="", password="", role=""):
        if id:
            self.id = id
        else:
            self.id = uuid.uuid1()
        self.username = username
        self.password = password
        self.role = role

class UserService:
    def addUser(self, user):
        sql = "insert into user(id,username,password,role) values('{}', '{}', '{}', '{}')".\
            format(user.id, user.username, user.password, user.role)
        return dbs.execute_update(sql)
    
    def updateUser(self, user):
        sql = "update user set username='{}',password='{}',role='{}' where id='{}'".\
            format(user.username, user.password, user.role, user.id)
        return dbs.execute_update(sql)

    def deleteUser(self, user):
        sql = "delete from user where id='{}'".format(user.id)
        return dbs.execute_update(sql)
    
    def deleteUserById(self, id):
        sql = "delete from user where id='{}'".format(id)
        return dbs.execute_update(sql)
    
    def getUserById(self, id):
        sql = "select id,username,password,role from user where id='{}'".format(id)
        record = dbs.execute_query(sql)
        id_ = record[0][0]
        username_ = record[0][1]
        password_ = record[0][2]
        role_ = record[0][3]
        return User(id_, username_, password_, role_)
    
    def getUser(self, username, password, role):
        sql = "select id,username,password,role from user where 1=1"
        if username:
            sql += " and username like '%{}%'".format(username)
        if password:
            sql += " and password like '%{}%'".format(password)
        if role:
            sql += " and role like '%{}%'".format(role)
        record = dbs.execute_query(sql)
        if record:
            id_ = record[0][0]
            username_ = record[0][1]
            password_ = record[0][2]
            role_ = record[0][3]
            return User(id_, username_, password_, role_)
        else:
            return None
    
    def getAllUserDatagrid(self, username, password, role, page, rows):
        sql = "select id,username,password,role from user where 1=1"
        if username:
            sql += " and username like '%{}%'".format(username)
        if password:
            sql += " and password like '%{}%'".format(password)
        if role:
            sql += " and role like '%{}%'".format(role)
        records = dbs.execute_query(sql)
        records_page = records[(page-1)*rows:page*rows]
        result = {}
        record_json = []
        for rec in records_page:
            record_json.append({"id":rec[0], "username":rec[1], "password":rec[2], "role":rec[3]})
        result["total"] = len(records)
        result["rows"] = record_json
        return result
    
    def getAllUserJson(self, username, password, role):
        sql = "select id,username,password,role from user where 1=1"
        if username:
            sql += " and username like '%{}%'".format(username)
        if password:
            sql += " and password like '%{}%'".format(password)
        if role:
            sql += " and role like '%{}%'".format(role)
        records = dbs.execute_query(sql)
        result = []
        for rec in records:
            result.append({"id":rec[0], "username":rec[1], "password":rec[2], "role":rec[3]})
        return result