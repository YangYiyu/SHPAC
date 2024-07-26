import json
import re
import os
import requests
import zipfile
import time

from flask import Flask
from flask import request, session, render_template, jsonify
from flask_socketio import SocketIO, emit, join_room

from database.PlatformService import Platform, PlatformService
from database.DeviceService import Device, DeviceService
from database.CapabilityService import Capability, CapabilityService
from database.AttributeService import Attribute, AttributeService
from database.ViewService import View, ViewService
from database.HookerService import Hooker, HookerService
from database.UserService import User, UserService
from database.PolicyService import PolicyService
from database.ScriptService import Script, ScriptService
from PubUtil import Util as pubutil
from PolicyUtil import Policy, PolicyUtil, RelationType, CalculateType, PolicyRelation

import UIMonitor
import HookLoader

app = Flask(__name__, template_folder="html")
app.secret_key = os.urandom(24)
socketio_app = SocketIO(app)

platform_service = PlatformService()
device_service = DeviceService()
capability_service = CapabilityService()
attribute_service = AttributeService()
view_service = ViewService()
hooker_service = HookerService()
script_service = ScriptService()
user_service = UserService()
policy_service = PolicyService()

monitor = UIMonitor.UIMonitor()
hookUtilMap = {}

inspector = None

policy_util = PolicyUtil()

# 存储用户会话ID的字典
username_session_map = {}

# 存储平台配置状态的字典
app_config_status_map = {}

# 存储订阅capability消息的字典
capability_subscriber_map = {}

# 存储用户位置的字典
user_location = {}

# 存储设备状态的字典
attri_status = {}

################## Begin HTML Router ##################
@app.route("/")
def default():
    return render_template("MainPage.html")

@app.route("/AppBasePage")
def AppBasePage():
    return render_template("AppBasePage.html")

@app.route("/DeviceBasePage")
def DeviceBasePage():
    return render_template("DeviceBasePage.html")

@app.route("/CapabilityBasePage")
def CapabilityBasePage():
    return render_template("CapabilityBasePage.html")

@app.route("/AttributeBasePage")
def AttributeBasePage():
    return render_template("AttributeBasePage.html")

@app.route("/XpathConfigPage")
def XpathConfigPage():
    return render_template("XpathConfigPage.html")

@app.route("/ScriptBasePage")
def ScriptBasePage():
    return render_template("ScriptBasePage.html")

@app.route("/OwnerPage")
def OwnerPage():
    return render_template("OwnerPage.html")

@app.route("/UserManagePage")
def UserManagePage():
    if "valid_user" not in session:
        return render_template("LoginPage.html")
    return render_template("UserManagePage.html")

@app.route("/PolicyManagePage")
def PolicyManagePage():
    if "valid_user" not in session:
        return render_template("LoginPage.html")
    return render_template("PolicyManagePage.html")

@app.route("/PolicyAddPage")
def PolicyAddPage():
    if "valid_user" not in session:
        return render_template("LoginPage.html")
    return render_template("PolicyAddPage.html")

@app.route("/LoginPage")
def LoginPage():
    return render_template("LoginPage.html")

@app.route("/usercheck", methods=["GET", "POST"])
def usercheck():
    username_ = request.form.get("username")
    password_ = request.form.get("password")
    user = user_service.getUser(username_, password_, "")
    if user:
        if user.role=="admin":
            session["valid_user"] = username_
            return "to_admin"
        else:
            session["valid_user"] = username_
            return "to_user"
    else:
        return "Wrong username or password!"
    
@app.route("/AdminControlPage", methods=["GET", "POST"])
def AdminControlPage():
    if "valid_user" not in session:
        return render_template("LoginPage.html")

    result_ = {}
    for platform_ in platform_service.getAllPlatformJson("", "", "", ""):
        device_map = {}
        for device_ in device_service.getAllDeviceJson("", "", "", platform_["id"]):
            capability_map = {}
            for capability_ in capability_service.getAllCapabilityJson("", device_["id"]):
                # 在这里做权限检查
                sub_user = session["valid_user"]
                permission = checkStatusPermission(sub_user, device_["virtualid"], capability_["name"])
                if not permission[0]:
                    continue

                attri_map = {}
                for attribute_ in attribute_service.getAllAttributeJson("", "", capability_["id"]):
                    attri_map[attribute_["name"]] = attribute_["control"]
                capability_map[capability_["name"]] = attri_map
            device_map[device_["name"]] = {"deviceid": device_["deviceid"], "devicevid": device_["virtualid"], "capability": capability_map}
        result_[platform_["name"]] = device_map

    print(result_)

    return render_template("AdminControlPage.html", platformMap=result_)

@app.route("/UserControlPage", methods=["GET", "POST"])
def UserControlPage():
    if "valid_user" not in session:
        return render_template("LoginPage.html")

    result_ = {}
    for platform_ in platform_service.getAllPlatformJson("", "", "", ""):
        device_map = {}
        for device_ in device_service.getAllDeviceJson("", "", "", platform_["id"]):
            capability_map = {}
            for capability_ in capability_service.getAllCapabilityJson("", device_["id"]):
                # 在这里做权限检查
                sub_user = session["valid_user"]
                permission = checkStatusPermission(sub_user, device_["virtualid"], capability_["name"])
                if not permission[0]:
                    continue
                
                attri_map = {}
                for attribute_ in attribute_service.getAllAttributeJson("", "", capability_["id"]):
                    attri_map[attribute_["name"]] = attribute_["control"]
                capability_map[capability_["name"]] = attri_map
            device_map[device_["name"]] = {"deviceid": device_["deviceid"], "devicevid": device_["virtualid"], "capability": capability_map}
        result_[platform_["name"]] = device_map

    return render_template("UserControlPage.html", platformMap=result_)
################## End HTML Router ##################

################## Begin User Management ##################
@app.route("/getUser", methods=["GET", "POST"])
def getUser():
    username_ = request.form.get("username")
    user = user_service.getUser(username_, "", "")
    if user:
        return {"id": user.id, "username":user.username, "password":user.password, "role":user.role}
    else:
        return ""

@app.route("/addUser", methods=["GET", "POST"])
def addUser():
    username_ = request.form.get("username")
    password_ = request.form.get("password")
    role_ = request.form.get("role")
    user = User(username=username_, password=password_, role=role_)
    if user_service.addUser(user):
        return "success"
    else:
        return "failed"

@app.route("/checkUsername", methods=["GET", "POST"])
def checkUsername():
    username_ = request.form.get("username")
    user = user_service.getUser(username_, "", "")
    if user:
        return "1"
    else:
        return "0"

@app.route("/updateUser", methods=["GET", "POST"])
def updateUser():
    id_ = request.form.get("id")
    password_ = request.form.get("password")
    role_ = request.form.get("role")
    user = user_service.getUserById(id_)
    user.password = password_
    user.role = role_
    if user_service.updateUser(user):
        return "success"
    else:
        return "failed"

@app.route("/removeUser", methods=["GET", "POST"])
def removeUser():
    id_ = request.form.get("id")
    if user_service.deleteUserById(id_):
        return "success"
    else:
        return "failed"

@app.route("/getAllUserDatagrid", methods=["GET", "POST"])
def getAllUserDatagrid():
    username_ = request.form.get("username")
    role_ = request.form.get("role")
    page = request.form.get("page")
    rows = request.form.get("rows")
    userJson = user_service.getAllUserDatagrid(username_, "", role_, int(page), int(rows))
    if userJson:
        return userJson
    else:
        return {"total":0,"rows":[]}
    
@app.route("/getAllUserJson", methods=["GET", "POST"])
def getAllUserJson():
    userJson = user_service.getAllUserJson("", "", "")
    if userJson:
        return userJson
    else:
        return {"total":0,"rows":[]}
################## End User Management ##################

################## Begin Capability Management ##################
@app.route("/getAllCapabilityDatagrid", methods=["GET", "POST"])
def getAllCapabilityDatagrid():
    name_ = request.form.get("name")
    device_ = request.form.get("device")
    page = request.form.get("page")
    rows = request.form.get("rows")
    capaJson = capability_service.getAllCapabilityFullDatagrid(name_, device_, int(page), int(rows))
    if capaJson:
        return capaJson
    else:
        return {"total":0,"rows":[]}

@app.route("/addCapability", methods=["GET", "POST"])
def addCapability():
    name_ = request.form.get("name")
    attribute_ = request.form.get("attribute")
    value_ = request.form.get("value")
    platform_ = request.form.get("platform")
    device_ = request.form.get("device")
    remark_ = request.form.get("remark")
    capa = Capability(name=name_, attribute=attribute_, value=value_, platform=platform_, device=device_, remark=remark_)
    if capability_service.addCapability(capa):
        return "success"
    else:
        return "failed"
    
@app.route("/saveCapability", methods=["GET", "POST"])
def saveCapability():
    id_ = request.form.get("id")
    name_ = request.form.get("name")
    attribute_ = request.form.get("attribute")
    value_ = request.form.get("value")
    platform_ = request.form.get("platform")
    device_ = request.form.get("device")
    remark_ = request.form.get("remark")
    capa = capability_service.getCapabilityById(id_);
    if capa:
        capa.name = name_
        capa.attribute = attribute_
        capa.value = value_
        capa.platform = platform_
        capa.device = device_
        capa.remark = remark_
        if capability_service.updateCapability(capa):
            return "success"
        else:
            return "failed"
    else:
        return "failed"

@app.route("/deleteCapability", methods=["GET", "POST"])
def deleteCapability():
    id_ = request.form.get("id")
    if capability_service.deleteCapabilityById(id_):
        return 'success'
    else:
        return 'failed'
    
@app.route("/getAllCapabilityJson", methods=["GET", "POST"])
def getAllCapabilityJson():
    device_ = request.args.get("device")
    capabilityJson = capability_service.getAllCapabilityJson("", device_)
    if capabilityJson:
        return capabilityJson
    else:
        return []
################## End Capability Management ##################

################## Begin Attribute Management ##################
@app.route("/getAllAttributeDatagrid", methods=["GET", "POST"])
def getAllAttributeDatagrid():
    name_ = request.form.get("name")
    control_ = request.form.get("control")
    capability_ = request.form.get("capability")
    page = request.form.get("page")
    rows = request.form.get("rows")
    attrJson = attribute_service.getAllAttributeFullDatagrid(name_, control_, capability_, int(page), int(rows))
    if attrJson:
        return attrJson
    else:
        return {"total":0,"rows":[]}

@app.route("/getAttributeJson", methods=["GET", "POST"])
def getAttributeJson():
    name_ = request.args.get("name")
    control_ = request.args.get("control")
    capability_ = request.args.get("capability")
    attrJson = attribute_service.getAllAttributeJson(name_, control_, capability_)
    if attrJson:
        return attrJson
    else:
        return {}

@app.route("/saveAttribute", methods=["GET", "POST"])
def saveAttribute():
    id_ = request.form.get("id")
    name_ = request.form.get("name")
    control_ = request.form.get("control")

    attri = attribute_service.getAttributeById(id_);
    if attri:
        attri.name = name_
        attri.control = control_
        if attribute_service.updateAttribute(attri):
            return "success"
        else:
            return "failed"
    else:
        return "failed"
################## End Attribute Management ##################

################## Begin Xpath Record Management ##################
@app.route("/startRecord", methods=["GET", "POST"])
def startRecord():
    global monitor
    if not monitor:
        monitor = UIMonitor.UIMonitor()
    package = request.form.get("package")
    activity = request.form.get("activity")
    monitor.start_listening(package, activity)
    return "success"

@app.route("/stopRecord", methods=["GET", "POST"])
def stopRecord():
    global monitor
    if not monitor:
        monitor = UIMonitor.UIMonitor()
    monitor.stop_listening()
    return "success"

@app.route("/replayRecord", methods=["GET", "POST"])
def replayRecord():
    global monitor
    if not monitor:
        monitor = UIMonitor.UIMonitor()
    app = request.form.get("app")
    activity = request.form.get("activity")
    monitor.replay_and_calculate(app, activity)
    result = {}
    xpath_json = []
    for x in monitor.view_quene:
        xpath_json.append({"xpath":x})
    result["total"] = len(monitor.view_quene)
    result["rows"] = xpath_json
    return result

@app.route("/clickXpath", methods=["GET", "POST"])
def clickXpath():
    platform = request.form.get("platform")
    app_info = platform_service.getPlatform(platform, "", "", "")
    
    xpaths = request.form.get("xpaths")
    xpaths_json = json.loads(xpaths)
    xpath_array = [x["xpath"] for x in xpaths_json]
    global monitor
    if not monitor:
        monitor = UIMonitor.UIMonitor()
    monitor.click_multi_elements_by_U2(xpath_array, app_info.package, app_info.activity)
    return "success"

@app.route("/clickXpathByIds", methods=["GET", "POST"])
def clickXpathByIds():
    platform = request.form.get("platform")
    app_info = platform_service.getPlatform(platform, "", "", "")
    xpath_array = []
    ids_ = request.form.get("ids")
    for id in ids_.split(","):
        if id:
            view_ = view_service.getViewById(id)
            xpath_array.append(view_.xpath)
    global monitor
    if not monitor:
        monitor = UIMonitor.UIMonitor()
    monitor.click_multi_elements_by_U2(xpath_array, app_info.package, app_info.activity)
    return "success"

@app.route("/replayXpath", methods=["GET", "POST"])
def replayXpath():
    app = request.form.get("app")
    activity = request.form.get("activity")
    
    xpaths = request.form.get("xpaths")
    xpaths_json = json.loads(xpaths)
    xpath_array = [x["xpath"] for x in xpaths_json]
    global monitor
    if not monitor:
        monitor = UIMonitor.UIMonitor()
    monitor.click_multi_elements_by_U2(xpath_array, app, activity)
    return "success"
################## End Xpath Record Management ##################

################## Begin View Management ##################
@app.route("/saveClickView", methods=["GET", "POST"])
def saveClickView():
    attriid = request.form.get("attriid")
    xpaths = request.form.get("xpaths")
    xpath_array = json.loads(xpaths)
    print(xpath_array)
    for i in range(len(xpath_array)):
        xpath = xpath_array[i]
        new_view = View("", xpath["xpath"], "click", attriid, i)
        view_service.addView(new_view)
    return "success"

@app.route("/getAllView", methods=["GET", "POST"])
def getAllView():
    type_ = request.form.get("type")
    attriid_ = request.form.get("attriid")
    page = 1
    rows = 20
    viewJson = view_service.getAllViewDatagrid(type_, "", attriid_, int(page), int(rows))
    if viewJson:
        return viewJson
    else:
        return {"total":0,"rows":[]}
    
@app.route("/deleteViewBatch", methods=["GET", "POST"])
def deleteViewBatch():
    ids_ = request.form.get("ids")
    for id_ in ids_.split(","):
        if id_:
            view_service.deleteViewById(id_)
    return 'success'
################## End View Management ##################

################## Begin Hooker Management (discarded) ##################
@app.route("/addOrUpdateHooker", methods=["GET", "POST"])
def addOrUpdateHooker():
    script_ = request.form.get("script").replace("'", "\"")
    type_ = request.form.get("type")
    capabilityid_ = request.form.get("capabilityid")
    method_ = request.form.get("method")
    hooker = hooker_service.getHookerByCapability(type_, capabilityid_)
    if hooker:
        hooker.script = script_
        hooker.type = type_
        hooker.method = method_
        if hooker_service.updateHooker(hooker):
            return "success"
        else:
            return "failed"
    else:
        hooker = Hooker("", script_, type_, capabilityid_, method_)
        if hooker_service.addHooker(hooker):
            return "success"
        else:
            return "failed"

@app.route("/getHookerScript", methods=["GET", "POST"])
def getHookerScript():
    type_ = request.form.get("type")
    capabilityid_ = request.form.get("capabilityid")
    hooker = hooker_service.getHookerByCapability(type_, capabilityid_)
    # socketio_app.emit("dev_status", "hello")
    if hooker:
        return hooker.script
    else:
        return ""
    
@app.route("/getHookerInfo", methods=["GET", "POST"])
def getHookerInfo():
    type_ = request.form.get("type")
    capabilityid_ = request.form.get("capabilityid")
    hooker = hooker_service.getHookerByCapability(type_, capabilityid_)
    # socketio_app.emit("dev_status", "hello")
    if hooker:
        return {"script":hooker.script, "method":hooker.method}
    else:
        return ""
################## End Hooker Management (discarded) ##################

################## Begin Platform Management ##################
@app.route("/getAllPlatformDatagrid", methods=["GET", "POST"])
def getAllPlatformDatagrid():
    name_ = request.form.get("name")
    package_ = request.form.get("package")
    activity_ = request.form.get("activity")
    modulename_ = request.form.get("modulename")
    page = request.form.get("page")
    rows = request.form.get("rows")
    appJson = platform_service.getAllPlatformDatagrid(name_, package_, activity_, modulename_, int(page), int(rows))
    if appJson:
        return appJson
    else:
        return {"total":0,"rows":[]}

@app.route("/getAllPlatformJson", methods=["GET", "POST"])
def getAllPlatformJson():
    appJson = platform_service.getAllPlatformJson("", "", "", "")
    if appJson:
        return appJson
    else:
        return []

@app.route("/getAppCurrent", methods=["GET", "POST"])
def getAppCurrent():
    global monitor
    if not monitor:
        monitor = UIMonitor.UIMonitor()
    basic = monitor.getAppBasicInfo()
    return {"package": basic["package"], "activity": basic["activity"]}

@app.route("/addPlatform", methods=["GET", "POST"])
def addPlatform():
    name_ = request.form.get("name")
    package_ = request.form.get("package")
    activity_ = request.form.get("activity")
    modulename_ = request.form.get("modulename")
    platform = Platform(name=name_, package=package_, activity=activity_, modulename=modulename_)
    if platform_service.addPlatform(platform):
        return "success"
    else:
        return "failed"
    
@app.route("/savePlatform", methods=["GET", "POST"])
def savePlatform():
    id_ = request.form.get("id")
    name_ = request.form.get("name")
    package_ = request.form.get("package")
    activity_ = request.form.get("activity")
    modulename_ = request.form.get("modulename")
    platform = platform_service.getPlatformById(id_)
    if app:
        app.name = name_
        app.package = package_
        app.activity = activity_
        app.modulename = modulename_
        if platform_service.updatePlatform(platform):
            return "success"
        else:
            return "failed"
    else:
        return "failed"
    
@app.route("/deleteApp", methods=["GET", "POST"])
def deleteApp():
    id_ = request.form.get("id")
    if platform_service.deletePlatformById(id_):
        return 'success'
    else:
        return 'failed'
################## End Platform Management ##################

################## Begin Device Management ##################
@app.route("/getAllDeviceDatagrid", methods=["GET", "POST"])
def getAllDeviceDatagrid():
    platform_ = request.form.get("platform")
    page = request.form.get("page")
    rows = request.form.get("rows")
    deviceJson = device_service.getAllDeviceFullDatagrid("", "", "", platform_, int(page), int(rows))
    if deviceJson:
        return deviceJson
    else:
        return {"total":0,"rows":[]}

@app.route("/getAllDeviceJson", methods=["GET", "POST"])
def getAllDeviceJson():
    platform_ = request.args.get("platform")
    deviceJson = device_service.getAllDeviceJson("", "", "", platform_)
    if deviceJson:
        return deviceJson
    else:
        return []
################## End Device Management ##################

################## Begin Policy Register ##################
@app.route("/getPolicy", methods=["GET", "POST"])
def getPolicy():
    id_ = request.form.get("id")
    policy = policy_service.getPolicyById(id_)
    if policy:
        return {"id": policy.id, "name":policy.name, "user":policy.user, "device":policy.device, "capability":policy.capability, "status_permit":policy.status_permit, "action_permit":policy.action_permit, "attri_permit":policy.attri_permit, "time_condition":policy.time_condition, "location_condition":policy.location_condition, "attri_condition":policy.attri_condition, "submitter":policy.submitter, "level":policy.level, "state":policy.state}
    else:
        return ""

def getPolicyByRequest(request):
    name_ = request.form.get("name")
    userid_ = request.form.get("user")
    deviceid_ = request.form.get("device")
    capabilityid_ = request.form.get("capability")
    status_permit_ = request.form.get("status_permit")
    action_permit_ = request.form.get("action_permit")
    attri_permit_ = request.form.get("attri_permit")
    time_condition_ = request.form.get("time_condition")
    location_condition_ = request.form.get("location_condition")
    attri_condition_ = request.form.get("attri_condition")
    flag_ = request.form.get("flag")

    print("++++++++++++++++++++ receive policy +++++++++++++++++++++++++++")
    print(name_)
    print(userid_)
    print(deviceid_)
    print(capabilityid_)
    print(status_permit_)
    print(action_permit_)
    print(attri_permit_)
    print(time_condition_)
    print(location_condition_)
    print(attri_condition_)

    attri_permit_map = {}
    for attri_p in json.loads(attri_permit_)["rows"]:
        attribute_ = attri_p["attribute"]
        value_ = attri_p["value"]
        if value_=="True" or value_=="False":
            value_ = True if value_=="True" else False
            attri_permit_map[attribute_] = value_
        else:
            # value_ = [int(v) for v in value_[1:len(value_)-1].split(",")]
            if attribute_ not in attri_permit_map:
                attri_permit_map[attribute_] = []
            attri_permit_map[attribute_].append(value_)
    
    time_condition_list = []
    for time_c in json.loads(time_condition_)["rows"]:
        time_condition_list.append(time_c["time"])
    if len(time_condition_list)==0:
        time_condition_list.append("any")

    attri_condition_map = {}
    for attri_c in json.loads(attri_condition_)["rows"]:
        attribute_ = attri_c["attribute"]
        value_ = attri_c["value"]
        if value_=="True" or value_=="False":
            value_ = True if value_=="True" else False
            attri_condition_map[attribute_] = value_
        else:
            if attribute_ not in attri_condition_map:
                attri_condition_map[attribute_] = []
            attri_condition_map[attribute_].append(value_)

    current_user = session.get("valid_user")
    user = user_service.getUser(current_user, "", "")
    level = user.role

    policy = Policy()
    policy.name = name_
    policy.user = user_service.getUserById(userid_).username
    policy.device = device_service.getDeviceById(deviceid_).virtualid
    policy.capability = capability_service.getCapabilityById(capabilityid_).name
    policy.status_permit = True if str(status_permit_)=="True" else False
    policy.action_permit = True if str(action_permit_)=="True" else False
    policy.attri_permit = attri_permit_map
    policy.time_condition = time_condition_list
    policy.location_condition = location_condition_
    policy.attri_condition = attri_condition_map
    policy.level = level
    policy.submitter = current_user
    policy.state = "check" if flag_=="0" else "accept"

    return policy

@app.route("/addPolicy", methods=["GET", "POST"])
def addPolicy():
    policy = getPolicyByRequest(request)

    if policy_service.addPolicy(policy):
        return "success"
    else:
        return "failed"

@app.route("/acceptPolicy", methods=["GET", "POST"])
def acceptPolicy():
    id_ = request.form.get("id")
    policy = policy_service.getPolicyById(id_)
    policy.state = "accept"
    if policy_service.updatePolicy(policy):
        return "success"
    else:
        return "failed"

@app.route("/rejectPolicy", methods=["GET", "POST"])
def rejectPolicy():
    id_ = request.form.get("id")
    policy = policy_service.getPolicyById(id_)
    policy.state = "reject"
    if policy_service.updatePolicy(policy):
        return "success"
    else:
        return "failed"

@app.route("/removePolicy", methods=["GET", "POST"])
def removePolicy():
    id_ = request.form.get("id")
    if policy_service.deletePolicyById(id_):
        return "success"
    else:
        return "failed"

@app.route("/getAllPolicyDatagrid", methods=["GET", "POST"])
def getAllPolicyDatagrid():
    user_ = request.form.get("user")
    device_ = request.form.get("device")
    capability_ = request.form.get("capability")
    page = request.form.get("page")
    rows = request.form.get("rows")
    policyJson = policy_service.getAllPolicyDatagrid("", user_, device_, capability_, "", "", "", "", "", "", "", "", "", int(page), int(rows))
    if policyJson:
        return policyJson
    else:
        return {"total":0,"rows":[]}
    
@app.route("/getAllUserPolicy", methods=["GET", "POST"])
def getAllUserPolicy():
    user_ = session.get("valid_user")
    related_policy_list = policy_service.getAllPolicyJson("", user_, "", "", "", "", "", "", "", "", "" ,"", "")
    submitted_policy_list = policy_service.getAllPolicyJson("", "", "", "", "", "", "", "", "", "", "", user_, "")
    return render_template("PolicyResultPage.html", policy_list={"related_policy_list":related_policy_list,"submitted_policy_list":submitted_policy_list})

@app.route("/checkPolicyByRequest", methods=["GET", "POST"])
def checkPolicyByRequest():
    N_P = getPolicyByRequest(request)
    accept_policy_list = policy_service.getPolicyList("", N_P.user, N_P.device, N_P.capability, "", "", "", "", "", "", "", "", "accept")
    result = policy_util.getCheckResult(N_P, accept_policy_list)
    return {
        "policy_relation": str(result["pr"]),
        "related_policy": result["related_policy"] if result["related_policy"] else "",
        "handle": result["handle"],
        "suggested_policy": result["suggested_policy"] if result["suggested_policy"] else ""
    }

@app.route("/checkPolicyById", methods=["GET", "POST"])
def checkPolicyById():
    policyid_ = request.form.get("policyid")
    N_P = policy_service.getPolicyById(policyid_)
    accept_policy_list = policy_service.getPolicyList("", N_P.user, N_P.device, N_P.capability, "", "", "", "", "", "", "", "", "accept")
    result = policy_util.getCheckResult(N_P, accept_policy_list)
    return {
        "policy_relation": str(result["pr"]),
        "related_policy": result["related_policy"] if result["related_policy"] else "",
        "handle": result["handle"],
        "suggested_policy": result["suggested_policy"] if result["suggested_policy"] else ""
    }

@app.route("/acceptSuggestion", methods=["GET", "POST"])
def acceptSuggestion():
    o_p_id_ = request.form.get("o_p_id")
    n_p_id_ = request.form.get("n_p_id")
    handle_ = request.form.get("handle")
    
    if "accept_np" in handle_:
        p_ = policy_service.getPolicyById(n_p_id_)
        p_.state = "accept"
        policy_service.updatePolicy(p_)
    if "reject_np" in handle_:
        p_ = policy_service.getPolicyById(n_p_id_)
        p_.state = "reject"
        policy_service.updatePolicy(p_)
    if "reject_op" in handle_:
        p_ = policy_service.getPolicyById(o_p_id_)
        p_.state = "reject"
        policy_service.updatePolicy(p_)
    if "remove_np" in handle_:
        policy_service.deletePolicyById(n_p_id_)

    return "success"

def checkNewPolicyAcceptable(policy_id):
    check_policy = policy_service.getPolicyById(policy_id)
    other_policy_list = policy_service.getPolicyList("", check_policy.user, check_policy.device, check_policy.capability, "", "", "", "", "", "", "", "", "accept")
    result = policy_util.getCheckResult(check_policy, other_policy_list)
    if result["pr"]==PolicyRelation.independent or result["pr"]==PolicyRelation.unrelated:
        return True
    else:
        return False

@app.route("/agreeSuggestPolicy", methods=["GET", "POST"])
def agreeSuggestPolicy():
    modified_policy_ = request.form.get("modified_policy")
    modified_policy_json = json.loads(modified_policy_)
    n_p_id_ = request.form.get("n_p_id")
    o_p_id_ = request.form.get("o_p_id")
    handle_ = request.form.get("handle")

    if handle_ == "accept_mnp":
        M_N_P = policy_service.getPolicyById(n_p_id_)
        M_N_P.status_permit = True if str(modified_policy_json["status_permit"])=="True" else False
        M_N_P.action_permit = True if str(modified_policy_json["action_permit"])=="True" else False
        M_N_P.attri_permit = modified_policy_json["attri_permit"]
        M_N_P.time_condition = modified_policy_json["time_condition"]
        M_N_P.location_condition = modified_policy_json["location_condition"]
        M_N_P.attri_condition = modified_policy_json["attri_condition"]
        M_N_P.state = "accept"
        policy_service.updatePolicy(M_N_P)

        if not checkNewPolicyAcceptable(M_N_P.id):
            M_N_P.state = "check"
            policy_service.updatePolicy(M_N_P)

    elif handle_ == "accept_mnp_reject_op":
        M_N_P = policy_service.getPolicyById(n_p_id_)
        M_N_P.status_permit = True if str(modified_policy_json["status_permit"])=="True" else False
        M_N_P.action_permit = True if str(modified_policy_json["action_permit"])=="True" else False
        M_N_P.attri_permit = modified_policy_json["attri_permit"]
        M_N_P.time_condition = modified_policy_json["time_condition"]
        M_N_P.location_condition = modified_policy_json["location_condition"]
        M_N_P.attri_condition = modified_policy_json["attri_condition"]
        M_N_P.state = "accept"
        policy_service.updatePolicy(M_N_P)

        if not checkNewPolicyAcceptable(M_N_P.id):
            M_N_P.state = "check"
            policy_service.updatePolicy(M_N_P)

        M_O_P = policy_service.getPolicyById(o_p_id_)
        M_O_P.state = "reject"
        policy_service.updatePolicy(M_O_P)
    elif handle_ == "accept_np_accept_mop":
        M_N_P = policy_service.getPolicyById(n_p_id_)
        M_N_P.state = "accept"
        policy_service.updatePolicy(M_N_P)

        if not checkNewPolicyAcceptable(M_N_P.id):
            M_N_P.state = "check"
            policy_service.updatePolicy(M_N_P)

        M_O_P = policy_service.getPolicyById(o_p_id_)
        M_O_P.status_permit = True if str(modified_policy_json["status_permit"])=="True" else False
        M_O_P.action_permit = True if str(modified_policy_json["action_permit"])=="True" else False
        M_O_P.attri_permit = modified_policy_json["attri_permit"]
        M_O_P.time_condition = modified_policy_json["time_condition"]
        M_O_P.location_condition = modified_policy_json["location_condition"]
        M_O_P.attri_condition = modified_policy_json["attri_condition"]
        M_O_P.state = "accept"
        policy_service.updatePolicy(M_O_P)

        if not checkNewPolicyAcceptable(M_O_P.id):
            M_N_P.state = "check"
            policy_service.updatePolicy(M_O_P)

    return "success"

@app.route("/agreeSubmitSuggestPolicy", methods=["GET", "POST"])
def agreeSubmitSuggestPolicy():
    modified_policy_ = request.form.get("modified_policy")
    modified_policy_json = json.loads(modified_policy_)

    M_N_P = Policy()
    M_N_P.id = modified_policy_json["id"]
    M_N_P.name = modified_policy_json["name"]
    M_N_P.user = modified_policy_json["user"]
    M_N_P.device = modified_policy_json["device"]
    M_N_P.capability = modified_policy_json["capability"]
    M_N_P.status_permit = True if str(modified_policy_json["status_permit"])=="True" else False
    M_N_P.action_permit = True if str(modified_policy_json["action_permit"])=="True" else False
    M_N_P.attri_permit = modified_policy_json["attri_permit"]
    M_N_P.time_condition = modified_policy_json["time_condition"]
    M_N_P.location_condition = modified_policy_json["location_condition"]
    M_N_P.attri_condition = modified_policy_json["attri_condition"]
    M_N_P.level = modified_policy_json["level"]
    M_N_P.submitter = modified_policy_json["submitter"]
    M_N_P.state = "check"
    policy_service.addPolicy(M_N_P)

    return "success"
################## End Policy Register ##################

################## Begin Device Register ##################
@app.route("/registerDevicePage", methods=["GET", "POST"])
def registerDevicePage():
    mname_ = request.args.get("mname")
    device_ = request.args.get("device")

    print("Downloading module from server ...")
    downloadDeviceModuleByName(mname_)
    print("Download completed!")
    
    config_json = pubutil.loadConfigJsonFromLocalFile(mname_)
    device_config = {}
    device_config["module"] = config_json["modulename"]
    device_config["platform"] = config_json["platform"]
    device_config["package"] = config_json["package"]
    device_config["activity"] = config_json["activity"]
    device_config["script"] = ",".join([scr["file"] for scr in config_json["script"]])
    device_config["version"] = config_json["version"]

    for dev in config_json["deviceList"]:
        if dev["device"]==device_:
            device_config["device"] = dev["device"]
            device_config["description"] = dev["description"]
            device_config["capabilityList"] = dev["capabilityList"]
            # 生成本地的 device id
            vitual_deviceid = "{}-{}-{}".format(config_json["platform"], dev["device"], int(time.time()))
            device_config["vitual_deviceid"] = vitual_deviceid
            break

    external_script = pubutil.loadFridaScriptFromConfigJson(config_json)
    hookUtilMap[config_json["platform"]].reload_script(external_js=external_script)

    app_config_status_map[config_json["platform"]] = True

    return render_template("RegisterDevicePage.html", configJson=device_config)

@app.route("/saveRegisterInfo", methods=["GET", "POST"])
def saveRegisterInfo():
    modulename_ = request.form.get("module")
    platform_ = request.form.get("platform")
    package_ = request.form.get("package")
    activity_ = request.form.get("activity")
    device_ = request.form.get("device")
    deviceid_ = request.form.get("deviceid")
    virtualid_ = request.form.get("virtualid")
    description_ = request.form.get("description")
    version_ = request.form.get("version")
    script_ = request.form.get("script")
    control_data = request.form.get("control_data")
    xpath_data_ = request.form.get("xpath_data")

    platform_obj = platform_service.getPlatform(platform_, "", "", "")
    if platform_obj:
        platform_service.updatePlatform(platform_obj)
    else:
        platform_obj = Platform(name=platform_, package=package_, activity=activity_, modulename=modulename_)
        platform_service.addPlatform(platform_obj)
    
    device_obj = device_service.getDevice("", deviceid_, "", "")
    if device_obj:
        device_service.updateDevice(device_obj)
    else:
        device_obj = Device(name=device_, deviceid=deviceid_, virtualid=virtualid_, platform=platform_obj.id)
        device_service.addDevice(device_obj)
    
    print("+++++++++++")
    print(control_data)
    control_data_json = json.loads(control_data)
    xpath_data_json = json.loads(xpath_data_)
    for capa_attr in xpath_data_json:
        capa = capa_attr.split("-")[0]
        attr = capa_attr.split("-")[1]
        capability_obj = capability_service.getCapability(capa, device_obj.id)
        if not capability_obj:
            capability_obj = Capability(name=capa, device=device_obj.id)
            capability_service.addCapability(capability_obj)
        
        attribute_obj = attribute_service.getAttribute(attr, "", capability_obj.id)
        print(attribute_obj)
        attri_control = control_data_json[f"{capa}-{attr}-control"]
        if not attribute_obj:
            attribute_obj = Attribute(name=attr, control=attri_control, capability=capability_obj.id)
            attribute_service.addAttribute(attribute_obj)
        else:
            attribute_obj.control = attri_control
            attribute_service.updateAttribute(attribute_obj)
        
        idx = 0
        view_service.deleteViewByAttribute(attribute_obj.id)
        for view in xpath_data_json[capa_attr]:
            xpath = view["xpath"]
            view_obj = View(xpath=xpath, type="click", attribute=attribute_obj.id, idx=idx)
            view_service.addView(view_obj)
            idx += 1

    for script_name in script_.split(","):
        relative_path = os.path.join("module", modulename_, script_name+".js")
        script_obj = script_service.getScript(relative_path, platform_obj.id)
        if not script_obj:
            script_obj = Script("", relative_path, platform_obj.id)
            script_service.addScript(script_obj)

    external_script = pubutil.loadFridaScriptFromConfigJson(pubutil.loadConfigJsonFromLocalFile(modulename_))
    hookUtilMap[platform_].reload_script(external_js=external_script)

    app_config_status_map[platform_] = False

    return "success"

@app.route("/getDeviceModuleList", methods=["GET", "POST"])
def getDeviceModuleList():
    resp = requests.get(url="http://127.0.0.1:8888/getDeviceModuleList")
    module_json = json.loads(resp.text)
    return module_json

@app.route("/getLocalDeviceModuleConfig", methods=["GET", "POST"])
def getLocalDeviceModuleConfig():
    config_json = {}
    mname_ = request.args.get("mname")
    config_path = os.path.join("module", mname_, "config.json")
    if not os.path.exists(config_path):
        print(f"The '{config_path}' does not exist!")
        return config_json

    config_str = ""
    with open(config_path) as f:
        config_str = f.read()
    if len(config_str)==0:
        print(f"The '{config_path}' is empty!")
        return config_json
    
    config_json = json.loads(config_str)
    return config_json

def downloadDeviceModuleByName(mname):
    resp = requests.get(url=f"http://127.0.0.1:8888/getModuleByName?mname={mname}")
    dir_name = os.path.join(os.path.dirname(os.path.abspath(__file__)), "module")
    zip_path = os.path.join(dir_name, mname+".zip")
    open(zip_path, "wb").write(resp.content)
    zip_file = zipfile.ZipFile(zip_path)
    zip_file.extractall(os.path.join(dir_name, mname))
    zip_file.close()
    os.remove(zip_path)
################## End Device Register ##################

################## Begin Socketio Interaction ##################
def checkStatusPermission(user, deviceid, capability):
    policy_list = policy_service.getPolicyList("", user, deviceid, capability, "", "", "", "", "", "", "", "", "accept")
    result = policy_util.checkStatusPermission(user, deviceid, capability, policy_list, user_location, attri_status)
    # print("++++++++++checkStatusPermission+++++++++++++++")
    # print(user, deviceid, capability)
    # print(result)
    return result

def checkActionPermission(user, deviceid, capability, attribute, value):
    policy_list = policy_service.getPolicyList("", user, deviceid, capability, "", "", "", "", "", "", "", "", "accept")
    return policy_util.checkActionPermission(user, deviceid, capability, attribute, value, policy_list, user_location, attri_status)

@app.route("/getCapabilityStatus", methods=["GET", "POST"])
def getCapabilityStatus():
    platform_ = request.form.get("platform")
    devicevid_ = request.form.get("devicevid")
    capability_ = request.form.get("capability")
    attribute_ = request.form.get("attribute")
    deviceid_ = device_service.getDeviceidByVirtualid(devicevid_, "")
    inspector = hookUtilMap[platform_]
    value_ = ""
    if inspector:
        key_ = "{}-{}-{}-{}".format(platform_, deviceid_, capability_, attribute_)
        value_ = ""
        # print("############# status_map ################")
        # print(inspector.status_map)
        if key_ in inspector.status_map:
            value_ = inspector.status_map[key_]

    # 在这里做权限检查
    sub_user = session["valid_user"]
    permission = checkStatusPermission(sub_user, devicevid_, capability_)
    if permission[0]:
        return value_
    else:
        return ""

@app.route("/doAction", methods=["GET", "POST"])
def doAction():
    username_ = request.form.get("username")
    platform_ = request.form.get("platform")
    device_ = request.form.get("device")
    devicevid_ = request.form.get("devicevid")
    capability_ = request.form.get("capability")
    attribute_ = request.form.get("attribute")
    value_ = request.form.get("value")
    deviceid_ = device_service.getDevice("", "", devicevid_, "").deviceid

    # 权限检查
    permission = checkActionPermission(username_, devicevid_, capability_, attribute_, value_)
    if not permission[0]:
        return "Permission Denied: " + permission[1]

    inspector = hookUtilMap[platform_]
    inspector.open_app()
    msg = {"type":"actionValue","message":{"platform":platform_, "deviceid":deviceid_, "capability":capability_, "attribute":attribute_, "value":value_}}
    inspector.script.post(msg)

    attributeid = attribute_service.getAttributeidByPlatformDeviceCapabilityAttribute(platform_, device_, capability_, attribute_)
    xpath_array = view_service.getViewXpathArrayByAttribute(attributeid)
    platform_info = platform_service.getPlatform(platform_, "", "", "")
    global monitor
    if not monitor:
        monitor = UIMonitor.UIMonitor()
    monitor.click_multi_elements_by_U2(xpath_array, platform_info.package, platform_info.activity)

    return "success"

def send_status_data(self, msg):
    global username_session_map
    global capability_subscriber_map
    platform_ = msg["platform"]
    device_ = msg["device"]
    deviceid_ = msg["deviceid"]
    capability_ = msg["capability"]
    attribute_ = msg["attribute"]
    value_ = msg["value"]

    device_obj = device_service.getDevice("", deviceid_, "", "")
    if device_obj:
        devicevid_ = device_obj.virtualid
    else:
        devicevid_ = ""
    msg["devicevid"] = devicevid_

    print("********** [status message] [web server] **********\n" + str(msg))

    if platform_ in app_config_status_map and app_config_status_map[platform_]:
        print("send message to owner: ", "", msg)
        socketio_app.emit("config_status", msg, room=username_session_map["owner"])
    else:
        dev_capa = "{}-{}".format(devicevid_, capability_)
        if dev_capa not in capability_subscriber_map:
            return
        sub_user_list = capability_subscriber_map[dev_capa]
        for sub_user in sub_user_list:
            # 在这里做权限检查
            event_ = "{}-{}-{}".format(devicevid_, capability_, attribute_)
            permission = checkStatusPermission(sub_user, devicevid_, capability_)
            if permission[0]:
                print("sending message to '{}' for event '{}'".format(sub_user, event_))
                socketio_app.emit(event_, msg, room=username_session_map[sub_user])
            else:
                print("[Permission Denied] '{}' query '{}' status".format(sub_user, event_))

@socketio_app.on("subscribemsg")
def on_subscribe_msg(msg):
    global username_session_map
    global capability_subscriber_map
    session_id = request.sid
    sub_user = ""
    for username in username_session_map:
        if username_session_map[username]==session_id:
            sub_user = username
            break

    for sub in msg:
        sub_capa = "{}-{}".format(sub["devicevid"], sub["capability"])
        if sub_capa not in capability_subscriber_map:
            capability_subscriber_map[sub_capa] = []
        capability_subscriber_map[sub_capa].append(sub_user)

@socketio_app.on("connect")
def on_connect():
    global username_session_map
    username = request.args.get("username")
    session_id = request.sid
    print("The clinet is : {}, {}".format(username, session_id))

    # some authentications ...

    username_session_map[username] = session_id
    socketio_app.emit("connected", "success", room=session_id)

# @socketio_app.on("disconnect")
# def on_disconnect():
#     print("Client disconnected")

# @socketio_app.on('join')
# def on_join(data):
#     username = data['username']
#     room = data['room']
#     join_room(room)
################## Begin Socketio Interaction ##################

if __name__ == "__main__":
    HookLoader.AppInspector.send_status = send_status_data
    for appIns in platform_service.getAllPlatformJson("", "", "", ""):
        # external_script = loadFridaScriptFromModule(appIns["name"])
        # print(external_script)
        # methodList = hooker_service.getAllMethodsByPlatform(appIns["name"])
        # for hook_target in methodList:
        #     print("hooking: " + hook_target)
        #     external_script += generateFridaScript(appIns["name"], hook_target) + "\n"
        # print(external_script)

        hookUtil = HookLoader.AppInspector(appIns["name"], appIns["package"], appIns["activity"])
        hookUtil.open_app()
        external_script = pubutil.loadFridaScriptFromConfigJson(pubutil.loadConfigJsonFromLocalFile(appIns["modulename"]))
        hookUtil.attach_to_app(external_js=external_script)
        hookUtilMap[appIns["name"]] = hookUtil

    # host: 绑定的ip(域名)
    # port: 监听的端口号
    # debug: 是否开启调试模式
    socketio_app.run(app, host="0.0.0.0", port=8080, debug=True)