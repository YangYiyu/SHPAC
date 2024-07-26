import time
import frida
import json
import os,sys
import re

import uiautomator2 as u2

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class MyCrushException(Exception):
    pass

class MyStuckException(Exception):
    pass

class AppInspector:
    def __init__(self, appname="", pkgname="", mainactivity=""):
        self.appname = appname
        self.pkgname = pkgname
        self.mainactivity = mainactivity

        self.device = None
        self.session = None
        self.script = None
        self.rpc = None

        self.running = False
        self.destroy = False
        self.onclick_listening = False

        self.status_map = {}

        self.initial()

    def initial(self):
        self.inherit_class_pair_cache = {}
        self.onclick_view_queue = []

        self.ui_d = u2.connect()

        self.event_list = [] # for temporary

        # signal.signal(signal.SIGUSR1, self.signal_handler)

    def open_app(self):
        if not self.ui_d.info.get('screenOn'):
            self.ui_d.unlock()
        if self.mainactivity:
            self.ui_d.app_start(self.pkgname, self.mainactivity)
            # os.system("adb shell am start -n {}/{}".format(self.pkgname, self.mainactivity))
        else:
            self.ui_d.app_start(self.pkgname)
        time.sleep(1)
        while self.ui_d.app_current()["package"]!=self.pkgname:
            if self.mainactivity:
                self.ui_d.app_start(self.pkgname, self.mainactivity)
                # os.system("adb shell am start -n {}/{}".format(self.pkgname, self.mainactivity))
            else:
                self.ui_d.app_start(self.pkgname)
            time.sleep(1)

    def attach_to_app(self, phone_serial="", spawn=False, js_script="HookScript.js", external_js=""):
        # 连接安卓机上的frida-server
        if len(phone_serial)>0:
            self.device = frida.get_device(phone_serial)
        else:
            self.device = frida.get_usb_device()
        
        if spawn: # 两种启动方式
            pid = self.device.spawn([self.pkgname])
            self.session = self.device.attach(pid)
        else:
            self.session = self.device.attach(self.pkgname)

        self.session.enable_jit() # 开启ES6支持
        script_str = ""
        with open(js_script, mode="r", encoding="UTF-8") as f:
            script_str += f.read()
        script_str += external_js

        self.script = self.session.create_script(script_str)
        self.script.on("message", self.my_message_handler)  # 消息处理回调
        self.script.on("destroyed", self.my_destroy_handler)  # app崩溃回调
        self.script.load()
        self.rpc = self.script.exports

        if spawn:
            self.device.resume(pid)
            time.sleep(1)  # Without it Java.perform silently fails

        self.running = True

    def reload_script(self, js_script="HookScript.js", external_js=""):
        if not self.session:
            return

        self.session.enable_jit() # 开启ES6支持
        script_str = ""
        with open(js_script, mode="r", encoding="UTF-8") as f:
            script_str += f.read()
        script_str += external_js

        self.script = self.session.create_script(script_str)
        self.script.on("message", self.my_message_handler)  # 消息处理回调
        self.script.on("destroyed", self.my_destroy_handler)  # app崩溃回调
        self.script.load()
        self.rpc = self.script.exports

        print(f"{self.pkgname}'s hook scripts have been reloaded!")

    def is_work_normal(self):
        if self.device and self.session and self.script:
            return True
        else:
            return False

    def send_status(self, event, msg):
        print(event, msg)

    def my_message_handler(self, message, data):
        if message['type'] == 'send':
            # print(bcolors.OKGREEN + "[*Payload]" + bcolors.ENDC + " " + message['payload'])
            pl = message['payload']
            # print(bcolors.OKGREEN + "[*Payload]" + bcolors.ENDC + " " + pl)
            pl_json = json.loads(pl)
            # print(pl_json)
            
            if pl_json["msgtype"] == "status":
                # tid = pl_json["tid"]
                time = pl_json["time"]
                sta = pl_json["log"]
                
                if sta:
                    platform = sta["platform"]
                    device = sta["device"]
                    deviceid = sta["deviceid"]
                    capability = sta["capability"]
                    attribute = sta["attribute"]
                    value = sta["value"]
                    print("********** [message] [frida loader] **********\n[{}]{}.{}({}).{}.{}={}".format(self.appname, platform, device, deviceid, capability, attribute, value))
                    key_ = "{}-{}-{}-{}".format(platform, deviceid, capability, attribute)
                    self.status_map[key_] = value
                    self.send_status(sta)
            elif pl_json["msgtype"] == "onclick":
                onclk_msg = pl_json["log"]
                listener = onclk_msg["listener"]
                view = onclk_msg["view"]
                if self.onclick_listening:
                    view_id = view
                    match_obj = re.match(r".*{.* app:id/(.*)}", view, re.M|re.I)
                    if match_obj:
                        view_id = match_obj.group(1)

                    print(pl_json["time"], (listener, view, view_id))
                    # print(self.ui_d(resourceId="{}:id/{}".format(self.pkgname, view_id)).all())
                    v_list = self.ui_d.xpath('//*[@resource-id="{}:id/{}"]'.format(self.pkgname, view_id)).all()
                    if len(v_list)>1:
                        print("Found muiltiple view of id : " + view_id)
                        for v in v_list:
                            print(v.info)
                    self.onclick_view_queue.append(view_id)
        
        elif message['type'] == 'error':
            print(bcolors.FAIL + "[*Error]" + bcolors.ENDC + " " + message['description'])
            # print("[-stack] " + message['stack'])
            # print("[-fileName] " + message['fileName'])
            # print("[-lineNumber] {}".format(message['lineNumber']))
            # print("[-columnNumber] {}".format(message['columnNumber']))
        else:
            print(message)
  
    def my_destroy_handler(self):
        self.destroy = True
        if not self.running:
            print("The app is killed actively!")
        else:
            print("Oops, the app '{}' is crashed!".format(self.pkgname))
            # raise MyCrushException("The app is crashed!")
        # if os is not None:
            # os.kill(os.getpid(), signal.SIGUSR1) # 给主线程发中断
        self.running = False

    # 系统软中断处理函数，只有Linux系统才可以用
    # def signal_handler(self, sig, frame):
    #     if sig == signal.SIGUSR1:
    #         raise Exception("Caugth signal " + str(sig))

    def kill_app(self, pkgname):
        try:
            print("Kill the app ......")
            process = self.device.get_process(pkgname)
            self.device.kill(process.pid)
            self.running = False
            # self.execute_adb_shell_cmd("am force-stop {}".format(pkgname))
            # time.sleep(1)
        except frida.ProcessNotFoundError:
            print("Kill app failed, " + pkgname + " is not found")
        except Exception as e:
            print(e)

    def reboot_app(self, pkgname):
        try:
            print("Reboot the app ......")
            process = self.device.get_process(pkgname)
            self.device.resume(process.pid)
            self.running = False
        except Exception as e:
            print(e)

    # hook一个方法
    def hookOneMethod(self, methodNode, recordObjFlag=False):
        try:
            self.rpc.hookonemethod(methodNode.className, methodNode.methodName, methodNode.paraTypeList, methodNode.retType, recordObjFlag)
            return True
        except Exception as e:
            print("We have a exception when hook {}.{}".format(methodNode.classname, methodNode.methodname))
            print(e)
            return False
    
    # hook一批方法
    def hookMultiMethods(self, methodNodeList, recordObjFlag=False):
        methods = []
        for node in methodNodeList:
            methods.append([node.className, node.methodName, node.paraTypeList, node.retType])
        try:
            self.rpc.hookmultimethods(methods, recordObjFlag)
            return True
        except Exception as e:
            print("We have a exception when hook {} methods".format(len(methods)))
            print(e)
            return False
        
    # 停止hook一个方法
    def stopHookOneMethod(self, methodNode):
        try:
            self.rpc.stophookonemethod(methodNode.className, methodNode.methodName, methodNode.paraTypeList)
            return True
        except Exception as e:
            print("We have a exception when stop hook {}.{}".format(methodNode.classname, methodNode.methodname))
            print(e)
            return False

    # 判断childClassName和parentClassName是否存在继承关系
    def is_child_and_parent_class(self, childClassName, parentClassName):
        # 为了减少查询次数，用一个dict将已经查过的信息缓存起来
        if (childClassName, parentClassName) in self.inherit_class_pair_cache:
            return self.inherit_class_pair_cache[(childClassName, parentClassName)]
        else:
            r = self.rpc.ischildandparent(childClassName, parentClassName)
            self.inherit_class_pair_cache[(childClassName, parentClassName)] = r
            return r

    # 获取某个方法的重载个数
    def get_method_overloads(self, className, methodName):
        return self.rpc.getmethodoverloads(className, methodName)

    def read_config_file(self, filepath):
        config_dic = {}
        with open(filepath) as f:
            for line in f.read().splitlines():
                key_value = line.split("=")
                config_dic[key_value[0]] = key_value[1]
        return config_dic
    
    def send_msg_to_script(self, msg):
        self.script.post({"type": "actionValue", "value": msg})

    def start_listen_onclick(self):
        self.rpc.watchonclick()
        self.onclick_listening = True

    def stop_listen_onclick(self):
        self.onclick_listening = False
        self.event_list.append(self.onclick_view_queue.copy())
        print("Recorded event list: {}".format(self.event_list))
        self.onclick_view_queue.clear()

    def invoke_onclick_view(self, view_id):
        view = self.ui_d(resourceId="{}:id/{}".format(self.pkgname, view_id))
        if view.wait(timeout=3):
            view.click()
        else:
            print("Error: cannot find view: " + view_id)

    def invoke_onclick_listener(self, listener_clz, listener_id, view_clz, view_id):
        self.rpc.callonclick(listener_clz, listener_id, view_clz, view_id)

if __name__=="__main__":
    inspector = AppInspector("Aqara", "com.lumiunited.aqarahome.play", "com.lumiunited.aqara.main.MainActivity")
    inspector.open_app()
    inspector.attach_to_app()
    print("{} booted".format(inspector.pkgname))
    # # # 手动操作
    while True:
        option = input()
        if option=="record":
            inspector.start_listen_onclick()
            inspector.open_app("com.lumiunited.aqara.main.MainActivity")
            print("Now you can trigger the app ...")
        elif option=="recordend":
            inspector.stop_listen_onclick()
            print("Record has stopped")
        elif option[:6]=="invoke":
            event_index = int(option[6:7])
            inspector.open_app("com.lumiunited.aqara.main.MainActivity")
            for v in inspector.event_list[event_index]:
                inspector.invoke_onclick_view(v)
        elif option[:4]=="post":
            inspector.script.post({"type":"actionValue","message":{"platform":"1", "device":"2", "capability":"3", "attribute":"4", "value":"5"}})
        elif option=="q":
            sys.exit(0)
