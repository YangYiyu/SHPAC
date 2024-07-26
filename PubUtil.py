import re
import os
import json
import time

class Util:
    basic_java_type = [
        "java.lang.String", 
        "java.lang.String[]", 
        "org.json.JSONObject", 
        "org.json.JSONArray"]
    frida_type_dict = {
                    "int": "I",
                    "byte": "B",
                    "short": "S",
                    "long": "J",
                    "float": "F",
                    "double": "D",
                    "char": "C",
                    "boolean": "Z"
                }
    frida_type_dict_reverse = {v:k for k,v in frida_type_dict.items()}

    # 从方法签名中提取基本元素
    @staticmethod
    def extract_method_factor(methodSignature):
        methodSignREResult = re.match(r"(.*) (.*)\((.*)\)", methodSignature, re.I)
        retType = ""
        classPath = ""
        methodName = ""
        paraTypeList = []
        if methodSignREResult:
            retType = methodSignREResult.group(1)
            classPath = ".".join(methodSignREResult.group(2).split(".")[:-1])
            methodName = methodSignREResult.group(2).split(".")[-1]
            paraTypeList = methodSignREResult.group(3).replace(" ", "").split(",")
        return {"ret":retType, "class":classPath, "method":methodName, "paraTypeList":paraTypeList}
    
    # 从带有实例值的方法签名中提取基本元素，不同之处是方法参数列表中是用中文，分开每个参数
    @staticmethod
    def extract_instance_factor(instanceSignature):
        methodSignREResult = re.match(r"(.*) (.*)\((.*)\)", instanceSignature, re.S)
        retType = ""
        classPath = ""
        methodName = ""
        paraTypeList = []
        if methodSignREResult:
            retType = methodSignREResult.group(1)
            classPath = ".".join(methodSignREResult.group(2).split(".")[:-1])
            methodName = methodSignREResult.group(2).split(".")[-1]
            paraTypeList = methodSignREResult.group(3).split(",")
        return {"ret":retType, "class":classPath, "method":methodName, "paraTypeList":paraTypeList}

    # 检查方法methodnode的返回值或者参数里面是否包含基本Java类型
    @staticmethod
    def contain_basic_type_data(methodSignature):
        methodObj = Util.extract_method_factor(methodSignature)
        if any([methodObj["ret"]==t for t in Util.basic_java_type]):
            return True
        else:
            for p in methodObj["paraTypeList"]:
                p = p.strip()
                if any([p==t for t in Util.basic_java_type]):
                    return True
        return False

    # 在frida的hook脚本中，传给overload方法的参数转换规则：
    #   - 如果不是数组，不用转换，填写原始Java类型
    #   - 如果是数组，则要转换：
    #       - int, byte, short, long, float, double, char, boolean基本类型的数组，转为“[”+Smail简写类型，比如“int[]”转为“[I”，“long[]”转为“[J”
    #       - 其他类的数组，转为“[L”+完整类名+“;”，比如“java.lang.String”转为“[Ljava.lang.String;”
    def frida_type_convert(paratype):
        paratype = paratype.strip()
        if paratype[-2:] != "[]":
            return paratype

        typePreStr = paratype.replace("[]", "")
        if "." in typePreStr:
            typeConvertStr = "[L{};".format(typePreStr)
        else:
            typeConvertStr = "[{}".format(Util.frida_type_dict[typePreStr])
        return typeConvertStr

    def frida_type_convert_reverse(paratype):
        paratype = paratype.strip()
        convertResult = paratype
        if paratype[:1] != "[":
            return convertResult

        convertResult = convertResult.replace("[", "")
        if convertResult[-1:] == ";":
            convertResult = convertResult[1:-1]
        else:
            convertResult = Util.frida_type_dict_reverse[convertResult]

        return "{}[]".format(convertResult)

    # 将方法签名转换成Frida Hook脚本的代码，类似Jadx的功能
    @staticmethod
    def frida_method(retStr, classStr, methodStr, paraList, overloads):
        js_header = "Java.perform(function x() {\n"
        js_footer = ""
        paraList = list(map(Util.frida_type_convert, paraList))
        paraListStr = ",".join([f"\"{p}\"" for p in paraList])

        classNameStr = classStr.split(".")[-1].replace("$", "_")
        methodStr = methodStr.replace("<init>", "$init") if "<init>" in methodStr else methodStr
        js_header += f"    let {classNameStr} = Java.use(\"{classStr}\");\n"
        if len(paraList)>0:
            paraListSimStr = ",".join([f"p{i}" for i in range(1,len(paraList)+1)])
        else:
            paraListSimStr = ""
        paraInsStr = ", ".join([f"{pi}=${{{pi}}}" for pi in paraListSimStr.split(",")])
        if overloads>1:
            js_header += f"    {classNameStr}[\"{methodStr}\"].overload({paraListStr}).implementation = function ({paraListSimStr}) {{\n"
            # js_header += f"        console.log(`{classNameStr}.{methodStr} is called: {paraInsStr}`);\n"
            if retStr=="void":
                js_footer += f"        this[\"{methodStr}\"]({paraListSimStr});\n"
                js_footer += f"    }};\n"
            else:
                js_footer += f"        let result = this[\"{methodStr}\"]({paraListSimStr});\n"
                # js_footer += f"        console.log(`{classNameStr}.{methodStr} result=${{result}}`);\n"
                js_footer += f"        return result;\n"
                js_footer += f"    }};\n"
        elif len(paraList)>0 and len(paraList[0])>0:
            js_header += f"    {classNameStr}[\"{methodStr}\"].implementation = function ({paraListSimStr}) {{\n"
            # js_header += f"        console.log(`{classNameStr}.{methodStr} is called: {paraInsStr}`);\n"
            if retStr=="void":
                js_footer += f"        this[\"{methodStr}\"]({paraListSimStr});\n"
                js_footer += f"    }};\n"
            else:
                js_footer += f"        let result = this[\"{methodStr}\"]({paraListSimStr});\n"
                # js_footer += f"        console.log(`{classNameStr}.{methodStr} result=${{result}}`);\n"
                js_footer += f"        return result;\n"
                js_footer += f"    }};\n"
        else:
            js_header += f"{classNameStr}[\"{methodStr}\"].implementation = function () {{\n"
            # js_header += f"        console.log(`{classNameStr}.{methodStr} is called`);\n"
            if retStr=="void":
                js_footer += f"        this[\"{methodStr}\"]();\n"
                js_footer += f"    }};\n"
            else:
                js_footer += f"        let result = this[\"{methodStr}\"]();\n"
                # js_footer += f"        console.log(`{classNameStr}.{methodStr} result=${{result}}`);\n"
                js_footer += f"        return result;\n"
                js_footer += f"    }};\n"
    
        js_footer += "});"

        return [js_header, js_footer]
    
    @staticmethod
    def get_flatten_methods_recur(rootJson):
        flatten_method_list = [rootJson["method"]]
        if "children" in rootJson and len(rootJson["children"])>0:
            for child in rootJson["children"]:
                flatten_method_list += Util.get_flatten_methods_recur(child)

        return flatten_method_list

    # 将树的所有节点拉平成一个列表
    @staticmethod
    def get_flatten_method_list(rootJson):
        flatten_method_list = Util.get_flatten_methods_recur(rootJson)
        # new_flatten_method_list=list(set(flatten_method_list)) # 去重
        # new_flatten_method_list.sort(key=flatten_method_list.index) # 保持原序

        return flatten_method_list

    @staticmethod
    def get_basic_type_methods_recur(rootJson):
        basic_type_method_list = []
        if Util.contain_basic_type_data(rootJson["method"]):
            basic_type_method_list.append(rootJson["method"])
        if "children" in rootJson and len(rootJson["children"])>0:
            for child in rootJson["children"]:
                basic_type_method_list += Util.get_basic_type_methods_recur(child)

        return basic_type_method_list
    
    # 从树里面找出返回值或参数包含基本Java类型的方法
    @staticmethod
    def get_basic_type_method_list(rootJson):
        basic_type_method_list = Util.get_basic_type_methods_recur(rootJson)
        new_basic_type_method_list=list(set(basic_type_method_list)) # 去重
        new_basic_type_method_list.sort(key=basic_type_method_list.index) # 保持原序

        return new_basic_type_method_list
    
    @staticmethod
    def get_string_methods_recur(rootJson):
        string_method_list = []
        if rootJson["hasstring"]=="1":
            string_method_list.append(rootJson["method"])
        if "children" in rootJson and len(rootJson["children"])>0:
            for child in rootJson["children"]:
                string_method_list += Util.get_string_methods_recur(child)

        return string_method_list
    
    # 从树里面找出带有String值的方法
    @staticmethod
    def get_string_method_list(rootJson):
        string_method_list = Util.get_string_methods_recur(rootJson)
        # new_string_method_list=list(set(string_method_list)) # 去重
        # new_string_method_list.sort(key=string_method_list.index) # 保持原序

        return string_method_list
    
    @staticmethod
    def get_instance_methods_recur(rootJson):
        instance_method_list = []
        if "instance"in rootJson and rootJson["instance"]:
            instance_method_list.append(rootJson["method"])
        if "children" in rootJson and len(rootJson["children"])>0:
            for child in rootJson["children"]:
                instance_method_list += Util.get_instance_methods_recur(child)

        return instance_method_list

    # 从树里面找出有instance值的节点，并且去重和保持原序
    @staticmethod
    def get_instance_method_list(rootJson):
        instance_method_list = Util.get_instance_methods_recur(rootJson)
        new_instance_method_list=list(set(instance_method_list))
        new_instance_method_list.sort(key=instance_method_list.index)

        return new_instance_method_list
    
    @staticmethod
    def loadScriptConfig(script_dir=""):
        if len(script_dir)==0:
            script_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "script")
        
        script_map = {}
        for d in os.listdir(script_dir):
            s_f_ = os.path.join(script_dir, d, "config.json")
            if os.path.exists(s_f_):
                config_str = None
                with open(s_f_) as f:
                    config_str = f.read()
                if config_str:
                    config_json = json.loads(config_str)
                    for module in config_json:
                        attr_name = f"{module['platform']}-{module['device']}-{module['capability']}-{module['attribute']}"

                        if attr_name in script_map:
                            print(f"The \"{attr_name}\" in \"{d}\" has been loaded, cannot load the same attribute for twice!")
                            continue

                        script_array = []
                        for scr_file in module["script"]:
                            scr_file_path = os.path.join(script_dir, d, scr_file["file"]+".js")
                            script_array.append(scr_file_path)
                        script_map[attr_name] = script_array
            else:
                print(f"{os.path.join(script_dir, d)} is not an available module!")

        return script_map
    
    # 以子函数的方式插入hook脚本，对于同一个方法的多个hook脚本，每个脚本放在一个单独的function中
    # 实践证明不好用.....
    @staticmethod
    def generateFridaScript(platform, methodSignature, inspector, hooker_service):
        result = ""
        if methodSignature:
            methodFactors = Util.extract_method_factor(methodSignature)
            retStr = methodFactors["ret"]
            classStr = methodFactors["class"]
            methodStr = methodFactors["method"].replace("&lt;", "<").replace("&gt;", ">")
            paraList = methodFactors["paraTypeList"]

            overloads = 1
            if inspector:
                overloads = inspector.get_method_overloads(classStr, methodStr)
            else:
                print("inspector is None !!!!!!!!!!!!!")

            suffix = Util.frida_method(retStr, classStr, methodStr, paraList, overloads)
            if len(paraList)>0:
                paraListStr = ",".join([f"p{i}" for i in range(1,len(paraList)+1)])
            else:
                paraListStr = ""

            func_name_list_str = ""
            func_body_list_str = ""
            scriptList = hooker_service.getScriptByPlatformMethod(platform, methodSignature)
            for s in scriptList:
                func_name = "{}_{}_{}_{}_{}({})".format(s["platform"], s["device"], s["capability"], s["attribute"], s["type"], paraListStr)
                func_name_list_str += func_name + ";\n"
                header = "function {}{{\n".format(func_name)
                footer = "}\n"
                scr_ = s["script"]
                scr_ = scr_.replace("@platform@", s["platform"])
                scr_ = scr_.replace("@device@", s["device"])
                scr_ = scr_.replace("@capability@", s["capability"])
                scr_ = scr_.replace("@attribute@", s["attribute"])
                func_str = header + scr_ + "\n" + footer
                func_body_list_str += func_str + "\n"

            result = suffix[0] + "\n" + func_name_list_str + "\n" + suffix[1] + "\n\n" + func_body_list_str

        return result

    @staticmethod
    def loadConfigJsonFromLocalFile(moduleName):
        configJson = {}
        if len(moduleName)==0:
            print(f"Error: the moduleName is null!")
            return configJson
        
        module_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "module", moduleName)
        if not os.path.exists(module_path):
            print(f"The '{module_path}' does not exist!")
            return configJson

        config_path = os.path.join(module_path, "config.json")
        if not os.path.exists(config_path):
            print(f"The '{config_path}' does not exist!")
            return configJson

        config_str = ""
        with open(config_path) as f:
            config_str = f.read()
        if len(config_str)==0:
            print(f"The '{config_path}' is empty!")
            return configJson
        
        configJson = json.loads(config_str)
        return configJson

    @staticmethod
    def loadFridaScriptFromConfigJson(config_json):
        script_ = ""
            
        loaded_script_array = []
        for script_name in config_json["script"]:
            if script_name["file"] in loaded_script_array:
                # print(f"The \"{script_file}\" has been loaded, cannot load the same script for twice!")
                continue
            loaded_script_array.append(script_name["file"])
            script_path = os.path.join("module", config_json["modulename"], script_name["file"]+".js")
            if not os.path.exists(script_path):
                print(f"The '{script_path}' does not exist!")
                continue
            with open(script_path) as f:
                script_ += f.read() + "\n"

        return script_

    @staticmethod
    def fromDatetimeStrToStamp(t):
        if "inf" in t:
            return t
        s_t = time.strptime(t, "%Y-%m-%d %H:%M:%S")
        mkt = int(time.mktime(s_t))
        return mkt
    
    @staticmethod
    def fromStampToDatetimeStr(s):
        if "inf" in s:
            return s
        s_l = time.localtime(s)
        ts = time.strftime("%Y-%m-%d %H:%M:%S", s_l)
        return ts

if __name__=="__main__":
    ts = "2024-01-6 15:53:27"
    print(Util.fromDatetimeToStamp(ts))
    st = 1704527666
    print(Util.fromStampToDatetime(st))