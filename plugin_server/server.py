import json
import re
import os
import zipfile

from flask import Flask
from flask import request, render_template, send_file

app = Flask(__name__, template_folder="html")

@app.route("/")
def default():
    return render_template("main.html")

@app.route("/getDeviceModuleList")
def getDeviceModuleList():
    module_list = []
    module_dir_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "module")

    for module in os.listdir(module_dir_path):
        module_path = os.path.join(module_dir_path, module)
        config_path = os.path.join(module_path, "config.json")
        if not os.path.exists(config_path):
            print(f"The '{config_path}' does not exist! '{module_path}' is not a valid module!")
            continue

        config_str = ""
        with open(config_path) as f:
            config_str = f.read()
        if len(config_str)==0:
            print(f"The '{config_path}' is empty!")
            continue
        
        config_json = json.loads(config_str)
        for dev in config_json["deviceList"]:
            module_json = {
                "modulename": config_json["modulename"],
                "platform": config_json["platform"],
                "package": config_json["package"],
                "activity": config_json["activity"],
                "device": dev["device"],
                "capability": ",".join([capa["capability"] for capa in dev["capabilityList"]]),
                "description": dev["description"]
            }
            module_list.append(module_json)

    return module_list

@app.route("/getModuleByName")
def getModuleByName():
    mname_ = request.args.get("mname")
    dir_name = os.path.join(os.path.dirname(os.path.abspath(__file__)), "module", mname_)
    zip_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "module", mname_+".zip")
    
    if not os.path.exists(dir_name):
        print(f"The '{mname_}' module does not existed!")
        return "failed"
    else:
        zip = zipfile.ZipFile(zip_file, "w", zipfile.ZIP_DEFLATED)
        for path, dirnames, filenames in os.walk(dir_name):
            for filename in filenames:
                zip.write(os.path.join(path, filename), os.path.join(filename))
        zip.close()
        return send_file(zip_file, mname_+".zip")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888, debug=True)