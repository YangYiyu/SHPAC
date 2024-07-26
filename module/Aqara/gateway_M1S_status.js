Java.perform(function x() {
    let MessageService = Java.use("org.android.agoo.message.MessageService");
    MessageService["a"].overload('java.lang.String','java.lang.String','java.lang.String','int').implementation = function (p1,p2,p3,p4) {
        var p2_parsed = p2;
        p2_parsed = p2_parsed.replace(new RegExp("\\\\\\\\\\\\\"","gm"), "\"");
        p2_parsed = p2_parsed.replace(new RegExp("\\\\\"","gm"), "\"");
        p2_parsed = p2_parsed.replace(new RegExp("\"{","gm"), "{");
        p2_parsed = p2_parsed.replace(new RegExp("\"\\\[","gm"), "\[");
        p2_parsed = p2_parsed.replace(new RegExp("}\"","gm"), "}");
        p2_parsed = p2_parsed.replace(new RegExp("\\\]\"","gm"), "\]");
        // console.log(p2_parsed);
        var p2_json = JSON.parse(p2_parsed);
        var type = p2_json.content.type;
        var result = p2_json.content.result;
        var info = {};
        info["deviceid"] = result.subjectId;
        if(type=="qlink_trait_subscribe") {
            var traitPath = result.traitPath;
            var value = result.value;
            if(Object.prototype.toString.call(value).indexOf("Object")>0) {
                var r_ = "";
                var g_ = "";
                var b_ = "";
                if(value.hasOwnProperty("2.134.33009")) {
                    r_ = Number(value["2.134.33009"]).toString(16);
                    if(r_.length==1) {
                        r_ = "0" + r_;
                    }
                }
                if(value.hasOwnProperty("2.134.33010")) {
                    g_ = Number(value["2.134.33010"]).toString(16);
                    if(g_.length==1) {
                        g_ = "0" + g_;
                    }
                }
                if(value.hasOwnProperty("2.134.33011")) {
                    b_ = Number(value["2.134.33011"]).toString(16);
                    if(b_.length==1) {
                        b_ = "0" + b_;
                    }
                }
                info["platform"] = "Aqara";
                info["device"] = "gateway";
                info["capability"] = "light";
                info["attribute"] = "color";
                info["value"] = "#"+(r_+g_+b_).toUpperCase();
            }
            else if(Object.prototype.toString.call(value).indexOf("String")>0) {
                if(traitPath=="2.132.32920") {
                    info["platform"] = "Aqara";
                    info["device"] = "gateway";
                    info["capability"] = "light";
                    info["attribute"] = "switch";
                    if(value=="1") {
                        info["value"] = "True";
                    }
                    else{
                        info["value"] = "False";
                    }
                }
                else if(traitPath=="2.133.32923") {
                    info["platform"] = "Aqara";
                    info["device"] = "gateway";
                    info["capability"] = "light";
                    info["attribute"] = "bright";
                    info["value"] = value;
                }
            }
            // console.log("qlink_trait_subscribe: " + JSON.stringify(info));
            sendLog(info, "status");
        }
        else if(type=="view_subscribe") {
            var attr = result.attr;
            var value = result.value;
            if(Object.prototype.toString.call(value).indexOf("String")>0) {
                if(attr=="14.7.85") {
                    var color = "#"+Number(value).toString(16).substring(2,8).toUpperCase();
                    info["platform"] = "Aqara";
                    info["device"] = "gateway";
                    info["capability"] = "light";
                    info["attribute"] = "color";
                    info["value"] = color;
                }
                else if(attr=="14.7.1006") {
                    info["platform"] = "Aqara";
                    info["device"] = "gateway";
                    info["capability"] = "light";
                    info["attribute"] = "bright";
                    info["value"] = value;
                }
                else if(attr=="14.7.111") {
                    info["platform"] = "Aqara";
                    info["device"] = "gateway";
                    info["capability"] = "light";
                    info["attribute"] = "switch";
                    if(value=="1") {
                        info["value"] = "True";
                    }
                    else{
                        info["value"] = "False";
                    }
                }
            }
            // console.log("view_subscribe: " + JSON.stringify(info));
            sendLog(info, "status");
        }

        this["a"](p1,p2,p3,p4);
    };
});