var action_value_map = {};

function handleMessage(msg){
    console.log("Got message from python side:" + JSON.stringify(msg));
    var key_ = `${msg["message"]["platform"]}@${msg["message"]["deviceid"]}@${msg["message"]["capability"]}@${msg["message"]["attribute"]}`;
    var value_ = msg["message"]["value"];
    action_value_map[key_] = value_;
    recv("actionValue", handleMessage);
}

function sendLog(log, type, to_server=true) {
    // var threadid = Process.getCurrentThreadId();
    var time = new Date().getTime();

    var msg = {};
    msg["msgtype"] = type;
    // msg["tid"] = threadid;
    msg["time"] = time;
    msg["log"] = log;
    if(to_server) {
        send(JSON.stringify(msg));
    }
    else{
        console.log(JSON.stringify(msg));
    }
}

function getActionValue(platform, deviceid, capability, attribute) {
    var key_ = `${platform}@${deviceid}@${capability}@${attribute}`;
    return action_value_map[key_];
}

/**
 * 获得某个方法的重载次数
 * @param {*} className 
 * @param {*} methodName 
 * @returns 
 */
function getMethodOverloads(className, methodName) {
    var overloads = 0;
    if(methodName=="<init>") {
        methodName = "$init";
    }
    Java.perform(function() {
        var hookclazz = Java.use(className);
        overloads = hookclazz[methodName].overloads.length;
    });
    return overloads;
}

recv("actionValue", handleMessage);

rpc.exports = {
    getmethodoverloads : getMethodOverloads
};

console.log("HookScript loaded successfully!");