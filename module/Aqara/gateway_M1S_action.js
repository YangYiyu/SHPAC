Java.perform(function x() {
    let BaseWidgetBean = Java.use("com.lumiunited.aqara.device.devicewidgets.BaseWidgetBean");
    BaseWidgetBean["changeValues"].overload("java.lang.String","java.lang.String","java.lang.String","boolean","boolean","com.lumiunited.aqara.application.utils.h","boolean").implementation = function (p1,p2,p3,p4,p5,p6,p7) {
        var device_id = p1;
        if(p2=="14.7.111") {
            let val_ = getActionValue("Aqara", device_id, "light", "switch");
            if(val_){
                if(val_=="True"){
                    val_ = "1";
                }
                else{
                    val_ = "0";
                }
                // console.log("new val_ is " + val_);
                p3 = val_;
            }
        }
        if(p2=="14.7.85") {
            let bright_ = getActionValue("Aqara", device_id, "light", "bright");
            // console.log("bright_ is " + bright_);
            if(!bright_) {
                bright_ = "30";
            }
            let color_ = getActionValue("Aqara", device_id, "light", "color");
            // console.log("color_ is " + color_);
            if(color_) {
                let val_ = parseInt(Number(bright_).toString(16) + color_.substring(1), 16)+""
                // console.log("new val_ is " + val_);
                p3 = val_;
            }
        }
        if(p2=="14.7.1006") {
            let val_ = getActionValue("Aqara", device_id, "light", "bright");
            if(val_){
                // console.log("new val_ is " + val_);
                p3 = val_;
            }
        }

        let result = this["changeValues"](p1,p2,p3,p4,p5,p6,p7);
        return result;
    }
});