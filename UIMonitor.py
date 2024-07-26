import uiautomator2 as u2
import xml.etree.ElementTree as ET
import re
import time
import subprocess
import sys, os, signal
import threading

class UIMonitor:
    def __init__(self):
        self.u2_device = u2.connect()

        self.process = None
        self.top_ele = {}
        self.xml_tree = None

        self.click_queue = []
        self.view_quene = []

    def in_position(self, position, bounds):
        bound_array = bounds
        if isinstance(bounds, str):
            match_groups = re.match(r"\[(.*),(.*)\]\[(.*),(.*)\]", bound_array, re.M|re.I).groups()
            bound_array = [[match_groups[0],match_groups[1]],[match_groups[2],match_groups[3]]]
        if (position[0]>=int(bound_array[0][0]) and position[0]<=int(bound_array[1][0])) and (position[1]>=int(bound_array[0][1]) and position[1]<=int(bound_array[1][1])):
            return True
        else:
            return False

    def compare_bounds(self, bounds1, bounds2):
        bound_array1 = bounds1
        if isinstance(bound_array1, str):
            match_groups1 = re.match(r"\[(.*),(.*)\]\[(.*),(.*)\]", bound_array1, re.M|re.I).groups()
            bound_array1 = [[int(match_groups1[0]),int(match_groups1[1])],[int(match_groups1[2]),int(match_groups1[3])]]
        bound_array2 = bounds2
        if isinstance(bound_array2, str):
            match_groups2 = re.match(r"\[(.*),(.*)\]\[(.*),(.*)\]", bound_array2, re.M|re.I).groups()
            bound_array2 = [[int(match_groups2[0]),int(match_groups2[1])],[int(match_groups2[2]),int(match_groups2[3])]]
        
        if bound_array1[0][0]>=bound_array2[0][0] and bound_array1[0][0]<bound_array2[1][0] and \
            bound_array1[1][0]>bound_array2[0][0] and bound_array1[1][0]<=bound_array2[1][0] and \
            bound_array1[0][1]>=bound_array2[0][1] and bound_array1[0][1]<bound_array2[1][1] and \
            bound_array1[1][1]>bound_array2[0][1] and bound_array1[1][1]<=bound_array2[1][1]:
            if ((bound_array1[1][0]-bound_array1[0][0])*(bound_array1[1][1]-bound_array1[0][1])) < \
                ((bound_array2[1][0]-bound_array2[0][0])*(bound_array2[1][1]-bound_array2[0][1])):
                return -1
            elif ((bound_array1[1][0]-bound_array1[0][0])*(bound_array1[1][1]-bound_array1[0][1])) == \
                ((bound_array2[1][0]-bound_array2[0][0])*(bound_array2[1][1]-bound_array2[0][1])):
                return 0
            else:
                return None
        elif bound_array2[0][0]>=bound_array1[0][0] and bound_array2[0][0]<bound_array1[1][0] and \
            bound_array2[1][0]>bound_array1[0][0] and bound_array2[1][0]<=bound_array1[1][0] and \
            bound_array2[0][1]>=bound_array1[0][1] and bound_array2[0][1]<bound_array1[1][1] and \
            bound_array2[1][1]>bound_array1[0][1] and bound_array2[1][1]<=bound_array1[1][1]:
            if ((bound_array2[1][0]-bound_array2[0][0])*(bound_array2[1][1]-bound_array2[0][1])) < \
                ((bound_array1[1][0]-bound_array1[0][0])*(bound_array1[1][1]-bound_array1[0][1])):
                return 1
            elif ((bound_array2[1][0]-bound_array2[0][0])*(bound_array2[1][1]-bound_array2[0][1])) == \
                ((bound_array1[1][0]-bound_array1[0][0])*(bound_array1[1][1]-bound_array1[0][1])):
                return 0
            else:
                return None
        else:
            if ((bound_array1[1][0]-bound_array1[0][0])*(bound_array1[1][1]-bound_array1[0][1])) < \
                ((bound_array2[1][0]-bound_array2[0][0])*(bound_array2[1][1]-bound_array2[0][1])):
                return -1
            elif ((bound_array1[1][0]-bound_array1[0][0])*(bound_array1[1][1]-bound_array1[0][1])) == \
                ((bound_array2[1][0]-bound_array2[0][0])*(bound_array2[1][1]-bound_array2[0][1])):
                return 0
            else:
                return 1

    def find_element_by_position1(self, element, position, level, xml_tree, top_ele):
        class_name_map = {}
        for ele in element:
            cur_class = ele.attrib["class"]
            if cur_class in class_name_map:
                class_name_map[cur_class] += 1
            else:
                class_name_map[cur_class] = 1
            cur_xpath = f"{cur_class}[{class_name_map[cur_class]}]"

            if "bounds" in ele.attrib and self.in_position(position, ele.attrib["bounds"]):
                if not top_ele["ele"]:
                    top_ele["ele"] = ele

                if level > top_ele["level"]:
                    if self.compare_bounds(ele.attrib["bounds"], top_ele["ele"].attrib["bounds"])<=0:
                        top_ele["ele"] = ele
                        top_ele["level"] = level
                        if top_ele["xpath"]:
                            top_ele["xpath"] = top_ele["xpath"] + "/" + cur_xpath
                        else:
                            top_ele["xpath"] = "//" + cur_xpath
                elif level == top_ele["level"]:
                    if self.compare_bounds(ele.attrib["bounds"], top_ele["ele"].attrib["bounds"])<=0:
                        # 遇上同级别的，先把之前拼上的路径剪掉
                        top_ele["xpath"] = top_ele["xpath"][:top_ele["xpath"].rindex("/")]

                        if top_ele["xpath"]:
                            top_ele["xpath"] = top_ele["xpath"] + "/" + cur_xpath
                        else:
                            top_ele["xpath"] = "//" + cur_xpath

                        top_ele["ele"] = ele
                        top_ele["level"] = level
                elif level < top_ele["level"]:
                    if self.compare_bounds(ele.attrib["bounds"], top_ele["ele"].attrib["bounds"])<=0:
                        # 遇到level更低的元素，xpath要退回
                        for i in range(top_ele["level"]-level+1):
                            top_ele["xpath"] = top_ele["xpath"][:top_ele["xpath"].rindex("/")]

                        if top_ele["xpath"]:
                            top_ele["xpath"] = top_ele["xpath"] + "/" + cur_xpath
                        else:
                            top_ele["xpath"] = "//" + cur_xpath

                        top_ele["ele"] = ele
                        top_ele["level"] = level

                # optimize the xpath
                text = ele.attrib["text"]
                resourceId = ele.attrib["resource-id"]
                contentDescription = ele.attrib["content-desc"]
                if self.count_attrib_by_xml(xml_tree, text, resourceId, contentDescription)==1:
                    top_ele["xpath"] = '//*'
                    if text:
                        top_ele["xpath"] += f'[@text="{text}"]'
                    if resourceId:
                        top_ele["xpath"] += f'[@resource-id="{resourceId}"]'
                    if contentDescription:
                        top_ele["xpath"] += f'[@content-desc="{contentDescription}"]'

                self.find_element_by_position1(ele, position, level+1, xml_tree, top_ele)

    def find_element_by_position2(self, element, position, xpathList):
        class_name_map = {}
        for ele in element:
            cur_class = ele.attrib["class"]
            if cur_class in class_name_map:
                class_name_map[cur_class] += 1
            else:
                class_name_map[cur_class] = 1
            cur_xpath = f"{cur_class}[{class_name_map[cur_class]}]"

            if "bounds" in ele.attrib and self.in_position(position, ele.attrib["bounds"]):
                if not self.top_ele["ele"]:
                    self.top_ele["ele"] = ele

                xp_list = xpathList.copy()
                if self.compare_bounds(ele.attrib["bounds"], self.top_ele["ele"].attrib["bounds"])<=0:
                    xp_list.append(cur_xpath)
                    self.top_ele["ele"] = ele
                    self.top_ele["level"] = len(xp_list)
                    self.top_ele["xpath"] = "//" + "/".join(xp_list)

                # optimize the xpath
                text = ele.attrib["text"]
                resourceId = ele.attrib["resource-id"]
                contentDescription = ele.attrib["content-desc"]
                if self.count_attrib_by_xml(self.xml_tree, text, resourceId, contentDescription)==1:
                    optimized_path = '*'
                    if text:
                        optimized_path += f'[@text="{text}"]'
                    if resourceId:
                        optimized_path += f'[@resource-id="{resourceId}"]'
                    if contentDescription:
                        optimized_path += f'[@content-desc="{contentDescription}"]'
                    
                    xp_list = [optimized_path]
                    self.top_ele["xpath"] = "//" + "/".join(xp_list)

                self.find_element_by_position2(ele, position, xp_list)

    def count_attrib_by_U2(self, text, resource_id, content_desc):
        count = 0
        if len(text)==0 and len(resource_id)==0 and len(content_desc)==0:
            return count
        
        xpath_str = '//*'
        if text:
            xpath_str += f'[@text="{text}"]'
        if resource_id:
            xpath_str += f'[@resource-id="{resource_id}"]'
        if content_desc:
            xpath_str += f'[@content-desc="{content_desc}"]'

        ele_list = self.u2_device.xpath(xpath_str).all()
        if ele_list:
            count = len(ele_list)

        return count

    def count_attrib_by_xml(self, xml_tree, text, resource_id, content_desc):
        count = 0
        if len(text)==0 and len(resource_id)==0 and len(content_desc)==0:
            return count
        
        for ele in xml_tree:
            if ele.attrib["text"]==text and ele.attrib["resource-id"]==resource_id and ele.attrib["content-desc"]==content_desc:
                count += 1
            else:
                count += self.count_attrib_by_xml(ele, text, resource_id, content_desc)

        return count

    def optimize_xpath(self, xml_tree, xpath_str):
        result = xpath_str
        xpath_part = xpath_str
        convert_part = ""
        while len(xpath_part)>2:
            ele = self.u2_device.xpath(xpath_part)
            info = ele.info
            text = info["text"]
            resourceId = info["resourceId"]
            contentDescription = info["contentDescription"]
            if self.countAttribByXml(xml_tree, text, resourceId, contentDescription)==1:
                convert_part = '//*'
                if text:
                    convert_part += f'[@text="{text}"]'
                if resourceId:
                    convert_part += f'[@resource-id="{resourceId}"]'
                if contentDescription:
                    convert_part += f'[@content-desc="{contentDescription}"]'
                
                result = xpath_str.replace(xpath_part, convert_part)
                break
            else:
                xpath_part = xpath_part[:xpath_part.rindex("/")]
        
        return result

    def click_element_by_ADB(self, xpath):
        bounds = self.u2_device.xpath(xpath).info["bounds"]
        os.system("adb shell input tap {} {}".format(bounds["left"]+(bounds["right"]-bounds["left"])/2, bounds["top"]+(bounds["bottom"]-bounds["top"])/2))
        time.sleep(0.5)

    def click_element_by_U2(self, xpath):
        if self.u2_device:
            self.u2_device.xpath(xpath).click()
            time.sleep(0.5)

    def click_multi_elements_by_U2(self, xpath_array, package, activity):
        os.system("adb shell am start -n {}/{}".format(package, activity))
        for xpath in xpath_array:
            # self.click_element_by_U2(xpath)
            self.click_element_by_ADB(xpath)

    def get_xpath_by_position(self, position_x, position_y):
        self.top_ele = {"ele": None, "level": 0, "xpath": ""}

        hierarchy_xml = self.u2_device.dump_hierarchy()
        self.xml_tree = ET.fromstring(hierarchy_xml)

        # os.system("adb shell uiautomator dump")
        # os.system("adb pull /sdcard/window_dump.xml .")
        # hierarchy_xml = ET.parse("window_dump.xml")
        # self.xml_tree = hierarchy_xml.getroot()

        # t = time.time()
        self.find_element_by_position2(self.xml_tree, (position_x, position_y), [])
        # print(time.time()-t)
        # print(top_ele["ele"].attrib, top_ele["xpath"])
        # d.xpath(top_ele["xpath"]).click()
        return self.top_ele["xpath"]
    
    def get_current_package_activity_by_adb(self):
        result = os.popen('adb shell "dumpsys window | grep mCurrentFocus="')
        result = result.read().strip()
        match_groups = re.match(r".*\{(.*) (.*) (.*)\}", result, re.M|re.I).groups()
        return match_groups[2].split("/")

    def wakeup_app(self, package, activity):
        result = os.popen('adb shell "dumpsys window policy | grep showing="')
        showing = result.read().strip()
        result = os.popen('adb shell "dumpsys window policy | grep screenState="')
        screenState = result.read().strip()
        if showing.split("=")[1]=="true" and screenState.split("=")[1]=="SCREEN_STATE_ON": # 亮屏且有锁
            os.system("adb shell input swipe 660 2400 660 990 100")
        elif showing.split("=")[1]=="true" and screenState.split("=")[1]=="SCREEN_STATE_OFF": # 灭屏且有锁
            os.system("adb shell input keyevent 26")
            os.system("adb shell input swipe 660 2400 660 990 100")
        # elif showing.split("=")[1]=="false" and screenState.split("=")[1]=="SCREEN_STATE_ON": # 亮屏且无锁
        time.sleep(1)
        while self.get_current_package_activity_by_adb()[0]!=package:
            os.system("adb shell am start -n {}/{}".format(package, activity))
            time.sleep(1)

    def start_listening(self, package="", activity=""):
        self.wakeup_app(package, activity)
        command = "adb shell getevent"
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        if package and activity:
            os.system("adb shell am start -n {}/{}".format(package, activity))
        else:
            os.system("adb shell am start -n {}/{}".format("com.lumiunited.aqarahome.play", "com.lumiunited.aqara.main.MainActivity"))
        self.click_queue.clear()
        t = threading.Thread(target=self.output_subprocess)
        t.start()

        print("Now you can trigger the app ...")

    def output_subprocess(self):
        position_x = 0
        position_y = 0
        while self.process.poll() is None:
            line = self.process.stdout.readline()
            if line:
                line = line.decode("gbk").strip()
                if line.startswith("/dev/input"):
                    eve_attr = line.split(" ")
                    if eve_attr[2]=="0035":
                        position_x = int(eve_attr[3], 16)
                    if eve_attr[2]=="0036":
                        position_y = int(eve_attr[3], 16)
                    if position_x!=0 and position_y!=0:
                        print((position_x, position_y))
                        self.click_queue.append((position_x, position_y))
                        # print(self.get_xpath_by_position(position_x, position_y))
                        # t = threading.Thread(target=self.get_xpath_by_position, args=(position_x, position_y))
                        # t.start()
                        position_x = 0
                        position_y = 0
                # else:
                #     print(line)

    def stop_listening(self):
        if self.process:
            # self.process.send_signal(signal.CTRL_C_EVENT)
            self.process.kill()
            self.process.wait(timeout=3)
            if self.process.poll():
                print("The subprocess of record has been terminated!")

    def replay_and_calculate(self, package="", activity=""):
        print("Now let's replay your click sequence ...")
        # 回到开始界面
        if package and activity:
            os.system("adb shell am start -n {}/{}".format(package, activity))
        else:
            os.system("adb shell am start -n {}/{}".format("com.lumiunited.aqarahome.play", "com.lumiunited.aqara.main.MainActivity"))
        time.sleep(1)
        self.view_quene.clear()
        for click in self.click_queue:
            xpath = self.get_xpath_by_position(click[0], click[1])
            self.view_quene.append(xpath)
            print("{},{}:{}".format(click[0], click[1], xpath))
            self.u2_device.click(click[0], click[1])
            time.sleep(1)
        print("Replay has stopped. Is the click sequence consistent with your operations?")

    def getAppBasicInfo(self):
        return self.u2_device.app_current()

if __name__=="__main__":
    monitor = UIMonitor()
    monitor.start_listening("com.lumiunited.aqarahome.play", "com.lumiunited.aqara.main.MainActivity")
    # i = input()
    # print(i)
    # monitor.stop_listening()