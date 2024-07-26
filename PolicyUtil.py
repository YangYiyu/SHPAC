import portion
import re
import enum
import time
import os
import json
import uuid

from PubUtil import Util

class PolicyRelation(enum.Enum):
    unrelated = 0
    duplicated = 1
    overlaped_condition = 2
    overlaped_permit = 3
    overlaped_condition_permit = 4
    hard_conflict = 5
    soft_conflict = 6
    independent = 7
    preinclude_condition = 8
    preinclude_permit = 9
    preinclude_condition_permit = 10
    postinclude_condition = 11
    postinclude_permit = 12
    postinclude_condition_permit = 13

class CalculateType(enum.Enum):
    union = 0
    intersect = 1
    difference = 2

class RelationType(enum.Enum):
    same = 0
    overlap = 1
    different = 2
    preinclude = 3
    postinclude = 4

class Policy:
    def __init__(self):
        self.id = uuid.uuid1()
        self.name = ""
        self.user = ""
        self.device = ""
        self.capability = ""
        self.status_permit = True
        self.action_permit = True
        self.attri_permit = {}
        self.time_condition = ["any"]
        self.location_condition = "any"
        self.attri_condition = {}
        self.level = ""
        self.submitter = ""
        self.state = "check"

    def isLegitimate(self):
        result = True
        if not isinstance(self.user, str) or len(self.user)==0:
            result = False
            print(f"Illegal policy '{self.name}': the user must not be empty")
        elif not isinstance(self.device, str) or len(self.device)==0:
            result = False
            print(f"Illegal policy '{self.name}': the device must not be empty")
        elif not isinstance(self.capability, str) or len(self.capability)==0:
            result = False
            print(f"Illegal policy '{self.name}': the capability must not be empty")
        elif not isinstance(self.status_permit, bool):
            result = False
            print(f"Illegal policy '{self.name}': the status_permit must be a bool")
        elif not isinstance(self.action_permit, bool):
            result = False
            print(f"Illegal policy '{self.name}': the action_permit must be a bool")
        elif not isinstance(self.attri_permit, dict):
            result = False
            print(f"Illegal policy '{self.name}': the attri_permit must be a map")
        elif not isinstance(self.time_condition, list):
            result = False
            print(f"Illegal policy '{self.name}': the time_condition must be a list")
        elif not isinstance(self.location_condition, str) or len(self.location_condition)==0:
            result = False
            print(f"Illegal policy '{self.name}': the location_condition must not be empty")
        elif not isinstance(self.attri_condition, dict):
            result = False
            print(f"Illegal policy '{self.name}': the attri_condition must be a map")
        return result
    
    def __str__(self):
        s = f"policy name: {self.name}\n"
        s += f"user: {self.user}\n"
        s += f"device: {self.device}\n"
        s += f"capability: {self.capability}\n"
        s += f"status_permit: {self.status_permit}\n"
        s += f"action_permit: {self.action_permit}\n"
        s += f"attri_permit: {self.attri_permit}\n"
        s += f"time_condition: {self.time_condition}\n"
        s += f"location_condition: {self.location_condition}\n"
        s += f"attri_condition: {self.attri_condition}\n"
        s += f"level: {self.level}\n"
        s += f"submitter: {self.submitter}\n"
        s += f"state: {self.state}"

        return s
    
    def copy(self):
        p = Policy()
        p.id = self.id
        p.name = self.name
        p.user = self.user
        p.device = self.device
        p.capability = self.capability
        p.status_permit = self.status_permit
        p.action_permit = self.action_permit
        p.attri_permit = self.attri_permit
        p.time_condition = self.time_condition
        p.location_condition = self.location_condition
        p.attri_condition = self.attri_condition
        p.level = self.level
        p.submitter = self.submitter
        p.state = self.state
        return p
    
    def to_json(self):
        obj = {}
        obj["id"] = self.id
        obj["name"] = self.name
        obj["user"] = self.user
        obj["device"] = self.device
        obj["capability"] = self.capability
        obj["status_permit"] = self.status_permit
        obj["action_permit"] = self.action_permit
        obj["attri_permit"] = self.attri_permit
        obj["time_condition"] = self.time_condition
        obj["location_condition"] = self.location_condition
        obj["attri_condition"] = self.attri_condition
        obj["level"] = self.level
        obj["submitter"] = self.submitter
        obj["state"] = self.state
        return obj

class PolicyUtil:
    def __init__(self):
        pass

    def isSameList(self, list1:list, list2:list):
        result = True
        for e1 in list1:
            if e1 not in list2:
                result = False
                break
        for e2 in list2:
            if e2 not in list1:
                result = False
                break
        return result

    def parseRange(self, numberRange:str):
        result = re.match(r"^([\+\-])\((.+),(.+)\)$", numberRange)
        return [result.group(1), result.group(2), result.group(3)]
    
    def getNegativeTimeRange(self, timerange:str):
        ne_range = []
        for tr in timerange:
            if tr.startswith("+"):
                ne_range.append(tr.replace("+", "-"))
            elif tr.startswith("-"):
                ne_range.append(tr.replace("-", "+"))
            else:
                ne_range.append(tr)
        return ne_range

    def getNumberRangeRelation(self, range1:list, range2:list, isClosed:bool):
        result = ""

        if self.isSameList(range1, range2):
            result = RelationType.same
        else:
            interval1 = portion.empty()
            for r1 in range1:
                r1_parse = self.parseRange(r1)
                if r1_parse[1].isdigit():
                    begin_ = int(r1_parse[1])
                elif r1_parse[1] == "-inf":
                    begin_ = -portion.inf
                else:
                    begin_ = r1_parse[1]
                if r1_parse[2].isdigit():
                    end_ = int(r1_parse[2])
                elif r1_parse[2] == "+inf":
                    end_ = portion.inf
                else:
                    end_ = r1_parse[2]
                
                if r1_parse[0]=="+":
                    if isClosed:
                        interval1 = interval1 | portion.closed(begin_, end_)
                    else:
                        interval1 = interval1 | portion.open(begin_, end_)
                else:
                    if isClosed:
                        interval1 = interval1 | portion.closed(begin_, end_).complement()
                    else:
                        interval1 = interval1 | portion.open(begin_, end_).complement()

            interval2 = portion.empty()
            for r2 in range2:
                r2_parse = self.parseRange(r2)
                if r2_parse[1].isdigit():
                    begin_ = int(r2_parse[1])
                elif r2_parse[1] == "-inf":
                    begin_ = -portion.inf
                else:
                    begin_ = r2_parse[1]
                if r2_parse[2].isdigit():
                    end_ = int(r2_parse[2])
                elif r2_parse[2] == "+inf":
                    end_ = portion.inf
                else:
                    end_ = r2_parse[2]
                if r2_parse[0]=="+":
                    if isClosed:
                        interval2 = interval2 | portion.closed(begin_, end_)
                    else:
                        interval2 = interval2 | portion.open(begin_, end_)
                else:
                    if isClosed:
                        interval2 = interval2 | portion.closed(begin_, end_).complement()
                    else:
                        interval2 = interval2 | portion.open(begin_, end_).complement()

            if interval1==interval2:
                result = RelationType.same
            elif interval1.contains(interval2):
                result = RelationType.preinclude
            elif interval2.contains(interval1):
                result = RelationType.postinclude
            elif interval1.overlaps(interval2):
                result = RelationType.overlap
            else:
                result = RelationType.different

        return result
    
    def calculateNumberRange(self, range1:list, range2:list, ctype:CalculateType):
        if ctype==CalculateType.union:
            interval1 = portion.empty()
            for r1 in range1:
                r1_parse = self.parseRange(r1)
                if r1_parse[1].isdigit():
                    begin_ = int(r1_parse[1])
                elif r1_parse[1] == "-inf":
                    begin_ = -portion.inf
                else:
                    begin_ = r1_parse[1]
                if r1_parse[2].isdigit():
                    end_ = int(r1_parse[2])
                elif r1_parse[2] == "+inf":
                    end_ = portion.inf
                else:
                    end_ = r1_parse[2]
                if r1_parse[0]=="+":
                    interval1 = interval1 | portion.closed(begin_, end_)
                else:
                    interval1 = interval1 | portion.closed(begin_, end_).complement()

            interval2 = portion.empty()
            for r2 in range2:
                r2_parse = self.parseRange(r2)
                if r2_parse[1].isdigit():
                    begin_ = int(r2_parse[1])
                elif r2_parse[1] == "-inf":
                    begin_ = -portion.inf
                else:
                    begin_ = r2_parse[1]
                if r2_parse[2].isdigit():
                    end_ = int(r2_parse[2])
                elif r2_parse[2] == "+inf":
                    end_ = portion.inf
                else:
                    end_ = r2_parse[2]
                if r2_parse[0]=="+":
                    interval2 = interval2 | portion.closed(begin_, end_)
                else:
                    interval2 = interval2 | portion.closed(begin_, end_).complement()
            return interval1 | interval2
        if ctype==CalculateType.intersect:
            interval1 = portion.closed(-portion.inf, portion.inf)
            for r1 in range1:
                r1_parse = self.parseRange(r1)
                if r1_parse[1].isdigit():
                    begin_ = int(r1_parse[1])
                elif r1_parse[1] == "-inf":
                    begin_ = -portion.inf
                else:
                    begin_ = r1_parse[1]
                if r1_parse[2].isdigit():
                    end_ = int(r1_parse[2])
                elif r1_parse[2] == "+inf":
                    end_ = portion.inf
                else:
                    end_ = r1_parse[2]
                if r1_parse[0]=="+":
                    interval1 = interval1 & portion.closed(begin_, end_)
                else:
                    interval1 = interval1 & portion.closed(begin_, end_).complement()

            interval2 = portion.closed(-portion.inf, portion.inf)
            for r2 in range2:
                r2_parse = self.parseRange(r2)
                if r2_parse[1].isdigit():
                    begin_ = int(r2_parse[1])
                elif r2_parse[1] == "-inf":
                    begin_ = -portion.inf
                else:
                    begin_ = r2_parse[1]
                if r2_parse[2].isdigit():
                    end_ = int(r2_parse[2])
                elif r2_parse[2] == "+inf":
                    end_ = portion.inf
                else:
                    end_ = r2_parse[2]
                if r2_parse[0]=="+":
                    interval2 = interval2 & portion.closed(begin_, end_)
                else:
                    interval2 = interval2 & portion.closed(begin_, end_).complement()
            return interval1 & interval2
        if ctype==CalculateType.difference:
            interval1 = portion.empty()
            for r1 in range1:
                r1_parse = self.parseRange(r1)
                if r1_parse[1].isdigit():
                    begin_ = int(r1_parse[1])
                elif r1_parse[1] == "-inf":
                    begin_ = -portion.inf
                else:
                    begin_ = r1_parse[1]
                if r1_parse[2].isdigit():
                    end_ = int(r1_parse[2])
                elif r1_parse[2] == "+inf":
                    end_ = portion.inf
                else:
                    end_ = r1_parse[2]
                if r1_parse[0]=="+":
                    interval1 = interval1 | portion.closed(begin_, end_)
                else:
                    interval1 = interval1 | portion.closed(begin_, end_).complement()

            interval2 = portion.empty()
            for r2 in range2:
                r2_parse = self.parseRange(r2)
                if r2_parse[1].isdigit():
                    begin_ = int(r2_parse[1])
                elif r2_parse[1] == "-inf":
                    begin_ = -portion.inf
                else:
                    begin_ = r2_parse[1]
                if r2_parse[2].isdigit():
                    end_ = int(r2_parse[2])
                elif r2_parse[2] == "+inf":
                    end_ = portion.inf
                else:
                    end_ = r2_parse[2]
                if r2_parse[0]=="+":
                    interval2 = interval2 | portion.closed(begin_, end_)
                else:
                    interval2 = interval2 | portion.closed(begin_, end_).complement()

            return interval1 - interval2
    
    def getDatetimeRangeRelation(self, range1:list, range2:list):
        if range1==range2:
            return RelationType.same
        else:
            anyInRange1 = any([r1=="any" for r1 in range1])
            anyInRange2 = any([r2=="any" for r2 in range2])
            if anyInRange1 and anyInRange2:
                return RelationType.same
            elif anyInRange1 and not anyInRange2:
                return RelationType.preinclude
            elif not anyInRange1 and anyInRange2:
                return RelationType.postinclude
            else:
                # converted_range1 = []
                # for r1 in range1:
                #     r1_parse = self.parseRange(r1)
                #     converted_range1.append("{}({},{})".format(r1_parse[0], Util.fromDatetimeStrToStamp(r1_parse[1]), Util.fromDatetimeStrToStamp(r1_parse[2])))

                # converted_range2 = []
                # for r2 in range2:
                #     r2_parse = self.parseRange(r2)
                #     converted_range2.append("{}({},{})".format(r2_parse[0], Util.fromDatetimeStrToStamp(r2_parse[1]), Util.fromDatetimeStrToStamp(r2_parse[2])))
                
                # return self.getNumberRangeRelation(converted_range1, converted_range2)
                return self.getNumberRangeRelation(range1, range2, False)
    
    def calculateOverlapedDatetimeRange(self, range1:list, range2:list, ctype:CalculateType):
        anyInRange1 = any([r1=="any" for r1 in range1])
        anyInRange2 = any([r2=="any" for r2 in range2])
        if anyInRange1 and anyInRange2:
            return ["any"]
        elif anyInRange1 and not anyInRange2:
            if ctype==CalculateType.union:
                return ["any"]
            elif ctype==CalculateType.intersect:
                return range2
            elif ctype==CalculateType.difference:
                return self.getNegativeTimeRange(range2)
        elif not anyInRange1 and anyInRange2:
            if ctype==CalculateType.union:
                return ["any"]
            elif ctype==CalculateType.intersect:
                return range1
            elif ctype==CalculateType.difference:
                return self.getNegativeTimeRange(range1)
        else:
            # converted_range1 = []
            # for r1 in range1:
            #     r1_parse = self.parseRange(r1)
            #     converted_range1.append("{}({},{})".format(r1_parse[0], Util.fromDatetimeStrToStamp(r1_parse[1]), Util.fromDatetimeStrToStamp(r1_parse[2])))
            # converted_range2 = []
            # for r2 in range2:
            #     r2_parse = self.parseRange(r2)
            #     converted_range2.append("{}({},{})".format(r2_parse[0], Util.fromDatetimeStrToStamp(r2_parse[1]), Util.fromDatetimeStrToStamp(r2_parse[2])))

            # calculate_result = list(self.calculateNumberRange(converted_range1, converted_range2, ctype))
            # datetime_result = []
            # for cal in calculate_result:
            #     datetime_result.append("+({},{})".format(Util.fromStampToDatetimeStr(cal.lower), Util.fromStampToDatetimeStr(cal.upper)))

            # return datetime_result
            resultRange = self.calculateNumberRange(range1, range2, ctype)
            resultList = []
            for r in list(resultRange):
                resultList.append("+({},{})".format(r.lower, r.upper))

            if any([r=="+(-inf,+inf)" for r in resultList]):
                resultList = ["any"]
            return resultList

    def get24hTimeRangeRelation(self, range1:list, range2:list):
        result = ""

        if range1==range2:
            result = RelationType.same
        else:
            if range1=="any" or range2=="any":
                result = RelationType.overlap
            else:
                interval1 = portion.empty()
                for r1 in range1:
                    if r1[0]>=0:
                        if r1[0]<r1[1]:
                            interval1 = interval1 | portion.closed(r1[0], r1[1])
                        elif r1[0]>r1[1]:
                            interval1 = interval1 | portion.closed(r1[0], 2400) | portion.closed(0, r1[1])
                    else:
                        interval1 = interval1 | portion.closed(0, r1[0]) | portion.closed(r1[1], 2400)

                interval2 = portion.empty()
                for r2 in range1:
                    if r2[0]>=0:
                        if r2[0]<r2[1]:
                            interval2 = interval2 | portion.closed(r2[0], r2[1])
                        elif r2[0]>r2[1]:
                            interval2 = interval2 | portion.closed(r2[0], 2400) | portion.closed(0, r2[1])
                    else:
                        interval2 = interval2 | portion.closed(0, r2[0]) | portion.closed(r2[1], 2400)

                if interval1==interval2:
                    result = RelationType.same
                elif interval1.contains(interval2):
                    result = RelationType.preinclude
                elif interval2.contains(interval1):
                    result = RelationType.postinclude
                elif interval1.overlaps(interval2):
                    result = RelationType.overlap
                else:
                    result = RelationType.different

        return result

    def calculate24hOverlapedTimeRange(self, range1:list, range2:list, ctype:CalculateType):
        if range1=="any" or range2=="any":
            if ctype==CalculateType.union:
                return any
            if ctype==CalculateType.intersect:
                return range1 if range1!="any" else range2
            if ctype==CalculateType.difference:
                range_ = range1 if range1!="any" else range2
                if range_.startswith("-"):
                    begin = int(range_[1:].split("-")[0])
                    end = int(range_[1:].split("-")[1])
                    interval1 = portion.closed(begin, end)
                else:
                    begin = int(range_.split("-")[0])
                    end = int(range_.split("-")[1])
                    interval1 = portion.closed(0, begin) | portion.closed(end, 2400)
                return interval1
        else:
            interval1 = portion.empty()
            for r1 in range1:
                if r1[0]>=0:
                    if r1[0]<r1[1]:
                        interval1 = interval1 | portion.closed(r1[0], r1[1])
                    elif r1[0]>r1[1]:
                        interval1 = interval1 | portion.closed(r1[0], 2400) | portion.closed(0, r1[1])
                else:
                    interval1 = interval1 | portion.closed(0, r1[0]) | portion.closed(r1[1], 2400)

            interval2 = portion.empty()
            for r2 in range1:
                if r2[0]>=0:
                    if r2[0]<r2[1]:
                        interval2 = interval2 | portion.closed(r2[0], r2[1])
                    elif r2[0]>r2[1]:
                        interval2 = interval2 | portion.closed(r2[0], 2400) | portion.closed(0, r2[1])
                else:
                    interval2 = interval2 | portion.closed(0, r2[0]) | portion.closed(r2[1], 2400)
            
            if ctype==CalculateType.union:
                return interval1 | interval2
            if ctype==CalculateType.intersect:
                return interval1 & interval2
            if ctype==CalculateType.difference:
                return interval1 - interval2

    def getLocationRelation(self, location1:list, location2:list):
        loc1 = location1
        loc2 = location2
        if loc1==loc2:
            return RelationType.same
        elif loc1=="any" and loc2!="any":
            return RelationType.preinclude
        elif loc1!="any" and loc2=="any":
            return RelationType.postinclude
        else:
            return RelationType.different

    # 有overlap才计算
    def calculateOverlapedLocation(self, location1:str, location2:str, ctype:CalculateType):
        loc1 = location1
        loc2 = location2
        result = ""
        if ctype==CalculateType.union:
            result = "any"
        if ctype==CalculateType.intersect:
            if loc1=="any" and loc2!="any":
                result = loc2
            else:
                result = loc1
        if ctype==CalculateType.difference:
            if loc1=="any" and loc2!="any":
                result = f"-{loc2}"
            elif loc1!="any" and loc2=="any":
                result = f"-{loc1}"
            else:
                result = loc1
        
        return result
    
    def getAttriRelation(self, map1:map, map2:map):
        result = {}
        for key1 in map1:
            if key1 in map2 and map1[key1]==map2[key1]:
                result[key1] = RelationType.same
            elif key1 in map2 and map1[key1]!=map2[key1]:
                # if isinstance(map1[key1], str) and re.match(r"^-?\d+-\d+", map1[key1]) and isinstance(map2[key1], str) and re.match(r"^-?\d+-\d+", map2[key1]):
                #     result[key1] = self.getNumberRangeRelation(map1[key1], map2[key1])
                if isinstance(map1[key1], bool) and isinstance(map2[key1], bool):
                    result[key1] = RelationType.different
                if isinstance(map1[key1], list) and isinstance(map2[key1], list):
                    result[key1] = self.getNumberRangeRelation(map1[key1], map2[key1], True)
            else:
                result[key1] = RelationType.postinclude
        
        for key2 in map2:
            if key2 in result:
                continue
            if key2 not in map1:
                result[key2] = RelationType.preinclude

        if all([result[r]==RelationType.same for r in result]):
            return RelationType.same
        elif all([result[r]==RelationType.preinclude for r in result]):
            return RelationType.preinclude
        elif all([result[r]==RelationType.postinclude for r in result]):
            return RelationType.postinclude
        elif any([result[r]==RelationType.different for r in result]):
            return RelationType.different
        else:
            return RelationType.overlap
    
    # 有overlap才计算
    def calculateOverlapedAttri(self, map1:map, map2:map, ctype:CalculateType):
        result = {}
        if ctype==CalculateType.union:
            for key1 in map1:
                if key1 in map2 and map1[key1]==map2[key1]:
                    result[key1] = map1[key1]
                elif key1 in map2 and map1[key1]!=map2[key1]:
                    # if isinstance(map1[key1], str) and re.match(r"^-?\d+-\d+", map1[key1]) and isinstance(map2[key1], str) and re.match(r"^-?\d+-\d+", map2[key1]):
                    #     result[key1] = self.calculateNumberRange(map1[key1], map2[key1], CalculateType.union)
                    if isinstance(map1[key1], list) and isinstance(map2[key1], list):
                        calculate_result = self.calculateNumberRange(map1[key1], map2[key1], CalculateType.union)
                        number_result = []
                        for cal in calculate_result:
                            if cal.lower!=cal.upper:
                                number_result.append([cal.lower, cal.upper])
                        result[key1] = number_result

        if ctype==CalculateType.intersect:
            for key1 in map1:
                if key1 in map2 and map1[key1]==map2[key1]:
                    result[key1] = map1[key1]
                elif key1 in map2 and map1[key1]!=map2[key1]:
                    # if isinstance(map1[key1], str) and re.match(r"^-?\d+-\d+", map1[key1]) and isinstance(map2[key1], str) and re.match(r"^-?\d+-\d+", map2[key1]):
                    #     result[key1] = self.calculateNumberRange(map1[key1], map2[key1], CalculateType.intersect)
                    if isinstance(map1[key1], list) and isinstance(map2[key1], list):
                        calculate_result = self.calculateNumberRange(map1[key1], map2[key1], CalculateType.intersect)
                        number_result = []
                        for cal in calculate_result:
                            if cal.lower!=cal.upper:
                                number_result.append([cal.lower, cal.upper])
                        result[key1] = number_result
                else:
                    result[key1] = map1[key1]
            for key2 in map2:
                if key2 in result:
                    continue
                if key2 not in map1:
                    result[key2] = map2[key2]
        if ctype==CalculateType.difference:
            for key1 in map1:
                if key1 in map2 and map1[key1]!=map2[key1]:
                    # if isinstance(map1[key1], str) and re.match(r"^-?\d+-\d+", map1[key1]) and isinstance(map2[key1], str) and re.match(r"^-?\d+-\d+", map2[key1]):
                    #     # !!!!!!!!!!!!! 注意map1和map2的顺序会产生不同结果
                    #     result[key1] = self.calculateNumberRange(map1[key1], map2[key1], CalculateType.difference)
                    if isinstance(map1[key1], list) and isinstance(map2[key1], list):
                        # !!!!!!!!!!!!! 注意map1和map2的顺序会产生不同结果
                        calculate_result = self.calculateNumberRange(map1[key1], map2[key1], CalculateType.difference)
                        number_result = []
                        for cal in calculate_result:
                            if cal.lower!=cal.upper:
                                number_result.append([cal.lower, cal.upper])
                        result[key1] = number_result
                elif key1 not in map2:
                    # if isinstance(map1[key1], str) and re.match(r"^-?\d+-\d+", map1[key1]):
                    #     result[key1] = f"-{map1[key1]}"
                    # if isinstance(map1[key1], bool):
                    #     result[key1] = not map1[key1]
                    # if isinstance(map1[key1], list):
                    #     result[key1] = [[-n[0],n[1]] for n in map1[key1]]
                    result[key1] = map1[key1]

            for key2 in map2:
                if key2 in result:
                    continue
                if key2 not in map1:
                    # if isinstance(map2[key2], str) and re.match(r"^-?\d+-\d+", map2[key2]):
                    #     result[key2] = f"-{map2[key2]}"
                    if isinstance(map2[key2], bool):
                        result[key2] = not map2[key2]
                    if isinstance(map2[key2], list):
                        result[key2] = [[-n[0],n[1]] for n in map2[key2]]
        
        c_r_ = {}
        for key in result:
            if isinstance(result[key], list):
                c_r_[key] =[]
                for ran_ in result[key]:
                    c_r_[key].append(ran_)
            else:
                c_r_[key] = result[key]

        return c_r_

    def calculatePolicyCondition(self, p1:Policy, p2:Policy):
        result = {}

        result["time_condition"] = self.getDatetimeRangeRelation(p1.time_condition, p2.time_condition)

        result["location_condition"] = self.getLocationRelation(p1.location_condition, p2.location_condition)

        result["attri_condition"] = self.getAttriRelation(p1.attri_condition, p2.attri_condition)

        return result
    
    def calculatePolicyPermit(self, p1:Policy, p2:Policy):
        result = {}

        if p1.action_permit==p2.action_permit:
            result["action_permit"] = RelationType.same
        else:
            result["action_permit"] = RelationType.different

        if p1.status_permit==p2.status_permit:
            result["status_permit"] = RelationType.same
        else:
            result["status_permit"] = RelationType.different

        result["attri_permit"] = self.getAttriRelation(p1.attri_permit, p2.attri_permit)

        return result

    def getConditionResult(self, condition:map):
        if condition["time_condition"]==RelationType.same and condition["location_condition"]==RelationType.same and condition["attri_condition"]==RelationType.same:
            return RelationType.same
        elif condition["time_condition"] in [RelationType.same,RelationType.preinclude] and condition["location_condition"] in [RelationType.same,RelationType.preinclude] and condition["attri_condition"] in [RelationType.same,RelationType.preinclude]:
            return RelationType.preinclude
        elif condition["time_condition"] in [RelationType.same,RelationType.postinclude] and condition["location_condition"] in [RelationType.same,RelationType.postinclude] and condition["attri_condition"] in [RelationType.same,RelationType.postinclude]:
            return RelationType.postinclude
        elif condition["time_condition"]==RelationType.different or condition["location_condition"]==RelationType.different or condition["attri_condition"]==RelationType.different:
            return RelationType.different
        else:
            return RelationType.overlap
    
    def getPermitResult(self, permit:map):
        if permit["action_permit"]==RelationType.same and permit["status_permit"]==RelationType.same and permit["attri_permit"]==RelationType.same:
            return RelationType.same
        elif permit["action_permit"] in [RelationType.same,RelationType.preinclude] and permit["status_permit"] in [RelationType.same,RelationType.preinclude] and permit["attri_permit"] in [RelationType.same,RelationType.preinclude]:
            return RelationType.preinclude
        elif permit["action_permit"] in [RelationType.same,RelationType.postinclude] and permit["status_permit"] in [RelationType.same,RelationType.postinclude] and permit["attri_permit"] in [RelationType.same,RelationType.postinclude]:
            return RelationType.postinclude
        elif permit["action_permit"]==RelationType.different or permit["status_permit"]==RelationType.different or permit["attri_permit"]==RelationType.different:
            return RelationType.different
        else:
            return RelationType.overlap

    def getPolicyRelationOnSingleUserDeviceCapability(self, p1:Policy, p2:Policy):
        relation = PolicyRelation.unrelated

        if not p1.isLegitimate() or not p2.isLegitimate():
            return relation

        if p1.user==p2.user and p1.device==p2.device and p1.capability==p2.capability:
            condition = self.calculatePolicyCondition(p1, p2)
            # print("condition result:", condition)
            conditionR = self.getConditionResult(condition)
            # print("condition relation:", conditionR)
            permit = self.calculatePolicyPermit(p1, p2)
            # print("permit result:", permit)
            permitR = self.getPermitResult(permit)
            # print("permit relation:", permitR)
            if conditionR==RelationType.different: # 独立
                relation = PolicyRelation.independent
            elif conditionR==RelationType.same and permitR==RelationType.same: # 重复
                relation = PolicyRelation.duplicated
            elif conditionR==RelationType.same and permitR==RelationType.different: # 完全冲突
                relation = PolicyRelation.hard_conflict
            elif conditionR in [RelationType.preinclude,RelationType.postinclude,RelationType.overlap] and permitR==RelationType.different: # 不完全冲突
                relation = PolicyRelation.soft_conflict
            elif conditionR==RelationType.same and permitR==RelationType.preinclude: # 权限前包含
                relation = PolicyRelation.preinclude_permit
            elif conditionR==RelationType.same and permitR==RelationType.postinclude: # 权限后包含
                relation = PolicyRelation.postinclude_permit
            elif conditionR==RelationType.preinclude and permitR==RelationType.same: # 条件前包含
                relation = PolicyRelation.preinclude_condition
            elif conditionR==RelationType.postinclude and permitR==RelationType.same: # 条件后包含
                relation = PolicyRelation.postinclude_condition
            elif conditionR==RelationType.preinclude and permitR==RelationType.preinclude: # 条件权限前包含
                relation = PolicyRelation.preinclude_condition_permit
            elif conditionR==RelationType.postinclude and permitR==RelationType.postinclude: # 条件权限后包含
                relation = PolicyRelation.postinclude_condition_permit
            elif conditionR==RelationType.same and permitR==RelationType.overlap: # 权限重叠
                relation = PolicyRelation.overlaped_permit
            elif conditionR==RelationType.overlap and permitR==RelationType.same: # 条件重叠
                relation = PolicyRelation.overlaped_condition
            elif conditionR in [RelationType.preinclude,RelationType.postinclude,RelationType.overlap] and permitR in [RelationType.preinclude,RelationType.postinclude,RelationType.overlap]: # 权限条件重叠
                relation = PolicyRelation.overlaped_condition_permit
        else:
            relation = PolicyRelation.independent
        return relation

    def getPolicyLevelRelation(self, p1:Policy, p2:Policy):
        if ((p1.level=="admin" and p2.level=="admin")) or (p1.level=="user" and p2.level=="user"):
            return "="
        elif p1.level=="admin" and p2.level=="user":
            return ">"
        else:
            return "<"

    def getModifiedPolicy(self, p1:Policy, p2:Policy, permitCalType:CalculateType, conditionCalType:CalculateType):
        modifiedPolicy = p1.copy()
        if permitCalType:
            modifiedPolicy.attri_permit = self.calculateOverlapedAttri(p1.attri_permit, p2.attri_permit, permitCalType)
        if conditionCalType:
            modifiedPolicy.time_condition = self.calculateOverlapedDatetimeRange(p1.time_condition, p2.time_condition, conditionCalType)
            modifiedPolicy.location_condition = self.calculateOverlapedLocation(p1.location_condition, p2.location_condition, conditionCalType)
            modifiedPolicy.attri_condition = self.calculateOverlapedAttri(p1.attri_condition, p2.attri_condition, conditionCalType)
        return modifiedPolicy

    def getSuggestPolicy(self, p1:Policy, p2:Policy, relation:PolicyRelation):
        suggested_policy = None
        
        if relation==PolicyRelation.overlaped_permit and self.getPolicyLevelRelation(p1, p2) in ["=","<"]:
            suggested_policy = self.getModifiedPolicy(p1, p2, CalculateType.union, None)
        elif relation==PolicyRelation.overlaped_condition and self.getPolicyLevelRelation(p1, p2) in ["=","<"]:
            suggested_policy = self.getModifiedPolicy(p1, p2, None, CalculateType.union)
        elif relation==PolicyRelation.overlaped_condition_permit and self.getPolicyLevelRelation(p1, p2) in ["=","<"]:
            suggested_policy = self.getModifiedPolicy(p1, p2, CalculateType.union, CalculateType.union)
        elif relation==PolicyRelation.soft_conflict and self.getPolicyLevelRelation(p1, p2) in ["=","<"]:
            suggested_policy = self.getModifiedPolicy(p1, p2, None, CalculateType.difference)
        
        return suggested_policy

    def getCheckResult(self, N_P, policy_list):
        pr = PolicyRelation.unrelated
        lr = ""
        handle = []
        handle.append("accept_np")
        suggested_policy = []
        related_policy = {}
        for O_P in policy_list:
            if N_P.id == O_P.id:
                continue

            pr = self.getPolicyRelationOnSingleUserDeviceCapability(N_P, O_P)
            lr = self.getPolicyLevelRelation(N_P, O_P)

            if pr == PolicyRelation.independent:
                handle = []
                handle.append("accept_np")
            elif pr != PolicyRelation.independent and lr==">":
                handle = []
                handle.append("accept_np_reject_op")
                related_policy = O_P.to_json()
                break
            elif (pr in [PolicyRelation.postinclude_permit, PolicyRelation.postinclude_condition, PolicyRelation.postinclude_condition_permit, PolicyRelation.duplicated] and lr=="=") or lr=="<":
                handle = []
                handle.append("reject_np")
                related_policy = O_P.to_json()
                break
            elif pr in [PolicyRelation.preinclude_permit, PolicyRelation.preinclude_condition, PolicyRelation.preinclude_condition_permit, PolicyRelation.hard_conflict] and lr=="=":
                handle = []
                handle.append("accept_np_reject_op")
                related_policy = O_P.to_json()
                break
            elif pr==PolicyRelation.overlaped_permit and lr=="=":
                handle = []
                handle.append("accept_mnp_reject_op")
                handle.append("accept_mnp_reject_op")
                suggested_policy.append(self.getModifiedPolicy(N_P, O_P, CalculateType.union, None).to_json())
                suggested_policy.append(self.getModifiedPolicy(N_P, O_P, CalculateType.intersect, None).to_json())
                related_policy = O_P.to_json()
                break
            elif pr==PolicyRelation.overlaped_condition and lr=="=":
                handle = []
                handle.append("accept_mnp_reject_op")
                handle.append("accept_mnp_reject_op")
                suggested_policy.append(self.getModifiedPolicy(N_P, O_P, None, CalculateType.union).to_json())
                suggested_policy.append(self.getModifiedPolicy(N_P, O_P, None, CalculateType.intersect).to_json())
                related_policy = O_P.to_json()
                break
            elif pr==PolicyRelation.overlaped_condition_permit and lr=="=":
                handle = []

                condition_relation = self.calculatePolicyCondition(N_P, O_P)
                if condition_relation["time_condition"] == RelationType.preinclude or condition_relation["location_condition"] == RelationType.preinclude or condition_relation["attri_condition"] == RelationType.preinclude:
                    handle.append("accept_mnp")
                    suggested_policy.append(self.getModifiedPolicy(N_P, O_P, None, CalculateType.difference).to_json())
                elif condition_relation["time_condition"] == RelationType.overlap or condition_relation["location_condition"] == RelationType.overlap or condition_relation["attri_condition"] == RelationType.overlap:
                    handle.append("accept_mnp")
                    suggested_policy.append(self.getModifiedPolicy(N_P, O_P, None, CalculateType.difference).to_json())
                else:
                    handle.append("accept_np_accept_mop")
                    suggested_policy.append(self.getModifiedPolicy(O_P, N_P, None, CalculateType.difference).to_json())
                
                handle.append("accept_mnp_reject_op")
                handle.append("accept_mnp_reject_op")
                handle.append("accept_mnp_reject_op")
                handle.append("accept_mnp_reject_op")
                suggested_policy.append(self.getModifiedPolicy(N_P, O_P, CalculateType.union, CalculateType.union).to_json())
                suggested_policy.append(self.getModifiedPolicy(N_P, O_P, CalculateType.intersect, CalculateType.union).to_json())
                suggested_policy.append(self.getModifiedPolicy(N_P, O_P, CalculateType.union, CalculateType.intersect).to_json())
                suggested_policy.append(self.getModifiedPolicy(N_P, O_P, CalculateType.intersect, CalculateType.intersect).to_json())

                related_policy = O_P.to_json()
                break
            elif pr==PolicyRelation.soft_conflict and lr=="=":
                handle = []
                condition_relation = self.calculatePolicyCondition(N_P, O_P)
                if condition_relation["time_condition"] == RelationType.preinclude or condition_relation["location_condition"] == RelationType.preinclude or condition_relation["attri_condition"] == RelationType.preinclude:
                    handle.append("accept_mnp")
                    suggested_policy.append(self.getModifiedPolicy(N_P, O_P, None, CalculateType.difference).to_json())
                elif condition_relation["time_condition"] == RelationType.overlap or condition_relation["location_condition"] == RelationType.overlap or condition_relation["attri_condition"] == RelationType.overlap:
                    handle.append("accept_mnp")
                    suggested_policy.append(self.getModifiedPolicy(N_P, O_P, None, CalculateType.difference).to_json())
                else:
                    handle.append("accept_np_accept_mop")
                    suggested_policy.append(self.getModifiedPolicy(O_P, N_P, None, CalculateType.difference).to_json())
                related_policy = O_P.to_json()
                break
        
        return {"pr":pr, "lr":lr, "handle":handle, "related_policy":related_policy, "suggested_policy":suggested_policy}

    def isValueInAttri(self, value, attri):
        val_ = value
        # if isinstance(value, str):
        #     val_ = int(value)

        interval = portion.empty()
        for r in attri:
            r_parse = self.parseRange(r)
            if r_parse[0]=="+":
                interval = interval | portion.closed(r_parse[1], r_parse[2])
            else:
                interval = interval | portion.closed(r_parse[1], r_parse[2]).complement()
        return interval.contains(val_)

    def isNowInTimeCondition(self, timeCondition):
        # converted_range = []
        # for r in timeCondition:
        #     if r[0].startswith("-"):
        #         converted_range.append([-Util.fromDatetimeStrToStamp(r[0][1:]), Util.fromDatetimeStrToStamp(r[1])])
        #     else:
        #         print(r)
        #         converted_range.append([Util.fromDatetimeStrToStamp(r[0][1:]), Util.fromDatetimeStrToStamp(r[1])])
        
        now = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        if self.getNumberRangeRelation(timeCondition, [f"+({now},{now})"], True)==RelationType.different:
            return False
        else:
            return True
        
    def isAttriConditionSatisfied(self, attriCondition, deviceid, capability, attri_status):
        result = False
        if len(attriCondition)==0:
            result = True
        else:
            for attri in attriCondition:
                condition = attriCondition[attri]
                full_attri = "{}.{}.{}".format(deviceid, capability, attri)
                if isinstance(condition, list) and self.isValueInAttri(attri_status[full_attri], condition):
                    result = True
                elif isinstance(condition, bool) and attri_status[full_attri]==condition:
                    result = True
        return result

    def checkActionPermission(self, user, device, capability, attribute, actionVal, policyList, user_location, attri_status):
        permit = False
        msg = ""
        print("Checking permission: {}, {}, {}, {}, {}".format(user, device, capability, attribute, actionVal))
        if actionVal=="True":
            actionVal = True
        elif actionVal=="False":
            actionVal = False
        for policy in policyList:
            if policy.user==user and policy.device==device and policy.capability==capability:
                if len(policy.time_condition)>0 and (any([t=="any" for t in policy.time_condition]) or self.isNowInTimeCondition(policy.time_condition)):
                    if policy.location_condition=="any" or user_location[user]==policy.location_condition:
                        if self.isAttriConditionSatisfied(policy.attri_condition, device, capability, attri_status):
                            if policy.action_permit:
                                if len(policy.attri_permit)>0 and attribute in policy.attri_permit:
                                    attri_permit = policy.attri_permit[attribute]
                                    if (isinstance(attri_permit, list) and self.isValueInAttri(actionVal, attri_permit)) or\
                                            (isinstance(attri_permit, bool) and actionVal==attri_permit):
                                        permit = True
                                        msg = f"success"
                                        break
                                    else:
                                        permit = False
                                        msg = f"The '{attribute}' value of '{actionVal}' is beyond the policy's attri permission: {attri_permit}"
                                else:
                                    permit = True
                                    msg = f"success"
                                    break
                            else:
                                permit = False
                                msg = f"The user '{user}' does not possess the action permision of '{capability}'"
                        else:
                            permit = False
                            msg = f"The current attri values are not meet the policy's attri condition: {policy.attri_condition}"
                    else:
                        permit = False
                        msg = f"The user location of '{user_location[user]}' is not meet the policy's location condition: {policy.location_condition}"
                else:
                    permit = False
                    msg = f"The current time is not meet the policy's time condition: {policy.time_condition}"
            else:
                continue

        if not permit and len(msg)==0:
            msg = "the permission of '{}' to  '{}.{}' is not defined!".format(user, device, capability)
        
        print("Checking result: {}, {}".format(permit, msg))
        return [permit, msg]

    def checkStatusPermission(self, user, device, capability, policyList, user_location, attri_status):
        permit = False
        msg = ""
        for policy in policyList:
            if policy.user==user and policy.device==device and policy.capability==capability:
                if len(policy.time_condition)>0 and (any([t=="any" for t in policy.time_condition]) or self.isNowInTimeCondition(policy.time_condition)):
                    if policy.location_condition=="any" or self.user_location[user]==policy.location_condition:
                        if self.isAttriConditionSatisfied(policy.attri_condition, device, capability, attri_status):
                            if policy.status_permit:
                                permit = True
                                msg = f"success"
                                break
                            else:
                                permit = False
                                msg = f"The user '{user}' does not possess the status permision of '{capability}'"
                        else:
                            permit = False
                            msg = f"The current attri values are not meet the policy's attri condition: {policy.attri_condition}"
                    else:
                        permit = False
                        msg = f"The user location of '{user_location[user]}' is not meet the policy's location condition: {policy.location_condition}"
                else:
                    permit = False
                    msg = f"The current time is not meet the policy's time condition: {policy.time_condition}"
            else:
                continue
        return [permit, msg]
    
    def loadPolicyFromJson(self, jsonfile):
        policy_list = []
        if len(jsonfile)==0:
            print(f"Error: the path is null!")
            return policy_list
        
        if not os.path.exists(jsonfile):
            print(f"The '{jsonfile}' does not exist!")
            return policy_list

        policy_json_str = ""
        with open(jsonfile) as f:
            policy_json_str = f.read()
        if len(policy_json_str)==0:
            print(f"The '{jsonfile}' is empty!")
            return policy_list
        
        policy_json = json.loads(policy_json_str)
        for p_json in policy_json:
            policy = Policy()
            policy.name = p_json["policy_name"]
            policy.user = p_json["user"]
            policy.device = p_json["device"]
            policy.capability = p_json["capability"]
            policy.status_permit = p_json["status_permit"]
            policy.action_permit = p_json["action_permit"]
            policy.attri_permit = p_json["attri_permit"]
            policy.time_condition = p_json["time_condition"]
            policy.location_condition = p_json["location_condition"]
            policy.attri_condition = p_json["attri_condition"]
            policy_list.append(policy)
        
        return policy_list

if __name__=="__main__":
    p1 = Policy()
    p1.name = "p1"
    p1.user = "Alice"
    p1.device = "Aqara-gateway-1703771210"
    p1.capability = "light"
    p1.status_permit = True
    p1.action_permit = True
    p1.attri_permit["bright"] = ["+(70,100)"]
    p1.time_condition = ["+(-inf,2024-01-18 08:00:00)", "+(2024-01-18 20:00:00,2024-01-22 18:00:00)", "+(2024-01-22 22:00:00,2024-01-24 21:00:00)", "+(2024-01-24 21:30:00,+inf)"]
    p1.location_condition = "any"
    # p1.attri_condition["switch"] = True
    p1.level = "admin"
    p1.submitter = "Alice"

    p2 = Policy()
    p2.name = "p2"
    p2.user = "Alice"
    p2.device = "Aqara-gateway-1703771210"
    p2.capability = "light"
    p2.status_permit = True
    p2.action_permit = True
    # p2.attri_permit["bright"] = ["+(70,100)"]
    p2.time_condition = ["+(2024-01-24 21:15:00,2024-01-24 22:00:00)"]
    p2.location_condition = "any"
    # p2.attri_condition["switch"] = True
    p2.level = "admin"
    p2.submitter = "Alice"

    util = PolicyUtil()
    result = util.getCheckResult(p2,[p1])
    print("lr: " + result["lr"])
    print("pr: " + str(result["pr"]))
    print("related_policy: " + str(result["related_policy"]))
    print()
    for i in range(len(result["handle"])):
        print(result["handle"][i])
        if i<len(result["suggested_policy"]):
            print(result["suggested_policy"][i])
        print()

    # pr = util.getPolicyRelationOnSingleUserDeviceCapability(p1, p2)
    # print("\nThe relation between p1 and p2 is: ", pr[0])
    # print("\nSuggested policy is:")
    # print(pr[1])

    # i1 = portion.closed(-portion.inf, 10) | portion.closed(18, portion.inf)
    # print(i1.contains(15))
    # i2 = portion.open("020", "031")
    # i3 = portion.open("030", "100")
    # print(i2.contains(i3))
    # print(i3.contains(i2))
    # print(i2.overlaps(i3))

    # range1 = ["+(2024-01-21 16:00:00,2024-01-21 22:00:00)"]
    # range2 = ["+(2024-01-21 08:00:00,2024-01-21 20:00:00)"]
    # print(util.getNumberRangeRelation(range1, range2))
    # print(util.calculateNumberRange(range1, range2, CalculateType.union))
    # print(util.calculateNumberRange(range1, range2, CalculateType.intersect))
    # print(util.calculateNumberRange(range1, range2, CalculateType.difference))