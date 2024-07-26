import random
import radar
import itertools
import time

from PolicyUtil import Policy, PolicyUtil

user_list = ["Alice", "Bob", "Gary"]
device_list = ["light1", "motion1", "smoke1", "plug1", "camera1", "lock1", "device1"]
capability_map = {
    "gateway1": ["light", "feature"],
    "light1": ["light"],
    "light2": ["light"],
    "motion1": ["sensor"],
    "smoke1": ["sensor"],
    "plug1": ["switch", "feature"],
    "plug2": ["switch", "feature"],
    "camera1": ["video", "sensor", "feature"],
    "thermostat1": ["temperature"],
    "lock1": ["lock"],
    "device1": ["capa1"]
}
attri_map = {
    "gateway1.light": [
        {"name": "switch", "type": "bool", "value":[True, False]},
        {"name": "bright", "type": "number", "value":[10, 100]},
        {"name": "color", "type": "number", "value":[225500, 775533]}
    ],
    "gateway1.feature": [
        {"name": "lampswitch", "type": "bool", "value":[True, False]},
        {"name": "volume", "type": "number", "value":[10, 100]}
    ],
    "light1.light": [
        {"name": "switch", "type": "bool", "value":[True, False]},
        {"name": "bright", "type": "number", "value":[10, 100]},
        {"name": "color", "type": "number", "value":[225500, 775533]}
    ],
    "light2.light": [
        {"name": "switch", "type": "bool", "value":[True, False]},
        {"name": "bright", "type": "number", "value":[10, 100]},
        {"name": "color", "type": "number", "value":[225500, 775533]}
    ],
    "motion1.sensor": [
        {"name": "hasmotion", "type": "bool", "value":[True, False]}
    ],
    "smoke1.sensor": [
        {"name": "hassmoke", "type": "bool", "value":[True, False]}
    ],
    "plug1.switch": [
        {"name": "switch", "type": "bool", "value":[True, False]}
    ],
    "plug1.feature": [
        {"name": "timeduration", "type": "number", "value":[1, 24]}
    ],
    "plug2.switch": [
        {"name": "switch", "type": "bool", "value":[True, False]}
    ],
    "plug2.feature": [
        {"name": "timeduration", "type": "number", "value":[1, 24]}
    ],
    "camera1.video": [
        {"name": "timeduration", "type": "number", "value":[1, 24]}
    ],
    "camera1.sensor": [
        {"name": "people", "type": "bool", "value":[True, False]}
    ],
    "camera1.feature": [
        {"name": "lampswitch", "type": "bool", "value":[True, False]},
        {"name": "aiswitch", "type": "bool", "value":[True, False]},
        {"name": "setpassword", "type": "bool", "value":[True, False]},
        {"name": "volume", "type": "number", "value":[10, 100]}
    ],
    "thermostat1.temperature": [
        {"name": "settemp", "type": "bool", "value":[True, False]},
        {"name": "temprange", "type": "bool", "value":[15, 35]}
    ],
    "lock1.lock": [
        {"name": "setlock", "type": "bool", "value":[True, False]}
    ],
    "device1.capa1": [
        {"name": "attri1", "type": "number", "value":[10, 100]},
        {"name": "attri2", "type": "number", "value":[10, 200]},
        {"name": "attri3", "type": "number", "value":[10, 300]},
        {"name": "attri4", "type": "number", "value":[10, 400]},
        {"name": "attri5", "type": "number", "value":[10, 500]},
        {"name": "attri6", "type": "number", "value":[10, 600]},
        {"name": "attri7", "type": "number", "value":[10, 700]},
        {"name": "attri8", "type": "number", "value":[10, 800]},
        {"name": "attri9", "type": "number", "value":[10, 900]},
        {"name": "attri10", "type": "number", "value":[50, 500]},
        {"name": "attri11", "type": "number", "value":[60, 1000]},
        {"name": "attri12", "type": "number", "value":[70, 1000]},
        {"name": "attri13", "type": "number", "value":[80, 1000]},
        {"name": "attri14", "type": "number", "value":[90, 1000]},
        {"name": "attri15", "type": "number", "value":[100, 1000]},
        {"name": "attri16", "type": "number", "value":[110, 1000]},
        {"name": "attri17", "type": "number", "value":[120, 1000]},
        {"name": "attri18", "type": "number", "value":[130, 1000]},
        {"name": "attri19", "type": "number", "value":[140, 1000]},
        {"name": "attri20", "type": "number", "value":[150, 1000]}
    ]
}

location_list = ["home", "company", "school"]

def isTrueOrFalse():
    if random.random()>=0.5:
        return True
    else:
        return False
    
def getRandomUser():
    return [random.choice(user_list)]

def getRandomDevice():
    return [random.choice(device_list)]

def getRandomCapability(device):
    return [random.choice(capability_map[device])]

def getRandomTimeRange(lower, upper):
    begin_time = radar.random_datetime(lower, upper)
    end_time = radar.random_datetime(lower, upper)
    while(end_time<=begin_time):
        end_time = radar.random_datetime(lower, upper)

    return [begin_time.strftime("%Y-%m-%d %H:%M:%S"), end_time.strftime("%Y-%m-%d %H:%M:%S")]

def getRandomNumberRange(lower, upper):
    begin = random.randint(lower, upper)
    if begin==upper:
        return [upper-1, upper]
    end = random.randint(lower, upper)
    while(end<=begin):
        end = random.randint(lower, upper)

    return [begin, end]

def getOneRandomAttriPermit(capaname):
    result = {}
    attri = random.choice(attri_map[capaname])
    attri_name = attri["name"]
    attri_type = attri["type"]
    attri_value = attri["value"]
    if attri_type=="bool":
        if isTrueOrFalse():
            result[f"{capaname}.{attri_name}"] = True
        else:
            result[f"{capaname}.{attri_name}"] = False
    if attri_type=="number":
        if f"{capaname}.{attri_name}" not in result:
            result[f"{capaname}.{attri_name}"] = []
        result[f"{capaname}.{attri_name}"].append(getRandomNumberRange(attri_value[0], attri_value[1]))

    return result

def getTwoRandomAttriPermit(capaname):
    p1 = getOneRandomAttriPermit(capaname)
    if p1 and len(attri_map[capaname])>1 and isTrueOrFalse():
        p2 = getOneRandomAttriPermit(capaname)
        p2_key = list(p2)[0]
        while p2_key in p1:
            p2 = getOneRandomAttriPermit(capaname)
            p2_key = list(p2)[0]
        p1[p2_key] = p2[p2_key]

    return p1

def getOneAttriPermit(capaname):
    result = {}
    attri = random.choice(attri_map[capaname])
    attri_name = attri["name"]
    attri_type = attri["type"]
    attri_value = attri["value"]
    if attri_type=="bool":
        if isTrueOrFalse():
            result[f"{capaname}.{attri_name}"] = True
        else:
            result[f"{capaname}.{attri_name}"] = False
    if attri_type=="number":
        if f"{capaname}.{attri_name}" not in result:
            result[f"{capaname}.{attri_name}"] = []
        result[f"{capaname}.{attri_name}"].append(getRandomNumberRange(attri_value[0], attri_value[1]))

    return result

def getMultiAttriPermit(capaname, num):
    result = {}
    attri_list = attri_map[capaname]
    attri_num = num if num<=len(attri_list) else len(attri_list)
    for i in range(attri_num):
        attri_permit = getOneAttriPermit(capaname)
        attri_name = list(attri_permit)[0]
        while attri_name in result:
            attri_permit = getOneAttriPermit(capaname)
            attri_name = list(attri_permit)[0]
        result[attri_name] = attri_permit[attri_name]
    return result

def getOneRandomAttriCondition(capaname):
    result = {}
    attri = random.choice(attri_map[capaname])
    attri_name = attri["name"]
    attri_type = attri["type"]
    attri_value = attri["value"]
    
    if attri_type=="bool":
        if isTrueOrFalse():
            result[f"{capaname}.{attri_name}"] = True
        else:
            result[f"{capaname}.{attri_name}"] = True
    if attri_type=="number":
        if f"{capaname}.{attri_name}" not in result:
            result[f"{capaname}.{attri_name}"] = []
        result[f"{capaname}.{attri_name}"].append(getRandomNumberRange(attri_value[0], attri_value[1]))
    return result

def getTwoRandomAttriCondition(capaname):
    c1 = getOneRandomAttriCondition(capaname)
    if len(attri_map[capaname])>1 and isTrueOrFalse():
        c2 = getOneRandomAttriCondition(capaname)
        c2_key = list(c2)[0]
        while c2_key in c1:
            c2 = getOneRandomAttriCondition(capaname)
            c2_key = list(c2)[0]
        c1[c2_key] = c2[c2_key]

    return c1

def getOneAttriCondition(capaname):
    result = {}
    attri = random.choice(attri_map[capaname])
    attri_name = attri["name"]
    attri_type = attri["type"]
    attri_value = attri["value"]
    if attri_type=="bool":
        if isTrueOrFalse():
            result[f"{capaname}.{attri_name}"] = True
        else:
            result[f"{capaname}.{attri_name}"] = True
    if attri_type=="number":
        if f"{capaname}.{attri_name}" not in result:
            result[f"{capaname}.{attri_name}"] = []
        result[f"{capaname}.{attri_name}"].append(getRandomNumberRange(attri_value[0], attri_value[1]))
    return result

def getMultiAttriCondition(capaname, num):
    result = {}
    for i in range(num):
        attri_condition = getOneAttriCondition(capaname)
        attri_name = list(attri_condition)[0]
        while attri_name in result:
            attri_condition = getOneAttriCondition(capaname)
            attri_name = list(attri_condition)[0]
        result[attri_name] = attri_condition[attri_name]
    return result

def getRandomPolicy(name):
    p = Policy()
    p.name = name
    p.user = ["Alice"] # getRandomUser() # ["Alice"]
    p.device = ["device1"] # getRandomDevice() # ["light1"]
    capa_list = ["capa1"] # getRandomCapability(p.device[0]) # ["light"]
    p.capability = [f"{p.device[0]}.{capa}" for capa in capa_list]

    p.status_permit = True if isTrueOrFalse() else False
    p.action_permit = True if isTrueOrFalse() else False

    # if isTrueOrFalse():
    #     p.attri_permit = {}
    #     capa = p.capability[0]
    #     attri_permit_map = getTwoRandomAttriPermit(capa)
    #     for key in attri_permit_map:
    #         p.attri_permit[key] = attri_permit_map[key]
    p.attri_permit = getMultiAttriPermit("device1.capa1", 20)

    # if isTrueOrFalse():
    p.time_condition = []
    range = getRandomTimeRange("2024-01-07T00:00:00", "2024-01-17T00:00:00")
    p.time_condition.append(range)
    if isTrueOrFalse():
        range = getRandomTimeRange("2024-01-07T00:00:00", "2024-01-17T00:00:00")
        p.time_condition.append(range)

    # if isTrueOrFalse():
    p.location_condition = [random.choice(location_list)]

    # if isTrueOrFalse():
    #     p.attri_condition = {}
    #     capa = p.capability[0]
    #     attri_condition_map = getTwoRandomAttriCondition(capa)
    #     for key in attri_condition_map:
    #         p.attri_condition[key] = attri_condition_map[key]
    p.attri_condition = getMultiAttriCondition("device1.capa1", 20)

    return p

def getRandomPolicyList(size):
    p_list = []
    for i in range(size):
        name = f"p{i}"
        p_list.append(getRandomPolicy(name))
    return p_list

def savePolicyList(policy_list):
    filename = f"policy_list_{time.time()}.txt"
    with open(filename, "w") as f:
        for policy in policy_list:
            f.write(str(policy))
            f.write("\n")

def checkPolicyRelation(policy_list):
    time_begin = time.time()
    policy_util = PolicyUtil()
    relation_map = {}
    combination = list(itertools.combinations(policy_list, 2))
    print(f"combination total: {len(combination)}")
    relation_time_list = []
    for comb in combination:
        time_begin_p = time.time()
        relation = policy_util.getPolicyRelationOnSingleUserDeviceCapability(comb[0], comb[1])
        time_end_p = time.time()
        relation_time_list.append(time_end_p-time_begin_p)

        if relation[0] not in relation_map:
            relation_map[relation[0]] = 1
        else:
            relation_map[relation[0]] = relation_map[relation[0]]+1
    time_end = time.time()

    count = 0
    for key in relation_map:
        count += relation_map[key]
        print(f"{key}: {relation_map[key]}")
    print(f"total time: {time_end-time_begin}")
    print(f"average time of combination: {sum(relation_time_list)/len(relation_time_list)}")

if __name__=="__main__":
    # print(getRandomPolicy("p1"))

    # l = getRandomPolicyList(10)
    # for p in l:
    #     print(p)

    policy_list = getRandomPolicyList(300)
    # savePolicyList(policy_list)
    checkPolicyRelation(policy_list)