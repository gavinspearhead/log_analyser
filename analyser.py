from pymongo import MongoClient

mc = MongoClient()

db = mc['logs']
col = db['logs']

for i in col.find({}):
    print(i)

print("Addresses Apache")
res1 = col.aggregate([{"$match": {"name": "apache_access"}}, {"$group": {"_id": "$ip_address", "total": {"$sum": 1}}}])

for k in res1:
    print(k)

print("IP Address ssh")
res2 = col.aggregate([{"$match": {"name": "auth_ssh"}}, {"$group": {"_id": "$ip_address", "total": {"$sum": 1}}}])
for j in res2:
    print(j)


print("")
print("usernames ssh")
res2 = col.aggregate([{"$match": {"name": "auth_ssh"}}, {"$group": {"_id": "$username", "total": {"$sum": 1}}}])
for j in res2:
    print(j)
print("")
res3 = col.aggregate([
    {
        "$match": {
            "name": "auth_ssh"
        }
    },
    {
        "$group": {
            "_id": {
                "day": {
                    "$dayOfMonth": "$timestamp"
                },
                "monh": {
                    "$month": "$timestamp"
                },
                "year": {
                    "$year": "$timestamp"
                }

            },
            "total": {
                "$sum": 1
            },
            "users": {"$addToSet": "$username"}
        }
    }
]
)
for k in res3:
    print(k)
print("")

res5 = col.aggregate(
    [
        {
            "$match": {
                "name": "apache_access"
            }
        },
        {
            "$group": {
                "_id": {
                    "day": {
                        "$dayOfMonth": "$timestamp"
                    },
                    "month": {
                        "$month": "$timestamp"
                    },
                    "year": {
                        "$year": "$timestamp"
                    },
                    "path": "$path"
                },
                "total": {
                    "$sum": 1
                },
                "ips": {"$addToSet": "$ip_address"}
            }
        }
    ]
)

print("res5")
for p in res5:
    print(p)
print("")
