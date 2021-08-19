import dateutil.parser
from config import Outputs
from output import MongoConnector
import dateutil.parser

output_file = "loganalyser.output"
output = Outputs()
output.parse_outputs(output_file)
config = output.get_output('mongo')

mc = MongoConnector(config)
col = mc.get_collection()

# db = mc['logs']
# col = db['logs']
#
# print("Addresses Apache")
# res1 = col.aggregate([{"$match": {"name": "apache_access"}}, {"$group": {"_id": "$ip_address", "total": {"$sum": 1}}}])
#
# for k in res1:
#     print(k)
#
# print("")
# print("Codes Apache")
# res1 = col.aggregate([{"$match": {"name": "apache_access"}}, {"$group": {"_id": "$code", "total": {"$sum": 1}}}])
#
# for k in res1:
#     print(k)
#
# print("")
# print("IP Address ssh")
# res2 = col.aggregate([{"$match": {"name": "auth_ssh"}},
#                       {"$group": {"_id": {"username": "$ip_address", "type": "$type"}, "total": {"$sum": 1}}}])
# for j in res2:
#     print(j)
#
# print("")
# print("usernames ssh")
# res2 = col.aggregate([{"$match": {"name": "auth_ssh"}}, {"$group": {"_id": "$username", "total": {"$sum": 1}}}])
# for j in res2:
#     print(j)
# print("")
# res3 = col.aggregate([
#     {
#         "$match": {
#             "name": "auth_ssh"
#         }
#     },
#     {
#         "$group": {
#             "_id": {
#                 "day": {
#                     "$dayOfMonth": "$timestamp"
#                 },
#                 "monh": {
#                     "$month": "$timestamp"
#                 },
#                 "year": {
#                     "$year": "$timestamp"
#                 }
#
#             },
#             "total": {
#                 "$sum": 1
#             },
#             "users": {"$addToSet": "$username"},
#             "ips": {"$addToSet": "$ip_address"}
#         }
#     }
# ]
# )
# for k in res3:
#     print(k)
# print("")

res5 = col.aggregate(
    [
        {
            "$match": {"$and": [{"name": "apache_access"},
                                 {"timestamp": {"$gte": dateutil.parser.isoparse("2021-05-23T00:00:00+0300")}},
                                {"timestamp": {"$lt": dateutil.parser.isoparse("2021-05-24T00:00:00+0300")}},
                                ]
                       }},
        {
            "$group": {
                "_id": {
                    "hour": {
                        "$hour": "$timestamp"
                    },
                    "path": "$path"
                },
                "total": {
                    "$sum": 1
                },
                "ips": {"$addToSet": "$ip_address"}
            }
        },
        { "$sort":  { '_id.hour' : 1,  'total': -1 }}
    ]
)

print("res5")
for p in res5:
    print(p)
print("")
