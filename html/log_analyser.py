#!/usr/bin/python3

import json
import time, datetime
from flask import Flask, render_template, request
from output import MongoConnector
from config import Outputs

app = Flask(__name__)
output_file = "../loganalyser.output"


#
# def get_fancy_time(sec):
#     t = datetime.timedelta(seconds=sec)
#     if t.days > 0:
#         return str(t.days) + " days"
#     elif (sec / 3600) > 1:
#         return str(int(sec // 3600)) + " hrs"
#     elif (sec / 60) > 1:
#         return str(int(sec // 60)) + " mins"
#     else:
#         return str(sec) + " sec"
#
#
# @app.route('/fancy_time/<int:sec>', methods=['POST'])
# def fancy_time(sec=0):
#     try:
#         val = str(datetime.timedelta(seconds=sec))
#         return json.dumps({'success': True, 'value': val}), 200, {'ContentType': 'application/json'}
#     except Exception as e:
#         #        raise e
#         return json.dumps({'success': False, 'message': str(e)}), 200, {'ContentType': 'application/json'}
#
#
# @app.route('/getfeed/<int:feedid>/')
# def getfeed(feedid):
#     try:
#         return json.dumps({'success': True, 'result': row}), 200, {'ContentType': 'application/json'}
#     except Exception as e:
#         #        raise e
#         return json.dumps({'success': False, 'message': str(e)}), 200, {'ContentType': 'application/json'}

#
# @app.route('/getfeedname/<int:feedid>', methods=['POST'])
# def getfeedname(feedid):
#     try:
#         check_feed_exists(feedid)
#         db = connect_db.connect_db()
#         cur = db.cursor()
#         sql = "SELECT feeds.name FROM feeds LEFT JOIN category ON feeds.category = category.id WHERE feeds.id = %s LIMIT 1"
#         cur.execute(sql, feedid)
#         row = cur.fetchone()
#         return json.dumps({'success': True, 'result': row['name']}), 200, {'ContentType': 'application/json'}
#     except Exception as e:
#         #        raise e
#         return json.dumps({'success': False, 'message': str(e)}), 200, {'ContentType': 'application/json'}

#
# @app.route('/addfeed/', methods=['POST'])
# def addfeed():
#     try:
#         name = request.form.get('name')
#         url = request.form.get('url')
#         update = request.form.get('update')
#         cleanup = request.form.get('cleanup')
#         feedid = request.form.get('feedid', None)
#         tag = request.form.get('tag', '')
#         category = request.form.get('category', 1)
#         tag_colour = request.form.get('tag_colour')
#
#         return json.dumps({'success': True}), 200, {'ContentType': 'application/json'}
#     except Exception as e:
#         # raise e
#         return json.dumps({'success': False, 'message': str(e)}), 200, {'ContentType': 'application/json'}




def get_mongo_connection():
    output = Outputs()
    output.parse_outputs(output_file)
    config = output.get_output('mongo')

    mc = MongoConnector(config)
    col = mc.get_collection()

    return col


def get_ssh_data(name):
    col = get_mongo_connection()
    rv = []
    keys = []
    if name == 'users':
        keys = ['username', 'count']
        res = col.aggregate([{"$match": {"name": "auth_ssh"}}, {"$group": {"_id": "$username", "total": {"$sum": 1}}}])
        for x in res:
            row = {'username': x['_id'], 'count': x['total']}
            rv.append(row)
    elif name == 'ip_addresses':
        keys = ['username', 'type', 'count']
        res = col.aggregate([{"$match": {"name": "auth_ssh"}},
                             {"$group": {"_id": {"ip_address": "$ip_address", "type": "$type"}, "total": {"$sum": 1}}}])
        for x in res:
            row = {'username': x['_id']['ip_address'], 'count': x['total'], 'type': x['_id']['type']}
            rv.append(row)
    else:
        raise ValueError(name)
    return rv, keys


def get_apache_data(name):
    col = get_mongo_connection()
    rv = []
    keys = []
    if name == 'codes':
        res = col.aggregate([{"$match": {"name": "apache_access"}}, {"$group": {"_id": "$code", "total": {"$sum": 1}}}])
        keys = ['code', 'count']
        for x in res:
            row = {'code': x['_id'], 'count': x['total']}
            rv.append(row)
    elif name == 'ip_addresses':
        res = col.aggregate([{"$match": {"name": "apache_access"}}, {"$group": {"_id": "$ip_address", "total": {"$sum": 1}}}])
        keys = ['ip_address', 'count']
        for x in res:
            row = {'code': x['_id'], 'count': x['total']}
            rv.append(row)
    elif name == 'urls':
        res = col.aggregate(
            [{"$match": {"name": "apache_access"}}, {"$group": {"_id": "$path", "total": {"$sum": 1}}}])
        keys = ['path', 'count']
        for x in res:
            row = {'path': x['_id'], 'count': x['total']}
            rv.append(row)
    elif name == 'urls':
        return rv
    else:
        raise ValueError(name)
    return rv, keys

@app.route('/data/', methods=['POST'])
def data():
    print(request.get_json())
    name = request.json.get('name', '').strip()
    type = request.json.get('type', '').strip()
    if type == 'ssh':
        res, keys = get_ssh_data(name)
    elif type == 'apache':
        res, keys = get_apache_data(name)
    rhtml = render_template("data_table.html", data=res, keys=keys)
    return json.dumps({'success': True, 'rhtml': rhtml}), 200, {'ContentType': 'application/json'}


@app.route('/')
def homepage():
    try:
        return render_template("main.html")
    except Exception as e:
        return json.dumps({'success': False, "message": str(e)}), 200, {'ContentType': 'application/json'}


if __name__ == "__main__":
    app.jinja_env.trim_blocks = True
    app.jinja_env.lstrip_blocks = True
    app.run(host='0.0.0.0', debug=True)
