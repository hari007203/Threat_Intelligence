from django.shortcuts import render
import pymysql
from datetime import datetime
from django.template import RequestContext
from django.contrib import messages
from django.http import HttpResponse
from django.core.files.storage import FileSystemStorage
import os
import matplotlib.pyplot as plt #use to visualize dataset vallues
import io
import base64
import numpy as np
import ipaddress
from maltiverse import Maltiverse
import socket

username = ""
details = None

api = Maltiverse(auth_token="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjIzNjcwMzM4NzYsImlhdCI6MTczNjMxMzg3Niwic3ViIjoyMDc1MiwidXNlcm5hbWUiOiJrYWxlZW0ubW1kIiwiYWRtaW4iOmZhbHNlLCJ0ZWFtX2lkIjpudWxsLCJ0ZWFtX25hbWUiOm51bGwsInRlYW1fbGVhZGVyIjpmYWxzZSwidGVhbV9yZXNlYXJjaGVyIjpmYWxzZSwidGVhbV9pbmRleCI6bnVsbCwiYXBpX2xpbWl0IjoxMDB9.R2lGorrRds3LTmyhA9dzANDFCLAUjUG0muzQYoTwmqw")

def VisualizeThreat(request):
    if request.method == 'GET':
        activity = []
        mysqlConnect = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'threat',charset='utf8')
        with mysqlConnect:
            result = mysqlConnect.cursor()
            result.execute("select url_classification from threats")
            lists = result.fetchall()
            for ls in lists:
                activity.append(ls[0])
        activity = np.asarray(activity)
        print(activity)
        atype, count = np.unique(activity, return_counts=True)
        height = count
        bars = atype
        y_pos = np.arange(len(bars))
        plt.figure(figsize = (6, 3)) 
        plt.bar(y_pos, height)
        plt.xticks(y_pos, bars)
        plt.xlabel("Employee Activities Graph")
        plt.ylabel("Count")
        plt.xticks(rotation=70)
        buf = io.BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight')
        img_b64 = base64.b64encode(buf.getvalue()).decode()
        plt.clf()
        plt.cla()
        context= {'data':"Employee Activities Graph", 'img': img_b64}
        return render(request, 'AdminScreen.html', context)
        

def ViewThreats(request):
    if request.method == 'GET':
        output = '<div class="table-container"><table border=1 align=center width="100%">'
        output+='<tr><th><font size=3 color=black>Employee Name</font></th>'
        output+='<th><font size=3 color=black>Visiting Domain</font></th>'
        output+='<th><font size=3 color=black>Domain Classification Result</font></th>'
        output+='<th><font size=3 color=black>Employee Activity Type</font></th>'
        output+='<th><font size=3 color=black>Activity Date</font></th></tr>'
        mysqlConnect = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'threat',charset='utf8')
        with mysqlConnect:
            result = mysqlConnect.cursor()
            result.execute("select * from threats")
            lists = result.fetchall()
            for ls in lists:
                output+='<tr><td><font size=2 color=black>'+str(ls[0])+'</font></td>'
                output+='<td><font size=2 color=black>'+ls[1]+'</font></td>'
                output+='<td><font size=2 color=black>'+ls[2]+'</font></td>'
                output+='<td><font size=2 color=black>'+ls[3]+'</font></td>'
                output+='<td><font size=2 color=black>'+str(ls[4])+'</font></td></tr>'
        output += "</table></div><br/><br/><br/><br/>"        
        context= {'data':output}            
        return render(request,'AdminScreen.html', context)

def ViewShareThreat(request):
    if request.method == 'GET':
        output = '<div class="table-container"><table border=1 align=center width="100%">'
        output+='<tr><th><font size=3 color=black>Employee Name</font></th>'
        output+='<th><font size=3 color=black>Visiting Domain</font></th>'
        output+='<th><font size=3 color=black>Domain Classification Result</font></th>'
        output+='<th><font size=3 color=black>Employee Activity Type</font></th>'
        output+='<th><font size=3 color=black>Activity Date</font></th></tr>'
        mysqlConnect = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'threat',charset='utf8')
        with mysqlConnect:
            result = mysqlConnect.cursor()
            result.execute("select * from threats")
            lists = result.fetchall()
            for ls in lists:
                output+='<tr><td><font size=2 color=black>'+str(ls[0])+'</font></td>'
                output+='<td><font size=2 color=black>'+ls[1]+'</font></td>'
                output+='<td><font size=2 color=black>'+ls[2]+'</font></td>'
                output+='<td><font size=2 color=black>'+ls[3]+'</font></td>'
                output+='<td><font size=2 color=black>'+str(ls[4])+'</font></td></tr>'
        output += "</table></div><br/><br/><br/><br/>"        
        context= {'data':output}            
        return render(request,'UserScreen.html', context)    

def logMalware(domain, classify, activity):
    global username
    dd = str(datetime.now())
    dbconnection = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'threat',charset='utf8')
    dbcursor = dbconnection.cursor()
    qry = "INSERT INTO threats VALUES('"+str(username)+"','"+domain+"','"+classify+"','"+activity+"','"+dd+"')"
    dbcursor.execute(qry)
    dbconnection.commit()  

def isMalicious(result):
    classification = result.get('classification', 'neutral')
    # Always trust whitelist/neutral - these are Maltiverse-confirmed safe domains
    if classification in ['whitelist', 'neutral']:
        return False
    # Explicitly malicious classification - always block
    if classification == 'malicious':
        return True
    # For 'suspicious' classification, require additional evidence before blocking
    is_phishing = result.get('is_phishing') or result.get('is_storing_phishing')
    tags = result.get('tag', [])
    dangerous_tags = set(['phishing', 'malware', 'trojan', 'ransomware', 'botnet', 'scam'])
    has_dangerous_tag = bool(dangerous_tags.intersection(set(tags))) if tags else False
    blacklist_malicious = False
    for bl in result.get('blacklist', []):
        labels = bl.get('labels', [])
        if 'malicious-activity' in labels or 'compromised' in labels:
            blacklist_malicious = True
            break
    # For suspicious: must also have phishing flag, dangerous tag, or blacklist evidence
    if classification == 'suspicious' and (is_phishing or has_dangerous_tag or blacklist_malicious):
        return True
    # Direct phishing or malware regardless of classification
    if is_phishing or has_dangerous_tag:
        return True
    return False

def AccessPagesAction(request):
    if request.method == 'POST':
        global username
        domain = request.POST.get('t1', False)
        status = ""
        output = ""
        
        # --- LOCAL BLOCKLIST CHECK ---
        try:
            with open('blocklist.txt', 'r') as f:
                blocklist = [line.strip().lower() for line in f if line.strip()]
            
            clean_domain = domain.strip().lower()
            if clean_domain.startswith('www.'):
                clean_domain = clean_domain[4:]
                
            if any(blocked in clean_domain for blocked in blocklist) or \
               any(clean_domain in blocked for blocked in blocklist):
                status = "malicious"
                output = '<td><font size="3" color="red">Domain ('+domain+') contains malicious/malware activities. Not allowed to access</font></a>'
                logMalware(domain, status, 'Browsing '+domain)
                context= {'data':output}
                return render(request,'AccessPages.html', context)
        except Exception:
            pass # Continue if file doesn't exist or other error
        # --- END LOCAL BLOCKLIST CHECK ---

        # --- LOCAL SAFELIST CHECK ---
        try:
            with open('safelist.txt', 'r') as f:
                safelist = [line.strip().lower() for line in f if line.strip()]
            
            clean_domain = domain.strip().lower()
            if clean_domain.startswith('www.'):
                clean_domain = clean_domain[4:]
                
            if any(safe in clean_domain for safe in safelist) or \
               any(clean_domain in safe for safe in safelist):
                status = "safe (local)"
                output = '<a href="https://'+domain+'" target="_blank"><font size="3" color="green">Domain ('+domain+') Is safe. You can proceed. Tap Here</font></a>'
                logMalware(domain, status, 'Browsing '+domain)
                context= {'data':output}
                return render(request,'AccessPages.html', context)
        except Exception:
            pass # Continue to API if file not found
        # --- END LOCAL SAFELIST CHECK ---

        # Strip www. prefix for better hostname matching
        lookup_domain = domain.strip()
        if lookup_domain.lower().startswith('www.'):
            lookup_domain = lookup_domain[4:]
        try:
            clean_ip = socket.gethostbyname(lookup_domain)
        except:
            status = "Invalid domain entered"
        if status != "Invalid domain entered":
            result = api.hostname_get(lookup_domain)
            
            # Check for API Quota Error
            is_quota_error = False
            if result and isinstance(result, dict) and result.get('status') == 'fail' and 'quota' in result.get('message', '').lower():
                is_quota_error = True
                status = "API Quota Exceeded"
            else:
                try:
                    status = result['classification']
                except (KeyError, TypeError):
                    status = "Unable to classify"
            
            print(status, result.get('tag', []) if isinstance(result, dict) else [], result.get('is_phishing') if isinstance(result, dict) else None)
            
            if not is_quota_error and isMalicious(result):
                output = '<td><font size="3" color="red">Domain ('+domain+') contains malicious/malware activities. Not allowed to access</font></a>'
                status = "malicious"
            elif status in ["neutral", "whitelist"] or (is_quota_error and status == "API Quota Exceeded"):
                msg = "is clean you can proceed" if not is_quota_error else "cannot be verified due to API Quota limit, but allowed by default"
                output = '<a href="https://'+domain+'" target="_blank"><font size="3" color="green">Domain ('+domain+') '+msg+'. Tap Here</font></a>'
            else:
                output = '<td><font size="3" color="red">Domain ('+domain+') cannot be verified as safe. Not allowed to access</font></a>'
        else:
            output = "Invalid domain entered"
        logMalware(domain, status, 'Browsing '+domain) 
        context= {'data':output}
        return render(request,'AccessPages.html', context)         

def AccessPages(request):
    if request.method == 'GET':
        return render(request,'AccessPages.html', {})

def index(request):
    if request.method == 'GET':
        return render(request,'index.html', {})

def AdminLogin(request):
    if request.method == 'GET':
       return render(request, 'AdminLogin.html', {})        

def UserLogin(request):
    if request.method == 'GET':
       return render(request, 'UserLogin.html', {})
    
def AddEmp(request):
    if request.method == 'GET':
       return render(request, 'AddEmp.html', {})

def isUserExists(username):
    is_user_exists = False
    global details
    mysqlConnect = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'threat',charset='utf8')
    with mysqlConnect:
        result = mysqlConnect.cursor()
        result.execute("select * from employees where username='"+username+"'")
        lists = result.fetchall()
        for ls in lists:
            is_user_exists = True
    return is_user_exists    

def AddEmpAction(request):
    if request.method == 'POST':
        username = request.POST.get('t1', False)
        password = request.POST.get('t2', False)
        contact = request.POST.get('t3', False)
        email = request.POST.get('t4', False)
        address = request.POST.get('t5', False)
        dept = request.POST.get('t6', False)
        salary = request.POST.get('t7', False)
        desc = request.POST.get('t8', False)
        record = isUserExists(username)
        page = None
        if record == False:
            dbconnection = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'threat',charset='utf8')
            dbcursor = dbconnection.cursor()
            qry = "INSERT INTO employees VALUES('"+str(username)+"','"+password+"','"+contact+"','"+email+"','"+address+"','"+dept+"','"+salary+"','"+desc+"')"
            dbcursor.execute(qry)
            dbconnection.commit()
            if dbcursor.rowcount == 1:
                data = "New employee details added"
                context= {'data':data}
                return render(request,'AddEmp.html', context)
            else:
                data = "Error in adding employee details"
                context= {'data':data}
                return render(request,'AddEmp.html', context) 
        else:
            data = "Given "+username+" already exists"
            context= {'data':data}
            return render(request,'AddEmp.html', context)


def checkUser(uname, password):
    global username
    msg = "Invalid Login Details"
    mysqlConnect = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'threat',charset='utf8')
    with mysqlConnect:
        result = mysqlConnect.cursor()
        result.execute("select * from employees where username='"+uname+"' and password='"+password+"'")
        lists = result.fetchall()
        for ls in lists:
            msg = "success"
            username = uname
            break
    return msg

def logData(username, request):
    ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', '')).split(',')[0].strip()
    print(ip)
    if ip is None:
        ip = "127.0.0.1"
    dd = str(datetime.now())
    classify = "Invalid Login"
    activity = "trying to login as admin"
    dbconnection = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'threat',charset='utf8')
    dbcursor = dbconnection.cursor()
    qry = "INSERT INTO threats VALUES('"+str(username)+"','"+ip+"','"+classify+"','"+activity+"','"+dd+"')"
    dbcursor.execute(qry)
    dbconnection.commit()    

def UserLoginAction(request):
    if request.method == 'POST':
        global username
        username = request.POST.get('t1', False)
        password = request.POST.get('t2', False)
        msg = checkUser(username, password)
        if msg == "success":
            context= {'data':"Welcome "+username}
            return render(request,'UserScreen.html', context)
        else:
            logData(username, request)
            context= {'data':msg}
            return render(request,'UserLogin.html', context)
        
def AdminLoginAction(request):
    if request.method == 'POST':
        global username
        username = request.POST.get('t1', False)
        password = request.POST.get('t2', False)
        if username == "admin" and password == "admin":
            context= {'data':"Welcome "+username}
            return render(request,'AdminScreen.html', context)
        else:
            context= {'data':"Invalid Login"}
            return render(request,'AdminLogin.html', context)










        


        
