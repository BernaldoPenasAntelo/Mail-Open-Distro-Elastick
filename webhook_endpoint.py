import os, re
from datetime import datetime, timedelta
from flask import Flask, request, abort, jsonify
import smtplib, ssl
from email.mime.text import MIMEText
from secrets import user, password, ser, port, port_SSL

messg = ""
msg = MIMEText(messg,"plain")
msg['From'] = ""
msg['To'] = "xturnerp_v662i@zmat.xyz"
msg['Subject'] = "Alerta test1"


def temp_token():
    import binascii
    temp_token = binascii.hexlify(os.urandom(24))
    return temp_token.decode('utf-8')

WEBHOOK_VERIFY_TOKEN = os.getenv('WEBHOOK_VERIFY_TOKEN')
CLIENT_AUTH_TIMEOUT = 1 # in Hours

app = Flask(__name__)

authorised_clients = {}


@app.route('/webhook', methods=['GET', 'POST'])
def webhook():
    if request.method == 'GET':
        verify_token = request.args.get('verify_token')
        if verify_token == WEBHOOK_VERIFY_TOKEN:
            authorised_clients[request.remote_addr] = datetime.now()
            return jsonify({'status':'success'}), 200
        else:
            return jsonify({'status':'bad token'}), 401

    elif request.method == 'POST':
        client = request.remote_addr
        if client in authorised_clients:
            if datetime.now() - authorised_clients.get(client) > timedelta(hours=CLIENT_AUTH_TIMEOUT):
                authorised_clients.pop(client)
                return jsonify({'status':'authorisation timeout'}), 401
            else:                
                print(authorised_clients)
                message = request.json
                m1 = 'Subject: {}\n\n{}'.format(msg['Subject'],message['text'])
                cont = sum(map(lambda x : 1 if '-' in x else 0, m1))
                if cont == 4:
                    monitor,trigger,severity,start,end = m1.split('-')
                    messg='Subject: {}\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}'.format(msg['Subject'],monitor,trigger,severity,start,end) 
                else:
                    messg=m1
                        
                context = ssl.create_default_context()
                try:
                    smtpObj = smtplib.SMTP(ser, port)
                except Exception as e:
                    print(e)
                    smtpObj = smtplib.SMTP_SSL(ser,port_SSL, context=context)
                smtpObj.ehlo()
                smtpObj.starttls()
                smtpObj.login(user, password)
                smtpObj.sendmail(msg['From'], msg['To'], messg) 

                smtpObj.quit()
                return jsonify({'status':'success'}), 200
        else:
            return jsonify({'status':'not authorised'}), 401

    else:
        abort(400)

if __name__ == '__main__':
    if WEBHOOK_VERIFY_TOKEN is None:
        print('WEBHOOK_VERIFY_TOKEN has not been set in the environment.\nGenerating random token...')
        token = temp_token()
        print('Token: %s' % token)
        WEBHOOK_VERIFY_TOKEN = token
    app.run()
