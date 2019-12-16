###########################################################
#  FLASK                                                  #
#  https://ogma-dev.github.io/posts/simple-flask-webhook/ #
#  pip install flask                                      #
#  -create a file with allowed ip instead of dictionary   #
#                                                         #
###########################################################

import os
from datetime import datetime, timedelta
from flask import Flask, request, abort, jsonify
import smtplib, ssl

port = 465  # For SSL
user = "USER"
password = "PASSWORD"
server = "SERVER"
messg = ""
msg = MIMEText(messg,"plain")
msg['From'] = "your_address"
msg['To'] = "to_address"
msg['Subject'] = "Subscription"


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
                message = request.json
                monitor,trigger,severity,start,end = message['text'].split('-')
                messg="{} {} {} {} {}".format(monitor,trigger,severity,start,end) 

                        
                print(monitor)
                print(trigger)
                print(severity)
                print(start)
                print(end)
                context = ssl.create_default_context()
                with smtplib.SMTP_SSL(server, port, context=context) as server:
                    server.login(user, password)
                    server.sendmail(msg['From'], msg['To'], msg.as_string())
                    server.quit()
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
