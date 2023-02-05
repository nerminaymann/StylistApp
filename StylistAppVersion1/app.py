from application import createapp
from werkzeug.serving import WSGIRequestHandler

if __name__ == '__main__':
    WSGIRequestHandler.protocol_version = "HTTP/1.1"

    app = createapp()
    app.run( debug=True,port=5001,host='0.0.0.0')