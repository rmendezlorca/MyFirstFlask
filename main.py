from flask import Flask
app = Flask('app')

@app.route('/')
def hello_world():
  return 'Hello, World!'
@app.route('/hellowworldspanish/', methods=['GET'])
def hellow_world_spanish():
  return "Hola Mundo"
app.run(host='0.0.0.0', port=8080)
