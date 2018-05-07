from eve import Eve
from flask import Blueprint

from auth.login import auth

app = Eve()
app.register_blueprint(auth, url_prefix='/auth')

if __name__ == '__main__':
    app.run(debug=True)