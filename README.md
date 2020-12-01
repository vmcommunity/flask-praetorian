# flask-praetorian
A modified version of flask-praetorian

With this version you need to put the protection after the api_route, the reason being is that it needs to get the headers and context that isn't available above this properly.

Use: @flask_praetorian.auth_required_jwt_or_api_token for api_token and required_jwt

