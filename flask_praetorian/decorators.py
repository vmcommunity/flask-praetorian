import functools

from flask_praetorian.exceptions import (
    PraetorianError,
    MissingRoleError,
    MissingToken,
)


from flask_praetorian.utilities import (
    current_guard,
    current_token,
    add_jwt_data_to_app_context,
    app_context_has_jwt_data,
    remove_jwt_data_from_app_context,
    current_rolenames
)


def _verify_and_add_jwt(optional=False):
    """
    This helper method just checks and adds jwt data to the app context.
    If optional is False and the header is missing the token, just returns.

    Will not add jwt data if it is already present.

    Only use in this module
    """
    if not app_context_has_jwt_data():
        guard = current_guard()
        try:
            token = guard.read_token_from_header()
        except MissingToken as err:
            if optional:
                return
            raise err
        jwt_data = guard.extract_jwt_token(token)
        add_jwt_data_to_app_context(jwt_data)


def auth_required(method):
    """
    This decorator is used to ensure that a user is authenticated before
    being able to access a flask route. It also adds the current user to the
    current flask context.
    """

    @functools.wraps(method)
    def wrapper(*args, **kwargs):
        _verify_and_add_jwt()
        try:
            return method(*args, **kwargs)
        finally:
            remove_jwt_data_from_app_context()

    return wrapper


def auth_accepted(method):
    """
    This decorator is used to allow an authenticated user to be identified
    while being able to access a flask route, and adds the current user to the
    current flask context.
    """
    @functools.wraps(method)
    def wrapper(*args, **kwargs):
        _verify_and_add_jwt(optional=True)
        try:
            return method(*args, **kwargs)
        finally:
            remove_jwt_data_from_app_context()
    return wrapper

from flask import request, abort, Response

def auth_required_jwt_or_api_token(method):
    """
    This decorator is used to allow an authenticated user to be identified
    while being able to access a flask route, and adds the current user to the
    current flask context.

    For Token store api we need to encode the token, then store the token decoded
    """
    @functools.wraps(method)
    def wrapper(*args, **kwargs):
        # check if we have a header for x-api-key or JWT token
        print("I am here!")
        token_id = request.headers.get('x-api-key', "")
        print(token_id)
        if token_id:
            print("found da x-api-key")
            print("creating a token_store based JWT")
            token = current_token(token_id)
            #token = {"id":1, "token_name":"my_api", "roles":"admin"}
            encoded_jwt = current_guard().encode_jwt_token(token, is_api=True)
            decoded_jwt = current_guard().extract_jwt_token(encoded_jwt)
            add_jwt_data_to_app_context(decoded_jwt)
            try:
                return method(*args, **kwargs)
            finally:
                remove_jwt_data_from_app_context()
        else:
            _verify_and_add_jwt(optional=True)
            try:
                return method(*args, **kwargs)
            finally:
                remove_jwt_data_from_app_context()
    return wrapper


def roles_required(*required_rolenames):
    """
    This decorator ensures that any uses accessing the decorated route have all
    the needed roles to access it. If an @auth_required decorator is not
    supplied already, this decorator will implicitly check @auth_required first
    """

    def decorator(method):
        @functools.wraps(method)
        def wrapper(*args, **kwargs):
            PraetorianError.require_condition(
                not current_guard().roles_disabled,
                "This feature is not available because roles are disabled",
            )
            role_set = set([str(n) for n in required_rolenames])
            #TODO remove this print statement
            print(role_set)
            _verify_and_add_jwt()
            try:
                MissingRoleError.require_condition(
                    current_rolenames().issuperset(role_set),
                    "This endpoint requires all the following roles: "
                    "{}".format([", ".join(role_set)]),
                )
                return method(*args, **kwargs)
            finally:
                remove_jwt_data_from_app_context()

        return wrapper

    return decorator


def roles_accepted(*accepted_rolenames):
    """
    This decorator ensures that any uses accessing the decorated route have one
    of the needed roles to access it. If an @auth_required decorator is not
    supplied already, this decorator will implicitly check @auth_required first
    """

    def decorator(method):
        @functools.wraps(method)
        def wrapper(*args, **kwargs):
            PraetorianError.require_condition(
                not current_guard().roles_disabled,
                "This feature is not available because roles are disabled",
            )
            role_set = set([str(n) for n in accepted_rolenames])
            _verify_and_add_jwt()
            try:
                MissingRoleError.require_condition(
                    not current_rolenames().isdisjoint(role_set),
                    "This endpoint requires one of the following roles: "
                    "{}".format([", ".join(role_set)]),
                )
                return method(*args, **kwargs)
            finally:
                remove_jwt_data_from_app_context()

        return wrapper

    return decorator
