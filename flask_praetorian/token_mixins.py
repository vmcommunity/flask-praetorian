class SQLAlchemyTokenMixin:
    """
    A short-cut providing required methods and attributes for a company class
    implemented with sqlalchemy. Makes many assumptions about how the class
    is defined.

    ASSUMPTIONS:
    * The model has an ``id`` column that uniquely identifies each instance
    * The model has a ``rolenames`` column that contains the roles for the
      user instance as a comma separated list of roles
    * The model has a ``token_name`` column that is a unique string for each
      instance
    * This presumes a user doesn't have an API token, but the company has API tokens for it's service
    * The model has a 1:M of tokens in some token store
    """

    @property
    def identity(self):
        """
        Provides the required attribute or property ``identity``
        """
        return self.id

    # TODO remove this - should not be available
    @property
    def password(self):
        """
        Provides the required attribute or property ``password``
        """
        return self.hashed_password

    @property
    def rolenames(self):
        """
        Provides the required attribute or property ``rolenames``
        """
        try:
            return self.roles.split(",")
        except Exception:
            return []

    # TODO today token_names are not unique!!
    # Fix - we shouldn't be using this feature in our code today
    @classmethod
    def lookup(cls, token_name):
        """
        Provides the required classmethod ``lookup()``
        """
        return cls.query.filter_by(token_name=token_name).one_or_none()

    # this is given a token if there is a token!
    @classmethod
    def identify(cls, id):
        """
        Provides the required classmethod ``identify()``
        """
        return cls.query.get(id)
