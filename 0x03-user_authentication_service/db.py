#!/usr/bin/env python3

"""Database class for managing and updating the database."""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError
from user import Base, User


class DB:
    """Class for handling database operations."""

    def __init__(self):
        """Initializes the database engine and creates tables."""
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self):
        """Provides a database session, creating it if necessary."""
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Adds a new user to the database.
        Args:
            email: The user's email address.
            hashed_password: The hashed password for the user.
        Returns:
            The newly created user object.
        """
        user = User(email=email, hashed_password=hashed_password)
        self._session.add(user)
        self._session.commit()
        return user

    def find_user_by(self, **kwargs) -> User:
        """Finds a user in the database by specified attributes.
        Args:
            **kwargs: Arbitrary keyword arguments to filter users.
        Returns:
            The first user matching the provided filters.
        Raises:
            InvalidRequestError: If an invalid filter key is provided.
            NoResultFound: If no user matches the filters.
        """
        valid_keys = [
            'id',
            'email',
            'hashed_password',
            'session_id',
            'reset_token'
        ]

        for key in kwargs.keys():
            if key not in valid_keys:
                raise InvalidRequestError
        result = self._session.query(User).filter_by(**kwargs).first()
        if result is None:
            raise NoResultFound
        return result

    def update_user(self, user_id: int, **kwargs) -> None:
        """Updates a user's attributes in the database.
        Args:
            user_id: The ID of the user to update.
            **kwargs: The attributes and their new values to update.
        Raises:
            ValueError: If an invalid attribute key is provided.
        """
        user_to_update = self.find_user_by(id=user_id)

        valid_keys = [
            'id',
            'email',
            'hashed_password',
            'session_id',
            'reset_token'
        ]

        for key, value in kwargs.items():
            if key in valid_keys:
                setattr(user_to_update, key, value)
            else:
                raise ValueError
        self._session.commit()
