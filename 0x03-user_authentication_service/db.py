#!/usr/bin/env python3
"""
Database interaction module.
"""


from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import InvalidRequestError, NoResultFound
from user import Base, User

class DB:
    """DB class for database operations"""

    def __init__(self) -> None:
        """Initialize the database engine and session."""
        self._engine = create_engine("sqlite:///a.db", echo=True)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self):
        """Memoized session object"""
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Add a user to the database."""
        user = User(email=email, hashed_password=hashed_password)
        self._session.add(user)
        self._session.commit()
        return user

    def find_user_by(self, **kwargs) -> User:
        """Find a user using keyword arguments."""
        try:
            return self._session.query(User).filter_by(**kwargs).first()
        except InvalidRequestError as e:
            raise InvalidRequestError("Invalid query argument.")
        except NoResultFound:
            raise NoResultFound("No result found for the given parameters.")

    def update_user(self, user_id: int, **kwargs) -> None:
        """Update a user's attributes."""
        user = self.find_user_by(id=user_id)
        for key, value in kwargs.items():
            if not hasattr(user, key):
                raise ValueError(f"{key} is not a valid attribute of User")
            setattr(user, key, value)
        self._session.commit()
