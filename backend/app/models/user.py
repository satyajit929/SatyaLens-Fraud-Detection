class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    full_name = Column(String)
    email = Column(String, unique=True)
    mobile = Column(String, unique=True)
    created_at = Column(DateTime)
