class ConnectedApp(Base):
    __tablename__ = "connected_apps"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    app_type = Column(String)
    connected_at = Column(DateTime)