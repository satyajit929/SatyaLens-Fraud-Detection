@router.post("/register")
async def register(user_data: dict):
    # Create user and send OTP
    pass

@router.post("/verify-otp") 
async def verify_otp(otp_data: dict):
    # Verify OTP and return user data + token
    pass